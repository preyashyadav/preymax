import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import {
  DEFAULT_CONFIG,
  generateSecret,
  generateTopic,
  loadConfig,
  saveConfig,
  type Config,
} from '../core/config.js';
import { ensurePolicyFile } from '../core/policy.js';
import { LAUNCHD_LABEL, paths } from '../core/paths.js';

/**
 * `preymax init` — register hooks, install the launch agent, generate secrets.
 *
 * Idempotent by requirement: re-running must not duplicate the hook entry, must
 * not regenerate the secret (that would invalidate every notification already on
 * your phone), and must not clobber a policy you have tuned.
 */

export interface HookEntry {
  type: 'http';
  url: string;
  timeout?: number;
  headers?: Record<string, string>;
  allowedEnvVars?: string[];
}

const HOOK_MARKER = '/hook';

export function buildHookEntry(port: number): HookEntry {
  return {
    type: 'http',
    url: `http://127.0.0.1:${port}${HOOK_MARKER}`,
    // Generous relative to the daemon's own decisionTimeoutMs so the daemon
    // always wins the race and returns a real decision. If the daemon is dead,
    // Claude Code treats a connection failure as non-blocking and prompts
    // normally — no waiting on this timeout.
    timeout: 120,
    headers: { 'X-Preymax-Name': '$PREYMAX_NAME' },
    // Without this allowlist, $PREYMAX_NAME silently interpolates to an empty
    // string. No warning, no error. This one line is worth hours.
    allowedEnvVars: ['PREYMAX_NAME'],
  };
}

function isPreymaxHook(h: unknown): boolean {
  return (
    !!h &&
    typeof h === 'object' &&
    (h as HookEntry).type === 'http' &&
    typeof (h as HookEntry).url === 'string' &&
    (h as HookEntry).url.includes(HOOK_MARKER) &&
    /127\.0\.0\.1|localhost/.test((h as HookEntry).url)
  );
}

/**
 * Merge our hook into a settings object. Pure — returns the new object and
 * whether anything changed, so it can be unit-tested without touching disk.
 */
export function mergeHook(
  settings: Record<string, unknown>,
  entry: HookEntry,
): { settings: Record<string, unknown>; changed: boolean } {
  const next = structuredClone(settings) as Record<string, unknown>;
  const hooks = (next.hooks ??= {}) as Record<string, unknown>;
  const preToolUse = (hooks.PreToolUse ??= []) as Array<Record<string, unknown>>;

  if (!Array.isArray(hooks.PreToolUse)) {
    throw new Error('settings.hooks.PreToolUse exists but is not an array — refusing to modify it');
  }

  for (const group of preToolUse) {
    const list = group.hooks;
    if (!Array.isArray(list)) continue;
    const idx = list.findIndex(isPreymaxHook);
    if (idx !== -1) {
      // Already registered. Replace in place so a port or header change takes
      // effect, but don't add a second entry.
      const before = JSON.stringify(list[idx]);
      list[idx] = entry;
      return { settings: next, changed: before !== JSON.stringify(entry) };
    }
  }

  preToolUse.push({ matcher: '*', hooks: [entry] });
  return { settings: next, changed: true };
}

export function removeHook(settings: Record<string, unknown>): {
  settings: Record<string, unknown>;
  changed: boolean;
} {
  const next = structuredClone(settings) as Record<string, unknown>;
  const hooks = next.hooks as Record<string, unknown> | undefined;
  const groups = hooks?.PreToolUse;
  if (!Array.isArray(groups)) return { settings: next, changed: false };

  let changed = false;
  for (const group of groups as Array<Record<string, unknown>>) {
    const list = group.hooks;
    if (!Array.isArray(list)) continue;
    const kept = (list as unknown[]).filter((h) => !isPreymaxHook(h));
    if (kept.length !== list.length) changed = true;
    group.hooks = kept;
  }
  // Drop groups we emptied.
  (hooks as Record<string, unknown>).PreToolUse = (groups as Array<Record<string, unknown>>).filter(
    (g) => !Array.isArray(g.hooks) || g.hooks.length > 0,
  );
  return { settings: next, changed };
}

function backupSettings(file: string): string | null {
  if (!existsSync(file)) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backup = `${file}.preymax-backup-${stamp}`;
  copyFileSync(file, backup);
  return backup;
}

function readSettings(file: string): Record<string, unknown> {
  if (!existsSync(file)) return {};
  const text = readFileSync(file, 'utf8').trim();
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch (err) {
    throw new Error(
      `${file} is not valid JSON (${(err as Error).message}). ` +
        'Fix it by hand before running preymax init — refusing to overwrite it.',
    );
  }
}

function daemonEntrypoint(): string {
  // dist/commands/init.js -> dist/cli.js
  return fileURLToPath(new URL('../cli.js', import.meta.url));
}

export function buildLaunchAgentPlist(cfg: Config): string {
  const node = process.execPath;
  const cli = daemonEntrypoint();
  const args = cfg.caffeinate
    ? // caffeinate -dis: no display sleep, no idle sleep, no system sleep while
      // the daemon runs. This has a real battery cost — documented in the README.
      ['/usr/bin/caffeinate', '-dis', node, cli, 'daemon']
    : [node, cli, 'daemon'];

  const argXml = args.map((a) => `      <string>${escapeXml(a)}</string>`).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
${argXml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>${escapeXml(paths.daemonLog())}</string>
    <key>StandardErrorPath</key>
    <string>${escapeXml(paths.daemonErrLog())}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PREYMAX_HOME</key>
        <string>${escapeXml(paths.home())}</string>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
`;
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export interface InitOptions {
  installAgent: boolean;
  port?: number;
  publicBaseUrl?: string;
}

export function runInit(opts: InitOptions): void {
  mkdirSync(paths.home(), { recursive: true });

  // 1. Config. Preserve an existing secret and topic — regenerating either
  // would orphan every notification already sitting on the phone.
  const existing = existsSync(paths.config()) ? loadConfig() : null;
  const cfg: Config = {
    ...DEFAULT_CONFIG,
    ...(existing ?? {}),
    port: opts.port ?? existing?.port ?? DEFAULT_CONFIG.port,
    secret: existing?.secret || generateSecret(),
    notify: {
      ...DEFAULT_CONFIG.notify,
      ...(existing?.notify ?? {}),
      ntfy: {
        ...DEFAULT_CONFIG.notify.ntfy,
        ...(existing?.notify?.ntfy ?? {}),
        topic: existing?.notify?.ntfy?.topic || generateTopic(),
      },
    },
    publicBaseUrl: opts.publicBaseUrl ?? existing?.publicBaseUrl ?? null,
  };
  saveConfig(cfg);
  console.log(`config      ${paths.config()}${existing ? ' (updated)' : ' (created)'}`);

  // 2. Policy — never overwrite a tuned policy.
  const policyFile = ensurePolicyFile();
  console.log(`policy      ${policyFile}`);

  // 3. Hook registration, with a backup first.
  const settingsFile = paths.claudeSettings();
  mkdirSync(dirname(settingsFile), { recursive: true });
  const backup = backupSettings(settingsFile);
  if (backup) console.log(`backup      ${backup}`);

  const settings = readSettings(settingsFile);
  const { settings: merged, changed } = mergeHook(settings, buildHookEntry(cfg.port));
  if (changed) {
    writeFileSync(settingsFile, JSON.stringify(merged, null, 2) + '\n');
    console.log(`hook        registered in ${settingsFile}`);
  } else {
    console.log(`hook        already registered (no change)`);
  }

  // 4. Launch agent.
  if (opts.installAgent) {
    const plistPath = paths.launchAgent();
    mkdirSync(dirname(plistPath), { recursive: true });
    writeFileSync(plistPath, buildLaunchAgentPlist(cfg));
    console.log(`launchd     ${plistPath}`);
    try {
      execFileSync('launchctl', ['unload', plistPath], { stdio: 'ignore' });
    } catch {
      /* not loaded yet — expected on first install */
    }
    try {
      execFileSync('launchctl', ['load', '-w', plistPath], { stdio: 'pipe' });
      console.log(`launchd     loaded (${LAUNCHD_LABEL})`);
    } catch (err) {
      console.log(`launchd     load failed: ${(err as Error).message}`);
      console.log(`            start it by hand with: preymax daemon`);
    }
  }

  console.log('');
  console.log('Next:');
  console.log('  1. Name your terminals. In .vscode/settings.json, give each profile');
  console.log('     a PREYMAX_NAME env var (see docs/vscode.md).');
  console.log('  2. preymax doctor      — verify the whole path end to end');
  console.log('  3. preymax tail        — watch events as they arrive');
  if (!cfg.publicBaseUrl) {
    console.log('');
    console.log('  Phone approval is OFF until you set publicBaseUrl:');
    console.log('     preymax init --public-url https://<your-mac>.<tailnet>.ts.net:7717');
    console.log('  Until then notifications are read-only and you approve with');
    console.log('  `preymax approve <id>` at the Mac.');
  }
  console.log('');
  console.log(`  ntfy topic: ${cfg.notify.ntfy.topic}`);
  console.log('  Subscribe to that topic in the ntfy app. Anyone who knows it can');
  console.log('  read your notifications — treat it as a secret.');
}
