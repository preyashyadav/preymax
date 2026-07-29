import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import {
  DEFAULT_CONFIG,
  generateSecret,
  generateTopic,
  loadConfig,
  resolveApiKey,
  saveConfig,
  type Config,
} from '../core/config.js';
import { ensurePolicyFile } from '../core/policy.js';
import { LAUNCHD_LABEL, paths } from '../core/paths.js';
import { buildHookEntry, mergeHook, type HookEntry } from '../hook/registry.js';
import { discoverConfigDirs, type ConfigDir } from '../hook/discover.js';

// Re-exported: these moved to hook/registry.ts when registration stopped being a
// single-file operation. Kept here so existing importers and tests still resolve.
export { buildHookEntry, mergeHook, removeHook, isPreymaxHook } from '../hook/registry.js';
export type { HookEntry } from '../hook/registry.js';

/**
 * `preymax init` — register hooks, install the launch agent, generate secrets.
 *
 * Idempotent by requirement: re-running must not duplicate the hook entry, must
 * not regenerate the secret (that would invalidate every notification already on
 * your phone), and must not clobber a policy you have tuned.
 */

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
        <string>${escapeXml(paths.home())}</string>${apiKeyXml(cfg)}
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

/**
 * Bake the API key into the launch agent.
 *
 * launchd does not inherit the user's shell environment, so `export
 * ANTHROPIC_API_KEY` in .zshrc never reaches the daemon — summaries silently
 * degraded to templates for the daemon's entire life while doctor reported
 * green (handoff bug 2). `init` runs *in* your shell, so this is the one moment
 * the key is visible and can be handed over.
 *
 * The plist therefore holds a secret and is chmod 600 by the caller.
 */
function apiKeyXml(cfg: Config): string {
  const key = resolveApiKey(cfg);
  if (!key) return '';
  return `
        <key>ANTHROPIC_API_KEY</key>
        <string>${escapeXml(key)}</string>`;
}

export interface InitOptions {
  installAgent: boolean;
  port?: number;
  publicBaseUrl?: string;
  /** Repeatable --config-dir. Registered even if not yet present on disk. */
  configDirs?: string[];
  /** Trees to scan for .envrc / .vscode CLAUDE_CONFIG_DIR declarations. */
  scanRoots?: string[];
}

/**
 * Register the hook in every discovered config directory.
 *
 * Each file is backed up before modification. A directory that cannot be
 * written is reported and skipped — one unwritable account must not abort
 * registration for the others.
 */
export function registerHooks(dirs: ConfigDir[], entry: HookEntry): void {
  for (const dir of dirs) {
    const label = dir.path.replace(process.env.HOME ?? '~', '~');

    if (dir.warning) {
      console.log(`hook        ${label} — SKIPPED`);
      console.log(`            ${dir.warning}`);
      continue;
    }
    if (!dir.exists && !dir.sources.includes('explicit')) {
      console.log(`hook        ${label} — not present, skipped`);
      continue;
    }
    if (dir.error) {
      console.log(`hook        ${label} — unreadable settings.json, skipped`);
      console.log(`            ${dir.error}`);
      continue;
    }

    try {
      mkdirSync(dirname(dir.settingsPath), { recursive: true });
      const backup = backupSettings(dir.settingsPath);
      const settings = readSettings(dir.settingsPath);
      const { settings: merged, changed } = mergeHook(settings, entry);
      if (changed) {
        writeFileSync(dir.settingsPath, JSON.stringify(merged, null, 2) + '\n');
        console.log(`hook        ${label} — registered [${dir.sources.join(',')}]`);
        if (backup) console.log(`            backup ${backup}`);
      } else {
        console.log(`hook        ${label} — already registered`);
      }
    } catch (err) {
      console.log(`hook        ${label} — FAILED: ${(err as Error).message}`);
    }
  }
}

export function runInit(opts: InitOptions): void {
  mkdirSync(paths.home(), { recursive: true });

  // 1. Config. Preserve an existing secret and topic — regenerating either
  // would orphan every notification already sitting on the phone.
  const existing = existsSync(paths.config()) ? loadConfig() : null;

  // Discover before saving: the resolved set is persisted into the config so it
  // is visible, auditable and hand-editable rather than re-derived each run.
  const dirs = discoverConfigDirs({
    explicit: opts.configDirs,
    persisted: existing?.configDirs,
    scanRoots: opts.scanRoots,
  });

  const cfg: Config = {
    ...DEFAULT_CONFIG,
    ...(existing ?? {}),
    port: opts.port ?? existing?.port ?? DEFAULT_CONFIG.port,
    configDirs: dirs.filter((d) => d.exists || d.sources.includes('explicit')).map((d) => d.path),
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

  // 3. Hook registration across every discovered config directory.
  registerHooks(dirs, buildHookEntry(cfg.port));

  // 4. Launch agent.
  if (opts.installAgent) {
    const plistPath = paths.launchAgent();
    mkdirSync(dirname(plistPath), { recursive: true });
    writeFileSync(plistPath, buildLaunchAgentPlist(cfg));
    // The plist may now carry the API key, so it must not be world-readable.
    chmodSync(plistPath, 0o600);
    console.log(`launchd     ${plistPath}`);
    if (resolveApiKey(cfg)) {
      console.log('launchd     ANTHROPIC_API_KEY passed to the daemon (plist is 0600)');
    }
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
