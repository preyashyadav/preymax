import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { loadConfig, resolveApiKey } from '../core/config.js';
import { LAUNCHD_LABEL, paths } from '../core/paths.js';
import { loadPolicy } from '../core/policy.js';
import { findTailnetAddress } from '../daemon/net.js';
import { publish } from '../notify/ntfy.js';
import { fetchHealth } from './client.js';

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

type Status = 'ok' | 'warn' | 'fail';

interface Check {
  name: string;
  status: Status;
  detail: string;
  fix?: string;
}

function mark(s: Status): string {
  return s === 'ok' ? `${GREEN}✓${RESET}` : s === 'warn' ? `${YELLOW}!${RESET}` : `${RED}✗${RESET}`;
}

/**
 * `preymax doctor` — verify hook registration, daemon health, tailnet
 * reachability, and push delivery. Each check reports the fix, not just the
 * failure, because this is the command you run when something is already wrong.
 */
export async function runDoctor(opts: { push: boolean }): Promise<number> {
  const checks: Check[] = [];
  let cfg;

  try {
    cfg = loadConfig();
    checks.push({ name: 'config', status: 'ok', detail: paths.config() });
  } catch (err) {
    checks.push({
      name: 'config',
      status: 'fail',
      detail: (err as Error).message,
      fix: 'preymax init',
    });
    report(checks);
    return 1;
  }

  // Secret
  checks.push(
    cfg.secret
      ? { name: 'secret', status: 'ok', detail: 'present' }
      : { name: 'secret', status: 'fail', detail: 'missing', fix: 'preymax init' }
  );

  // Config file permissions — it holds the approval secret.
  try {
    const mode = statSync(paths.config()).mode & 0o777;
    checks.push(
      mode === 0o600
        ? { name: 'config perms', status: 'ok', detail: '0600' }
        : {
            name: 'config perms',
            status: 'warn',
            detail: `0${mode.toString(8)} — the approval secret is readable by others`,
            fix: `chmod 600 ${paths.config()}`,
          },
    );
  } catch {
    /* covered by the config check above */
  }

  // Policy
  try {
    const p = loadPolicy();
    checks.push({
      name: 'policy',
      status: 'ok',
      detail: `${p.auto_allow.length} allow / ${p.auto_deny.length} deny rules`,
    });
  } catch (err) {
    checks.push({
      name: 'policy',
      status: 'fail',
      detail: (err as Error).message,
      fix: `edit ${paths.policy()}`,
    });
  }

  // Hook registration
  const settingsFile = paths.claudeSettings();
  if (!existsSync(settingsFile)) {
    checks.push({
      name: 'hook',
      status: 'fail',
      detail: `${settingsFile} does not exist`,
      fix: 'preymax init',
    });
  } else {
    try {
      const settings = JSON.parse(readFileSync(settingsFile, 'utf8')) as Record<string, unknown>;
      const groups = (settings.hooks as Record<string, unknown> | undefined)?.PreToolUse;
      const entries = Array.isArray(groups)
        ? (groups as Array<{ hooks?: unknown[] }>).flatMap((g) => g.hooks ?? [])
        : [];
      const ours = entries.filter(
        (h): h is { url: string; allowedEnvVars?: string[] } =>
          !!h && typeof h === 'object' && typeof (h as { url?: unknown }).url === 'string' &&
          (h as { url: string }).url.includes('/hook'),
      );

      if (ours.length === 0) {
        checks.push({ name: 'hook', status: 'fail', detail: 'not registered', fix: 'preymax init' });
      } else if (ours.length > 1) {
        checks.push({
          name: 'hook',
          status: 'warn',
          detail: `${ours.length} preymax hooks registered — every tool call fires all of them`,
          fix: `remove the duplicates from ${settingsFile}`,
        });
      } else {
        const entry = ours[0]!;
        const portMatches = entry.url.includes(`:${cfg.port}/`);
        const envAllowed = entry.allowedEnvVars?.includes('PREYMAX_NAME') ?? false;
        checks.push({
          name: 'hook',
          status: portMatches ? 'ok' : 'warn',
          detail: portMatches
            ? entry.url
            : `${entry.url} but config.port is ${cfg.port} — the hook points at nothing`,
          ...(portMatches ? {} : { fix: 'preymax init' }),
        });
        checks.push(
          envAllowed
            ? { name: 'PREYMAX_NAME', status: 'ok', detail: 'allowlisted for header interpolation' }
            : {
                name: 'PREYMAX_NAME',
                status: 'warn',
                detail:
                  'not in allowedEnvVars — $PREYMAX_NAME resolves to an empty string, silently, ' +
                  'and every terminal falls back to cwd+branch naming',
                fix: 'preymax init',
              },
        );
      }
    } catch (err) {
      checks.push({
        name: 'hook',
        status: 'fail',
        detail: `${settingsFile} is not valid JSON: ${(err as Error).message}`,
        fix: 'fix the JSON by hand, then preymax init',
      });
    }
  }

  // Daemon
  let daemonUp = false;
  try {
    const health = await fetchHealth();
    daemonUp = true;
    checks.push({
      name: 'daemon',
      status: 'ok',
      detail: `up on 127.0.0.1:${cfg.port} · ${health.pending} pending · summarizer ${health.summarizer}`,
    });
  } catch (err) {
    checks.push({
      name: 'daemon',
      status: 'fail',
      detail: (err as Error).message.split('\n')[0]!,
      fix: 'preymax daemon   (or: launchctl load -w ' + paths.launchAgent() + ')',
    });
  }

  // launchd
  try {
    const out = execFileSync('launchctl', ['list'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const line = out.split('\n').find((l) => l.includes(LAUNCHD_LABEL));
    checks.push(
      line
        ? { name: 'launchd', status: 'ok', detail: line.trim() }
        : {
            name: 'launchd',
            status: 'warn',
            detail: 'agent not loaded — the daemon will not survive a reboot',
            fix: `launchctl load -w ${paths.launchAgent()}`,
          },
    );
  } catch {
    checks.push({ name: 'launchd', status: 'warn', detail: 'launchctl unavailable' });
  }

  // Tailnet
  const tailnet = findTailnetAddress();
  if (!cfg.bindTailnet) {
    checks.push({ name: 'tailnet', status: 'warn', detail: 'disabled in config — loopback only' });
  } else if (tailnet) {
    checks.push({ name: 'tailnet', status: 'ok', detail: `bound ${tailnet}` });
  } else {
    checks.push({
      name: 'tailnet',
      status: 'warn',
      detail: 'no Tailscale interface found — the phone cannot reach the daemon',
      fix: 'install and start Tailscale, then restart the daemon',
    });
  }

  // Public base URL / action buttons
  checks.push(
    cfg.publicBaseUrl
      ? { name: 'approve URL', status: 'ok', detail: cfg.publicBaseUrl }
      : {
          name: 'approve URL',
          status: 'warn',
          detail: 'not set — notifications have no action buttons (read-only)',
          fix: 'preymax init --public-url https://<mac>.<tailnet>.ts.net:' + cfg.port,
        },
  );

  // Summarizer
  const apiKey = resolveApiKey(cfg);
  if (!cfg.summarize.enabled) {
    checks.push({ name: 'summaries', status: 'warn', detail: 'disabled — template summaries only' });
  } else if (!apiKey) {
    checks.push({
      name: 'summaries',
      status: 'warn',
      detail: 'no ANTHROPIC_API_KEY — falling back to template summaries',
      fix: 'export ANTHROPIC_API_KEY=…',
    });
  } else {
    checks.push({ name: 'summaries', status: 'ok', detail: `${cfg.summarize.model} via API key` });
  }

  // Push delivery
  if (cfg.notify.transport === 'none') {
    checks.push({ name: 'push', status: 'warn', detail: 'transport disabled' });
  } else if (!cfg.notify.ntfy.topic) {
    checks.push({ name: 'push', status: 'fail', detail: 'no ntfy topic', fix: 'preymax init' });
  } else if (opts.push) {
    const result = await publish(cfg, {
      topic: cfg.notify.ntfy.topic,
      title: 'preymax doctor',
      message: 'If you can read this, push delivery works.',
      priority: 3,
      tags: ['white_check_mark'],
    });
    checks.push(
      result.ok
        ? { name: 'push', status: 'ok', detail: 'test notification sent — check your phone' }
        : { name: 'push', status: 'fail', detail: result.error ?? `status ${result.status}` },
    );
  } else {
    checks.push({
      name: 'push',
      status: 'ok',
      detail: `${cfg.notify.ntfy.server} (not tested — rerun with --push)`,
    });
  }

  report(checks);

  const failed = checks.filter((c) => c.status === 'fail').length;
  if (failed === 0 && daemonUp) {
    console.log(`\n${GREEN}ready${RESET}`);
  }
  return failed > 0 ? 1 : 0;
}

function report(checks: Check[]): void {
  const width = Math.max(...checks.map((c) => c.name.length));
  for (const c of checks) {
    console.log(`  ${mark(c.status)} ${c.name.padEnd(width)}  ${c.detail}`);
    if (c.fix) console.log(`    ${DIM}fix: ${c.fix}${RESET}`);
  }
}
