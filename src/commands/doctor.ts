import { execFileSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { loadConfig } from '../core/config.js';
import { LAUNCHD_LABEL, paths } from '../core/paths.js';
import type { DaemonStatus } from '../daemon/status.js';
import { fetchStatus } from './client.js';

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

/** Home-relative path, so a column of config dirs stays readable. */
function short(p: string): string {
  const home = process.env.HOME;
  return home && p.startsWith(home) ? `~${p.slice(home.length)}` : p;
}

/**
 * A constructed summarizer is not a working summarizer. `available` only means
 * the daemon holds an API key, so reporting it green hid a run of 21 failed
 * calls and 0 successes — the summary layer had never worked at all. Grade on
 * outcomes: what came back, and what did not.
 */
function summarizerHealth(s: DaemonStatus['summarizer']): Check {
  const { ok, hits, errors, timeouts } = s.stats;
  const attempts = ok + errors + timeouts;
  const tally = `${ok} ok, ${hits} cached, ${errors} errors, ${timeouts} timeouts`;

  if (attempts === 0) {
    return { name: 'summaries', status: 'ok', detail: `${s.model} · ready, nothing summarized yet` };
  }
  if (ok === 0 && hits === 0) {
    return {
      name: 'summaries',
      status: 'fail',
      detail: `${s.model} · never succeeded — ${tally}, every notification used the template`,
      fix:
        timeouts >= errors
          ? 'raise summaryBudgetMs in ~/.preymax/config.json — the model is slower than the budget'
          : 'check the key and model in the launchd plist: preymax init',
    };
  }
  // Some working, some not. Worth a flag but not a failure — the template
  // summary is a correct fallback, only a less readable one.
  const failed = errors + timeouts;
  if (failed > 0 && failed >= attempts / 2) {
    return { name: 'summaries', status: 'warn', detail: `${s.model} · degraded — ${tally}` };
  }
  return { name: 'summaries', status: 'ok', detail: `${s.model} · ${tally}` };
}

function humanUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60)}m`;
}

/**
 * `preymax doctor` — verify the whole path end to end.
 *
 * **Everything the daemon can answer, the daemon answers.** doctor renders
 * `GET /status` and computes nothing about hooks, policy, the log, the tailnet
 * or the summarizer itself. v1 did compute them, in this process, reading this
 * process's environment — and reported a green summarizer while the daemon
 * under launchd had no API key at all (handoff bug 2). When the daemon is down
 * those facts are reported as *unverified* rather than guessed at.
 */
export async function runDoctor(opts: { push: boolean }): Promise<number> {
  const checks: Check[] = [];
  let cfg;

  // --- Local facts: true regardless of whether the daemon is running. -------

  try {
    cfg = loadConfig();
    checks.push({ name: 'config', status: 'ok', detail: paths.config() });
  } catch (err) {
    checks.push({ name: 'config', status: 'fail', detail: (err as Error).message, fix: 'preymax init' });
    report(checks);
    return 1;
  }

  checks.push(
    cfg.secret
      ? { name: 'secret', status: 'ok', detail: 'present' }
      : { name: 'secret', status: 'fail', detail: 'missing', fix: 'preymax init' },
  );

  // The config file holds the approval secret and possibly the API key.
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

  // launchd is about the agent, not the daemon's internal view, so it stays here.
  try {
    const out = execFileSync('launchctl', ['list'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
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

  // --- The daemon's own view. -----------------------------------------------

  let status: DaemonStatus | null = null;
  let daemonError = '';
  try {
    status = await fetchStatus();
  } catch (err) {
    daemonError = (err as Error).message.split('\n')[0]!;
  }

  if (!status) {
    checks.push({
      name: 'daemon',
      status: 'fail',
      detail: daemonError,
      fix: `preymax daemon   (or: launchctl load -w ${paths.launchAgent()})`,
    });
    checks.push({
      name: 'unverified',
      status: 'warn',
      detail:
        'hook registration, policy, event log, tailnet and summarizer state all live in ' +
        'the daemon and cannot be confirmed while it is down',
    });
    report(checks);
    return 1;
  }

  checks.push({
    name: 'daemon',
    status: 'ok',
    detail:
      `up on ${status.bind.addresses.join(', ')}:${status.bind.port} · pid ${status.pid} · ` +
      `up ${humanUptime(status.uptimeMs)} · ${status.pending} pending`,
  });

  // Policy
  checks.push(
    status.policy.error
      ? {
          name: 'policy',
          status: 'fail',
          detail: status.policy.error,
          fix: `edit ${status.policy.path}`,
        }
      : {
          name: 'policy',
          status: 'ok',
          detail: `${status.policy.allowRules} allow rules`,
        },
  );

  // Event log — if this is not writable, every measurement downstream is empty.
  checks.push(
    status.log.writable
      ? { name: 'event log', status: 'ok', detail: status.log.path }
      : {
          name: 'event log',
          status: 'fail',
          detail: `not writable: ${status.log.error ?? 'unknown'} — nothing is being recorded`,
          fix: `check permissions on ${status.log.path}`,
        },
  );

  // Config directories, per directory.
  const visible = status.configDirs.filter((d) => d.exists);
  const hooked = visible.filter((d) => d.hooked && !d.error);
  const unhooked = visible.filter((d) => !d.hooked || d.error);

  checks.push(
    visible.length === 0
      ? { name: 'config dirs', status: 'fail', detail: 'no Claude config directory found', fix: 'preymax init' }
      : {
          name: 'config dirs',
          status: hooked.length === 0 ? 'fail' : unhooked.length > 0 ? 'warn' : 'ok',
          detail: `${hooked.length}/${visible.length} hooked`,
          ...(unhooked.length > 0 ? { fix: 'preymax init' } : {}),
        },
  );

  for (const d of visible) {
    checks.push({
      name: `  ${short(d.path)}`,
      status: d.error ? 'fail' : d.hooked ? 'ok' : 'warn',
      detail: d.error
        ? `settings.json unreadable: ${d.error}`
        : d.hooked
          ? `hooked [${d.sources.join(',')}]`
          : `no preymax hook — sessions using this account are invisible [${d.sources.join(',')}]`,
      ...(d.hooked || d.error ? {} : { fix: 'preymax init' }),
    });
  }

  for (const d of status.configDirs.filter((x) => x.warning)) {
    checks.push({ name: `  ${short(d.path)}`, status: 'warn', detail: d.warning! });
  }

  // Tailnet — reported as the daemon actually bound it, not as this process sees it.
  checks.push(
    status.bind.tailnet
      ? { name: 'tailnet', status: 'ok', detail: `bound ${status.bind.tailnet}` }
      : {
          name: 'tailnet',
          // Only worth flagging if you actually intend to use the phone.
          status: status.relay.enabled ? 'warn' : 'ok',
          detail: status.relay.enabled
            ? 'not bound — the phone cannot reach the daemon'
            : 'not bound (not needed — the relay is off)',
          ...(status.relay.enabled
            ? { fix: 'start Tailscale, then restart the daemon' }
            : {}),
        },
  );

  // Approve URL / action buttons.
  checks.push(
    status.relay.publicBaseUrl
      ? { name: 'approve URL', status: 'ok', detail: status.relay.publicBaseUrl }
      : {
          name: 'approve URL',
          status: 'warn',
          detail: 'not set — notifications have no action buttons (read-only)',
          // The daemon speaks plain HTTP; TLS is terminated by Tailscale Serve
          // on 443, so the URL carries no port. See docs/ios-shortcuts.md.
          fix:
            `tailscale serve --bg --https=443 http://127.0.0.1:${status.bind.port}` +
            '  then  preymax init --public-url https://<mac>.<tailnet>.ts.net',
        },
  );

  // Summarizer — the daemon's answer, in the daemon's environment.
  checks.push(
    status.summarizer.available
      ? summarizerHealth(status.summarizer)
      : {
          name: 'summaries',
          // Not running because the relay is off is the expected v2 default,
          // not a fault. Only a genuinely broken summarizer warrants a warning.
          status: status.summarizer.reason.startsWith('not running') ? 'ok' : 'warn',
          detail: status.summarizer.reason,
          ...(status.summarizer.reason.includes('API key')
            ? { fix: 'preymax init   (writes the key where the daemon can see it)' }
            : {}),
        },
  );

  // Shadow mode is a deliberate state, and doctor must not present it as broken.
  // Read the flag; the old `decisionTimeoutMs <= 1000` inference was detecting
  // v1's hand-rolled shadow hack, which `preymax shadow on` replaced.
  if (status.shadow) {
    checks.push({
      name: 'shadow mode',
      status: 'ok',
      detail: 'on — escalations are logged and fall straight through to the normal prompt',
    });
  }

  // Push delivery.
  if (!status.relay.enabled) {
    checks.push({ name: 'push', status: 'warn', detail: `transport ${status.relay.transport}` });
  } else if (!cfg.notify.ntfy.topic) {
    checks.push({ name: 'push', status: 'fail', detail: 'no ntfy topic', fix: 'preymax init' });
  } else if (opts.push) {
    // Lazily imported: the transport belongs to the relay, and doctor must be
    // runnable — and useful — on an install where the relay is off.
    const { publish } = await import('../relay/transports/ntfy.js');
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
  if (failed === 0) console.log(`\n${GREEN}ready${RESET}`);
  return failed > 0 ? 1 : 0;
}

function report(checks: Check[]): void {
  const width = Math.max(...checks.map((c) => c.name.length));
  for (const c of checks) {
    console.log(`  ${mark(c.status)} ${c.name.padEnd(width)}  ${c.detail}`);
    if (c.fix) console.log(`    ${DIM}fix: ${c.fix}${RESET}`);
  }
}
