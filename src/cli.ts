#!/usr/bin/env node
import { loadConfig } from './core/config.js';
import { paths } from './core/paths.js';
import { Daemon } from './daemon/server.js';
import { UnsafeBindError } from './daemon/net.js';
import { runInit } from './commands/init.js';
import { runTail } from './commands/tail.js';
import { runDecide, runGrants, runPending } from './commands/decide.js';
import { runStats } from './commands/stats.js';
import { runDoctor } from './commands/doctor.js';
import { DaemonUnreachableError } from './commands/client.js';

const USAGE = `preymax — named permission triage for parallel Claude Code sessions

  preymax init [--no-agent] [--port N] [--public-url URL]
      Register the PreToolUse hook, generate a secret and ntfy topic,
      write a default policy, and install the launchd agent. Idempotent.

  preymax daemon
      Run the daemon in the foreground. Normally launchd does this for you.

  preymax tail
      Live, colorized event stream. The primary debugging surface.

  preymax pending
      List escalations awaiting a decision.

  preymax approve <id> [--grant]
      Allow a pending request. --grant also allows the pattern for a while.

  preymax deny <id>
      Deny a pending request.

  preymax grants
      List active temporary grants.

  preymax stats [--hours N]
      Escalation rate, per-terminal volume, latency percentiles.

  preymax doctor [--push]
      Verify hooks, daemon, tailnet, and (with --push) real push delivery.

preymax is not a sandbox and not a security product. It reduces noise and
lets you unblock a terminal from your phone. Every failure mode falls back to
the normal Claude Code prompt.
`;

function flag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

function value(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  const v = argv[i + 1];
  return v && !v.startsWith('--') ? v : undefined;
}

async function runDaemon(): Promise<number> {
  const cfg = loadConfig();
  if (!cfg.secret) {
    console.error('no secret configured — run `preymax init` first');
    return 1;
  }

  const daemon = new Daemon(cfg);
  let handle;
  try {
    handle = await daemon.start();
  } catch (err) {
    if (err instanceof UnsafeBindError) {
      console.error(`preymax refused to start: ${err.message}`);
      return 1;
    }
    if ((err as NodeJS.ErrnoException).code === 'EADDRINUSE') {
      console.error(
        `port ${cfg.port} is already in use — another preymax daemon is probably running.\n` +
          `  check with: launchctl list | grep preymax`,
      );
      return 1;
    }
    throw err;
  }

  console.log(`preymax daemon listening on ${handle.addresses.map((a) => `${a}:${cfg.port}`).join(', ')}`);
  if (handle.tailnet) console.log(`  tailnet: ${handle.tailnet}`);
  else if (cfg.bindTailnet) console.log('  tailnet: not found — loopback only, phone approval unavailable');
  console.log(`  events:  ${paths.events()}`);
  console.log(`  timeout: ${cfg.decisionTimeoutMs}ms, then falls through to the normal prompt`);

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n${signal} — releasing blocked terminals to the normal prompt`);
    await handle.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  // Keep the process alive; the servers hold the loop open.
  return new Promise<number>(() => {});
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  switch (cmd) {
    case undefined:
    case '-h':
    case '--help':
    case 'help':
      console.log(USAGE);
      return 0;

    case '--version':
    case 'version':
      console.log('0.1.0');
      return 0;

    case 'init': {
      const port = value(argv, '--port');
      runInit({
        installAgent: !flag(argv, '--no-agent'),
        ...(port ? { port: Number(port) } : {}),
        ...(value(argv, '--public-url') ? { publicBaseUrl: value(argv, '--public-url')! } : {}),
      });
      return 0;
    }

    case 'daemon':
      return runDaemon();

    case 'tail':
      await runTail();
      return 0;

    case 'pending':
      return runPending();

    case 'approve':
      return runDecide(argv[1], 'allow', flag(argv, '--grant'));

    case 'deny':
      return runDecide(argv[1], 'deny', false);

    case 'grants':
      return runGrants();

    case 'stats':
      return runStats(Number(value(argv, '--hours') ?? 24));

    case 'doctor':
      return runDoctor({ push: flag(argv, '--push') });

    default:
      console.error(`unknown command: ${cmd}\n`);
      console.log(USAGE);
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    if (err instanceof DaemonUnreachableError) {
      console.error(err.message);
      process.exit(1);
    }
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
