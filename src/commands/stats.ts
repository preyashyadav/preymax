import { readEvents } from '../core/log.js';
import { colorFor } from '../core/identity.js';
import type { EventRecord } from '../types.js';

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

/**
 * `preymax stats` — the number that decides whether this product is livable.
 *
 * The plan's Phase 2 gate is an escalation rate under roughly eight per hour.
 * At forty per hour the notification product is dead on arrival. This command
 * exists so that judgement is made against data instead of vibes.
 */

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx]!;
}

export function summarize(events: EventRecord[], windowMs: number) {
  const escalations = events.filter((e) => e.event === 'escalation');
  const decisions = events.filter((e) => e.event === 'decision');
  const autoAllow = events.filter((e) => e.event === 'auto_allow');
  const autoDeny = events.filter((e) => e.event === 'auto_deny');

  const hours = Math.max(windowMs / 3_600_000, 1 / 60);
  const perSession = new Map<string, number>();
  const perTool = new Map<string, number>();
  const perCommand = new Map<string, number>();

  for (const e of escalations) {
    perSession.set(e.session, (perSession.get(e.session) ?? 0) + 1);
    perTool.set(e.tool, (perTool.get(e.tool) ?? 0) + 1);
    if (e.summary) perCommand.set(e.summary, (perCommand.get(e.summary) ?? 0) + 1);
  }

  const bySource = new Map<string, number>();
  for (const d of decisions) {
    bySource.set(d.decisionSource ?? 'unknown', (bySource.get(d.decisionSource ?? 'unknown') ?? 0) + 1);
  }

  const latencies = decisions
    .map((d) => d.latencyMs)
    .filter((n): n is number => typeof n === 'number')
    .sort((a, b) => a - b);

  const total = escalations.length + autoAllow.length + autoDeny.length;

  return {
    windowHours: hours,
    total,
    escalations: escalations.length,
    autoAllow: autoAllow.length,
    autoDeny: autoDeny.length,
    escalationsPerHour: escalations.length / hours,
    suppressionRate: total === 0 ? 0 : 1 - escalations.length / total,
    perSession: [...perSession].sort((a, b) => b[1] - a[1]),
    perTool: [...perTool].sort((a, b) => b[1] - a[1]),
    topCommands: [...perCommand].sort((a, b) => b[1] - a[1]).slice(0, 10),
    bySource: [...bySource].sort((a, b) => b[1] - a[1]),
    latency: {
      p50: percentile(latencies, 50),
      p95: percentile(latencies, 95),
      p99: percentile(latencies, 99),
      n: latencies.length,
    },
  };
}

export function runStats(hours: number): number {
  const windowMs = hours * 3_600_000;
  const events = readEvents(Date.now() - windowMs);
  const s = summarize(events, windowMs);

  if (s.total === 0) {
    console.log(`no events in the last ${hours}h — has the daemon seen any traffic?`);
    return 0;
  }

  const rate = s.escalationsPerHour;
  const verdict =
    rate < 8
      ? `${'\x1b[32m'}under the 8/hr target${RESET}`
      : rate < 20
        ? `${'\x1b[33m'}above target — tune the policy${RESET}`
        : `${'\x1b[31m'}far above target — fix this before trusting notifications${RESET}`;

  console.log(`last ${hours}h · ${s.total} tool calls seen\n`);
  console.log(`  escalations      ${s.escalations}  (${rate.toFixed(1)}/hr)  ${verdict}`);
  console.log(`  auto-allowed     ${s.autoAllow}`);
  console.log(`  auto-denied      ${s.autoDeny}`);
  console.log(`  suppression      ${(s.suppressionRate * 100).toFixed(1)}% handled without paging you`);

  if (s.latency.n > 0) {
    console.log(
      `\n  decision latency p50 ${s.latency.p50}ms · p95 ${s.latency.p95}ms · p99 ${s.latency.p99}ms  ${DIM}(n=${s.latency.n})${RESET}`,
    );
  }

  if (s.bySource.length > 0) {
    console.log('\n  decided by');
    for (const [src, n] of s.bySource) console.log(`    ${src.padEnd(10)} ${n}`);
  }

  if (s.perSession.length > 0) {
    console.log('\n  escalations per terminal');
    for (const [name, n] of s.perSession) {
      console.log(`    ${colorFor(name)}${name.padEnd(20)}${RESET} ${n}`);
    }
  }

  if (s.perTool.length > 0) {
    console.log('\n  escalations per tool');
    for (const [tool, n] of s.perTool) console.log(`    ${tool.padEnd(20)} ${n}`);
  }

  if (s.topCommands.length > 0) {
    console.log('\n  top escalating calls — each of these is a candidate policy rule');
    for (const [cmd, n] of s.topCommands) {
      console.log(`    ${String(n).padStart(3)}  ${cmd.slice(0, 68)}`);
    }
  }

  return 0;
}
