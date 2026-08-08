import { readFileSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { paths } from '../core/paths.js';
import { ensurePolicyFile, parsePolicy } from '../core/policy.js';
import { readEvents } from '../log/events.js';
import { daemonBase } from './client.js';
import { buildReport, renderRules, type Suggestion } from '../insight/suggest.js';

const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function colourFor(s: Suggestion): string {
  return s.safety === 'safe' ? GREEN : s.safety === 'review' ? YELLOW : RED;
}

export interface SuggestOptions {
  hours: number;
  apply: boolean;
  includeReview: boolean;
  minCount: number;
}

/**
 * `preymax suggest` — turn the event log into policy.
 *
 * Read-only unless `--apply`. Applying writes an annotated block into
 * policy.yaml after backing the file up, and re-parses the result before
 * keeping it: a suggestion that produces an unloadable policy is a bug that
 * must not survive contact with the user's config.
 */
export async function runSuggest(opts: SuggestOptions): Promise<number> {
  const since = Date.now() - opts.hours * 3600_000;
  const events = readEvents(since);
  const report = buildReport(events, opts.hours);

  if (report.escalations === 0) {
    console.log(`no escalations in the last ${opts.hours}h — nothing to suggest`);
    console.log(`${DIM}the log is at ${paths.logDir()}${RESET}`);
    return 0;
  }

  console.log(
    `Analyzed ${BOLD}${report.escalations}${RESET} escalations over ${opts.hours}h ` +
      `across ${report.sessions} session${report.sessions === 1 ? '' : 's'}.\n`,
  );

  const candidates = report.suggestions.filter(
    (s) => s.count >= opts.minCount && s.safety !== 'unsafe',
  );

  if (candidates.length === 0) {
    console.log('no candidates above the threshold.');
    return 0;
  }

  // A path rule's pattern is a full absolute path plus a guard, which is
  // unreadable in a table. Every suggestion carries a label for this reason.
  const width = Math.max(...candidates.map((s) => s.label.length), 20);
  for (const s of candidates) {
    const pct = `(${Math.round(s.share * 100)}%)`;
    const votes =
      s.approved > 0 || s.denied > 0 ? ` ${DIM}[${s.approved}✓ ${s.denied}✗]${RESET}` : '';
    console.log(
      `  ${s.label.padEnd(width)}  ${String(s.count).padStart(4)} escalations ${pct.padStart(6)}   ` +
        `${colourFor(s)}${s.safety}${RESET} — ${s.reason}${votes}`,
    );
  }

  const safe = candidates.filter((s) => s.safety === 'safe');
  const review = candidates.filter((s) => s.safety === 'review');
  const picked = opts.includeReview ? candidates : safe;
  const removed = picked.reduce((n, s) => n + s.count, 0);
  const share = report.escalations ? Math.round((removed / report.escalations) * 100) : 0;

  console.log('');
  if (!opts.apply) {
    if (safe.length > 0) {
      const safeRemoved = safe.reduce((n, s) => n + s.count, 0);
      const safeShare = Math.round((safeRemoved / report.escalations) * 100);
      console.log(
        `Apply the ${safe.length} marked ${GREEN}safe${RESET}? ` +
          `→ removes ~${safeRemoved} escalations/${opts.hours}h (${safeShare}%)`,
      );
      console.log(`  ${DIM}preymax suggest --apply${RESET}`);
    }
    if (review.length > 0) {
      console.log(
        `${review.length} marked ${YELLOW}review${RESET} are never applied automatically. ` +
          `Read them, then:`,
      );
      console.log(`  ${DIM}preymax suggest --apply --include-review${RESET}`);
    }
    return 0;
  }

  if (picked.length === 0) {
    console.log('nothing to apply.');
    return 0;
  }

  const file = ensurePolicyFile();
  const before = readFileSync(file, 'utf8');
  const block = renderRules(picked);

  // Append inside auto_allow. The default policy ends with a trailing comment,
  // so splice the block in after the last rule line rather than at EOF.
  const marker = /\n(# Everything not matched above escalates\.)/;
  // A *function* replacer, never a string. Generated patterns contain `$\`` and
  // `$&`, which String.replace treats as substitution directives — a string
  // replacement here spliced the whole file into the middle of a regex.
  const next = marker.test(before)
    ? before.replace(marker, (_match, tail: string) => `\n${block}\n${tail}`)
    : before.trimEnd() + '\n' + block;

  // Never leave the user with a policy that will not load.
  try {
    parsePolicy(next, file);
  } catch (err) {
    console.error(`${RED}refusing to write${RESET}: generated policy does not parse`);
    console.error(`  ${(err as Error).message}`);
    return 1;
  }

  const backup = `${file}.bak-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  if (existsSync(file)) copyFileSync(file, backup);
  writeFileSync(file, next);

  console.log(`${GREEN}applied${RESET} ${picked.length} rule(s) to ${file}`);
  console.log(`  backup: ${backup}`);
  console.log(`  expected reduction: ~${removed} escalations/${opts.hours}h (${share}%)`);

  // The daemon loads policy once at startup, so a freshly written rule does
  // nothing until it is told. Applying a suggestion that silently has no effect
  // until the next reboot is worse than not applying it.
  await reloadDaemon();

  console.log(`\n${DIM}verify the effect over your next working day:${RESET}`);
  console.log(`  preymax stats --hours ${opts.hours}`);
  return 0;
}

async function reloadDaemon(): Promise<void> {
  try {
    const res = await fetch(`${daemonBase()}/reload`, {
      method: 'POST',
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      console.log(`  ${GREEN}daemon reloaded${RESET} — the new rules are live now`);
      return;
    }
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    console.log(`  ${YELLOW}daemon rejected the new policy${RESET}: ${body.error ?? res.status}`);
    console.log(`  ${DIM}the file is written; fix it and run: preymax doctor${RESET}`);
  } catch {
    console.log(`  ${YELLOW}daemon not reachable${RESET} — rules apply when it next starts`);
    console.log(`  ${DIM}launchctl kickstart -k gui/$(id -u)/com.preymax.daemon${RESET}`);
  }
}
