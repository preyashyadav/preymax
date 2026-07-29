import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { join } from 'node:path';
import type { EventRecord } from '../types.js';
import { paths } from '../core/paths.js';

/**
 * Append-only JSONL, one file per day, no database.
 *
 * The log *is* the product: `stats` and `suggest` are both pure functions of
 * it, and the notification layer is a feature layered on top. A single
 * ever-growing file made retention a size-based rotation that silently threw
 * away the oldest data mid-file; a day per file makes retention a date
 * comparison and makes "the last 7 days" a directory listing.
 *
 * Writing must never take the daemon down — this runs on the permission gate.
 */

const RETENTION_DAYS_DEFAULT = 90;

/** YYYY-MM-DD in local time, which is how a human means "today". */
export function dayKey(d: Date = new Date()): string {
  const pad = (n: number): string => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export function logFileFor(d: Date = new Date()): string {
  return join(paths.logDir(), `${dayKey(d)}.jsonl`);
}

export function logEvent(record: Omit<EventRecord, 'ts'> & { ts?: string }): void {
  try {
    mkdirSync(paths.logDir(), { recursive: true });
    const line = JSON.stringify({ ts: new Date().toISOString(), ...record }) + '\n';
    appendFileSync(logFileFor(), line);
  } catch {
    // Invisible by design. The alternative is crashing on the gate path, which
    // would block a terminal to report a logging problem.
  }
}

function parseLines(text: string, sinceMs: number | undefined, out: EventRecord[]): void {
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line) as EventRecord;
      if (sinceMs !== undefined && Date.parse(rec.ts) < sinceMs) continue;
      out.push(rec);
    } catch {
      continue; // torn final line from a concurrent append; skip it
    }
  }
}

/**
 * Every event at or after `sinceMs`, oldest first.
 *
 * Reads the daily files *and* v1's single `events.jsonl`, so history collected
 * before the split still feeds `stats` and `suggest`.
 */
export function readEvents(sinceMs?: number): EventRecord[] {
  const out: EventRecord[] = [];

  const legacy = paths.legacyEvents();
  if (existsSync(legacy)) {
    try {
      parseLines(readFileSync(legacy, 'utf8'), sinceMs, out);
    } catch {
      /* unreadable legacy log is not fatal */
    }
  }

  const dir = paths.logDir();
  if (existsSync(dir)) {
    // Filenames sort chronologically because the key is YYYY-MM-DD.
    const files = readdirSync(dir)
      .filter((f) => f.endsWith('.jsonl'))
      .sort();
    for (const f of files) {
      // Cheap skip: a whole day older than the cutoff cannot contain a hit.
      if (sinceMs !== undefined) {
        const dayEnd = Date.parse(`${f.replace('.jsonl', '')}T23:59:59.999`);
        if (!Number.isNaN(dayEnd) && dayEnd < sinceMs) continue;
      }
      try {
        parseLines(readFileSync(join(dir, f), 'utf8'), sinceMs, out);
      } catch {
        continue;
      }
    }
  }

  out.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  return out;
}

/** Delete day files older than the retention window. Returns how many went. */
export function pruneLog(retentionDays = RETENTION_DAYS_DEFAULT): number {
  const dir = paths.logDir();
  if (!existsSync(dir)) return 0;
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  let removed = 0;
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.jsonl')) continue;
    const dayEnd = Date.parse(`${f.replace('.jsonl', '')}T23:59:59.999`);
    if (Number.isNaN(dayEnd) || dayEnd >= cutoff) continue;
    try {
      rmSync(join(dir, f));
      removed++;
    } catch {
      continue;
    }
  }
  return removed;
}

/** Total bytes on disk, for `doctor` and for noticing runaway growth. */
export function logSizeBytes(): number {
  let total = 0;
  for (const f of [paths.legacyEvents(), ...dayFiles()]) {
    try {
      total += statSync(f).size;
    } catch {
      continue;
    }
  }
  return total;
}

export function dayFiles(): string[] {
  const dir = paths.logDir();
  if (!existsSync(dir)) return [];
  try {
    return readdirSync(dir)
      .filter((f) => f.endsWith('.jsonl'))
      .sort()
      .map((f) => join(dir, f));
  } catch {
    return [];
  }
}
