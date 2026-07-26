import { appendFileSync, mkdirSync, statSync, renameSync, existsSync, readFileSync } from 'node:fs';
import type { EventRecord } from '../types.js';
import { paths } from './paths.js';

/**
 * Structured JSONL from the start, in a shape SessionLint can parse.
 * Every escalation records: session, tool, decision, decision source, and
 * end-to-end latency — the inputs `preymax stats` needs to answer "is the
 * escalation rate livable".
 */

const MAX_BYTES = 8 * 1024 * 1024;

function rotateIfNeeded(file: string): void {
  try {
    if (statSync(file).size > MAX_BYTES) renameSync(file, file + '.1');
  } catch {
    // File doesn't exist yet, or rotation raced another writer. Either is fine.
  }
}

export function logEvent(record: Omit<EventRecord, 'ts'> & { ts?: string }): void {
  const file = paths.events();
  try {
    mkdirSync(paths.home(), { recursive: true });
    rotateIfNeeded(file);
    const line = JSON.stringify({ ts: new Date().toISOString(), ...record }) + '\n';
    appendFileSync(file, line);
  } catch {
    // Logging must never take the daemon down. A failed write is invisible by
    // design — the alternative is a crash on the permission-gate path.
  }
}

export function readEvents(sinceMs?: number): EventRecord[] {
  const file = paths.events();
  if (!existsSync(file)) return [];
  const out: EventRecord[] = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line) as EventRecord;
      if (sinceMs !== undefined && Date.parse(rec.ts) < sinceMs) continue;
      out.push(rec);
    } catch {
      continue; // torn line from a rotation; skip it
    }
  }
  return out;
}
