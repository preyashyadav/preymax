import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { newNonce } from '../core/hmac.js';
import { paths } from '../core/paths.js';
import type { PendingRequest, PermissionDecision, DecisionSource } from '../types.js';

/**
 * The pending-decision table.
 *
 * This is where the single most important rule in the project lives: a request
 * that is never answered resolves to `ask`, never to `allow`. Timeout, daemon
 * death, tailnet loss, and push failure all converge on the same outcome — the
 * terminal prompts normally, exactly as if preymax were not installed.
 */

export interface ResolvedDecision {
  decision: PermissionDecision;
  source: DecisionSource;
  reason?: string;
  grant?: boolean;
}

interface Waiter {
  resolve: (d: ResolvedDecision) => void;
  timer: NodeJS.Timeout;
}

/** Nonces already spent. Replaying one is rejected. */
class NonceLedger {
  private used = new Map<string, number>();

  consume(nonce: string, now = Date.now()): boolean {
    this.prune(now);
    if (this.used.has(nonce)) return false;
    this.used.set(nonce, now);
    return true;
  }

  private prune(now: number): void {
    // Nonces are minted per pending request and die with it; an hour is
    // generous and bounds memory regardless of traffic.
    for (const [n, at] of this.used) {
      if (now - at > 60 * 60_000) this.used.delete(n);
    }
  }
}

export class PendingStore {
  private readonly items = new Map<string, PendingRequest>();
  private readonly waiters = new Map<string, Waiter>();
  private readonly nonces = new NonceLedger();

  constructor(private readonly file = paths.pending()) {}

  /**
   * Restore pending requests written by a previous daemon.
   *
   * Anything found on disk is expired immediately rather than revived: the hook
   * that was waiting on it died with the old process, so its terminal has
   * already fallen through to a normal prompt. Resurrecting the entry would let
   * a stale phone tap approve a command nobody is waiting on any more. Failing
   * closed here is the whole point.
   */
  recoverAndExpire(): number {
    if (!existsSync(this.file)) return 0;
    let recovered: PendingRequest[] = [];
    try {
      const parsed = JSON.parse(readFileSync(this.file, 'utf8'));
      recovered = Array.isArray(parsed) ? parsed : [];
    } catch {
      recovered = [];
    }
    const count = recovered.filter((p) => !p.decision).length;
    this.persist();
    return count;
  }

  private persist(): void {
    try {
      mkdirSync(paths.home(), { recursive: true });
      writeFileSync(this.file, JSON.stringify([...this.items.values()], null, 2) + '\n', {
        mode: 0o600,
      });
    } catch {
      // If we cannot persist we still operate in memory. The consequence is that
      // a restart loses pending state — which is the fail-closed direction.
    }
  }

  create(
    base: Omit<PendingRequest, 'id' | 'nonce' | 'createdAt' | 'expiresAt'>,
    ttlMs: number,
  ): PendingRequest {
    const now = Date.now();
    const pending: PendingRequest = {
      ...base,
      id: randomBytes(8).toString('hex'),
      nonce: newNonce(),
      createdAt: now,
      expiresAt: now + ttlMs,
    };
    this.items.set(pending.id, pending);
    this.persist();
    return pending;
  }

  get(id: string): PendingRequest | undefined {
    return this.items.get(id);
  }

  list(): PendingRequest[] {
    return [...this.items.values()].filter((p) => !p.decision);
  }

  /** How many undecided requests this session currently has. Drives the digest. */
  countForSession(sessionName: string): number {
    return this.list().filter((p) => p.identity.name === sessionName).length;
  }

  /**
   * Block until someone decides, or the timeout fires.
   * On timeout the result is `ask` — never `allow`.
   */
  wait(id: string, timeoutMs: number): Promise<ResolvedDecision> {
    return new Promise((resolve) => {
      const existing = this.items.get(id);
      if (existing?.decision) {
        resolve({
          decision: existing.decision,
          source: existing.decisionSource ?? 'local',
        });
        return;
      }
      const timer = setTimeout(() => {
        this.waiters.delete(id);
        this.finalize(id, 'ask', 'timeout');
        resolve({
          decision: 'ask',
          source: 'timeout',
          reason: 'preymax: no response in time — falling through to the normal prompt',
        });
      }, timeoutMs);
      // Deliberately NOT unref'd. This timer is the fail-safe: it is what turns
      // an unanswered escalation into `ask`. An unref'd timer can be skipped
      // entirely if the loop drains first, which would leave the promise
      // dangling and the hook without a response.
      this.waiters.set(id, { resolve, timer });
    });
  }

  private finalize(id: string, decision: PermissionDecision, source: DecisionSource): void {
    const p = this.items.get(id);
    if (!p || p.decision) return;
    p.decision = decision;
    p.decisionSource = source;
    p.decidedAt = Date.now();
    this.persist();
  }

  /**
   * Apply a decision. Idempotent by construction: the second call for the same
   * id is a no-op, so a duplicate push delivery or a double-tap cannot decide
   * twice, and a late `deny` cannot override an `allow` already returned to the
   * terminal.
   */
  decide(
    id: string,
    decision: 'allow' | 'deny',
    source: DecisionSource,
    opts: { nonce?: string; grant?: boolean } = {},
  ): { ok: true } | { ok: false; reason: 'unknown' | 'already_decided' | 'expired' | 'nonce_replayed' } {
    const p = this.items.get(id);
    if (!p) return { ok: false, reason: 'unknown' };
    if (p.decision) return { ok: false, reason: 'already_decided' };
    if (Date.now() > p.expiresAt) return { ok: false, reason: 'expired' };

    // Phone approvals carry a single-use nonce. Local CLI approvals are already
    // authenticated by filesystem access to the secret, but still consume it so
    // a captured webhook cannot be replayed after a local approval.
    if (opts.nonce !== undefined) {
      if (opts.nonce !== p.nonce) return { ok: false, reason: 'nonce_replayed' };
      if (!this.nonces.consume(opts.nonce)) return { ok: false, reason: 'nonce_replayed' };
    }

    p.decision = decision;
    p.decisionSource = source;
    p.decidedAt = Date.now();
    if (opts.grant) p.grantPattern = p.fingerprint;
    this.persist();

    const waiter = this.waiters.get(id);
    if (waiter) {
      clearTimeout(waiter.timer);
      this.waiters.delete(id);
      waiter.resolve({ decision, source, grant: opts.grant });
    }
    return { ok: true };
  }

  /**
   * Release every waiter as `ask` on shutdown, so a terminal blocked on a
   * pending decision falls through to its normal prompt instead of hanging
   * until the hook's own timeout.
   */
  releaseAll(): void {
    for (const [id, waiter] of this.waiters) {
      clearTimeout(waiter.timer);
      this.finalize(id, 'ask', 'shutdown');
      waiter.resolve({
        decision: 'ask',
        source: 'shutdown',
        reason: 'preymax: daemon shutting down — falling through to the normal prompt',
      });
    }
    this.waiters.clear();
    this.persist();
  }

  /** Drop decided/expired entries so the table and its file stay small. */
  sweep(now = Date.now()): void {
    let changed = false;
    for (const [id, p] of this.items) {
      const done = p.decision !== undefined;
      const stale = now > p.expiresAt + 60_000;
      if ((done && now - (p.decidedAt ?? p.createdAt) > 10 * 60_000) || stale) {
        this.items.delete(id);
        changed = true;
      }
    }
    if (changed) this.persist();
  }
}
