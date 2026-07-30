import type { Config } from '../core/config.js';
import type { SummarizerStats } from '../daemon/status.js';
import { verify } from '../core/hmac.js';
import { logEvent } from '../log/events.js';
import type { PermissionDecision, SessionIdentity } from '../types.js';
import { GrantStore, grantPatternFor } from './grants.js';
import { PendingStore } from './pending.js';
import { Summarizer } from './summarize.js';
import { templateSummary } from '../core/template.js';
import { buildDigestMessage, buildEscalationMessage, publish } from './transports/ntfy.js';

/**
 * The relay: notification, remote approval, temporary grants, summarization.
 *
 * **Nothing in `src/relay/**` may be imported from the hook path.** The daemon
 * reaches this module through a dynamic `import()` guarded by
 * `config.relay.enabled`, so when the relay is off none of it — no summarizer,
 * no transport, no blocking-wait state machine — is ever constructed or even
 * loaded. That is the enforcement mechanism for "no network I/O and no model
 * calls in the hot path": structure, not discipline (PLANv2 §4).
 *
 * v1 paid ~875ms of Haiku latency on every escalation *including* in shadow
 * mode, where the summary it produced was delivered nowhere (handoff bug 5).
 */

export interface EscalationContext {
  identity: SessionIdentity;
  toolName: string;
  /** Already redacted by the caller. Raw input never reaches this module. */
  redacted: Record<string, unknown>;
  /** Canonical human-readable form. Grants are prefixes of THIS, not the hash. */
  normalized: string;
  fingerprint: string;
}

export interface RelayDecision {
  decision: PermissionDecision;
  source: string;
  reason?: string;
}

export class Relay {
  readonly pending = new PendingStore();
  readonly grants = new GrantStore();
  private readonly summarizer: Summarizer;
  /** fingerprint -> last push time, for dedupe. */
  private readonly lastNotified = new Map<string, number>();
  /** session name -> time of first escalation in the current burst. */
  private readonly burstStart = new Map<string, number>();

  constructor(
    private readonly cfg: Config,
    private readonly broadcast: (payload: unknown) => void,
  ) {
    this.summarizer = new Summarizer(cfg);
  }

  get summarizerAvailable(): boolean {
    return this.summarizer.available;
  }

  get summarizerStats(): SummarizerStats {
    return this.summarizer.stats;
  }

  /** Expire anything a previous daemon left pending. Fail-closed. */
  start(): void {
    const orphaned = this.pending.recoverAndExpire();
    if (orphaned > 0) {
      logEvent({
        event: 'error',
        session: '-',
        tool: '-',
        detail: `expired ${orphaned} pending request(s) left by a previous daemon (fail-closed)`,
      });
    }
  }

  /** Release blocked terminals to the normal prompt before sockets close. */
  stop(): void {
    this.pending.releaseAll();
  }

  sweep(): void {
    this.pending.sweep();
    this.grants.prune();
    const cutoff = Date.now() - this.cfg.dedupeWindowMs * 4;
    for (const [k, t] of this.lastNotified) if (t < cutoff) this.lastNotified.delete(k);
  }

  /** A live temporary grant covering this call, if any. */
  matchGrant(session: string, toolName: string, normalized: string): boolean {
    return !!this.grants.match(session, toolName, normalized);
  }

  /**
   * Summarize, push, and block until a decision arrives or the timeout expires.
   * Returns `ask` on every failure path, including timeout and shutdown.
   */
  async escalate(ctx: EscalationContext): Promise<RelayDecision> {
    const template = templateSummary(ctx.toolName, ctx.redacted);
    const summary = await this.summarizer
      .summarizeWithinBudget(ctx.fingerprint, ctx.toolName, ctx.redacted, this.cfg.summaryBudgetMs)
      .catch(() => null);

    const pending = this.pending.create(
      {
        identity: ctx.identity,
        toolName: ctx.toolName,
        redactedInput: ctx.redacted,
        fingerprint: ctx.fingerprint,
        summary: summary?.text ?? template,
        templateSummary: template,
        summarySource: summary?.source ?? 'template',
      },
      this.cfg.decisionTimeoutMs,
    );

    this.broadcast({
      type: 'escalation',
      id: pending.id,
      session: ctx.identity.name,
      tool: ctx.toolName,
      summary: pending.summary,
      summarySource: pending.summarySource,
    });

    // Not awaited: a slow or dead transport must not add latency to a decision
    // that `preymax approve` can still resolve locally.
    void this.notify(pending.id, ctx.fingerprint, ctx.identity.name);

    const result = await this.pending.wait(pending.id, this.cfg.decisionTimeoutMs);

    if (result.decision === 'allow' && result.grant) {
      this.grants.add({
        session: ctx.identity.name,
        toolName: ctx.toolName,
        pattern: grantPatternFor(ctx.normalized),
        isRegex: false,
        expiresAt: Date.now() + this.cfg.grantTtlMs,
      });
    }

    return { decision: result.decision, source: result.source, reason: result.reason };
  }

  private async notify(pendingId: string, fingerprint: string, sessionName: string): Promise<void> {
    const pending = this.pending.get(pendingId);
    if (!pending) return;

    const now = Date.now();

    // Dedupe: an identical call already pushed inside the window doesn't buzz
    // again. The escalation still exists and is still resolvable.
    const last = this.lastNotified.get(fingerprint);
    if (last !== undefined && now - last < this.cfg.dedupeWindowMs) {
      logEvent({
        event: 'notify',
        session: sessionName,
        tool: pending.toolName,
        detail: 'suppressed: duplicate',
      });
      return;
    }

    // Burst: after the first escalation in a window, collapse the rest into one
    // digest rather than a push per call.
    const burstOpenedAt = this.burstStart.get(sessionName);
    const inBurst = burstOpenedAt !== undefined && now - burstOpenedAt < this.cfg.burstWindowMs;
    if (!inBurst) this.burstStart.set(sessionName, now);

    this.lastNotified.set(fingerprint, now);

    const msg = inBurst
      ? buildDigestMessage(this.cfg, sessionName, this.pending.countForSession(sessionName))
      : buildEscalationMessage(this.cfg, pending);

    const result = await publish(this.cfg, msg);
    if (!result.attempted) return;
    logEvent({
      event: 'notify',
      session: sessionName,
      tool: pending.toolName,
      detail: result.ok ? (inBurst ? 'digest' : 'sent') : `failed: ${result.error ?? result.status}`,
    });
  }

  /**
   * Apply a signed approval. Verification is identical for the phone and for
   * `preymax approve` over loopback — one code path, one trust model.
   */
  approve(
    body: unknown,
    remoteAddress: string | undefined,
  ): { status: number; payload: Record<string, unknown> } {
    const v = verify(this.cfg.secret, body, { ttlMs: this.cfg.nonceTtlMs });
    if (!v.ok) {
      // Log loudly. An unsigned or replayed approval is the signature of someone
      // probing the endpoint, and it is the one thing you want in the record.
      logEvent({
        event: 'error',
        session: '-',
        tool: '-',
        detail: `approval REJECTED (${v.reason}) from ${remoteAddress ?? 'unknown'}`,
      });
      return { status: 401, payload: { ok: false, error: v.reason } };
    }

    const a = body as { id: string; decision: 'allow' | 'deny'; nonce: string; grant?: boolean };
    const source = remoteAddress?.includes('127.0.0.1') ? 'local' : 'phone';
    const result = this.pending.decide(a.id, a.decision, source, {
      nonce: a.nonce,
      grant: a.grant === true,
    });

    if (!result.ok) {
      // already_decided is the expected outcome of a duplicate push delivery or
      // a double tap. It is a no-op, not an error condition.
      const status = result.reason === 'already_decided' ? 200 : 409;
      logEvent({
        event: 'error',
        session: '-',
        tool: '-',
        detail: `approval not applied (${result.reason}) id=${a.id}`,
      });
      return { status, payload: { ok: false, error: result.reason } };
    }

    this.broadcast({ type: 'approval', id: a.id, decision: a.decision, source });
    return { status: 200, payload: { ok: true, decision: a.decision } };
  }
}

/**
 * The only entry point the daemon may use. Keeping the `import()` behind this
 * function means one place to audit that the relay is never pulled in when it
 * is disabled.
 */
export async function loadRelay(
  cfg: Config,
  broadcast: (payload: unknown) => void,
): Promise<Relay> {
  return new Relay(cfg, broadcast);
}
