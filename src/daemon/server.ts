import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Config } from '../core/config.js';
import { GrantStore, grantPatternFor } from '../core/grants.js';
import { verify } from '../core/hmac.js';
import { resolveIdentity } from '../core/identity.js';
import { logEvent } from '../core/log.js';
import { evaluate, loadPolicy, type Policy } from '../core/policy.js';
import { normalizeForFingerprint, redactToolInput } from '../core/redact.js';
import { Summarizer } from '../core/summarize.js';
import { templateSummary } from '../core/template.js';
import { buildDigestMessage, buildEscalationMessage, publish } from '../notify/ntfy.js';
import type {
  PermissionDecision,
  PreToolUseHookOutput,
  PreToolUsePayload,
} from '../types.js';
import { assertSafeBind, resolveBindAddresses } from './net.js';
import { PendingStore } from './pending.js';
import { createHash } from 'node:crypto';

const MAX_BODY_BYTES = 2 * 1024 * 1024;

function decision(
  d: PermissionDecision,
  reason?: string,
): PreToolUseHookOutput {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: d,
      ...(reason ? { permissionDecisionReason: reason } : {}),
    },
  };
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

export interface DaemonHandle {
  servers: Server[];
  addresses: string[];
  tailnet: string | null;
  close: () => Promise<void>;
}

export class Daemon {
  private readonly pending: PendingStore;
  private readonly grants: GrantStore;
  private readonly summarizer: Summarizer;
  private policy: Policy;
  private readonly servers: Server[] = [];
  private readonly sseClients = new Set<ServerResponse>();
  /** fingerprint -> last push time, for dedupe. */
  private readonly lastNotified = new Map<string, number>();
  /** session name -> time of first escalation in the current burst. */
  private readonly burstStart = new Map<string, number>();
  private sweeper: NodeJS.Timeout | null = null;

  constructor(private readonly cfg: Config) {
    this.pending = new PendingStore();
    this.grants = new GrantStore();
    this.summarizer = new Summarizer(cfg);
    this.policy = loadPolicy();
  }

  async start(): Promise<DaemonHandle> {
    const { addresses, tailnet } = resolveBindAddresses(this.cfg.bindTailnet);
    // Throws before any listener opens if a non-loopback, non-tailnet address
    // is in the list. This is the assertion Phase 5 requires.
    assertSafeBind(addresses);

    const orphaned = this.pending.recoverAndExpire();
    if (orphaned > 0) {
      logEvent({
        event: 'error',
        session: '-',
        tool: '-',
        detail: `expired ${orphaned} pending request(s) left by a previous daemon (fail-closed)`,
      });
    }

    for (const addr of addresses) {
      const server = createServer((req, res) => {
        this.handle(req, res).catch((err) => {
          try {
            sendJson(res, 500, { error: (err as Error).message });
          } catch {
            /* response already sent */
          }
        });
      });
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(this.cfg.port, addr, () => {
          server.removeListener('error', reject);
          resolve();
        });
      });
      this.servers.push(server);
    }

    this.sweeper = setInterval(() => {
      this.pending.sweep();
      this.grants.prune();
      const cutoff = Date.now() - this.cfg.dedupeWindowMs * 4;
      for (const [k, t] of this.lastNotified) if (t < cutoff) this.lastNotified.delete(k);
    }, 30_000);
    this.sweeper.unref?.();

    return {
      servers: this.servers,
      addresses,
      tailnet,
      close: () => this.close(),
    };
  }

  async close(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper);
    // Release blocked terminals to `ask` before the sockets go away.
    this.pending.releaseAll();
    for (const res of this.sseClients) res.end();
    this.sseClients.clear();
    await Promise.all(
      this.servers.map((s) => new Promise<void>((resolve) => s.close(() => resolve()))),
    );
  }

  private broadcast(payload: unknown): void {
    const line = `data: ${JSON.stringify(payload)}\n\n`;
    for (const res of this.sseClients) {
      try {
        res.write(line);
      } catch {
        this.sseClients.delete(res);
      }
    }
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, {
        ok: true,
        version: '0.1.0',
        pending: this.pending.list().length,
        grants: this.grants.list().length,
        summarizer: this.summarizer.available ? 'ready' : 'disabled',
        summarizerStats: this.summarizer.stats,
        publicBaseUrl: this.cfg.publicBaseUrl,
        notify: this.cfg.notify.transport,
      });
    }

    if (req.method === 'POST' && url.pathname === '/hook') {
      return this.handleHook(req, res);
    }

    if (req.method === 'POST' && url.pathname === '/approve') {
      return this.handleApprove(req, res);
    }

    if (req.method === 'GET' && url.pathname === '/pending') {
      return sendJson(res, 200, {
        pending: this.pending.list().map((p) => ({
          id: p.id,
          session: p.identity.name,
          tool: p.toolName,
          summary: p.summary,
          createdAt: p.createdAt,
          expiresAt: p.expiresAt,
        })),
      });
    }

    if (req.method === 'GET' && url.pathname === '/grants') {
      return sendJson(res, 200, { grants: this.grants.list() });
    }

    if (req.method === 'POST' && url.pathname === '/reload') {
      try {
        this.policy = loadPolicy();
        return sendJson(res, 200, { ok: true });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: (err as Error).message });
      }
    }

    if (req.method === 'GET' && url.pathname === '/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-store',
        Connection: 'keep-alive',
      });
      res.write(': connected\n\n');
      this.sseClients.add(res);
      req.on('close', () => this.sseClients.delete(res));
      return;
    }

    sendJson(res, 404, { error: 'not found' });
  }

  /**
   * The gate. Every path out of this function returns a decision, and the only
   * paths that return `allow` are an explicit policy match, a live grant, or a
   * signed human approval. Everything else — unparseable body, unknown error,
   * timeout, shutdown — returns `ask`, which reproduces stock Claude Code
   * behaviour exactly.
   */
  private async handleHook(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const startedAt = Date.now();
    let payload: PreToolUsePayload;

    try {
      payload = JSON.parse(await readBody(req)) as PreToolUsePayload;
    } catch (err) {
      logEvent({ event: 'error', session: '-', tool: '-', detail: `bad hook body: ${(err as Error).message}` });
      return sendJson(res, 200, decision('ask'));
    }

    if (payload?.hook_event_name !== 'PreToolUse' || typeof payload.tool_name !== 'string') {
      return sendJson(res, 200, decision('ask'));
    }

    const toolName = payload.tool_name;
    const rawInput = (payload.tool_input ?? {}) as Record<string, unknown>;

    // Identity: PREYMAX_NAME arrives as a header because Claude Code only
    // interpolates env vars into hook header values. An unlisted var becomes an
    // empty string with no error, which resolveIdentity treats as absent.
    const headerName = req.headers['x-preymax-name'];
    const envName = Array.isArray(headerName) ? headerName[0] : headerName;
    const identity = resolveIdentity(payload, envName);

    // Redact before anything is stored, logged, or transmitted.
    const redacted = redactToolInput(toolName, rawInput);

    // Two derived values, and they are NOT interchangeable:
    //   normalized  — the human-readable canonical form. Grants are prefixes of
    //                 THIS, so grant matching must compare against it.
    //   fingerprint — its hash, used as the dedupe and summary-cache key, where
    //                 a fixed-width opaque token is what we want.
    // Matching a grant against the hash silently never fires; that was a real bug.
    const normalized = normalizeForFingerprint(toolName, rawInput);
    const fingerprint = createHash('sha256').update(normalized).digest('hex').slice(0, 32);

    const finish = (d: PermissionDecision, source: string, reason?: string): void => {
      const latencyMs = Date.now() - startedAt;
      logEvent({
        event: d === 'allow' && source === 'policy' ? 'auto_allow' : d === 'deny' && source === 'policy' ? 'auto_deny' : 'decision',
        session: identity.name,
        tool: toolName,
        decision: d,
        decisionSource: source as never,
        latencyMs,
        fingerprint,
      });
      this.broadcast({
        type: 'decision',
        session: identity.name,
        tool: toolName,
        decision: d,
        source,
        latencyMs,
        summary: templateSummary(toolName, redacted),
      });
      sendJson(res, 200, decision(d, reason));
    };

    // 1. Policy.
    let match;
    try {
      match = evaluate(this.policy, toolName, rawInput);
    } catch (err) {
      logEvent({ event: 'error', session: identity.name, tool: toolName, detail: `policy error: ${(err as Error).message}` });
      return finish('ask', 'timeout');
    }

    if (match.bucket === 'auto_deny') {
      return finish('deny', 'policy', match.reason);
    }
    if (match.bucket === 'auto_allow') {
      return finish('allow', 'policy');
    }

    // 2. Live temporary grant. Matched against `normalized`, not the hash.
    const grant = this.grants.match(identity.name, toolName, normalized);
    if (grant) {
      return finish('allow', 'grant', 'preymax: covered by a temporary grant');
    }

    // 3. Escalate.
    const template = templateSummary(toolName, redacted);
    const summary = await this.summarizer
      .summarizeWithinBudget(fingerprint, toolName, redacted, this.cfg.summaryBudgetMs)
      .catch(() => null);

    const pending = this.pending.create(
      {
        identity,
        toolName,
        redactedInput: redacted,
        fingerprint,
        summary: summary?.text ?? template,
        templateSummary: template,
        summarySource: summary?.source ?? 'template',
      },
      this.cfg.decisionTimeoutMs,
    );

    logEvent({
      event: 'escalation',
      session: identity.name,
      tool: toolName,
      fingerprint,
      summary: pending.summary,
    });
    this.broadcast({
      type: 'escalation',
      id: pending.id,
      session: identity.name,
      tool: toolName,
      summary: pending.summary,
      summarySource: pending.summarySource,
    });

    void this.notify(pending.id, fingerprint, identity.name);

    const result = await this.pending.wait(pending.id, this.cfg.decisionTimeoutMs);

    if (result.decision === 'allow' && result.grant) {
      this.grants.add({
        session: identity.name,
        toolName,
        pattern: grantPatternFor(normalized),
        isRegex: false,
        expiresAt: Date.now() + this.cfg.grantTtlMs,
      });
    }

    return finish(result.decision, result.source, result.reason);
  }

  /**
   * Send the push. Deliberately not awaited by the hook path — a slow or dead
   * ntfy must not add latency to a decision that `preymax approve` can still
   * resolve locally.
   */
  private async notify(pendingId: string, fingerprint: string, sessionName: string): Promise<void> {
    const pending = this.pending.get(pendingId);
    if (!pending) return;

    const now = Date.now();

    // Dedupe: an identical call already pushed inside the window doesn't buzz
    // again. The escalation still exists and is still resolvable.
    const last = this.lastNotified.get(fingerprint);
    if (last !== undefined && now - last < this.cfg.dedupeWindowMs) {
      logEvent({ event: 'notify', session: sessionName, tool: pending.toolName, detail: 'suppressed: duplicate' });
      return;
    }

    // Burst: after the first escalation in a window, collapse the rest of the
    // burst into one digest rather than a push per call.
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

  /** Signed approvals from the phone, or from `preymax approve` over loopback. */
  private async handleApprove(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: unknown;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      logEvent({ event: 'error', session: '-', tool: '-', detail: 'approval rejected: malformed body' });
      return sendJson(res, 400, { ok: false, error: 'malformed' });
    }

    const v = verify(this.cfg.secret, body, { ttlMs: this.cfg.nonceTtlMs });
    if (!v.ok) {
      // Log loudly. An unsigned or replayed approval is the signature of someone
      // probing the endpoint, and it is the one thing you want in the record.
      logEvent({
        event: 'error',
        session: '-',
        tool: '-',
        detail: `approval REJECTED (${v.reason}) from ${req.socket.remoteAddress ?? 'unknown'}`,
      });
      return sendJson(res, 401, { ok: false, error: v.reason });
    }

    const a = body as { id: string; decision: 'allow' | 'deny'; nonce: string; grant?: boolean };
    const source = req.socket.remoteAddress?.includes('127.0.0.1') ? 'local' : 'phone';
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
      return sendJson(res, status, { ok: false, error: result.reason });
    }

    this.broadcast({ type: 'approval', id: a.id, decision: a.decision, source });
    return sendJson(res, 200, { ok: true, decision: a.decision });
  }
}
