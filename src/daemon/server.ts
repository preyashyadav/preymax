import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { bindsTailnet, relayActive, type Config } from '../core/config.js';
import { resolveIdentity } from '../core/identity.js';
import { logEvent } from '../log/events.js';
import { evaluate, loadPolicy, type Policy } from '../core/policy.js';
import { normalizeForFingerprint, redactToolInput } from '../core/redact.js';
import { isMultilineCommand, templateSummary } from '../core/template.js';
// Type-only: erased at compile time, so this does NOT pull the relay in.
import type { Relay } from '../relay/index.js';
import type { PermissionDecision, PreToolUseHookOutput, PreToolUsePayload } from '../types.js';
import { assertSafeBind, resolveBindAddresses } from './net.js';
import { buildStatus } from './status.js';

const MAX_BODY_BYTES = 2 * 1024 * 1024;

function decision(d: PermissionDecision, reason?: string): PreToolUseHookOutput {
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
  private policy: Policy;
  private readonly servers: Server[] = [];
  private readonly sseClients = new Set<ServerResponse>();
  private sweeper: NodeJS.Timeout | null = null;
  private readonly startedAt = Date.now();
  private boundAddresses: string[] = [];
  private boundTailnet: string | null = null;

  /**
   * Loaded on first use and only when `relay.enabled`. Never referenced from
   * the hook path unless that flag is on — see relayIfEnabled().
   */
  private relay: Relay | null = null;
  private relayLoading: Promise<Relay> | null = null;

  constructor(private readonly cfg: Config) {
    this.policy = loadPolicy();
  }

  /**
   * The relay, or null when it is disabled.
   *
   * The dynamic import is the enforcement mechanism for "no network I/O and no
   * model calls in the hot path". With the relay off, `src/relay/**` is never
   * evaluated: no Summarizer is constructed, no transport module is parsed, and
   * there is no blocking-wait machinery to accidentally await.
   */
  private async relayIfEnabled(): Promise<Relay | null> {
    if (!relayActive(this.cfg)) return null;
    if (this.relay) return this.relay;
    if (!this.relayLoading) {
      this.relayLoading = import('../relay/index.js').then(({ loadRelay }) =>
        loadRelay(this.cfg, (p) => this.broadcast(p)),
      );
    }
    this.relay = await this.relayLoading;
    return this.relay;
  }

  async start(): Promise<DaemonHandle> {
    // The tailnet address exists so a phone can reach the daemon; with the
    // relay off there is no phone, and `/hook` answering out there is more
    // surface than the config asked for. See `bindsTailnet`.
    const { addresses, tailnet } = resolveBindAddresses(bindsTailnet(this.cfg));
    // Throws before any listener opens if a non-loopback, non-tailnet address
    // is in the list. This is the assertion Phase 5 requires.
    assertSafeBind(addresses);
    this.boundAddresses = addresses;
    this.boundTailnet = tailnet;

    const relay = await this.relayIfEnabled();
    relay?.start();

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

    this.sweeper = setInterval(() => this.relay?.sweep(), 30_000);
    this.sweeper.unref?.();

    return { servers: this.servers, addresses, tailnet, close: () => this.close() };
  }

  async close(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper);
    // Release blocked terminals to `ask` before the sockets go away.
    this.relay?.stop();
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
        pending: this.relay?.pending.list().length ?? 0,
        relay: this.cfg.relay.enabled,
        shadow: this.cfg.shadow,
      });
    }

    // The authoritative health surface. `preymax doctor` renders this and
    // computes nothing itself — see daemon/status.ts for why.
    if (req.method === 'GET' && url.pathname === '/status') {
      return sendJson(
        res,
        200,
        buildStatus({
          cfg: this.cfg,
          version: '0.1.0',
          startedAt: this.startedAt,
          addresses: this.boundAddresses,
          tailnet: this.boundTailnet,
          pending: this.relay?.pending.list().length ?? 0,
          grants: this.relay?.grants.list().length ?? 0,
          summarizerAvailable: this.relay?.summarizerAvailable ?? false,
          summarizerStats:
            this.relay?.summarizerStats ?? { ok: 0, hits: 0, misses: 0, errors: 0, timeouts: 0 },
        }),
      );
    }

    if (req.method === 'POST' && url.pathname === '/hook') {
      return this.handleHook(req, res);
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

    // --- Relay-only endpoints. 409 rather than 404 so the CLI can say why. ---

    const relayRoutes = ['/approve', '/pending', '/grants'];
    if (relayRoutes.includes(url.pathname)) {
      const relay = await this.relayIfEnabled();
      if (!relay) {
        return sendJson(res, 409, {
          ok: false,
          error: this.cfg.shadow
            ? 'shadow mode is on — nothing is pending and nothing can be approved'
            : 'relay is disabled — enable it with `preymax relay enable`',
        });
      }

      if (req.method === 'POST' && url.pathname === '/approve') {
        let body: unknown;
        try {
          body = JSON.parse(await readBody(req));
        } catch {
          logEvent({ event: 'error', session: '-', tool: '-', detail: 'approval rejected: malformed body' });
          return sendJson(res, 400, { ok: false, error: 'malformed' });
        }
        const out = relay.approve(body, req.socket.remoteAddress);
        return sendJson(res, out.status, out.payload);
      }

      if (req.method === 'GET' && url.pathname === '/pending') {
        return sendJson(res, 200, {
          pending: relay.pending.list().map((p) => ({
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
        return sendJson(res, 200, { grants: relay.grants.list() });
      }
    }

    sendJson(res, 404, { error: 'not found' });
  }

  /**
   * The gate. Every path out of this function returns a decision, and the only
   * paths that return `allow` are an explicit policy match, a live grant, or a
   * signed human approval. Everything else — unparseable body, unknown error,
   * timeout, shutdown — returns `ask`, which reproduces stock Claude Code
   * behaviour exactly.
   *
   * With the relay off this function performs **no I/O beyond one appended log
   * line**: parse, resolve identity, redact, match a regex, respond.
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
        event: d === 'allow' && source === 'policy' ? 'auto_allow' : 'decision',
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

    // 1. Policy. Pure, synchronous, no I/O.
    let match;
    try {
      match = evaluate(this.policy, toolName, rawInput);
    } catch (err) {
      logEvent({ event: 'error', session: identity.name, tool: toolName, detail: `policy error: ${(err as Error).message}` });
      return finish('ask', 'policy-error');
    }

    if (match.bucket === 'auto_allow') {
      return finish('allow', 'policy');
    }

    // 2. Escalation. Recorded regardless of whether anyone will be told about
    // it — the log is the product, the notification is a feature.
    const summary = templateSummary(toolName, redacted);
    const cmd = redacted.command;
    logEvent({
      event: 'escalation',
      session: identity.name,
      tool: toolName,
      fingerprint,
      summary,
      ...(typeof cmd === 'string' && isMultilineCommand(cmd) ? { multiline: true } : {}),
    });

    const relay = await this.relayIfEnabled();

    // 3. Shadow / relay-off: fall straight through to the normal prompt. No
    // summarizer, no push, no blocking wait, no stalled terminal.
    if (!relay) {
      this.broadcast({ type: 'escalation', session: identity.name, tool: toolName, summary, shadow: true });
      return finish('ask', this.cfg.shadow ? 'shadow' : 'no-relay');
    }

    // 4. Live temporary grant. Matched against `normalized`, not the hash.
    if (relay.matchGrant(identity.name, toolName, normalized)) {
      return finish('allow', 'grant', 'preymax: covered by a temporary grant');
    }

    const result = await relay.escalate({ identity, toolName, redacted, normalized, fingerprint });
    return finish(result.decision, result.source, result.reason);
  }
}
