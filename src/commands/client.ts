import { existsSync, readFileSync } from 'node:fs';
import { loadConfig } from '../core/config.js';
import { makeApproval } from '../core/hmac.js';
import { paths } from '../core/paths.js';

/**
 * Loopback client used by `preymax pending / approve / deny / stats / doctor`.
 *
 * This is the escape hatch that must keep working when the phone, the tailnet,
 * and the push service are all unavailable — so it talks to 127.0.0.1 directly
 * and signs with the same secret the phone path uses. One code path, one
 * verification routine, no second trust model to reason about.
 */

export function daemonBase(): string {
  const cfg = loadConfig();
  return `http://127.0.0.1:${cfg.port}`;
}

export class DaemonUnreachableError extends Error {
  constructor(base: string, cause: string) {
    super(
      `cannot reach the preymax daemon at ${base} (${cause})\n` +
        `  start it with:  preymax daemon\n` +
        `  or check:       launchctl list | grep preymax`,
    );
  }
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  const base = daemonBase();
  try {
    return await fetch(base + path, {
      ...init,
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    throw new DaemonUnreachableError(base, (err as Error).message);
  }
}

export interface PendingSummary {
  id: string;
  session: string;
  tool: string;
  summary: string;
  createdAt: number;
  expiresAt: number;
}

export async function fetchPending(): Promise<PendingSummary[]> {
  const res = await request('/pending');
  const body = (await res.json()) as { pending: PendingSummary[] };
  return body.pending;
}

export async function fetchHealth(): Promise<Record<string, unknown>> {
  const res = await request('/health');
  return (await res.json()) as Record<string, unknown>;
}

export async function fetchGrants(): Promise<unknown[]> {
  const res = await request('/grants');
  return ((await res.json()) as { grants: unknown[] }).grants;
}

/**
 * Send a locally-signed decision. The nonce comes from the pending record the
 * daemon minted, so a local approval consumes the same single-use nonce the
 * phone would have used — a captured push cannot be replayed afterwards.
 */
export async function sendDecision(
  id: string,
  dec: 'allow' | 'deny',
  grant: boolean,
): Promise<{ ok: boolean; error?: string }> {
  const cfg = loadConfig();

  // Fetch the nonce for this id straight from the daemon's pending table.
  const res = await request('/pending');
  const { pending } = (await res.json()) as { pending: PendingSummary[] };
  const match = pending.find((p) => p.id === id || p.id.startsWith(id));
  if (!match) {
    return { ok: false, error: `no pending request matching "${id}"` };
  }

  // The daemon does not expose nonces over /pending on purpose, so ask it to
  // sign on our behalf via the authenticated local path: we hold the secret,
  // so we can mint the approval — but we need the nonce. It is stored in the
  // pending file, which only we (mode 0600) can read.
  const nonce = readNonce(match.id);
  if (!nonce) return { ok: false, error: `could not read nonce for ${match.id}` };

  const approval = makeApproval(cfg.secret, {
    id: match.id,
    decision: dec,
    nonce,
    ts: Date.now(),
    grant,
  });

  const post = await request('/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(approval),
  });
  const body = (await post.json()) as { ok: boolean; error?: string };
  return body;
}

/**
 * Read the nonce for a pending id straight off disk.
 *
 * The daemon deliberately does not expose nonces over /pending — that endpoint
 * is readable by anything that can reach loopback. The pending file is mode
 * 0600, so possession of the nonce is equivalent to possession of the secret,
 * which the local CLI already has.
 */
function readNonce(id: string): string | null {
  if (!existsSync(paths.pending())) return null;
  try {
    const items = JSON.parse(readFileSync(paths.pending(), 'utf8')) as Array<{
      id: string;
      nonce: string;
    }>;
    return items.find((p) => p.id === id)?.nonce ?? null;
  } catch {
    return null;
  }
}
