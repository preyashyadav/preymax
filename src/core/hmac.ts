import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

/**
 * Approval authentication.
 *
 * An approval lets a phone notification authorize a shell command, so every
 * field that matters is inside the signed string: the pending id, the decision,
 * a single-use nonce, and a timestamp. Changing any of them invalidates the
 * signature.
 */

export interface SignedApproval {
  id: string;
  decision: 'allow' | 'deny';
  /** Single-use, minted with the pending request and consumed on first use. */
  nonce: string;
  /** Milliseconds since epoch. Rejected outside the TTL window. */
  ts: number;
  /** Optional: also grant this pattern for a while. Part of the signed payload. */
  grant?: boolean;
  sig: string;
}

export function newNonce(): string {
  return randomBytes(16).toString('hex');
}

/**
 * The signed string. Field order is fixed and every field is length-delimited by
 * the separator, so no two distinct payloads can produce the same input.
 */
export function canonicalString(a: Omit<SignedApproval, 'sig'>): string {
  return [a.id, a.decision, a.nonce, String(a.ts), a.grant ? '1' : '0'].join('\n');
}

export function sign(secret: string, a: Omit<SignedApproval, 'sig'>): string {
  return createHmac('sha256', secret).update(canonicalString(a)).digest('hex');
}

export function makeApproval(
  secret: string,
  a: Omit<SignedApproval, 'sig'>,
): SignedApproval {
  return { ...a, sig: sign(secret, a) };
}

export type VerifyResult =
  | { ok: true }
  | { ok: false; reason: 'malformed' | 'bad_signature' | 'expired' | 'future' };

export function verify(
  secret: string,
  approval: unknown,
  opts: { ttlMs: number; now?: number },
): VerifyResult {
  const now = opts.now ?? Date.now();
  if (!approval || typeof approval !== 'object') return { ok: false, reason: 'malformed' };
  const a = approval as Record<string, unknown>;

  if (
    typeof a.id !== 'string' ||
    typeof a.nonce !== 'string' ||
    typeof a.sig !== 'string' ||
    typeof a.ts !== 'number' ||
    !Number.isFinite(a.ts) ||
    (a.decision !== 'allow' && a.decision !== 'deny')
  ) {
    return { ok: false, reason: 'malformed' };
  }

  const candidate: Omit<SignedApproval, 'sig'> = {
    id: a.id,
    decision: a.decision,
    nonce: a.nonce,
    ts: a.ts,
    grant: a.grant === true,
  };

  const expected = sign(secret, candidate);
  const given = a.sig;
  // Compare in constant time. Length check first — timingSafeEqual throws on a
  // length mismatch, and the length of a hex digest is not a secret.
  if (given.length !== expected.length) return { ok: false, reason: 'bad_signature' };
  if (!timingSafeEqual(Buffer.from(given, 'utf8'), Buffer.from(expected, 'utf8'))) {
    return { ok: false, reason: 'bad_signature' };
  }

  // Check the clock only after the signature proves the timestamp wasn't forged.
  if (now - candidate.ts > opts.ttlMs) return { ok: false, reason: 'expired' };
  if (candidate.ts - now > 60_000) return { ok: false, reason: 'future' };

  return { ok: true };
}
