import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeApproval, sign, verify, newNonce } from '../src/core/hmac.js';
import { PendingStore } from '../src/daemon/pending.js';
import { assertSafeBind, isTailscaleAddress, UnsafeBindError } from '../src/daemon/net.js';
import type { SessionIdentity } from '../src/types.js';

/**
 * The Phase 5 red-team table, as executable tests.
 * Each row of THREAT_MODEL.md maps to a case here.
 */

const SECRET = 'a'.repeat(64);
const OTHER_SECRET = 'b'.repeat(64);

const identity: SessionIdentity = {
  name: 'api',
  source: 'env',
  sessionId: 'sess123',
  cwd: '/tmp/api',
};

function newStore(): { store: PendingStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'preymax-test-'));
  return { store: new PendingStore(join(dir, 'pending.json')), dir };
}

function makePending(store: PendingStore, ttlMs = 1000) {
  return store.create(
    {
      identity,
      toolName: 'Bash',
      redactedInput: { command: 'npx prisma migrate reset' },
      fingerprint: 'fp1',
      summary: 'reset the database',
      templateSummary: 'run: npx prisma migrate reset',
      summarySource: 'template',
    },
    ttlMs,
  );
}

describe('HMAC approval signing', () => {
  it('accepts a correctly signed approval', () => {
    const a = makeApproval(SECRET, { id: 'x', decision: 'allow', nonce: newNonce(), ts: Date.now() });
    assert.deepEqual(verify(SECRET, a, { ttlMs: 60_000 }), { ok: true });
  });

  it('rejects an unsigned approval', () => {
    const a = { id: 'x', decision: 'allow', nonce: newNonce(), ts: Date.now() };
    assert.equal(verify(SECRET, a, { ttlMs: 60_000 }).ok, false);
  });

  it('rejects a signature made with a different secret', () => {
    const a = makeApproval(OTHER_SECRET, { id: 'x', decision: 'allow', nonce: 'n', ts: Date.now() });
    const r = verify(SECRET, a, { ttlMs: 60_000 });
    assert.equal(r.ok, false);
    assert.equal(r.ok === false && r.reason, 'bad_signature');
  });

  it('rejects a flipped decision (deny -> allow) without re-signing', () => {
    const a = makeApproval(SECRET, { id: 'x', decision: 'deny', nonce: 'n', ts: Date.now() });
    const tampered = { ...a, decision: 'allow' as const };
    assert.equal(verify(SECRET, tampered, { ttlMs: 60_000 }).ok, false);
  });

  it('rejects a swapped pending id', () => {
    const a = makeApproval(SECRET, { id: 'x', decision: 'allow', nonce: 'n', ts: Date.now() });
    assert.equal(verify(SECRET, { ...a, id: 'y' }, { ttlMs: 60_000 }).ok, false);
  });

  it('rejects a smuggled grant flag', () => {
    const a = makeApproval(SECRET, { id: 'x', decision: 'allow', nonce: 'n', ts: Date.now(), grant: false });
    assert.equal(verify(SECRET, { ...a, grant: true }, { ttlMs: 60_000 }).ok, false);
  });

  it('rejects an expired approval', () => {
    const a = makeApproval(SECRET, { id: 'x', decision: 'allow', nonce: 'n', ts: Date.now() - 600_000 });
    const r = verify(SECRET, a, { ttlMs: 60_000 });
    assert.equal(r.ok === false && r.reason, 'expired');
  });

  it('rejects a timestamp from the future', () => {
    const a = makeApproval(SECRET, { id: 'x', decision: 'allow', nonce: 'n', ts: Date.now() + 600_000 });
    const r = verify(SECRET, a, { ttlMs: 60_000 });
    assert.equal(r.ok === false && r.reason, 'future');
  });

  it('rejects malformed payloads without throwing', () => {
    for (const bad of [null, undefined, 42, 'str', {}, { id: 1 }, { id: 'x', decision: 'maybe' }]) {
      assert.doesNotThrow(() => verify(SECRET, bad, { ttlMs: 60_000 }));
      assert.equal(verify(SECRET, bad, { ttlMs: 60_000 }).ok, false);
    }
  });

  it('binds every field into the signature (no field is free)', () => {
    const base = { id: 'x', decision: 'allow' as const, nonce: 'n', ts: 1000, grant: false };
    const sigs = new Set([
      sign(SECRET, base),
      sign(SECRET, { ...base, id: 'y' }),
      sign(SECRET, { ...base, decision: 'deny' }),
      sign(SECRET, { ...base, nonce: 'm' }),
      sign(SECRET, { ...base, ts: 1001 }),
      sign(SECRET, { ...base, grant: true }),
    ]);
    assert.equal(sigs.size, 6, 'two different payloads produced the same signature');
  });
});

describe('pending decisions: the fail-safe invariant', () => {
  let ctx: ReturnType<typeof newStore>;
  beforeEach(() => { ctx = newStore(); });
  afterEach(() => rmSync(ctx.dir, { recursive: true, force: true }));

  it('resolves to ask on timeout, never allow', async () => {
    const p = makePending(ctx.store);
    const result = await ctx.store.wait(p.id, 30);
    assert.equal(result.decision, 'ask');
    assert.equal(result.source, 'timeout');
  });

  it('resolves to ask on shutdown, never allow', async () => {
    const p = makePending(ctx.store);
    const waiting = ctx.store.wait(p.id, 60_000);
    ctx.store.releaseAll();
    const result = await waiting;
    assert.equal(result.decision, 'ask');
    assert.equal(result.source, 'shutdown');
  });

  it('applies a valid decision and releases the waiter', async () => {
    const p = makePending(ctx.store);
    const waiting = ctx.store.wait(p.id, 60_000);
    assert.deepEqual(ctx.store.decide(p.id, 'allow', 'phone', { nonce: p.nonce }), { ok: true });
    assert.equal((await waiting).decision, 'allow');
  });

  it('is idempotent: a duplicate delivery is a no-op, not a second decision', async () => {
    const p = makePending(ctx.store);
    const waiting = ctx.store.wait(p.id, 60_000);
    assert.equal(ctx.store.decide(p.id, 'allow', 'phone', { nonce: p.nonce }).ok, true);
    const second = ctx.store.decide(p.id, 'allow', 'phone', { nonce: p.nonce });
    assert.equal(second.ok, false);
    assert.equal(second.ok === false && second.reason, 'already_decided');
    assert.equal((await waiting).decision, 'allow');
  });

  it('a later deny cannot override an allow already returned to the terminal', async () => {
    const p = makePending(ctx.store);
    const waiting = ctx.store.wait(p.id, 60_000);
    ctx.store.decide(p.id, 'allow', 'phone', { nonce: p.nonce });
    const late = ctx.store.decide(p.id, 'deny', 'local', { nonce: p.nonce });
    assert.equal(late.ok, false);
    assert.equal((await waiting).decision, 'allow');
  });

  it('rejects a replayed nonce', () => {
    const p1 = makePending(ctx.store);
    assert.equal(ctx.store.decide(p1.id, 'allow', 'phone', { nonce: p1.nonce }).ok, true);
    // A captured webhook replayed against a fresh pending id carries the old nonce.
    const p2 = makePending(ctx.store);
    const replay = ctx.store.decide(p2.id, 'allow', 'phone', { nonce: p1.nonce });
    assert.equal(replay.ok, false);
    assert.equal(replay.ok === false && replay.reason, 'nonce_replayed');
  });

  it('rejects a decision for an unknown id', () => {
    const r = ctx.store.decide('nonexistent', 'allow', 'phone', { nonce: 'n' });
    assert.equal(r.ok === false && r.reason, 'unknown');
  });

  it('rejects a decision after the request expired', async () => {
    const p = makePending(ctx.store, 10);
    await new Promise((r) => setTimeout(r, 30));
    const r = ctx.store.decide(p.id, 'allow', 'phone', { nonce: p.nonce });
    assert.equal(r.ok === false && r.reason, 'expired');
  });

  it('expires rather than revives pending requests left by a dead daemon', async () => {
    const p = makePending(ctx.store);
    const file = join(ctx.dir, 'pending.json');
    // Simulate a restart against the same file.
    const restarted = new PendingStore(file);
    const orphaned = restarted.recoverAndExpire();
    assert.ok(orphaned >= 1, 'should have counted the orphaned request');
    // The revived daemon must not accept a decision for it.
    assert.equal(restarted.decide(p.id, 'allow', 'phone', { nonce: p.nonce }).ok, false);
  });
});

describe('network binding', () => {
  it('accepts loopback', () => {
    assert.doesNotThrow(() => assertSafeBind(['127.0.0.1']));
  });

  it('accepts a Tailscale CGNAT address', () => {
    assert.doesNotThrow(() => assertSafeBind(['127.0.0.1', '100.101.102.103']));
  });

  it('refuses the wildcard address', () => {
    assert.throws(() => assertSafeBind(['0.0.0.0']), UnsafeBindError);
  });

  it('refuses a LAN address', () => {
    assert.throws(() => assertSafeBind(['192.168.1.50']), UnsafeBindError);
    assert.throws(() => assertSafeBind(['10.0.0.5']), UnsafeBindError);
  });

  it('refuses a public address', () => {
    assert.throws(() => assertSafeBind(['203.0.113.7']), UnsafeBindError);
  });

  it('refuses an empty bind list', () => {
    assert.throws(() => assertSafeBind([]), UnsafeBindError);
  });

  it('identifies the CGNAT range precisely', () => {
    assert.equal(isTailscaleAddress('100.64.0.1'), true);
    assert.equal(isTailscaleAddress('100.127.255.254'), true);
    // 100.0.0.0/8 outside 64-127 is ordinary public space, not Tailscale.
    assert.equal(isTailscaleAddress('100.63.0.1'), false);
    assert.equal(isTailscaleAddress('100.128.0.1'), false);
  });
});
