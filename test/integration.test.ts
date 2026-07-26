import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * End-to-end: a real daemon, a real HTTP POST shaped exactly like Claude Code's
 * PreToolUse payload, and assertions on the JSON that comes back.
 *
 * PREYMAX_HOME is redirected to a temp dir before any preymax module is
 * imported, so this never touches the developer's real ~/.preymax.
 */

const HOME = mkdtempSync(join(tmpdir(), 'preymax-e2e-'));
process.env.PREYMAX_HOME = HOME;

const SECRET = 'c'.repeat(64);
const PORT = 7000 + Math.floor(Math.random() * 900);

writeFileSync(
  join(HOME, 'config.json'),
  JSON.stringify({
    port: PORT,
    bindTailnet: false,
    publicBaseUrl: null,
    secret: SECRET,
    decisionTimeoutMs: 700,
    summaryBudgetMs: 1,
    notify: { transport: 'none', ntfy: { server: '', topic: '', token: null, priority: 5, sound: null } },
    summarize: { enabled: false, model: 'claude-haiku-4-5', apiKey: null },
  }),
);

writeFileSync(
  join(HOME, 'policy.yaml'),
  `
auto_deny:
  - tool: Bash
    command_matches: ['\\brm\\b.*-rf']
    reason: "destructive pattern — blocked by preymax policy"
auto_allow:
  - tool: [Read, Glob]
  - tool: Bash
    command_matches: ['^git status']
`,
);

const { Daemon } = await import('../src/daemon/server.js');
const { loadConfig } = await import('../src/core/config.js');
const { makeApproval } = await import('../src/core/hmac.js');

const base = `http://127.0.0.1:${PORT}`;
let handle: Awaited<ReturnType<InstanceType<typeof Daemon>['start']>>;

function hookPayload(toolName: string, toolInput: Record<string, unknown>) {
  return {
    session_id: 'sess-abc123',
    cwd: '/tmp/api-project',
    permission_mode: 'default',
    hook_event_name: 'PreToolUse',
    tool_name: toolName,
    tool_input: toolInput,
    tool_use_id: 'toolu_01',
  };
}

async function postHook(toolName: string, toolInput: Record<string, unknown>, name = 'api') {
  const res = await fetch(`${base}/hook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Preymax-Name': name },
    body: JSON.stringify(hookPayload(toolName, toolInput)),
  });
  return (await res.json()) as {
    hookSpecificOutput: { permissionDecision: string; permissionDecisionReason?: string; hookEventName: string };
  };
}

describe('daemon end-to-end', () => {
  before(async () => {
    handle = await new Daemon(loadConfig()).start();
  });
  after(async () => {
    await handle.close();
    rmSync(HOME, { recursive: true, force: true });
  });

  it('reports healthy', async () => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { ok: boolean };
    assert.equal(body.ok, true);
  });

  it('auto-allows a policy-matched read', async () => {
    const out = await postHook('Read', { file_path: '/tmp/x.ts' });
    assert.equal(out.hookSpecificOutput.hookEventName, 'PreToolUse');
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow');
  });

  it('auto-allows a policy-matched command', async () => {
    const out = await postHook('Bash', { command: 'git status --short' });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow');
  });

  it('auto-denies a destructive command and explains why', async () => {
    const out = await postHook('Bash', { command: 'rm -rf /important' });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(out.hookSpecificOutput.permissionDecisionReason ?? '', /preymax policy/);
  });

  it('escalates an unmatched command and falls through to ask on timeout', async () => {
    const started = Date.now();
    const out = await postHook('Bash', { command: 'npx prisma migrate reset' });
    const elapsed = Date.now() - started;
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
    assert.ok(elapsed >= 600, `should have blocked for the timeout, took ${elapsed}ms`);
  });

  it('a signed approval unblocks a waiting terminal with allow', async () => {
    const inFlight = postHook('Bash', { command: 'terraform apply -auto-approve' });

    // Poll until the escalation appears, then approve it.
    let id: string | undefined;
    let nonce: string | undefined;
    for (let i = 0; i < 30 && !id; i++) {
      await new Promise((r) => setTimeout(r, 15));
      const res = await fetch(`${base}/pending`);
      const { pending } = (await res.json()) as { pending: Array<{ id: string }> };
      if (pending.length > 0) {
        id = pending[0]!.id;
        const items = JSON.parse(readFileSync(join(HOME, 'pending.json'), 'utf8')) as Array<{
          id: string;
          nonce: string;
        }>;
        nonce = items.find((p) => p.id === id)!.nonce;
      }
    }
    assert.ok(id && nonce, 'escalation never appeared in the pending table');

    const approval = makeApproval(SECRET, { id, decision: 'allow', nonce, ts: Date.now() });
    const res = await fetch(`${base}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(approval),
    });
    assert.equal(res.status, 200);

    const out = await inFlight;
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow');
  });

  it('a granted pattern short-circuits the next identical call', async () => {
    const cmd = 'npm run deploy --stage staging';
    const inFlight = postHook('Bash', { command: cmd });

    let id: string | undefined;
    let nonce: string | undefined;
    for (let i = 0; i < 30 && !id; i++) {
      await new Promise((r) => setTimeout(r, 15));
      const res = await fetch(`${base}/pending`);
      const { pending } = (await res.json()) as { pending: Array<{ id: string }> };
      if (pending.length > 0) {
        id = pending[0]!.id;
        const items = JSON.parse(readFileSync(join(HOME, 'pending.json'), 'utf8')) as Array<{
          id: string;
          nonce: string;
        }>;
        nonce = items.find((p) => p.id === id)!.nonce;
      }
    }
    assert.ok(id && nonce, 'escalation never appeared');

    // Approve WITH a grant.
    await fetch(`${base}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeApproval(SECRET, { id, decision: 'allow', nonce, ts: Date.now(), grant: true })),
    });
    assert.equal((await inFlight).hookSpecificOutput.permissionDecision, 'allow');

    // The same call again must be allowed immediately by the grant, not
    // escalated. Regression guard: the grant pattern is a prefix of the
    // normalized command, so it must be matched against that and not its hash.
    const started = Date.now();
    const second = await postHook('Bash', { command: cmd });
    const elapsed = Date.now() - started;
    assert.equal(second.hookSpecificOutput.permissionDecision, 'allow');
    assert.match(second.hookSpecificOutput.permissionDecisionReason ?? '', /temporary grant/);
    assert.ok(elapsed < 400, `grant should be instant, took ${elapsed}ms`);
  });

  it('a grant does not cover an unrelated command', async () => {
    const out = await postHook('Bash', { command: 'kubectl delete namespace prod' });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
  });

  it('rejects an unsigned approval with 401 and does not decide', async () => {
    const res = await fetch(`${base}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'whatever', decision: 'allow', nonce: 'n', ts: Date.now(), sig: 'bad' }),
    });
    assert.equal(res.status, 401);
  });

  it('rejects an approval signed with the wrong secret', async () => {
    const forged = makeApproval('f'.repeat(64), {
      id: 'x',
      decision: 'allow',
      nonce: 'n',
      ts: Date.now(),
    });
    const res = await fetch(`${base}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(forged),
    });
    assert.equal(res.status, 401);
  });

  it('returns ask (never allow) for a malformed hook body', async () => {
    const res = await fetch(`${base}/hook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json at all',
    });
    const out = (await res.json()) as { hookSpecificOutput: { permissionDecision: string } };
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
  });

  it('returns ask for an unrecognized hook event', async () => {
    const res = await fetch(`${base}/hook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hook_event_name: 'SomethingElse', tool_name: 'Bash' }),
    });
    const out = (await res.json()) as { hookSpecificOutput: { permissionDecision: string } };
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
  });

  it('writes a JSONL event log with latency and decision source', async () => {
    await postHook('Read', { file_path: '/tmp/logged.ts' });
    const file = join(HOME, 'events.jsonl');
    assert.ok(existsSync(file), 'no event log was written');
    const lines = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const allow = lines.find(
      (l) => l.tool === 'Read' && (l.event === 'auto_allow' || l.decision === 'allow'),
    );
    assert.ok(allow, 'no allow decision recorded');
    assert.equal(allow.session, 'api');
    assert.equal(typeof allow.latencyMs, 'number');
    assert.equal(allow.decisionSource, 'policy');
  });

  it('resolves the terminal name from the X-Preymax-Name header', async () => {
    await postHook('Read', { file_path: '/tmp/named.ts' }, 'infra');
    const lines = readFileSync(join(HOME, 'events.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l));
    assert.ok(lines.some((l) => l.session === 'infra'), 'header-supplied name was not used');
  });

  it('falls back to cwd-based naming when the header is empty', async () => {
    // An env var missing from allowedEnvVars interpolates to "" — silently.
    // That must not produce a session literally named "".
    const res = await fetch(`${base}/hook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Preymax-Name': '' },
      body: JSON.stringify(hookPayload('Read', { file_path: '/tmp/y.ts' })),
    });
    await res.json();
    const lines = readFileSync(join(HOME, 'events.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l));
    const last = lines[lines.length - 1];
    assert.ok(last.session && last.session.length > 0);
    assert.ok(last.session.startsWith('api-project'), `got ${last.session}`);
  });
});
