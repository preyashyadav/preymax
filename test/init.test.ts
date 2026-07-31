import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildHookEntry, buildLaunchAgentPlist, mergeHook, removeHook } from '../src/commands/init.js';
import { DEFAULT_CONFIG } from '../src/core/config.js';
import { GrantStore, grantPatternFor } from '../src/relay/grants.js';
import { templateSummary, notificationBody } from '../src/core/template.js';
import { resolveIdentity } from '../src/core/identity.js';
import type { PreToolUsePayload } from '../src/types.js';

describe('hook registration is idempotent', () => {
  const entry = buildHookEntry(7717);

  it('adds the hook to empty settings', () => {
    const { settings, changed } = mergeHook({}, entry);
    assert.equal(changed, true);
    const groups = (settings.hooks as { PreToolUse: Array<{ hooks: unknown[] }> }).PreToolUse;
    assert.equal(groups.length, 1);
    assert.equal(groups[0]!.hooks.length, 1);
  });

  it('does not duplicate on a second run', () => {
    const first = mergeHook({}, entry).settings;
    const second = mergeHook(first, entry);
    assert.equal(second.changed, false, 're-running init reported a change');
    const groups = (second.settings.hooks as { PreToolUse: Array<{ hooks: unknown[] }> }).PreToolUse;
    assert.equal(groups.length, 1);
    assert.equal(groups[0]!.hooks.length, 1, 'duplicate hook entry created');
  });

  it('is stable across many runs', () => {
    let settings: Record<string, unknown> = {};
    for (let i = 0; i < 10; i++) settings = mergeHook(settings, entry).settings;
    const groups = (settings.hooks as { PreToolUse: Array<{ hooks: unknown[] }> }).PreToolUse;
    assert.equal(groups.flatMap((g) => g.hooks).length, 1);
  });

  it('updates in place when the port changes, without adding a second entry', () => {
    const first = mergeHook({}, buildHookEntry(7717)).settings;
    const second = mergeHook(first, buildHookEntry(9999));
    assert.equal(second.changed, true);
    const hooks = (second.settings.hooks as { PreToolUse: Array<{ hooks: Array<{ url: string }> }> })
      .PreToolUse.flatMap((g) => g.hooks);
    assert.equal(hooks.length, 1);
    assert.match(hooks[0]!.url, /:9999\//);
  });

  it('preserves unrelated user hooks', () => {
    const existing = {
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: '/usr/local/bin/mine.sh' }] }],
        PostToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'echo done' }] }],
      },
      permissions: { allow: ['Read'] },
    };
    const { settings } = mergeHook(existing, entry);
    const hooks = settings.hooks as Record<string, Array<{ hooks: unknown[] }>>;
    assert.equal(hooks.PostToolUse!.length, 1, 'PostToolUse was disturbed');
    assert.deepEqual((settings as typeof existing).permissions, { allow: ['Read'] });
    const all = hooks.PreToolUse!.flatMap((g) => g.hooks);
    assert.ok(all.some((h) => (h as { command?: string }).command === '/usr/local/bin/mine.sh'));
  });

  it('allowlists PREYMAX_NAME — without it the env var silently becomes ""', () => {
    assert.deepEqual(entry.allowedEnvVars, ['PREYMAX_NAME']);
    assert.equal(entry.headers?.['X-Preymax-Name'], '$PREYMAX_NAME');
  });

  it('registers a loopback URL, never a wildcard or public host', () => {
    assert.match(entry.url, /^http:\/\/127\.0\.0\.1:\d+\/hook$/);
  });

  it('refuses to touch a PreToolUse key that is not an array', () => {
    assert.throws(() => mergeHook({ hooks: { PreToolUse: 'nope' } }, entry), /not an array/);
  });

  it('removeHook is the exact inverse of mergeHook', () => {
    const added = mergeHook({}, entry).settings;
    const { settings, changed } = removeHook(added);
    assert.equal(changed, true);
    const groups = (settings.hooks as { PreToolUse: unknown[] }).PreToolUse;
    assert.equal(groups.length, 0);
  });

  it('removeHook leaves other hooks alone', () => {
    const existing = mergeHook(
      { hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'mine' }] }] } },
      entry,
    ).settings;
    const { settings } = removeHook(existing);
    const all = (settings.hooks as { PreToolUse: Array<{ hooks: unknown[] }> }).PreToolUse.flatMap(
      (g) => g.hooks,
    );
    assert.equal(all.length, 1);
    assert.equal((all[0] as { command: string }).command, 'mine');
  });
});

describe('temporary grants', () => {
  let dir: string;
  let store: GrantStore;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'preymax-grants-'));
    store = new GrantStore(join(dir, 'grants.json'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('matches a repeat of the granted call', () => {
    const fp = 'bash {"command":"npm run deploy --stage staging"}';
    store.add({
      session: 'api',
      toolName: 'Bash',
      pattern: grantPatternFor(fp),
      isRegex: false,
      expiresAt: Date.now() + 60_000,
    });
    assert.ok(store.match('api', 'Bash', fp));
  });

  it('does not leak across sessions', () => {
    store.add({ session: 'api', toolName: 'Bash', pattern: 'abc', isRegex: false, expiresAt: Date.now() + 60_000 });
    assert.equal(store.match('web', 'Bash', 'abcdef'), null);
  });

  it('does not leak across tools', () => {
    store.add({ session: 'api', toolName: 'Bash', pattern: 'abc', isRegex: false, expiresAt: Date.now() + 60_000 });
    assert.equal(store.match('api', 'Write', 'abcdef'), null);
  });

  it('does not match an unrelated command', () => {
    store.add({
      session: 'api',
      toolName: 'Bash',
      pattern: grantPatternFor('bash {"command":"npm test"}'),
      isRegex: false,
      expiresAt: Date.now() + 60_000,
    });
    assert.equal(store.match('api', 'Bash', 'bash {"command":"rm -rf /"}'), null);
  });

  it('expires', () => {
    store.add({ session: 'api', toolName: 'Bash', pattern: 'abc', isRegex: false, expiresAt: Date.now() - 1 });
    assert.equal(store.match('api', 'Bash', 'abcdef'), null);
  });

  it('survives a restart', () => {
    store.add({ session: 'api', toolName: 'Bash', pattern: 'abc', isRegex: false, expiresAt: Date.now() + 60_000 });
    const reloaded = new GrantStore(join(dir, 'grants.json'));
    assert.ok(reloaded.match('api', 'Bash', 'abcdef'));
  });
});

describe('notification formatting', () => {
  it('puts the terminal name in the first three words', () => {
    const body = notificationBody('api', templateSummary('Bash', { command: 'npx prisma migrate reset' }));
    assert.equal(body, '[api] run: npx prisma migrate reset');
    assert.ok(body.split(' ').slice(0, 3).join(' ').includes('api'));
  });

  it('formats each tool type readably', () => {
    assert.match(templateSummary('Write', { file_path: '/a/terraform/prod/main.tf' }), /^write: /);
    assert.match(templateSummary('Edit', { file_path: '/a/x.ts' }), /^edit: /);
    assert.match(templateSummary('WebFetch', { url: 'https://example.com' }), /^fetch: /);
    assert.match(templateSummary('Task', { description: 'audit deps' }), /^subagent: /);
  });

  it('degrades gracefully for an unknown future tool', () => {
    assert.equal(templateSummary('QuantumTool', {}), 'use QuantumTool');
    assert.match(templateSummary('QuantumTool', { command: 'entangle' }), /QuantumTool: entangle/);
  });

  it('truncates a multi-line command to its first line', () => {
    const s = templateSummary('Bash', { command: 'line one\nline two\nline three' });
    assert.equal(s, 'run: line one');
  });
});

describe('session identity resolution', () => {
  const payload: PreToolUsePayload = {
    session_id: 'abcdef123456',
    cwd: '/tmp/some-project',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: {},
  };

  it('prefers PREYMAX_NAME', () => {
    const id = resolveIdentity(payload, 'api');
    assert.equal(id.name, 'api');
    assert.equal(id.source, 'env');
  });

  it('trims whitespace from the header', () => {
    assert.equal(resolveIdentity(payload, '  web  ').name, 'web');
  });

  it('falls back to cwd when the env var is empty (the allowlist trap)', () => {
    const id = resolveIdentity(payload, '');
    assert.equal(id.source, 'cwd+branch');
    assert.ok(id.name.startsWith('some-project'));
  });

  it('falls back to cwd when the header is absent entirely', () => {
    assert.equal(resolveIdentity(payload, undefined).source, 'cwd+branch');
  });

  it('falls back to the session id when there is no usable cwd', () => {
    const id = resolveIdentity({ ...payload, cwd: '/' }, undefined);
    assert.equal(id.source, 'session_id');
    assert.equal(id.name, 'abcdef');
  });
});

describe('launch agent: caffeinate is gated on the relay', () => {
  const base = { ...DEFAULT_CONFIG, configDirs: [], secret: 'x' };

  it('does not keep the Mac awake for a local-only install', () => {
    // The only reason to hold sleep off is so a phone can reach the daemon.
    // v2 ships with no phone, so the default install must cost no battery.
    const plist = buildLaunchAgentPlist({ ...base, caffeinate: true });
    assert.equal(plist.includes('caffeinate'), false);
  });

  it('keeps it awake once the relay is on and the flag is set', () => {
    const plist = buildLaunchAgentPlist({
      ...base,
      caffeinate: true,
      relay: { ...base.relay, enabled: true },
    });
    assert.match(plist, /\/usr\/bin\/caffeinate/);
    assert.match(plist, /-dis/);
  });

  it('stays off when the flag is off, relay or not', () => {
    const plist = buildLaunchAgentPlist({
      ...base,
      caffeinate: false,
      relay: { ...base.relay, enabled: true },
    });
    assert.equal(plist.includes('caffeinate'), false);
  });
});
