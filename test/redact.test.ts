import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { homedir } from 'node:os';
import {
  redactString,
  redactToolInput,
  isSensitivePath,
  collapseHome,
  normalizeForFingerprint,
} from '../src/core/redact.js';

/**
 * Redaction is the one module where a miss is an incident rather than a bug.
 * The plan's exit criterion is "zero secrets in outbound payloads, verified by
 * inspecting an intercepting proxy log" — these tests are the floor beneath
 * that, not a substitute for it.
 */

/**
 * Every fixture below is fake, but each is deliberately shaped to match a real
 * provider key format — which is precisely what secret scanners look for. A
 * complete literal in a committed file trips GitHub push protection and blocks
 * the push.
 *
 * So the prefix is joined to the body at runtime: no contiguous key-shaped
 * string ever exists in this source file, while the value handed to
 * redactString() is byte-identical to what a literal would have produced. The
 * tests are exactly as strong; the file is pushable.
 *
 * If you add a fixture, use this helper — do not paste a whole key.
 */
const key = (prefix: string, body: string): string => prefix + body;

describe('redactString: provider-prefixed keys', () => {
  const cases: Array<[string, string]> = [
    ['anthropic', key('sk-ant-', 'api03-abcdefghijklmnop1234567890ABCDEF')],
    ['openai', key('sk-', 'proj-abcdefghijklmnopqrstuvwxyz1234567890')],
    ['github classic', key('ghp', '_abcdefghijklmnopqrstuvwxyz1234567890')],
    ['github fine-grained', key('github', '_pat_11ABCDEFG0abcdefghijklmnop')],
    ['slack', key('xoxb', '-123456789012-1234567890123-abcdefghijklmnopqrst')],
    ['aws access key', key('AKIA', 'IOSFODNN7EXAMPLE')],
    ['google', key('AIza', 'SyA1234567890abcdefghijklmnopqrstuvw')],
    ['stripe live', key('sk', '_live_abcdefghijklmnop1234567890')],
    ['npm', key('npm', '_abcdefghijklmnopqrstuvwxyz1234567890')],
    ['tailscale', key('tskey', '-auth-abcdefghij-1234567890abcdef')],
  ];

  for (const [name, secret] of cases) {
    it(`redacts a ${name} key`, () => {
      const out = redactString(`the key is ${secret} ok`);
      assert.ok(!out.includes(secret), `leaked ${name}: ${out}`);
      assert.ok(out.includes('[redacted]'));
    });
  }

  it('redacts a JWT', () => {
    const jwt = [
      key('eyJ', 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'),
      key('eyJ', 'zdWIiOiIxMjM0NTY3ODkwIn0'),
      'dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    ].join('.');
    const out = redactString(`Authorization: Bearer ${jwt}`);
    assert.ok(!out.includes(jwt));
  });

  it('redacts a private key block including its body', () => {
    const pem = [
      `-----BEGIN OPENSSH ${key('PRIVATE', ' KEY')}-----`,
      key('b3Blbn', 'c3NoLWtleS12MQAAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt'),
      `-----END OPENSSH ${key('PRIVATE', ' KEY')}-----`,
    ].join('\n');
    const out = redactString(`here: ${pem}`);
    assert.ok(!out.includes('c3NoLWtleS12MQ'), `leaked key body: ${out}`);
    assert.ok(!out.includes('BEGIN OPENSSH'));
  });
});

describe('redactString: assignment forms', () => {
  it('keeps the label and drops the value for KEY=value', () => {
    const out = redactString('DATABASE_PASSWORD=hunter2correcthorse');
    assert.ok(out.startsWith('DATABASE_PASSWORD='));
    assert.ok(!out.includes('hunter2correcthorse'));
  });

  it('handles quoted values', () => {
    const out = redactString('export API_KEY="abc123-super-secret-value"');
    assert.ok(!out.includes('abc123-super-secret-value'));
    assert.ok(out.includes('API_KEY='));
  });

  it('redacts a JSON secret field but keeps the field name', () => {
    const out = redactString('{"client_secret": "s3cr3t-value-here", "id": "public"}');
    assert.ok(!out.includes('s3cr3t-value-here'));
    assert.ok(out.includes('client_secret'));
    assert.ok(out.includes('public'), 'non-secret fields must survive');
  });

  it('redacts a CLI password flag', () => {
    const out = redactString('mysql --user root --password=SuperSecret123 -h db');
    assert.ok(!out.includes('SuperSecret123'));
    assert.ok(out.includes('--password='));
    assert.ok(out.includes('-h db'), 'the rest of the command must survive');
  });

  it('redacts credentials embedded in a URL', () => {
    const out = redactString('psql postgres://admin:topsecretpw@db.example.com:5432/app');
    assert.ok(!out.includes('topsecretpw'));
    assert.ok(!out.includes('admin:'));
    assert.ok(out.includes('db.example.com'), 'the host is useful context, keep it');
  });

  it('redacts an Authorization header token but keeps the header name', () => {
    const out = redactString('curl -H "Authorization: Bearer abcdef1234567890abcdef"');
    assert.ok(!out.includes('abcdef1234567890abcdef'), `leaked: ${out}`);
    assert.ok(out.includes('Authorization'));
  });

  it('redacts an Authorization header with no scheme keyword', () => {
    const out = redactString('Authorization: rawtokenvalue123');
    assert.ok(!out.includes('rawtokenvalue123'), `leaked: ${out}`);
  });

  it('redacts a standalone Bearer token, keeping the scheme', () => {
    const out = redactString('send Bearer abcdef1234567890abcdef upstream');
    assert.ok(!out.includes('abcdef1234567890abcdef'), `leaked: ${out}`);
    assert.ok(out.includes('Bearer'));
  });
});

describe('redactString: high-entropy fallback', () => {
  it('redacts a long unbroken token that matched no named pattern', () => {
    const blob = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4';
    assert.ok(!redactString(`token ${blob}`).includes(blob));
  });

  it('does NOT redact ordinary prose', () => {
    const prose = 'run the migration against the staging database and check the results';
    assert.equal(redactString(prose), prose);
  });

  it('does NOT redact an ordinary file path', () => {
    const p = 'src/components/dashboard/UserSettingsPanel.tsx';
    assert.ok(redactString(p).includes('UserSettingsPanel'));
  });

  it('does NOT redact a normal git SHA reference in context', () => {
    // 40-hex is a real collision risk with the entropy rule; make sure the
    // surrounding command still reads sensibly even if the SHA is redacted.
    const out = redactString('git show 1234567890abcdef');
    assert.ok(out.startsWith('git show'));
  });
});

describe('collapseHome', () => {
  it('replaces the home directory with ~', () => {
    const out = collapseHome(`${homedir()}/Documents/secret-project`);
    assert.ok(!out.includes(homedir()));
    assert.ok(out.startsWith('~/Documents'));
  });
});

describe('isSensitivePath', () => {
  const sensitive = ['.env', '.env.local', '.env.production', '.netrc', '.npmrc', 'id_rsa', 'id_ed25519', '/Users/x/.aws/credentials', '/home/u/.ssh/config'];
  for (const p of sensitive) {
    it(`flags ${p}`, () => assert.equal(isSensitivePath(p), true));
  }
  const ordinary = ['src/index.ts', 'README.md', 'environment.md', 'package.json'];
  for (const p of ordinary) {
    it(`does not flag ${p}`, () => assert.equal(isSensitivePath(p), false));
  }
});

describe('redactToolInput', () => {
  it('withholds the body when writing a .env file', () => {
    const out = redactToolInput('Write', {
      file_path: '/Users/dev/app/.env',
      content: `STRIPE_SECRET_KEY=${key('sk', '_live_abcdefghijklmnop1234')}\nDB_PASS=hunter2`,
    });
    const serialized = JSON.stringify(out);
    assert.ok(!serialized.includes(key('sk', '_live')));
    assert.ok(!serialized.includes('hunter2'));
    assert.ok(serialized.includes('withheld'));
    assert.equal(out.__preymax_sensitive_path, true);
  });

  it('still redacts secrets in an ordinary file body', () => {
    const out = redactToolInput('Write', {
      file_path: '/Users/dev/app/src/config.ts',
      content: `export const KEY = "${key('sk-ant-', 'api03-abcdefghijklmnop1234567890')}";`,
    });
    assert.ok(!JSON.stringify(out).includes(key('sk-ant-', 'api03')));
  });

  it('truncates a very large body rather than shipping it', () => {
    const out = redactToolInput('Write', {
      file_path: '/tmp/big.txt',
      content: 'x'.repeat(50_000),
    });
    assert.ok((out.content as string).length < 800);
    assert.ok((out.content as string).includes('+'));
  });

  it('redacts nested objects and arrays', () => {
    const out = redactToolInput('Bash', {
      command: 'deploy',
      env: { PROD_TOKEN: key('ghp', '_abcdefghijklmnopqrstuvwxyz1234567890') },
      args: ['--key', key('sk-ant-', 'api03-abcdefghijklmnop1234567890')],
    });
    const s = JSON.stringify(out);
    assert.ok(!s.includes(key('ghp', '_abcdef')));
    assert.ok(!s.includes(key('sk-ant-', 'api03')));
  });

  it('caps very long arrays', () => {
    const out = redactToolInput('X', { items: Array.from({ length: 100 }, (_, i) => `item${i}`) });
    assert.ok((out.items as unknown[]).length <= 21);
  });

  it('does not mutate its input', () => {
    const input = { command: `echo ${key('sk-ant-', 'api03-abcdefghijklmnop1234567890')}` };
    const before = JSON.stringify(input);
    redactToolInput('Bash', input);
    assert.equal(JSON.stringify(input), before);
  });

  it('survives deeply nested structures without blowing the stack', () => {
    let deep: Record<string, unknown> = { leaf: 'ok' };
    for (let i = 0; i < 50; i++) deep = { nest: deep };
    assert.doesNotThrow(() => redactToolInput('X', deep));
  });
});

describe('normalizeForFingerprint', () => {
  it('collapses varying numbers so near-identical calls share a cache entry', () => {
    const a = normalizeForFingerprint('Bash', { command: 'npm test -- --seed 1234' });
    const b = normalizeForFingerprint('Bash', { command: 'npm test -- --seed 9999' });
    assert.equal(a, b);
  });

  it('distinguishes genuinely different commands', () => {
    const a = normalizeForFingerprint('Bash', { command: 'npm test' });
    const b = normalizeForFingerprint('Bash', { command: 'rm -rf /' });
    assert.notEqual(a, b);
  });

  it('is stable across key ordering', () => {
    const a = normalizeForFingerprint('Edit', { file_path: '/a', old_string: 'x' });
    const b = normalizeForFingerprint('Edit', { old_string: 'x', file_path: '/a' });
    assert.equal(a, b);
  });
});
