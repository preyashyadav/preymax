import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { approveUrlHealth, summarizerHealth } from '../src/commands/doctor.js';
import type { DaemonStatus } from '../src/daemon/status.js';

/**
 * doctor has now reported a green summarizer twice while it was doing nothing:
 * once with no API key at all (handoff bug 2), and once with 21 consecutive
 * failed calls and zero successes. Both times the check graded *configuration*
 * rather than *outcomes*. These cases pin the grading to outcomes.
 */

function summarizer(
  stats: Partial<DaemonStatus['summarizer']['stats']>,
): DaemonStatus['summarizer'] {
  return {
    enabled: true,
    available: true,
    model: 'claude-haiku-4-5',
    reason: 'ready',
    stats: { ok: 0, hits: 0, misses: 0, errors: 0, timeouts: 0, ...stats },
  };
}

describe('doctor: summarizer health', () => {
  it('is ok before anything has been summarized', () => {
    assert.equal(summarizerHealth(summarizer({})).status, 'ok');
  });

  it('fails — never green — when every call has failed', () => {
    const check = summarizerHealth(summarizer({ errors: 21 }));
    assert.equal(check.status, 'fail');
    assert.match(check.detail, /never succeeded/);
  });

  it('fails on all-timeouts and points at the budget, not the key', () => {
    const check = summarizerHealth(summarizer({ timeouts: 19 }));
    assert.equal(check.status, 'fail');
    assert.match(check.fix ?? '', /summaryBudgetMs/);
  });

  it('points at the key when the failures are not timeouts', () => {
    const check = summarizerHealth(summarizer({ errors: 19, timeouts: 0 }));
    assert.match(check.fix ?? '', /preymax init/);
  });

  it('warns rather than fails when half the calls land', () => {
    assert.equal(summarizerHealth(summarizer({ ok: 4, errors: 6 })).status, 'warn');
  });

  it('is ok when the model is mostly answering', () => {
    assert.equal(summarizerHealth(summarizer({ ok: 40, hits: 12, errors: 1 })).status, 'ok');
  });

  it('counts a cache hit as working — the summary still shipped', () => {
    assert.notEqual(summarizerHealth(summarizer({ hits: 9, errors: 1 })).status, 'fail');
  });
});

describe('doctor: approve URL', () => {
  it('fails on plain HTTP — the buttons render and do nothing', () => {
    const check = approveUrlHealth('http://100.101.188.22:7717', 7717);
    assert.equal(check.status, 'fail');
    assert.match(check.fix ?? '', /tailscale serve/);
  });

  it('warns when https still carries a port, so Serve is not in front', () => {
    assert.equal(approveUrlHealth('https://mac.tailnet.ts.net:7717', 7717).status, 'warn');
  });

  it('accepts the Serve shape', () => {
    assert.equal(approveUrlHealth('https://mac.tailnet.ts.net', 7717).status, 'ok');
  });
});
