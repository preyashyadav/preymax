import type { EventRecord } from '../types.js';

/**
 * `preymax suggest` — mine the event log for auto-allow candidates.
 *
 * This is the product. Everything else records what happened; this is the part
 * that turns the record into a smaller number of interruptions tomorrow.
 *
 * Two constraints shape the implementation:
 *
 * 1. **No model call.** Scoring is a fixed table and a set of regexes. A
 *    suggestion you cannot audit is a suggestion you should not apply.
 * 2. **Key on the command head, not the command.** The log stores a template
 *    summary truncated at 90 characters, so the tail of a long command is not
 *    recoverable. The head is, it is what a rule keys on anyway, and it is
 *    stable under truncation.
 * 3. **Only score what a rule could actually match.** Truncation is safe to key
 *    through; losing whole *lines* is not. A multi-line command is unmatchable
 *    by any rule generated here, so it is evidence for nothing and is dropped
 *    rather than credited to its first line. See `shapeOf`.
 */

export type Safety = 'safe' | 'review' | 'unsafe';

export interface Suggestion {
  /** Human label, e.g. `cd` or `git status`. */
  shape: string;
  /** The rule this would add. */
  pattern: string;
  /** Bash command rule, or a whole-tool rule. */
  kind: 'bash' | 'tool';
  count: number;
  share: number;
  safety: Safety;
  reason: string;
  sessions: number;
  approved: number;
  denied: number;
}

export interface SuggestReport {
  escalations: number;
  windowHours: number;
  sessions: number;
  suggestions: Suggestion[];
}

/**
 * Command heads that only read or navigate. A rule generated for one of these
 * still carries the metacharacter guard below, so `cat x > y` and `echo x | sh`
 * do not match it.
 */
const SAFE_HEADS = new Set([
  'cd', 'ls', 'pwd', 'cat', 'head', 'tail', 'wc', 'which', 'file', 'stat', 'echo',
  'basename', 'dirname', 'realpath', 'whoami', 'date', 'uname', 'env', 'printenv',
  'git status', 'git diff', 'git log', 'git branch', 'git show', 'git remote',
  'npm ls', 'npm list', 'jq', 'tree',
]);

/**
 * Heads that are routine but execute project code, write, or reach the network.
 * Never auto-applied; surfaced so the decision is yours.
 */
const REVIEW_HEADS = new Set([
  'npm test', 'npm run', 'npm ci', 'npm install', 'npx', 'pnpm', 'yarn',
  'node', 'python', 'python3', 'make', 'cargo', 'go', 'swift', 'xcodebuild',
  'docker', 'terraform', 'kubectl', 'psql', 'mkdir', 'cp', 'mv', 'touch',
  'git add', 'git commit', 'git checkout', 'git switch', 'git pull', 'git fetch',
]);

/** Tools that are pure interaction or pure reads. */
const SAFE_TOOLS = new Set([
  'AskUserQuestion', 'Read', 'Glob', 'Grep', 'NotebookRead', 'TodoWrite', 'TaskList',
]);

/**
 * Tools with no safe whole-tool rule. `policy.yaml` matches tools by name and
 * Bash by command; there is no per-path form, so the only rule that can be
 * written for `Edit` is *every edit, anywhere*. Suggesting one as `review` was
 * not a smaller version of that — `--include-review` applied it verbatim, and
 * this machine spent a day auto-allowing writes to `~/.ssh/authorized_keys`.
 * Until a path-scoped rule exists, these are never suggested at any level.
 */
const UNSCOPABLE_TOOLS = new Set(['Write', 'Edit', 'NotebookEdit', 'MultiEdit']);

/**
 * Sessions that generate load rather than doing work. Benchmarks hit the same
 * daemon and land in the same log, so a latency run of 120 `npx prisma migrate
 * reset` calls reads as the top policy candidate on the machine — which is
 * exactly how `^npx\b` came to be auto-allowed here. Excluded from the report
 * entirely: no count, no share, no denominator.
 */
const SYNTHETIC_SESSIONS = new Set(['bench', 'benchmark', 'loadtest']);

/** A summary carrying one of these has touched something sensitive. */
const SENSITIVE = /\[redacted\]|secret|token|password|api[_-]?key|credential/i;

/**
 * Shell metacharacters excluded from every generated rule. Without this a
 * suggestion for `echo` would allow `echo SECRET=x > .env`, which is a write.
 * There is no deny bucket behind these rules to catch the tail.
 */
const GUARD = '[^;&|><$`\\n]*$';

/** `run: git status --short` -> `git status`; `run: cd ~/x` -> `cd`. */
export function commandHead(command: string): string | null {
  const trimmed = command.trim();
  if (!trimmed) return null;
  // A command that opens with an assignment or a subshell has no stable head.
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(trimmed) || /^[($`]/.test(trimmed)) return null;

  const tokens = trimmed.split(/\s+/);
  const first = tokens[0]!;
  if (!/^[a-zA-Z][\w.-]*$/.test(first)) return null;

  // Two-word heads for the porcelain commands where the verb is what matters.
  const second = tokens[1];
  if (second && /^[a-z][\w-]*$/.test(second)) {
    const pair = `${first} ${second}`;
    if (SAFE_HEADS.has(pair) || REVIEW_HEADS.has(pair)) return pair;
    if (['git', 'npm', 'pnpm', 'yarn', 'cargo', 'go', 'docker'].includes(first)) return pair;
  }
  return first;
}

/** The ` +3 lines` tail `templateSummary` appends to a multi-line command. */
const MULTILINE_MARKER = /\s\+\d+ lines?$/;

/**
 * The characters `GUARD` excludes. A command containing one of these cannot be
 * matched by any rule generated here, so its first token is not its shape and
 * crediting it to one is wrong in both directions:
 *
 *   - it inflates the head's count with calls the rule would never have allowed;
 *   - it lends the head the *sensitivity* of a command that merely follows it.
 *     `cd ~/x; cat creds/README.md` marked the whole `cd` group sensitive, which
 *     scored `cd` unsafe and hid a 39% suggestion — until that day aged out of
 *     the window, when the same suggestion silently reappeared.
 *
 * Residual: the summary is truncated at 90 characters, so a metacharacter past
 * the cut is invisible here. Truncation is marked with `…`, so that case is
 * detectable but not currently excluded — see `shapeOf`.
 */
const UNMATCHABLE = /[;&|><$`\n]/;

/**
 * Recover the tool call shape from a logged event.
 *
 * One rule decides this: **if no rule generated here could match the command,
 * the command is evidence for nothing.** That covers the two ways a command
 * stops being described by its first token — chained (`cd ~/x; cat creds`) and
 * multi-line — and it is the same set of characters `GUARD` excludes, so the
 * test and the rule it protects cannot drift apart.
 */
export function shapeOf(rec: EventRecord): { kind: 'bash' | 'tool'; shape: string } | null {
  if (rec.tool.toLowerCase() === 'bash') {
    if (rec.multiline) return null;
    const m = /^run:\s*(.+)$/.exec(rec.summary ?? '');
    if (!m) return null;
    const line = m[1]!;
    if (MULTILINE_MARKER.test(line)) return null;
    if (UNMATCHABLE.test(line)) return null;
    const head = commandHead(line);
    return head ? { kind: 'bash', shape: head } : null;
  }
  if (!rec.tool || rec.tool === '-') return null;
  return { kind: 'tool', shape: rec.tool };
}

function scoreBash(
  head: string,
  denied: number,
  sensitive: boolean,
): { safety: Safety; reason: string } {
  if (denied > 0) return { safety: 'unsafe', reason: `denied ${denied}× — never suggested` };
  if (sensitive) return { safety: 'unsafe', reason: 'touched a redacted or secret-shaped value' };
  if (SAFE_HEADS.has(head)) return { safety: 'safe', reason: 'read-only or navigation' };
  if (REVIEW_HEADS.has(head)) {
    return { safety: 'review', reason: 'writes, networks, or executes project code' };
  }
  return { safety: 'review', reason: 'unrecognised command — read it before applying' };
}

function scoreTool(tool: string, denied: number): { safety: Safety; reason: string } {
  if (denied > 0) return { safety: 'unsafe', reason: `denied ${denied}× — never suggested` };
  if (SAFE_TOOLS.has(tool)) return { safety: 'safe', reason: 'interaction or read-only tool' };
  if (UNSCOPABLE_TOOLS.has(tool)) {
    return {
      safety: 'unsafe',
      reason: 'writes files, and a tool rule cannot be scoped to a path — never suggested',
    };
  }
  return { safety: 'review', reason: 'unrecognised tool' };
}

export function patternFor(kind: 'bash' | 'tool', shape: string): string {
  if (kind === 'tool') return shape;
  // Escape regex metacharacters in the head, then anchor and guard.
  const escaped = shape.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ /g, '\\s+');
  return `^${escaped}\\b${GUARD}`;
}

/** A load generator's traffic is not evidence about how you work. */
export function isSyntheticSession(session: string | undefined): boolean {
  return session !== undefined && SYNTHETIC_SESSIONS.has(session.split(':')[0]!.toLowerCase());
}

/**
 * Summaries that provably do not determine the command behind them.
 *
 * `fingerprint` hashes the whole normalized command, so one command run twenty
 * times yields one fingerprint. Two fingerprints under one summary therefore
 * prove the summary dropped something — a second line, a truncated tail, or a
 * redacted secret — and a shape cannot be keyed on text that lossy.
 *
 * This is what makes the log collected *before* multi-line commands were
 * flagged still usable: on this machine four `cd` summaries covered 42 distinct
 * fingerprints, every one of them a script that merely opened with `cd`.
 *
 * Exact in the direction that matters — it never excludes a summary that does
 * determine its command. The residual is the reverse: an identical multi-line
 * script repeated verbatim collapses to one fingerprint and is not caught here.
 * Events logged since the flag exists are caught by the flag instead.
 */
function lossySummaries(escalations: EventRecord[]): Set<string> {
  const seen = new Map<string, Set<string>>();
  for (const e of escalations) {
    if (!e.summary || !e.fingerprint) continue;
    const fps = seen.get(e.summary) ?? new Set<string>();
    fps.add(e.fingerprint);
    seen.set(e.summary, fps);
  }
  const lossy = new Set<string>();
  for (const [summary, fps] of seen) {
    if (fps.size > 1) lossy.add(summary);
  }
  return lossy;
}

export function buildReport(events: EventRecord[], windowHours: number): SuggestReport {
  const escalations = events.filter(
    (e) => e.event === 'escalation' && !isSyntheticSession(e.session),
  );
  const lossy = lossySummaries(escalations);

  // fingerprint -> final decision, so a shape can be scored on outcomes.
  const outcome = new Map<string, { decision?: string; source?: string }>();
  for (const e of events) {
    if (e.event === 'decision' && e.fingerprint) {
      outcome.set(e.fingerprint, { decision: e.decision, source: e.decisionSource });
    }
  }

  interface Acc {
    kind: 'bash' | 'tool';
    count: number;
    sessions: Set<string>;
    approved: number;
    denied: number;
    sensitive: boolean;
  }
  const groups = new Map<string, Acc>();

  for (const e of escalations) {
    const s = shapeOf(e);
    if (!s) continue;
    // Bash shapes come from the summary text; a tool shape comes from the tool
    // name, which truncation cannot corrupt.
    if (s.kind === 'bash' && e.summary && lossy.has(e.summary)) continue;
    const key = `${s.kind}:${s.shape}`;
    const acc = groups.get(key) ?? {
      kind: s.kind,
      count: 0,
      sessions: new Set<string>(),
      approved: 0,
      denied: 0,
      sensitive: false,
    };
    acc.count++;
    acc.sessions.add(e.session);
    if (SENSITIVE.test(e.summary ?? '')) acc.sensitive = true;

    const o = e.fingerprint ? outcome.get(e.fingerprint) : undefined;
    // Only a human answer counts. A timeout or a shadow-mode fall-through is
    // an absence of evidence, not evidence of approval.
    if (o?.source === 'phone' || o?.source === 'local') {
      if (o.decision === 'allow') acc.approved++;
      if (o.decision === 'deny') acc.denied++;
    }
    groups.set(key, acc);
  }

  const total = escalations.length;
  const suggestions: Suggestion[] = [];
  for (const [key, acc] of groups) {
    const shape = key.slice(key.indexOf(':') + 1);
    const { safety, reason } =
      acc.kind === 'bash'
        ? scoreBash(shape, acc.denied, acc.sensitive)
        : scoreTool(shape, acc.denied);
    suggestions.push({
      shape,
      kind: acc.kind,
      pattern: patternFor(acc.kind, shape),
      count: acc.count,
      share: total ? acc.count / total : 0,
      safety,
      reason,
      sessions: acc.sessions.size,
      approved: acc.approved,
      denied: acc.denied,
    });
  }

  suggestions.sort((a, b) => b.count - a.count);

  return {
    escalations: total,
    windowHours,
    sessions: new Set(escalations.map((e) => e.session)).size,
    suggestions,
  };
}

/**
 * Render the YAML rules for a set of suggestions, annotated so every generated
 * rule is auditable and revertable.
 */
export function renderRules(picked: Suggestion[], now = new Date()): string {
  if (picked.length === 0) return '';
  const stamp = now.toISOString().slice(0, 10);
  const bash = picked.filter((s) => s.kind === 'bash');
  const tools = picked.filter((s) => s.kind === 'tool');

  const lines: string[] = ['', `  # suggested by preymax on ${stamp}`];
  if (tools.length > 0) {
    lines.push(
      `  - tool: [${tools.map((t) => t.shape).join(', ')}]   # ${tools
        .map((t) => `${t.shape} ${t.count} observations`)
        .join(', ')}`,
    );
  }
  if (bash.length > 0) {
    lines.push('  - tool: Bash');
    lines.push('    command_matches:');
    for (const s of bash) {
      lines.push(`      # ${s.shape} — ${s.count} observations, ${s.reason}`);
      lines.push(`      - '${s.pattern}'`);
    }
  }
  return lines.join('\n') + '\n';
}
