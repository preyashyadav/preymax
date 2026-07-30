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

/** Recover the tool call shape from a logged event. */
export function shapeOf(rec: EventRecord): { kind: 'bash' | 'tool'; shape: string } | null {
  if (rec.tool.toLowerCase() === 'bash') {
    const m = /^run:\s*(.+)$/.exec(rec.summary ?? '');
    if (!m) return null;
    const head = commandHead(m[1]!);
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
  if (['Write', 'Edit', 'NotebookEdit'].includes(tool)) {
    return { safety: 'review', reason: 'writes files — allow per-path, not wholesale' };
  }
  return { safety: 'review', reason: 'unrecognised tool' };
}

export function patternFor(kind: 'bash' | 'tool', shape: string): string {
  if (kind === 'tool') return shape;
  // Escape regex metacharacters in the head, then anchor and guard.
  const escaped = shape.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/ /g, '\\s+');
  return `^${escaped}\\b${GUARD}`;
}

export function buildReport(events: EventRecord[], windowHours: number): SuggestReport {
  const escalations = events.filter((e) => e.event === 'escalation');

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
