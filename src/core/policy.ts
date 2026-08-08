import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { normalize } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { paths } from './paths.js';
import { isSensitivePath } from './redact.js';

/**
 * The policy engine exists to cut escalation volume, not to provide security.
 * preymax is not a sandbox and must never be described as one. See README,
 * "Not a security product".
 *
 * **There is no deny bucket.** v1 had one; in 48h of real use it fired once,
 * and that once was a false positive on a legitimate `rm -rf` of a temp
 * directory, with no override short of editing the policy file. Claude Code's
 * native `permissions.deny` already does this properly and is a real boundary.
 * Duplicating it here bought nothing and inherited a failure mode, so v2
 * removes it (PLANv2 §3).
 *
 * Consequence for rule authors: an allow rule must be safe *on its own*. It can
 * no longer assume a deny rule will catch the tail of a chained command.
 *
 * Design principle carried forward: push everything you can into Claude Code's
 * native `permissions.allow` so it never reaches preymax at all. If this engine
 * is deciding on Read calls, the configuration is wrong.
 */

export interface Rule {
  /** Tool name or names this rule applies to. Omit to match any tool. */
  tool?: string | string[];
  /** Regexes tested against the Bash command string. */
  command_matches?: string[];
  /**
   * Regexes tested against the normalized absolute file path (Write/Edit/Read).
   * See `pathOf` for what a rule written here can and cannot assume.
   */
  path_matches?: string[];
  /** Shown to Claude as permissionDecisionReason on a deny. */
  reason?: string;
}

export interface Policy {
  auto_allow: Rule[];
}

export interface PolicyMatch {
  bucket: 'auto_allow' | 'escalate';
  rule?: Rule;
  reason?: string;
}

export const DEFAULT_POLICY_YAML = `# preymax policy
#
# Two outcomes: auto_allow, or escalate. Anything not matched below escalates.
#
# There is deliberately NO deny bucket. preymax is not a security boundary and
# a determined command evades any regex here. Real guarantees belong in Claude
# Code's native permissions.deny; obvious reads belong in its permissions.allow
# so they never reach preymax at all.
#
# Because nothing catches the tail of a command, every rule below must be safe
# on its own. Anchor with ^...$ and exclude shell metacharacters rather than
# matching a bare prefix — a bare '^cd\\s' would allow 'cd x && anything'.

auto_allow:
  - tool: [Read, Glob, Grep, NotebookRead, TodoWrite, AskUserQuestion]
  - tool: Bash
    command_matches:
      # Every rule ends with [^;&|><$\`\\n]*$ — no chaining, no redirection, no
      # substitution. Without it, '^echo\\b' allows 'echo SECRET=x > .env', which
      # is a write. v1 got away with prefix rules only because a deny bucket
      # caught the tail; there is no such backstop now.
      - '^cd\\s+[^;&|><$\`\\n]+$'
      - '^git\\s+(status|diff|log|branch|show|remote|stash list)\\b[^;&|><$\`\\n]*$'
      - '^npm\\s+(test|run\\s+(lint|test|typecheck|build))\\b[^;&|><$\`\\n]*$'
      - '^(ls|cat|pwd|head|tail|wc|which|echo)\\b[^;&|><$\`\\n]*$'
      - '^(node|python3?)\\s+--version\\b[^;&|><$\`\\n]*$'
      - '^jq\\b[^;&|><$\`\\n]*$'

# Everything not matched above escalates.
`;

export function ensurePolicyFile(): string {
  const file = paths.policy();
  if (!existsSync(file)) {
    mkdirSync(paths.home(), { recursive: true });
    writeFileSync(file, DEFAULT_POLICY_YAML);
  }
  return file;
}

export function loadPolicy(): Policy {
  const file = paths.policy();
  if (!existsSync(file)) return parsePolicy(DEFAULT_POLICY_YAML);
  return parsePolicy(readFileSync(file, 'utf8'), file);
}

export function parsePolicy(yaml: string, source = '<inline>'): Policy {
  let raw: unknown;
  try {
    raw = parseYaml(yaml);
  } catch (err) {
    throw new Error(`policy at ${source} is not valid YAML: ${(err as Error).message}`);
  }
  const obj = (raw ?? {}) as Record<string, unknown>;
  if (obj.auto_deny != null) {
    // Loud rather than silent: a v1 policy carrying deny rules would otherwise
    // look like it still blocked things while quietly allowing every one.
    console.warn(
      'preymax: `auto_deny` in the policy file is ignored — v2 removed the deny ' +
        "bucket (PLANv2 §3). Move real blocks to Claude Code's permissions.deny.",
    );
  }
  const policy: Policy = {
    auto_allow: coerceRules(obj.auto_allow, `${source}:auto_allow`),
  };
  // Fail loudly at load time rather than silently never matching at 3am.
  for (const rule of policy.auto_allow) {
    for (const p of [...(rule.command_matches ?? []), ...(rule.path_matches ?? [])]) {
      try {
        new RegExp(p);
      } catch (err) {
        throw new Error(
          `policy auto_allow: invalid regex ${JSON.stringify(p)} — ${(err as Error).message}`,
        );
      }
    }
  }
  return policy;
}

function coerceRules(value: unknown, where: string): Rule[] {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error(`policy ${where} must be a list`);
  return value.map((r, i) => {
    if (!r || typeof r !== 'object') throw new Error(`policy ${where}[${i}] must be a mapping`);
    const rule = r as Record<string, unknown>;
    if ('default' in rule) return {}; // tolerate the plan's `- default: true` escalate marker
    return {
      tool: rule.tool as string | string[] | undefined,
      command_matches: rule.command_matches as string[] | undefined,
      path_matches: rule.path_matches as string[] | undefined,
      reason: rule.reason as string | undefined,
    };
  });
}

function toolMatches(rule: Rule, toolName: string): boolean {
  if (rule.tool === undefined) return true;
  const tools = Array.isArray(rule.tool) ? rule.tool : [rule.tool];
  return tools.some((t) => t.toLowerCase() === toolName.toLowerCase());
}

/** Pull the string a command_matches rule should be tested against. */
export function commandOf(toolName: string, input: Record<string, unknown>): string | null {
  if (toolName.toLowerCase() !== 'bash') return null;
  const c = input.command;
  return typeof c === 'string' ? c : null;
}

/**
 * Pull the path a `path_matches` rule is tested against, normalized.
 *
 * Three things happen here and all three are load-bearing, because a generated
 * path rule is a *directory prefix* and a prefix is only as good as the string
 * it is matched against:
 *
 *  - **`..` is resolved first.** `<project>/../../.ssh/authorized_keys` carries
 *    `<project>/` as a literal prefix while pointing nowhere near it. Matching
 *    the raw string would allow the write; matching the normalized one does not.
 *  - **A relative path never matches.** The daemon's cwd is not the session's,
 *    so nothing here can resolve one correctly, and a wrong resolution is how a
 *    prefix rule ends up matching the wrong file. Returning null escalates.
 *  - **A sensitive path never matches**, wherever it sits. A `.env` or an
 *    `.ssh/` key inside a directory you work in every day is still not
 *    something a mined suggestion should ever have allowed. This is a floor a
 *    hand-written rule cannot lift, which is deliberate.
 */
export function pathOf(input: Record<string, unknown>): string | null {
  for (const k of ['file_path', 'path', 'notebook_path']) {
    const v = input[k];
    if (typeof v !== 'string' || v === '') continue;
    if (!v.startsWith('/')) return null;
    const resolved = normalize(v);
    return isSensitivePath(resolved) ? null : resolved;
  }
  return null;
}

function ruleMatches(rule: Rule, toolName: string, input: Record<string, unknown>): boolean {
  if (!toolMatches(rule, toolName)) return false;

  const hasCommandPatterns = (rule.command_matches?.length ?? 0) > 0;
  const hasPathPatterns = (rule.path_matches?.length ?? 0) > 0;

  // A rule with only a `tool:` key matches every call to that tool.
  if (!hasCommandPatterns && !hasPathPatterns) return true;

  if (hasCommandPatterns) {
    const cmd = commandOf(toolName, input);
    if (cmd !== null && rule.command_matches!.some((p) => new RegExp(p).test(cmd))) return true;
  }
  if (hasPathPatterns) {
    const p = pathOf(input);
    if (p !== null && rule.path_matches!.some((pat) => new RegExp(pat).test(p))) return true;
  }
  return false;
}

/**
 * Evaluate a tool call: allow it, or escalate it. Pure and synchronous — this
 * runs on the hook hot path, which performs no I/O of any kind.
 */
export function evaluate(
  policy: Policy,
  toolName: string,
  input: Record<string, unknown>,
): PolicyMatch {
  for (const rule of policy.auto_allow) {
    if (ruleMatches(rule, toolName, input)) {
      return { bucket: 'auto_allow', rule };
    }
  }
  return { bucket: 'escalate' };
}
