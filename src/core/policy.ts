import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { paths } from './paths.js';

/**
 * The policy engine exists to cut escalation volume, not to provide security.
 * A `deny` here stops a tool call, but preymax is not a sandbox and must never
 * be described as one. See README, "Not a security product".
 *
 * Design principle from the plan: push everything you can into Claude Code's
 * native `permissions.allow` so it never reaches preymax at all. If this engine
 * is deciding on Read calls, the configuration is wrong.
 */

export interface Rule {
  /** Tool name or names this rule applies to. Omit to match any tool. */
  tool?: string | string[];
  /** Regexes tested against the Bash command string. */
  command_matches?: string[];
  /** Regexes tested against the file path (Write/Edit/Read). */
  path_matches?: string[];
  /** Shown to Claude as permissionDecisionReason on a deny. */
  reason?: string;
}

export interface Policy {
  auto_allow: Rule[];
  auto_deny: Rule[];
}

export interface PolicyMatch {
  bucket: 'auto_allow' | 'auto_deny' | 'escalate';
  rule?: Rule;
  reason?: string;
}

export const DEFAULT_POLICY_YAML = `# preymax policy
#
# Three buckets, evaluated in order: auto_deny, then auto_allow, then escalate.
# auto_deny wins ties on purpose — a command that matches both is denied.
#
# This layer reduces noise. It is NOT a security boundary: a determined command
# can evade any regex here. Put real guarantees in Claude Code's native
# permissions.deny, and prefer native permissions.allow for the obvious reads so
# they never reach preymax at all.

auto_deny:
  - tool: Bash
    command_matches:
      - '\\brm\\b.*(-rf|-fr|-r\\s+-f)'
      - 'git\\s+push\\b.*--force(-with-lease)?\\b.*\\b(main|master|prod|production)\\b'
      - '>\\s*\\.env'
      - '--no-verify'
      - '\\bcurl\\b[^|]*\\|\\s*(sudo\\s+)?(ba|z|)sh'
      - '\\bchmod\\b\\s+(-R\\s+)?777'
    reason: "destructive pattern — blocked by preymax policy"

auto_allow:
  - tool: [Read, Glob, Grep, NotebookRead, TodoWrite]
  - tool: Bash
    command_matches:
      - '^git\\s+(status|diff|log|branch|show|remote|stash list)\\b'
      - '^npm\\s+(test|run\\s+(lint|test|typecheck|build))\\b'
      - '^(ls|cat|pwd|head|tail|wc|which|echo)\\b'
      - '^(node|python3?)\\s+--version\\b'
      - '^jq\\b'

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
  const policy: Policy = {
    auto_allow: coerceRules(obj.auto_allow, `${source}:auto_allow`),
    auto_deny: coerceRules(obj.auto_deny, `${source}:auto_deny`),
  };
  // Fail loudly at load time rather than silently never matching at 3am.
  for (const bucket of ['auto_allow', 'auto_deny'] as const) {
    for (const rule of policy[bucket]) {
      for (const p of [...(rule.command_matches ?? []), ...(rule.path_matches ?? [])]) {
        try {
          new RegExp(p);
        } catch (err) {
          throw new Error(`policy ${bucket}: invalid regex ${JSON.stringify(p)} — ${(err as Error).message}`);
        }
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

export function pathOf(input: Record<string, unknown>): string | null {
  for (const k of ['file_path', 'path', 'notebook_path']) {
    const v = input[k];
    if (typeof v === 'string') return v;
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
 * Evaluate a tool call. auto_deny is checked first so a command that matches
 * both buckets is denied rather than allowed.
 */
export function evaluate(
  policy: Policy,
  toolName: string,
  input: Record<string, unknown>,
): PolicyMatch {
  for (const rule of policy.auto_deny) {
    if (ruleMatches(rule, toolName, input)) {
      return {
        bucket: 'auto_deny',
        rule,
        reason: rule.reason ?? 'blocked by preymax policy',
      };
    }
  }
  for (const rule of policy.auto_allow) {
    if (ruleMatches(rule, toolName, input)) {
      return { bucket: 'auto_allow', rule };
    }
  }
  return { bucket: 'escalate' };
}
