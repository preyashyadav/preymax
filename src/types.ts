/**
 * Wire types for the Claude Code hook contract and preymax's internal records.
 *
 * The PreToolUse input/output shapes here were verified against
 * https://code.claude.com/docs/en/hooks on 2026-07-25. Re-verify before
 * assuming any field still exists: the hook event set is actively expanding.
 */

/** Permission modes Claude Code reports on the hook payload. */
export type PermissionMode =
  | 'default'
  | 'plan'
  | 'acceptEdits'
  | 'auto'
  | 'dontAsk'
  | 'bypassPermissions';

/** The JSON body Claude Code POSTs to an `http` PreToolUse hook. */
export interface PreToolUsePayload {
  session_id: string;
  prompt_id?: string;
  transcript_path?: string;
  cwd: string;
  permission_mode?: PermissionMode;
  hook_event_name: 'PreToolUse';
  tool_name: string;
  tool_input: Record<string, unknown>;
  tool_use_id?: string;
  effort?: { level?: string };
}

/**
 * `defer` is documented as a fourth value but its exact semantics could not be
 * retrieved from the reference (the section was truncated). preymax never emits
 * it — see THREAT_MODEL.md, "Unresolved: defer".
 */
export type PermissionDecision = 'allow' | 'deny' | 'ask' | 'defer';

/** The JSON body preymax returns to Claude Code. */
export interface PreToolUseHookOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: PermissionDecision;
    permissionDecisionReason?: string;
  };
}

/** Where a decision came from. Recorded on every escalation for `preymax stats`. */
export type DecisionSource =
  | 'policy'      // matched an auto_allow / auto_deny rule
  | 'grant'       // matched a live temporary pattern grant
  | 'phone'       // signed approval arrived over HTTP
  | 'local'       // `preymax approve` / `preymax deny`
  | 'timeout'     // nobody answered; fell through to `ask`
  | 'shutdown';   // daemon stopped while the decision was pending

/** Resolved identity of the terminal a hook event came from. */
export interface SessionIdentity {
  /** Short display name. Appears in the first three words of every notification. */
  name: string;
  /** How the name was resolved, for `preymax doctor`. */
  source: 'env' | 'cwd+branch' | 'session_id';
  sessionId: string;
  cwd: string;
}

/** One escalation awaiting a decision. */
export interface PendingRequest {
  id: string;
  nonce: string;
  createdAt: number;
  expiresAt: number;
  identity: SessionIdentity;
  toolName: string;
  /** Redacted. The raw input is never stored or transmitted. */
  redactedInput: Record<string, unknown>;
  /** Hash of (tool_name, normalized_input) — the dedupe and cache key. */
  fingerprint: string;
  /** One-line human summary shown on the phone. */
  summary: string;
  /** Template summary, kept so we can tell whether the model call landed. */
  templateSummary: string;
  summarySource: 'template' | 'model' | 'cache';
  /** Set once resolved. */
  decision?: PermissionDecision;
  decisionSource?: DecisionSource;
  decidedAt?: number;
  /** Pattern grant requested alongside an allow, e.g. "allow this for 30m". */
  grantPattern?: string;
}

/** A single line in the JSONL event log. */
export interface EventRecord {
  ts: string;
  event: 'escalation' | 'auto_allow' | 'auto_deny' | 'decision' | 'notify' | 'error';
  session: string;
  tool: string;
  decision?: PermissionDecision;
  decisionSource?: DecisionSource;
  /** End-to-end milliseconds from hook receipt to hook response. */
  latencyMs?: number;
  fingerprint?: string;
  summary?: string;
  detail?: string;
}
