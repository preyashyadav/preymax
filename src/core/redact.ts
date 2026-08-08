import { homedir } from 'node:os';

/**
 * Redaction runs on every tool input before it is logged, stored in the pending
 * table, sent to ntfy, or sent to the Anthropic API. Nothing downstream of this
 * module ever sees a raw tool input.
 *
 * This is a heuristic filter, not a guarantee. It is written to over-redact:
 * a mangled notification is a nuisance, a leaked key is an incident. If you add
 * a pattern, add a test alongside it.
 */

const PLACEHOLDER = '[redacted]';

/**
 * Ordered most-specific-first. A broad rule placed early would eat the context
 * a later, more precise rule needs.
 */
const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  // Provider-prefixed keys. These are unambiguous — match them before anything generic.
  { name: 'anthropic', re: /\bsk-ant-[A-Za-z0-9_\-]{10,}/g },
  { name: 'openai', re: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g },
  { name: 'github', re: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}/g },
  { name: 'slack', re: /\bxox[abposr]-[A-Za-z0-9\-]{10,}/g },
  { name: 'aws-access-key', re: /\b(?:AKIA|ASIA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g },
  { name: 'google', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { name: 'stripe', re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { name: 'npm', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: 'tailscale', re: /\btskey-[A-Za-z0-9\-]{10,}/g },
  { name: 'private-key-block', re: /-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[^-]*-----/g },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g },

  // An Authorization header, with or without a scheme keyword.
  //
  // This MUST stay ahead of the generic assignment rule below. That rule would
  // otherwise match `Authorization: Bearer <token>`, treat the bare word
  // "Bearer" as the value, redact the scheme, and leave the actual token in the
  // clear. A test covers exactly this.
  {
    name: 'authorization-header',
    re: /\b(Authorization\s*[:=]\s*)(?:Bearer|Basic|Token|Digest)?\s*[^\s"',;&|)]+/gi,
  },
  // A standalone `Bearer xyz` with no Authorization label.
  { name: 'bearer', re: /\b(Bearer|Basic|Token)\s+[A-Za-z0-9_\-.=+/]{12,}/gi },

  // Assignment forms: KEY=value, "key": "value", --password value.
  // Capture the label, replace only the value, so the summary still reads sensibly.
  {
    name: 'assignment',
    // The leading segment is optional (`*`, not `[A-Za-z_]...`) so a variable
    // named exactly API_KEY matches, not just DATABASE_API_KEY.
    // Bare AUTH is deliberately absent: it collides with `--author=`, and
    // TOKEN already covers AUTH_TOKEN. AUTHORIZATION is handled above.
    re: /\b([A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|`[^`]*`|[^\s,;&|)]+)/gi,
  },
  {
    name: 'json-secret-field',
    re: /("(?:[A-Za-z0-9_\-]*(?:secret|token|password|passwd|apikey|api_key|access_key|private_key|credential|authorization)[A-Za-z0-9_\-]*)"\s*:\s*)"(?:[^"\\]|\\.)*"/gi,
  },
  {
    name: 'cli-flag',
    re: /(--(?:password|passwd|token|secret|api-key|apikey|auth|credential)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)/gi,
  },
  { name: 'url-userinfo', re: /(\b[a-z][a-z0-9+.\-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi },
];

/** Paths whose *contents* must never be summarized, only named. */
const SENSITIVE_FILE = /(^|[\\/])(\.env(\.[\w.-]+)?|\.netrc|\.npmrc|\.pgpass|id_(rsa|ed25519|ecdsa)|credentials|\.aws[\\/]credentials|\.ssh[\\/].*)$/i;

/** Tool input keys that carry file bodies. */
const CONTENT_KEYS = new Set(['content', 'new_string', 'old_string', 'file_text', 'new_str', 'old_str']);

/** Tool input keys that carry a path. */
const PATH_KEYS = new Set(['file_path', 'path', 'notebook_path']);

export function isSensitivePath(p: string): boolean {
  return SENSITIVE_FILE.test(p.trim());
}

/** Replace $HOME with ~ so absolute home paths never leave the machine. */
export function collapseHome(s: string): string {
  const home = homedir();
  if (!home || home === '/') return s;
  return s.split(home).join('~');
}

/**
 * Inverse of `collapseHome`, for the one caller that needs it: the event log
 * stores collapsed paths, and a policy rule is matched against the real one.
 * Only a leading `~/` is expanded — a `~` further into a string is a character,
 * not a home directory.
 */
export function expandHome(s: string): string {
  const home = homedir();
  if (!home || home === '/') return s;
  if (s === '~') return home;
  return s.startsWith('~/') ? home + s.slice(1) : s;
}

/**
 * Redact secrets from a free-text string. Safe to call on anything.
 */
export function redactString(input: string): string {
  let out = input;

  for (const { name, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    switch (name) {
      case 'assignment':
        out = out.replace(re, (_m, key: string, sep: string) => `${key}${sep}${PLACEHOLDER}`);
        break;
      case 'json-secret-field':
        out = out.replace(re, (_m, prefix: string) => `${prefix}"${PLACEHOLDER}"`);
        break;
      case 'bearer':
        out = out.replace(re, (_m, scheme: string) => `${scheme} ${PLACEHOLDER}`);
        break;
      case 'authorization-header':
        // Keep the header name so the command still reads sensibly; the scheme
        // keyword goes with the token, since it carries no useful information
        // once the credential is gone.
        out = out.replace(re, (_m, label: string) => `${label}${PLACEHOLDER}`);
        break;
      case 'cli-flag':
        out = out.replace(re, (_m, flag: string) => `${flag}${PLACEHOLDER}`);
        break;
      case 'url-userinfo':
        out = out.replace(re, (_m, scheme: string) => `${scheme}${PLACEHOLDER}@`);
        break;
      default:
        out = out.replace(re, PLACEHOLDER);
    }
  }

  // High-entropy bare tokens that matched no named pattern. Deliberately last and
  // deliberately conservative: 32+ chars of unbroken base64/hex with at least one
  // digit and one letter. Plain English and file paths do not look like this.
  out = out.replace(/\b(?=[A-Za-z0-9+/_\-]*\d)(?=[A-Za-z0-9+/_\-]*[A-Za-z])[A-Za-z0-9+/_\-]{32,}={0,2}\b/g, (m) =>
    // Don't eat things that are clearly a path segment or dotted identifier.
    m.includes('/') && m.split('/').every((seg) => seg.length < 20) ? m : PLACEHOLDER,
  );

  return collapseHome(out);
}

/**
 * Redact a whole tool input object. Returns a new object; the input is untouched.
 *
 * Beyond pattern matching, this applies two structural rules:
 *  - a write/edit targeting a sensitive path has its body dropped entirely
 *  - any string is truncated, so a 400KB file body can't be shipped to a
 *    notification service or an LLM by accident
 */
export function redactToolInput(
  toolName: string,
  input: Record<string, unknown>,
  opts: { maxStringLength?: number } = {},
): Record<string, unknown> {
  const maxLen = opts.maxStringLength ?? 600;

  const targetPath = PATH_KEYS.has('file_path')
    ? String(input.file_path ?? input.path ?? input.notebook_path ?? '')
    : '';
  const sensitiveTarget = targetPath !== '' && isSensitivePath(targetPath);

  const walk = (value: unknown, key: string | null, depth: number): unknown => {
    if (depth > 6) return '[deep]';

    if (typeof value === 'string') {
      // Never summarize the body of a secret-bearing file — name it and stop.
      if (sensitiveTarget && key !== null && CONTENT_KEYS.has(key)) {
        return `[contents of ${collapseHome(targetPath)} withheld]`;
      }
      let s = redactString(value);
      if (s.length > maxLen) s = s.slice(0, maxLen) + `… [+${s.length - maxLen} chars]`;
      return s;
    }

    if (Array.isArray(value)) {
      const capped = value.slice(0, 20).map((v) => walk(v, key, depth + 1));
      if (value.length > 20) capped.push(`… [+${value.length - 20} items]`);
      return capped;
    }

    if (value && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = walk(v, k, depth + 1);
      }
      return out;
    }

    return value;
  };

  const result = walk(input, null, 0) as Record<string, unknown>;

  // A Read of a sensitive file is fine to describe, but flag it so the
  // notification and the policy layer can both see what is going on.
  if (sensitiveTarget) result.__preymax_sensitive_path = true;

  return result;
}

/**
 * Normalized form used for the dedupe / cache fingerprint. Strips volatile
 * detail (whitespace, numbers, quoted literals) so "npm test -- --seed 1234"
 * and "npm test -- --seed 9999" share a cache entry.
 */
export function normalizeForFingerprint(toolName: string, input: Record<string, unknown>): string {
  const json = JSON.stringify(input, Object.keys(input).sort());
  return (
    toolName +
    ' ' +
    json
      .replace(/\b\d+\b/g, '#')
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase()
  );
}
