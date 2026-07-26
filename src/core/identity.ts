import { execFileSync } from 'node:child_process';
import { basename } from 'node:path';
import type { PreToolUsePayload, SessionIdentity } from '../types.js';

/**
 * Resolve which terminal an event came from, in the priority order the plan
 * specifies:
 *   1. PREYMAX_NAME, forwarded by the hook as the X-Preymax-Name header
 *   2. basename(cwd) + git branch
 *   3. session_id[:6]
 *
 * Note on (1): Claude Code only interpolates `$VAR` into hook *header values*,
 * and only for variables listed in `allowedEnvVars`. A variable that is not
 * allowlisted resolves to an empty string with no warning and no error — which
 * is why an empty header falls through to (2) rather than producing a session
 * literally named "".
 */

const branchCache = new Map<string, { branch: string | null; at: number }>();
const BRANCH_TTL_MS = 10_000;

function gitBranch(cwd: string): string | null {
  const hit = branchCache.get(cwd);
  const now = Date.now();
  if (hit && now - hit.at < BRANCH_TTL_MS) return hit.branch;

  let branch: string | null = null;
  try {
    // A gate hook is on the critical path — this must be fast and must never throw.
    const out = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
      cwd,
      encoding: 'utf8',
      timeout: 400,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (out && out !== 'HEAD') branch = out;
  } catch {
    branch = null;
  }

  branchCache.set(cwd, { branch, at: now });
  return branch;
}

export function resolveIdentity(
  payload: PreToolUsePayload,
  envName: string | undefined,
): SessionIdentity {
  const sessionId = payload.session_id ?? 'unknown';
  const cwd = payload.cwd ?? process.cwd();

  const trimmed = (envName ?? '').trim();
  if (trimmed) {
    return { name: trimmed, source: 'env', sessionId, cwd };
  }

  const dir = basename(cwd);
  if (dir) {
    const branch = gitBranch(cwd);
    return {
      name: branch ? `${dir}:${branch}` : dir,
      source: 'cwd+branch',
      sessionId,
      cwd,
    };
  }

  return { name: sessionId.slice(0, 6), source: 'session_id', sessionId, cwd };
}

/** Deterministic terminal colour for `preymax tail`, keyed on the session name. */
export function colorFor(name: string): string {
  const palette = [36, 32, 33, 35, 34, 96, 92, 93, 95, 94];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return `\x1b[${palette[h % palette.length]}m`;
}
