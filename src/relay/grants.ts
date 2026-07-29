import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { paths } from '../core/paths.js';

/**
 * Temporary allow grants: "allow this pattern for 30 minutes".
 *
 * These are the real fix for burst escalations — a repeated command gets
 * approved once and stops paging you. They are deliberately short-lived and
 * scoped to one session, and they are persisted so a daemon restart doesn't
 * silently drop them (which would look like preymax spontaneously getting
 * noisier again).
 */

export interface Grant {
  /** Session name the grant applies to. '*' matches any session. */
  session: string;
  toolName: string;
  /** Literal prefix of the normalized fingerprint, or a regex if `isRegex`. */
  pattern: string;
  isRegex: boolean;
  expiresAt: number;
}

export class GrantStore {
  private grants: Grant[] = [];

  constructor(private readonly file = paths.grants()) {
    this.load();
  }

  private load(): void {
    if (!existsSync(this.file)) return;
    try {
      const parsed = JSON.parse(readFileSync(this.file, 'utf8'));
      this.grants = Array.isArray(parsed) ? parsed : [];
    } catch {
      // A corrupt grants file must not stop the daemon. Worst case we lose
      // grants and escalate more, which is the safe direction.
      this.grants = [];
    }
    this.prune();
  }

  private persist(): void {
    mkdirSync(paths.home(), { recursive: true });
    writeFileSync(this.file, JSON.stringify(this.grants, null, 2) + '\n', { mode: 0o600 });
  }

  prune(now = Date.now()): void {
    const before = this.grants.length;
    this.grants = this.grants.filter((g) => g.expiresAt > now);
    if (this.grants.length !== before) this.persist();
  }

  add(grant: Grant): void {
    this.grants.push(grant);
    this.persist();
  }

  list(now = Date.now()): Grant[] {
    return this.grants.filter((g) => g.expiresAt > now);
  }

  clear(): void {
    this.grants = [];
    this.persist();
  }

  /** Does a live grant cover this call? */
  match(
    session: string,
    toolName: string,
    fingerprint: string,
    now = Date.now(),
  ): Grant | null {
    for (const g of this.grants) {
      if (g.expiresAt <= now) continue;
      if (g.session !== '*' && g.session !== session) continue;
      if (g.toolName.toLowerCase() !== toolName.toLowerCase()) continue;
      if (g.isRegex) {
        try {
          if (new RegExp(g.pattern).test(fingerprint)) return g;
        } catch {
          continue;
        }
      } else if (fingerprint.startsWith(g.pattern)) {
        return g;
      }
    }
    return null;
  }
}

/**
 * Turn a concrete call into a grant pattern. Uses the normalized fingerprint
 * prefix so near-identical repeats are covered but an unrelated command is not.
 */
export function grantPatternFor(fingerprint: string): string {
  // 60 chars of the normalized form is enough to pin the command shape without
  // pinning every argument.
  return fingerprint.slice(0, 60);
}
