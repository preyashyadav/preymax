import { homedir } from 'node:os';
import { join } from 'node:path';

/** Root of preymax's own state. Override with PREYMAX_HOME (used by tests). */
export function preymaxHome(): string {
  return process.env.PREYMAX_HOME || join(homedir(), '.preymax');
}

export const paths = {
  home: preymaxHome,
  config: () => join(preymaxHome(), 'config.json'),
  policy: () => join(preymaxHome(), 'policy.yaml'),
  events: () => join(preymaxHome(), 'events.jsonl'),
  pending: () => join(preymaxHome(), 'pending.json'),
  grants: () => join(preymaxHome(), 'grants.json'),
  daemonLog: () => join(preymaxHome(), 'daemon.log'),
  daemonErrLog: () => join(preymaxHome(), 'daemon.err.log'),
  /**
   * Claude Code's settings file — the one `preymax init` edits.
   * PREYMAX_CLAUDE_SETTINGS redirects it, so init can be exercised without
   * touching a live config. Used by tests and by anyone trying preymax out.
   */
  claudeSettings: () =>
    process.env.PREYMAX_CLAUDE_SETTINGS || join(homedir(), '.claude', 'settings.json'),
  launchAgent: () =>
    join(homedir(), 'Library', 'LaunchAgents', 'com.preymax.daemon.plist'),
};

export const LAUNCHD_LABEL = 'com.preymax.daemon';
