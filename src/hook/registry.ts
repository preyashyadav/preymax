/**
 * Hook entry construction and merge/remove against a Claude Code settings
 * object. Pure functions — no disk access — so they can be unit-tested and
 * reused across every config directory `discover.ts` finds.
 *
 * Moved out of `commands/init.ts` in v2: registration is no longer a
 * single-file operation, so the merge logic can't live in the command that
 * happened to call it first.
 */

export interface HookEntry {
  type: 'http';
  url: string;
  timeout?: number;
  headers?: Record<string, string>;
  allowedEnvVars?: string[];
}

const HOOK_MARKER = '/hook';

export function buildHookEntry(port: number): HookEntry {
  return {
    type: 'http',
    url: `http://127.0.0.1:${port}${HOOK_MARKER}`,
    // Generous relative to the daemon's own decision timeout so the daemon
    // always wins the race and returns a real decision. If the daemon is dead,
    // Claude Code treats a connection failure as non-blocking and prompts
    // normally — no waiting on this timeout.
    timeout: 120,
    headers: { 'X-Preymax-Name': '$PREYMAX_NAME' },
    // Without this allowlist, $PREYMAX_NAME silently interpolates to an empty
    // string. No warning, no error. This one line is worth hours.
    allowedEnvVars: ['PREYMAX_NAME'],
  };
}

export function isPreymaxHook(h: unknown): boolean {
  return (
    !!h &&
    typeof h === 'object' &&
    (h as HookEntry).type === 'http' &&
    typeof (h as HookEntry).url === 'string' &&
    (h as HookEntry).url.includes(HOOK_MARKER) &&
    /127\.0\.0\.1|localhost/.test((h as HookEntry).url)
  );
}

/** True if a settings object already carries our hook. */
export function hasPreymaxHook(settings: Record<string, unknown>): boolean {
  const groups = (settings.hooks as Record<string, unknown> | undefined)?.PreToolUse;
  if (!Array.isArray(groups)) return false;
  return groups.some(
    (g) => Array.isArray((g as Record<string, unknown>)?.hooks) &&
      ((g as Record<string, unknown>).hooks as unknown[]).some(isPreymaxHook),
  );
}

/**
 * Merge our hook into a settings object. Pure — returns the new object and
 * whether anything changed, so it can be unit-tested without touching disk.
 */
export function mergeHook(
  settings: Record<string, unknown>,
  entry: HookEntry,
): { settings: Record<string, unknown>; changed: boolean } {
  const next = structuredClone(settings) as Record<string, unknown>;
  const hooks = (next.hooks ??= {}) as Record<string, unknown>;
  const preToolUse = (hooks.PreToolUse ??= []) as Array<Record<string, unknown>>;

  if (!Array.isArray(hooks.PreToolUse)) {
    throw new Error('settings.hooks.PreToolUse exists but is not an array — refusing to modify it');
  }

  for (const group of preToolUse) {
    const list = group.hooks;
    if (!Array.isArray(list)) continue;
    const idx = list.findIndex(isPreymaxHook);
    if (idx !== -1) {
      // Already registered. Replace in place so a port or header change takes
      // effect, but don't add a second entry.
      const before = JSON.stringify(list[idx]);
      list[idx] = entry;
      return { settings: next, changed: before !== JSON.stringify(entry) };
    }
  }

  preToolUse.push({ matcher: '*', hooks: [entry] });
  return { settings: next, changed: true };
}

export function removeHook(settings: Record<string, unknown>): {
  settings: Record<string, unknown>;
  changed: boolean;
} {
  const next = structuredClone(settings) as Record<string, unknown>;
  const hooks = next.hooks as Record<string, unknown> | undefined;
  const groups = hooks?.PreToolUse;
  if (!Array.isArray(groups)) return { settings: next, changed: false };

  let changed = false;
  for (const group of groups as Array<Record<string, unknown>>) {
    const list = group.hooks;
    if (!Array.isArray(list)) continue;
    const kept = (list as unknown[]).filter((h) => !isPreymaxHook(h));
    if (kept.length !== list.length) changed = true;
    group.hooks = kept;
  }
  // Drop groups we emptied.
  (hooks as Record<string, unknown>).PreToolUse = (groups as Array<Record<string, unknown>>).filter(
    (g) => !Array.isArray(g.hooks) || g.hooks.length > 0,
  );
  return { settings: next, changed };
}
