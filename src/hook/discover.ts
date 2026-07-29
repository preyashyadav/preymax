import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, isAbsolute } from 'node:path';
import { hasPreymaxHook } from './registry.js';

/**
 * Claude config directory discovery.
 *
 * v1 registered the hook in `~/.claude/settings.json` and nowhere else. Any
 * project setting `CLAUDE_CONFIG_DIR` to a different account directory got no
 * hook at all, while `preymax doctor` reported fully green — silently
 * collecting nothing for a full day. That is handoff bug 1, and this module
 * exists to make that failure impossible to reproduce.
 *
 * Discovery is deliberately over-inclusive: finding a directory costs a line of
 * output, missing one costs a day of data.
 */

export type ConfigDirSource =
  | 'default'   // ~/.claude
  | 'sibling'   // ~/.claude-* present on disk
  | 'env'       // CLAUDE_CONFIG_DIR in the current environment
  | 'shell-rc'  // exported from a shell startup file
  | 'project'   // .envrc or .vscode/settings.json under a scanned root
  | 'explicit'  // --config-dir
  | 'config';   // persisted in config.json `configDirs`

export interface ConfigDir {
  /** Absolute, tilde-expanded. */
  path: string;
  settingsPath: string;
  sources: ConfigDirSource[];
  exists: boolean;
  hooked: boolean;
  /** Set when settings.json exists but could not be read or parsed. */
  error?: string;
  /**
   * Set when the source declared a path that will not work as written — most
   * commonly a literal `~` in an env var, which the shell does not expand and
   * which therefore resolves to a directory named `~`.
   */
  warning?: string;
}

export interface DiscoverOptions {
  /** From repeatable --config-dir. Always included, even if absent on disk. */
  explicit?: string[];
  /** From config.json `configDirs`. Always included. */
  persisted?: string[];
  /** Directory trees to scan for .envrc / .vscode/settings.json. Bounded depth. */
  scanRoots?: string[];
  /** Override for tests. */
  env?: NodeJS.ProcessEnv;
}

const SIBLING_RE = /^\.claude(-[\w.@-]+)?$/;
// Matches shell (`export CLAUDE_CONFIG_DIR=~/x`, `CLAUDE_CONFIG_DIR="/x"`) and
// JSON (`"CLAUDE_CONFIG_DIR": "/x"`). The optional quote before the separator is
// what makes the JSON form match — without it .vscode/settings.json is silently
// skipped, which is the exact class of failure this module exists to prevent.
const CONFIG_DIR_RE = /CLAUDE_CONFIG_DIR["']?\s*[:=]\s*["']?([^"'\s,}]+)/g;

const SHELL_RC_FILES = [
  '.zshrc',
  '.zshenv',
  '.zprofile',
  '.bashrc',
  '.bash_profile',
  '.profile',
];

/** Expand a leading `~` and resolve to an absolute path. */
export function expandHome(p: string): string {
  const t = p.trim();
  if (t === '~') return homedir();
  if (t.startsWith('~/')) return join(homedir(), t.slice(2));
  return isAbsolute(t) ? t : resolve(t);
}

/** A literal tilde inside a quoted env value is not expanded by the shell. */
function tildeWarning(raw: string): string | undefined {
  return raw.trim().startsWith('~')
    ? `declared as "${raw.trim()}" — a literal ~ is not expanded in an env var, ` +
      'so Claude Code will use a directory literally named "~". Use an absolute path.'
    : undefined;
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Grep a file for CLAUDE_CONFIG_DIR assignments. Never throws. */
function extractConfigDirs(file: string): string[] {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  const out: string[] = [];
  for (const m of text.matchAll(CONFIG_DIR_RE)) {
    if (m[1]) out.push(m[1]);
  }
  return out;
}

/** Shallow walk looking for .envrc and .vscode/settings.json. */
function scanProjects(root: string, maxDepth: number): Array<{ raw: string; from: string }> {
  const found: Array<{ raw: string; from: string }> = [];
  const walk = (dir: string, depth: number): void => {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (name === 'node_modules' || name === '.git') continue;
      const full = join(dir, name);
      if (name === '.envrc' && !isDir(full)) {
        for (const raw of extractConfigDirs(full)) found.push({ raw, from: full });
      } else if (name === '.vscode' && isDir(full)) {
        const s = join(full, 'settings.json');
        if (existsSync(s)) {
          for (const raw of extractConfigDirs(s)) found.push({ raw, from: s });
        }
      } else if (depth < maxDepth && isDir(full) && !name.startsWith('.')) {
        walk(full, depth + 1);
      }
    }
  };
  walk(root, 0);
  return found;
}

/**
 * Every Claude config directory preymax should hook, deduplicated by resolved
 * path with all contributing sources recorded.
 */
export function discoverConfigDirs(opts: DiscoverOptions = {}): ConfigDir[] {
  const env = opts.env ?? process.env;

  // Test/escape hatch: when the settings file is pinned, that is the only
  // target. Keeps `init` runnable against a scratch file.
  const pinned = env.PREYMAX_CLAUDE_SETTINGS;
  if (pinned) {
    return [finalize(resolve(pinned, '..'), ['explicit'], undefined, pinned)];
  }

  const acc = new Map<string, { sources: Set<ConfigDirSource>; warning?: string }>();
  const add = (raw: string, source: ConfigDirSource, warning?: string): void => {
    const path = expandHome(raw);
    const entry = acc.get(path) ?? { sources: new Set<ConfigDirSource>() };
    entry.sources.add(source);
    entry.warning ??= warning;
    acc.set(path, entry);
  };

  add(join(homedir(), '.claude'), 'default');

  // Siblings on disk: ~/.claude, ~/.claude-account-tago, ~/.claude-work, ...
  try {
    for (const name of readdirSync(homedir())) {
      if (!SIBLING_RE.test(name)) continue;
      const full = join(homedir(), name);
      if (isDir(full)) add(full, 'sibling');
    }
  } catch {
    /* unreadable home — the default entry still stands */
  }

  if (env.CLAUDE_CONFIG_DIR) {
    add(env.CLAUDE_CONFIG_DIR, 'env', tildeWarning(env.CLAUDE_CONFIG_DIR));
  }

  for (const rc of SHELL_RC_FILES) {
    for (const raw of extractConfigDirs(join(homedir(), rc))) {
      add(raw, 'shell-rc', tildeWarning(raw));
    }
  }

  for (const root of opts.scanRoots ?? []) {
    for (const { raw } of scanProjects(root, 3)) {
      add(raw, 'project', tildeWarning(raw));
    }
  }

  for (const raw of opts.persisted ?? []) add(raw, 'config', tildeWarning(raw));
  for (const raw of opts.explicit ?? []) add(raw, 'explicit', tildeWarning(raw));

  return [...acc.entries()]
    .map(([path, { sources, warning }]) => finalize(path, [...sources], warning))
    .sort((a, b) => a.path.localeCompare(b.path));
}

function finalize(
  path: string,
  sources: ConfigDirSource[],
  warning?: string,
  settingsOverride?: string,
): ConfigDir {
  const settingsPath = settingsOverride ?? join(path, 'settings.json');
  const dir: ConfigDir = {
    path,
    settingsPath,
    sources,
    exists: isDir(path),
    hooked: false,
    warning,
  };
  if (!existsSync(settingsPath)) return dir;
  try {
    const text = readFileSync(settingsPath, 'utf8').trim();
    dir.hooked = text ? hasPreymaxHook(JSON.parse(text) as Record<string, unknown>) : false;
  } catch (err) {
    dir.error = (err as Error).message;
  }
  return dir;
}
