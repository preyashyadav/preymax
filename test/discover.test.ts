import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverConfigDirs, expandHome } from '../src/hook/discover.js';
import { buildHookEntry, mergeHook, hasPreymaxHook } from '../src/hook/registry.js';

/**
 * Discovery is the fix for the failure that cost a full day of data: a project
 * pointing CLAUDE_CONFIG_DIR at an unhooked directory while doctor reported
 * green. These tests exist to keep that specific silence impossible.
 */

let home: string;
let savedHome: string | undefined;
let savedEnvDir: string | undefined;
let savedPin: string | undefined;

/** A Claude config dir, optionally already carrying our hook. */
function makeConfigDir(path: string, opts: { hooked?: boolean } = {}): void {
  mkdirSync(path, { recursive: true });
  const settings = opts.hooked
    ? mergeHook({}, buildHookEntry(7717)).settings
    : { model: 'opus' };
  writeFileSync(join(path, 'settings.json'), JSON.stringify(settings, null, 2));
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'preymax-discover-'));
  savedHome = process.env.HOME;
  savedEnvDir = process.env.CLAUDE_CONFIG_DIR;
  savedPin = process.env.PREYMAX_CLAUDE_SETTINGS;
  process.env.HOME = home;
  delete process.env.CLAUDE_CONFIG_DIR;
  delete process.env.PREYMAX_CLAUDE_SETTINGS;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  if (savedEnvDir === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = savedEnvDir;
  if (savedPin === undefined) delete process.env.PREYMAX_CLAUDE_SETTINGS;
  else process.env.PREYMAX_CLAUDE_SETTINGS = savedPin;
  rmSync(home, { recursive: true, force: true });
});

describe('expandHome', () => {
  it('expands a leading tilde', () => {
    assert.equal(expandHome('~/x'), join(home, 'x'));
  });

  it('leaves absolute paths alone', () => {
    assert.equal(expandHome('/etc/x'), '/etc/x');
  });
});

describe('config dir discovery', () => {
  it('always includes the default ~/.claude', () => {
    const dirs = discoverConfigDirs({ env: {} });
    const def = dirs.find((d) => d.path === join(home, '.claude'));
    assert.ok(def, 'default dir must always be present');
    assert.ok(def!.sources.includes('default'));
  });

  it('finds sibling account directories on disk', () => {
    makeConfigDir(join(home, '.claude'));
    makeConfigDir(join(home, '.claude-account-tago'));
    makeConfigDir(join(home, '.claude-work'));

    const found = discoverConfigDirs({ env: {} }).filter((d) => d.exists).map((d) => d.path);
    assert.ok(found.includes(join(home, '.claude-account-tago')));
    assert.ok(found.includes(join(home, '.claude-work')));
  });

  it('ignores non-directories and unrelated dotfiles', () => {
    writeFileSync(join(home, '.claude.json'), '{}');
    mkdirSync(join(home, '.claudius'), { recursive: true });

    const paths = discoverConfigDirs({ env: {} }).map((d) => d.path);
    assert.ok(!paths.includes(join(home, '.claude.json')));
    assert.ok(!paths.includes(join(home, '.claudius')));
  });

  it('reports per-directory hook status', () => {
    makeConfigDir(join(home, '.claude'), { hooked: true });
    makeConfigDir(join(home, '.claude-account-b'), { hooked: false });

    const dirs = discoverConfigDirs({ env: {} });
    assert.equal(dirs.find((d) => d.path.endsWith('.claude'))!.hooked, true);
    assert.equal(dirs.find((d) => d.path.endsWith('.claude-account-b'))!.hooked, false);
  });

  it('reads CLAUDE_CONFIG_DIR from the environment', () => {
    const target = join(home, 'elsewhere');
    makeConfigDir(target);
    const dirs = discoverConfigDirs({ env: { CLAUDE_CONFIG_DIR: target } });
    assert.ok(dirs.find((d) => d.path === target)?.sources.includes('env'));
  });

  it('reads CLAUDE_CONFIG_DIR out of shell rc files', () => {
    const target = join(home, 'from-rc');
    makeConfigDir(target);
    writeFileSync(join(home, '.zshrc'), `export CLAUDE_CONFIG_DIR="${target}"\n`);
    const dirs = discoverConfigDirs({ env: {} });
    assert.ok(dirs.find((d) => d.path === target)?.sources.includes('shell-rc'));
  });

  // The JSON form is the one that silently failed first: a closing quote sits
  // between the key and the colon, which a shell-only regex does not match.
  it('reads CLAUDE_CONFIG_DIR out of .vscode/settings.json', () => {
    const project = join(home, 'proj');
    const target = join(home, 'from-vscode');
    makeConfigDir(target);
    mkdirSync(join(project, '.vscode'), { recursive: true });
    writeFileSync(
      join(project, '.vscode', 'settings.json'),
      JSON.stringify({
        'terminal.integrated.env.osx': { CLAUDE_CONFIG_DIR: target, PREYMAX_NAME: 'proj' },
      }),
    );

    const dirs = discoverConfigDirs({ env: {}, scanRoots: [project] });
    assert.ok(dirs.find((d) => d.path === target)?.sources.includes('project'));
  });

  it('reads CLAUDE_CONFIG_DIR out of .envrc', () => {
    const project = join(home, 'proj2');
    const target = join(home, 'from-envrc');
    makeConfigDir(target);
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, '.envrc'), `export CLAUDE_CONFIG_DIR=${target}\n`);

    const dirs = discoverConfigDirs({ env: {}, scanRoots: [project] });
    assert.ok(dirs.find((d) => d.path === target)?.sources.includes('project'));
  });

  it('warns on a literal tilde, which the shell never expands', () => {
    const project = join(home, 'proj3');
    mkdirSync(join(project, '.vscode'), { recursive: true });
    writeFileSync(
      join(project, '.vscode', 'settings.json'),
      JSON.stringify({ 'terminal.integrated.env.osx': { CLAUDE_CONFIG_DIR: '~/.claude-tilde' } }),
    );

    const dirs = discoverConfigDirs({ env: {}, scanRoots: [project] });
    const hit = dirs.find((d) => d.path === join(home, '.claude-tilde'));
    assert.ok(hit?.warning, 'a literal ~ must be reported, not silently expanded');
    assert.match(hit!.warning!, /literal ~/);
  });

  it('merges sources for a directory found more than one way', () => {
    const target = join(home, '.claude-account-tago');
    makeConfigDir(target);
    const dirs = discoverConfigDirs({ env: { CLAUDE_CONFIG_DIR: target }, explicit: [target] });
    const hit = dirs.find((d) => d.path === target)!;
    assert.ok(hit.sources.includes('sibling'));
    assert.ok(hit.sources.includes('env'));
    assert.ok(hit.sources.includes('explicit'));
    assert.equal(dirs.filter((d) => d.path === target).length, 1, 'must not duplicate');
  });

  it('includes an explicit dir that does not exist yet', () => {
    const target = join(home, 'not-yet');
    const dirs = discoverConfigDirs({ env: {}, explicit: [target] });
    const hit = dirs.find((d) => d.path === target);
    assert.ok(hit, 'an explicitly requested dir must survive discovery');
    assert.equal(hit!.exists, false);
  });

  it('records a parse error rather than throwing', () => {
    const bad = join(home, '.claude-broken');
    mkdirSync(bad, { recursive: true });
    writeFileSync(join(bad, 'settings.json'), '{ not json');
    const hit = discoverConfigDirs({ env: {} }).find((d) => d.path === bad);
    assert.ok(hit?.error, 'a malformed settings.json must be reported, not fatal');
    assert.equal(hit!.hooked, false);
  });
});

describe('hasPreymaxHook', () => {
  it('is false for settings with no hooks at all', () => {
    assert.equal(hasPreymaxHook({ model: 'opus' }), false);
  });

  it('is true once the hook is merged in', () => {
    const { settings } = mergeHook({}, buildHookEntry(7717));
    assert.equal(hasPreymaxHook(settings), true);
  });

  it('ignores a foreign http hook on another port and path', () => {
    const foreign = {
      hooks: {
        PreToolUse: [{ matcher: '*', hooks: [{ type: 'http', url: 'http://example.com/other' }] }],
      },
    };
    assert.equal(hasPreymaxHook(foreign), false);
  });
});
