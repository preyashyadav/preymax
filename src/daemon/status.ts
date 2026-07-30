import { accessSync, constants, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Config } from '../core/config.js';
import { resolveApiKey } from '../core/config.js';
import { paths } from '../core/paths.js';
import { loadPolicy } from '../core/policy.js';
import { discoverConfigDirs, type ConfigDir } from '../hook/discover.js';

/**
 * The daemon's own view of its health.
 *
 * Standing rule: **any health check that runs outside the daemon lies.**
 *
 * v1's `doctor` computed the summarizer's availability by calling
 * `resolveApiKey()` in the *doctor* process, which reads the user's shell
 * environment. The daemon runs under launchd and inherits none of it, so
 * `doctor` reported a green summarizer while the daemon had no key and had
 * silently been emitting template summaries for its entire life (handoff bug
 * 2). Every fact a caller could get wrong is computed here instead, in the
 * process that actually has to act on it.
 */

export interface ConfigDirStatus {
  path: string;
  exists: boolean;
  hooked: boolean;
  sources: string[];
  error?: string;
  warning?: string;
}

export interface DaemonStatus {
  ok: true;
  version: string;
  pid: number;
  uptimeMs: number;
  bind: { addresses: string[]; tailnet: string | null; port: number };
  configPath: string;
  configDirs: ConfigDirStatus[];
  policy: { path: string; allowRules: number; error?: string };
  log: { path: string; writable: boolean; error?: string };
  summarizer: {
    enabled: boolean;
    available: boolean;
    model: string;
    /** Why it is unavailable, in the daemon's own terms. */
    reason: string;
    stats: SummarizerStats;
  };
  relay: {
    enabled: boolean;
    transport: string;
    publicBaseUrl: string | null;
    decisionTimeoutMs: number;
  };
  shadow: boolean;
  pending: number;
  grants: number;
}

/**
 * `ok` counts summaries the model actually returned. Without it, a summarizer
 * that has failed every single call is indistinguishable from one that has
 * never been asked — which is how a 21-error, 0-success summarizer reported
 * green for a day.
 */
export interface SummarizerStats {
  ok: number;
  hits: number;
  misses: number;
  errors: number;
  timeouts: number;
}

export interface StatusInputs {
  cfg: Config;
  version: string;
  startedAt: number;
  addresses: string[];
  tailnet: string | null;
  pending: number;
  grants: number;
  summarizerAvailable: boolean;
  summarizerStats: SummarizerStats;
}

function toStatus(d: ConfigDir): ConfigDirStatus {
  return {
    path: d.path,
    exists: d.exists,
    hooked: d.hooked,
    sources: d.sources,
    ...(d.error ? { error: d.error } : {}),
    ...(d.warning ? { warning: d.warning } : {}),
  };
}

function writable(file: string): { writable: boolean; error?: string } {
  const dir = dirname(file);
  try {
    accessSync(existsSync(file) ? file : dir, constants.W_OK);
    return { writable: true };
  } catch (err) {
    return { writable: false, error: (err as Error).message };
  }
}

/** Why the summarizer is or is not usable, phrased for a human reading doctor. */
function summarizerReason(cfg: Config, available: boolean): string {
  if (available) return 'ready';
  // Check this first: with the relay off the summarizer is not merely
  // unavailable, it is never constructed. Reporting a missing API key here
  // would send the user to fix something that is not the reason.
  if (!cfg.relay.enabled || cfg.shadow) {
    return cfg.shadow
      ? 'not running — shadow mode is on, so nothing is summarized or sent'
      : 'not running — the relay is off, so no summary is needed';
  }
  if (!cfg.summarize.enabled) return 'disabled in config — template summaries only';
  if (!resolveApiKey(cfg)) {
    return (
      'no API key visible to the daemon. The daemon runs under launchd and does ' +
      'not inherit your shell environment, so `export ANTHROPIC_API_KEY` has no ' +
      'effect here. Set summarize.apiKey in config.json, or re-run `preymax init` ' +
      'to write the key into the launch agent.'
    );
  }
  return 'unavailable';
}

export function buildStatus(input: StatusInputs): DaemonStatus {
  const { cfg } = input;

  let allowRules = 0;
  let policyError: string | undefined;
  try {
    allowRules = loadPolicy().auto_allow.length;
  } catch (err) {
    policyError = (err as Error).message;
  }

  // Events are written to the daily directory, not v1's single file. Report
  // what is actually being written to, or doctor greenlights the wrong path.
  const log = writable(paths.logDir());

  return {
    ok: true,
    version: input.version,
    pid: process.pid,
    uptimeMs: Date.now() - input.startedAt,
    bind: { addresses: input.addresses, tailnet: input.tailnet, port: cfg.port },
    configPath: paths.config(),
    configDirs: discoverConfigDirs({ persisted: cfg.configDirs }).map(toStatus),
    policy: {
      path: paths.policy(),
      allowRules,
      ...(policyError ? { error: policyError } : {}),
    },
    log: { path: paths.logDir(), ...log },
    summarizer: {
      enabled: cfg.summarize.enabled,
      available: input.summarizerAvailable,
      model: cfg.summarize.model,
      reason: summarizerReason(cfg, input.summarizerAvailable),
      stats: input.summarizerStats,
    },
    relay: {
      // `relay.enabled` is the flag `preymax relay enable|disable` writes, and
      // the one the daemon branches on. Deriving this from the transport (as it
      // did before that flag existed) made doctor report an enabled relay
      // minutes after it had been disabled — standing rule 3, one directory up.
      enabled: cfg.relay.enabled,
      transport: cfg.notify.transport,
      publicBaseUrl: cfg.publicBaseUrl,
      decisionTimeoutMs: cfg.decisionTimeoutMs,
    },
    shadow: cfg.shadow,
    pending: input.pending,
    grants: input.grants,
  };
}
