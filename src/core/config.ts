import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { paths } from './paths.js';

export interface Config {
  /** Loopback port the daemon binds. */
  port: number;
  /**
   * Every Claude config directory preymax registers its hook in. Populated by
   * `preymax init` via hook/discover.ts and editable by hand. A project that
   * points CLAUDE_CONFIG_DIR at a directory missing from this list gets no hook
   * and is invisible to preymax — see handoff bug 1.
   */
  configDirs: string[];
  /**
   * Also bind the Tailscale interface address so the phone can reach us.
   * Never 0.0.0.0 — the daemon refuses to start if it resolves to one.
   */
  bindTailnet: boolean;
  /**
   * Base URL the phone uses to reach the daemon, e.g. https://mac.tail1234.ts.net:7717
   * Required for action buttons; without it notifications are read-only.
   */
  publicBaseUrl: string | null;
  /** Shared secret for HMAC-signing approvals. Generated on `preymax init`. */
  secret: string;
  /** How long the hook blocks waiting for a decision before returning `ask`. */
  decisionTimeoutMs: number;
  /** Hard cap on waiting for the model summary before sending the notification. */
  summaryBudgetMs: number;
  /** Suppress a duplicate push for the same fingerprint within this window. */
  dedupeWindowMs: number;
  /** Two or more escalations for one session inside this window become a digest. */
  burstWindowMs: number;
  /** Single-use approval nonce lifetime. */
  nonceTtlMs: number;
  /** Default lifetime of an "allow this pattern for a while" grant. */
  grantTtlMs: number;
  /**
   * Shadow mode: log every escalation, decide nothing, notify nobody, and
   * return `ask` immediately so no terminal ever stalls. This is the mode you
   * measure in. v1 required faking it with `transport: none` +
   * `decisionTimeoutMs: 1`, which was easy to set wrong and easy to forget to
   * revert (handoff bug 4). Toggle with `preymax shadow on|off`.
   */
  shadow: boolean;
  relay: {
    /**
     * The single gate for the entire notification/approval subsystem. When
     * false, `src/relay/**` is never imported — so no summarizer is
     * constructed, no transport is loaded, and the hook path cannot perform
     * network I/O even by mistake. Structure, not discipline (PLANv2 §4).
     */
    enabled: boolean;
  };
  notify: {
    /** 'ntfy' | 'none'. 'none' disables push entirely (Phase 1/2 operation). */
    transport: 'ntfy' | 'none';
    ntfy: {
      server: string;
      /** High-entropy topic. Anyone who knows it can read your notifications. */
      topic: string;
      /** Optional bearer token for a protected/self-hosted ntfy. */
      token: string | null;
      priority: number;
      sound: string | null;
    };
  };
  summarize: {
    enabled: boolean;
    model: string;
    /** Read from ANTHROPIC_API_KEY if null. Never written to disk by init. */
    apiKey: string | null;
  };
  /** Run the daemon under `caffeinate -dis` so the Mac stays reachable. */
  caffeinate: boolean;
}

export const DEFAULT_CONFIG: Config = {
  port: 7717,
  configDirs: [],
  bindTailnet: true,
  publicBaseUrl: null,
  secret: '',
  decisionTimeoutMs: 60_000,
  summaryBudgetMs: 800,
  dedupeWindowMs: 30_000,
  burstWindowMs: 5_000,
  nonceTtlMs: 5 * 60_000,
  grantTtlMs: 30 * 60_000,
  // v2 default: local-only. The relay is opt-in and has never been validated
  // against a real device (PLANv2 §6).
  shadow: false,
  relay: { enabled: false },
  notify: {
    transport: 'ntfy',
    ntfy: {
      server: 'https://ntfy.sh',
      topic: '',
      token: null,
      priority: 5,
      sound: null,
    },
  },
  summarize: {
    enabled: true,
    model: 'claude-haiku-4-5',
    apiKey: null,
  },
  caffeinate: true,
};

function deepMerge<T>(base: T, patch: unknown): T {
  if (patch === null || typeof patch !== 'object' || Array.isArray(patch)) {
    return (patch === undefined ? base : (patch as T));
  }
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(patch as Record<string, unknown>)) {
    const b = (base as Record<string, unknown>)[k];
    out[k] = b && typeof b === 'object' && !Array.isArray(b) ? deepMerge(b, v) : v;
  }
  return out as T;
}

export function loadConfig(): Config {
  const file = paths.config();
  if (!existsSync(file)) return { ...DEFAULT_CONFIG };
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  } catch (err) {
    throw new Error(`config at ${file} is not valid JSON: ${(err as Error).message}`);
  }
  return migrate(deepMerge(DEFAULT_CONFIG, raw), raw);
}

/**
 * Map a v1 config onto v2's `shadow` / `relay` fields.
 *
 * v1 had no way to say "observe but do not act", so shadow mode was faked with
 * `notify.transport: "none"` plus a sub-second `decisionTimeoutMs`. That exact
 * pair is recognised here and becomes `shadow: true`, so an existing install
 * keeps behaving identically without the user editing anything.
 */
function migrate(cfg: Config, raw: Record<string, unknown>): Config {
  const notify = raw.notify as { transport?: string } | undefined;
  const transportOff = notify?.transport === 'none';

  if (raw.relay === undefined) {
    cfg.relay = { ...cfg.relay, enabled: notify?.transport !== undefined && !transportOff };
  }
  if (raw.shadow === undefined) {
    const timeout = typeof raw.decisionTimeoutMs === 'number' ? raw.decisionTimeoutMs : 60_000;
    cfg.shadow = transportOff && timeout <= 1_000;
  }
  return cfg;
}

export function saveConfig(cfg: Config): void {
  mkdirSync(paths.home(), { recursive: true });
  writeFileSync(paths.config(), JSON.stringify(cfg, null, 2) + '\n', { mode: 0o600 });
  // The secret lives here. Make the tightening explicit rather than relying on
  // the writeFileSync mode, which is masked by umask on an existing file.
  chmodSync(paths.config(), 0o600);
}

export function generateSecret(): string {
  return randomBytes(32).toString('hex');
}

/** High-entropy ntfy topic. Guessing this is the only access control ntfy.sh offers. */
export function generateTopic(): string {
  return 'preymax-' + randomBytes(16).toString('base64url');
}

export function resolveApiKey(cfg: Config): string | null {
  return cfg.summarize.apiKey || process.env.ANTHROPIC_API_KEY || null;
}
