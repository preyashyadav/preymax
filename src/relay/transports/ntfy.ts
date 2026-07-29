import type { Config } from '../core/config.js';
import { makeApproval } from '../core/hmac.js';
import type { PendingRequest } from '../types.js';
import { notificationBody } from '../core/template.js';

/**
 * Push transport: ntfy.
 *
 * Uses ntfy's JSON publish format (POST to the server root with a JSON body)
 * rather than the header-based format. Headers are latin1-only, and summaries
 * are model-written prose that can contain anything; the JSON form carries
 * UTF-8 cleanly and expresses action buttons as structured data instead of a
 * comma-quoting minefield.
 *
 * Security note: on the public ntfy.sh, the topic name IS the access control.
 * Anyone who knows the topic can read every notification and see your summaries.
 * `preymax init` generates a 128-bit topic for this reason. Self-host or use an
 * access-token-protected topic if that isn't good enough for you.
 */

export interface NtfyAction {
  action: 'http' | 'view' | 'broadcast';
  label: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  clear?: boolean;
}

export interface NtfyMessage {
  topic: string;
  message: string;
  title?: string;
  priority?: number;
  tags?: string[];
  actions?: NtfyAction[];
}

export interface NotifyResult {
  ok: boolean;
  status?: number;
  error?: string;
  /** False when no push was attempted (transport disabled or suppressed). */
  attempted: boolean;
}

/**
 * Build the Allow / Deny / Allow-for-30m buttons for a pending request.
 * Returns [] when there is no reachable base URL — the notification still goes
 * out, it just can't be acted on from the phone, and `preymax approve` remains.
 */
export function buildActions(cfg: Config, pending: PendingRequest): NtfyAction[] {
  const base = cfg.publicBaseUrl;
  if (!base) return [];

  const url = `${base.replace(/\/+$/, '')}/approve`;
  const ts = Date.now();
  const headers = { 'Content-Type': 'application/json' };

  const mk = (decision: 'allow' | 'deny', grant: boolean, label: string): NtfyAction => ({
    action: 'http',
    label,
    url,
    method: 'POST',
    headers,
    body: JSON.stringify(
      makeApproval(cfg.secret, { id: pending.id, decision, nonce: pending.nonce, ts, grant }),
    ),
    clear: true,
  });

  const minutes = Math.round(cfg.grantTtlMs / 60_000);
  return [
    mk('allow', false, 'Allow'),
    mk('deny', false, 'Deny'),
    mk('allow', true, `Allow ${minutes}m`),
  ];
}

export function buildEscalationMessage(cfg: Config, pending: PendingRequest): NtfyMessage {
  return {
    topic: cfg.notify.ntfy.topic,
    // Terminal name in the first three words — this gets read off a lock screen.
    message: notificationBody(pending.identity.name, pending.summary),
    title: `[${pending.identity.name}] ${pending.toolName}`,
    priority: cfg.notify.ntfy.priority,
    tags: ['lock'],
    actions: buildActions(cfg, pending),
  };
}

export function buildDigestMessage(
  cfg: Config,
  sessionName: string,
  count: number,
): NtfyMessage {
  return {
    topic: cfg.notify.ntfy.topic,
    message: `[${sessionName}] ${count} more waiting — run preymax pending`,
    title: `[${sessionName}] ${count} pending`,
    priority: Math.max(1, cfg.notify.ntfy.priority - 1),
    tags: ['hourglass'],
  };
}

export async function publish(
  cfg: Config,
  msg: NtfyMessage,
  timeoutMs = 4000,
): Promise<NotifyResult> {
  if (cfg.notify.transport === 'none') return { ok: true, attempted: false };
  if (!cfg.notify.ntfy.topic) {
    return { ok: false, attempted: false, error: 'no ntfy topic configured' };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (cfg.notify.ntfy.token) headers.Authorization = `Bearer ${cfg.notify.ntfy.token}`;

    const res = await fetch(cfg.notify.ntfy.server, {
      method: 'POST',
      headers,
      body: JSON.stringify(msg),
      signal: controller.signal,
    });

    if (!res.ok) {
      return { ok: false, attempted: true, status: res.status, error: await res.text().catch(() => '') };
    }
    return { ok: true, attempted: true, status: res.status };
  } catch (err) {
    // A push failure must never affect the decision path. The escalation is
    // still pending and still resolvable via `preymax approve`.
    return { ok: false, attempted: true, error: (err as Error).message };
  } finally {
    clearTimeout(timer);
  }
}
