import { networkInterfaces } from 'node:os';

/**
 * Network binding policy.
 *
 * The daemon binds loopback plus, optionally, the Tailscale interface address.
 * Never 0.0.0.0. This is asserted at startup and the daemon refuses to start if
 * a configured address violates it — a wildcard bind would expose an endpoint
 * that authorizes shell commands to every network the Mac is attached to,
 * including whatever coffee-shop wifi it joins next.
 */

const LOOPBACK = new Set(['127.0.0.1', '::1']);

/** Tailscale's CGNAT range is 100.64.0.0/10. */
export function isTailscaleAddress(addr: string): boolean {
  const m = /^100\.(\d+)\./.exec(addr);
  if (!m) return false;
  const second = Number(m[1]);
  return second >= 64 && second <= 127;
}

export function findTailnetAddress(): string | null {
  for (const addrs of Object.values(networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === 'IPv4' && !a.internal && isTailscaleAddress(a.address)) {
        return a.address;
      }
    }
  }
  return null;
}

export class UnsafeBindError extends Error {}

/**
 * Throws unless every address is loopback or a Tailscale CGNAT address.
 * Called before any listener is opened.
 */
export function assertSafeBind(addresses: string[]): void {
  if (addresses.length === 0) throw new UnsafeBindError('refusing to start with no bind address');
  for (const addr of addresses) {
    if (LOOPBACK.has(addr)) continue;
    if (isTailscaleAddress(addr)) continue;
    throw new UnsafeBindError(
      `refusing to bind ${addr}: preymax binds loopback and the Tailscale interface only. ` +
        'Binding a public or LAN address would expose an endpoint that authorizes shell commands.',
    );
  }
}

/** The addresses the daemon should listen on, given config. */
export function resolveBindAddresses(bindTailnet: boolean): {
  addresses: string[];
  tailnet: string | null;
} {
  const tailnet = bindTailnet ? findTailnetAddress() : null;
  const addresses = ['127.0.0.1'];
  if (tailnet) addresses.push(tailnet);
  return { addresses, tailnet };
}
