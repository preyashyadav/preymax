import { colorFor } from '../core/identity.js';
import { fetchGrants, fetchPending, sendDecision } from './client.js';

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

/**
 * The local escape hatch. Non-optional by design: this must work when the
 * phone, the tailnet, and ntfy are all unavailable.
 */

function age(ms: number): string {
  const s = Math.round((Date.now() - ms) / 1000);
  return s < 60 ? `${s}s` : `${Math.round(s / 60)}m`;
}

function remaining(expiresAt: number): string {
  const s = Math.round((expiresAt - Date.now()) / 1000);
  return s <= 0 ? 'expired' : `${s}s left`;
}

export async function runPending(): Promise<number> {
  const pending = await fetchPending();
  if (pending.length === 0) {
    console.log('nothing pending');
    const grants = await fetchGrants();
    if (grants.length > 0) console.log(`${DIM}${grants.length} active grant(s) — preymax grants${RESET}`);
    return 0;
  }

  console.log(`${pending.length} pending:\n`);
  for (const p of pending) {
    const c = colorFor(p.session);
    console.log(`  ${DIM}${p.id.slice(0, 8)}${RESET}  ${c}[${p.session}]${RESET} ${p.summary}`);
    console.log(`  ${DIM}          ${p.tool} · ${age(p.createdAt)} ago · ${remaining(p.expiresAt)}${RESET}`);
    console.log('');
  }
  console.log(`${DIM}preymax approve <id>   preymax deny <id>   preymax approve <id> --grant${RESET}`);
  return 0;
}

export async function runDecide(
  id: string | undefined,
  dec: 'allow' | 'deny',
  grant: boolean,
): Promise<number> {
  if (!id) {
    console.error(`usage: preymax ${dec === 'allow' ? 'approve' : 'deny'} <id> [--grant]`);
    return 2;
  }
  const result = await sendDecision(id, dec, grant);
  if (!result.ok) {
    console.error(`failed: ${result.error}`);
    return 1;
  }
  console.log(`${dec === 'allow' ? 'allowed' : 'denied'} ${id}${grant ? ' (+ temporary grant)' : ''}`);
  return 0;
}

export async function runGrants(): Promise<number> {
  const grants = (await fetchGrants()) as Array<{
    session: string;
    toolName: string;
    pattern: string;
    expiresAt: number;
  }>;
  if (grants.length === 0) {
    console.log('no active grants');
    return 0;
  }
  for (const g of grants) {
    const mins = Math.max(0, Math.round((g.expiresAt - Date.now()) / 60_000));
    console.log(`  ${colorFor(g.session)}[${g.session}]${RESET} ${g.toolName}  ${DIM}${mins}m left${RESET}`);
    console.log(`  ${DIM}    ${g.pattern.slice(0, 72)}${RESET}`);
  }
  return 0;
}
