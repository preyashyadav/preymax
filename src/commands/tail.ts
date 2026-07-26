import { loadConfig } from '../core/config.js';
import { colorFor } from '../core/identity.js';
import { daemonBase, DaemonUnreachableError } from './client.js';

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

/**
 * `preymax tail` — the primary debugging surface.
 *
 * Streams the daemon's event bus over SSE with per-terminal colorization, so
 * three sessions named api / web / infra are visually separable at a glance.
 */

interface TailEvent {
  type: string;
  session?: string;
  tool?: string;
  decision?: string;
  source?: string;
  summary?: string;
  summarySource?: string;
  latencyMs?: number;
  id?: string;
}

function decorate(e: TailEvent): string {
  const t = new Date().toLocaleTimeString();
  const name = e.session ?? '-';
  const color = colorFor(name);
  const tag = `${color}[${name}]${RESET}`;

  switch (e.type) {
    case 'escalation':
      return `${DIM}${t}${RESET} ${tag} ${'\x1b[33m'}ESCALATE${RESET} ${e.tool} — ${e.summary ?? ''} ${DIM}(${e.summarySource})${RESET}`;
    case 'decision': {
      const color2 =
        e.decision === 'allow' ? '\x1b[32m' : e.decision === 'deny' ? '\x1b[31m' : '\x1b[90m';
      const lat = e.latencyMs !== undefined ? ` ${DIM}${e.latencyMs}ms${RESET}` : '';
      return `${DIM}${t}${RESET} ${tag} ${color2}${(e.decision ?? '?').toUpperCase()}${RESET} ${e.tool} ${DIM}via ${e.source}${RESET}${lat}`;
    }
    case 'approval':
      return `${DIM}${t}${RESET} ${DIM}approval${RESET} ${e.id} → ${e.decision} ${DIM}(${e.source})${RESET}`;
    default:
      return `${DIM}${t}${RESET} ${JSON.stringify(e)}`;
  }
}

export async function runTail(): Promise<void> {
  const cfg = loadConfig();
  const base = daemonBase();

  console.log(`${DIM}preymax tail — ${base}  (ctrl-c to stop)${RESET}`);
  if (cfg.notify.transport === 'none') {
    console.log(`${DIM}push transport is disabled; escalations are visible here only${RESET}`);
  }

  let res: Response;
  try {
    res = await fetch(base + '/events', { headers: { Accept: 'text/event-stream' } });
  } catch (err) {
    throw new DaemonUnreachableError(base, (err as Error).message);
  }
  if (!res.body) throw new Error('daemon returned no event stream');

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let idx: number;
    while ((idx = buffer.indexOf('\n\n')) !== -1) {
      const frame = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      for (const line of frame.split('\n')) {
        if (!line.startsWith('data: ')) continue;
        try {
          console.log(decorate(JSON.parse(line.slice(6)) as TailEvent));
        } catch {
          continue;
        }
      }
    }
  }
  console.log(`${DIM}stream closed — the daemon stopped${RESET}`);
}
