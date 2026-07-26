import { basename } from 'node:path';
import { collapseHome } from './redact.js';

/**
 * Template summaries. Deterministic, instant, no network. This is the Phase 3
 * product and the permanent fallback for Phase 4 — if the model call is slow,
 * rate-limited, or down, this is what ships and the user sees no error.
 *
 * Format rule from the plan: the terminal name goes in the first three words,
 * because this gets read off a lock screen at a glance. The name is prepended by
 * the notifier, so these functions produce only the part after it.
 */

function firstLine(s: string, max = 90): string {
  const line = s.split('\n')[0]!.trim();
  return line.length > max ? line.slice(0, max - 1) + '…' : line;
}

export function templateSummary(
  toolName: string,
  redactedInput: Record<string, unknown>,
): string {
  const str = (k: string): string | null => {
    const v = redactedInput[k];
    return typeof v === 'string' ? v : null;
  };

  const path = str('file_path') ?? str('path') ?? str('notebook_path');
  const short = path ? collapseHome(path) : null;

  switch (toolName.toLowerCase()) {
    case 'bash': {
      const cmd = str('command');
      return cmd ? `run: ${firstLine(cmd)}` : 'run a shell command';
    }
    case 'write':
      return short ? `write: ${short}` : 'write a file';
    case 'edit':
      return short ? `edit: ${short}` : 'edit a file';
    case 'notebookedit':
      return short ? `edit notebook: ${short}` : 'edit a notebook';
    case 'read':
      return short ? `read: ${short}` : 'read a file';
    case 'webfetch': {
      const url = str('url');
      return url ? `fetch: ${firstLine(url)}` : 'fetch a URL';
    }
    case 'websearch': {
      const q = str('query');
      return q ? `search: ${firstLine(q)}` : 'run a web search';
    }
    case 'task': {
      const d = str('description');
      return d ? `subagent: ${firstLine(d)}` : 'launch a subagent';
    }
    default: {
      // Unknown tool — name it and show the most useful-looking string field.
      const candidate =
        str('command') ?? str('description') ?? str('query') ?? str('url') ?? short;
      return candidate ? `${toolName}: ${firstLine(candidate)}` : `use ${toolName}`;
    }
  }
}

/** The notification title. Terminal name first, always. */
export function notificationTitle(sessionName: string, toolName: string): string {
  return `[${sessionName}] ${toolName}`;
}

/** The notification body: "[api] run: npx prisma migrate reset" */
export function notificationBody(sessionName: string, summary: string): string {
  return `[${sessionName}] ${summary}`;
}

/** Short label used in `preymax pending` and the digest push. */
export function shortLabel(toolName: string, redactedInput: Record<string, unknown>): string {
  const s = templateSummary(toolName, redactedInput);
  return s.length > 60 ? s.slice(0, 59) + '…' : s;
}

export function fileBase(p: string | null): string {
  return p ? basename(p) : '';
}
