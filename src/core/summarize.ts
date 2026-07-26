import Anthropic from '@anthropic-ai/sdk';
import type { Config } from './config.js';
import { resolveApiKey } from './config.js';

/**
 * One-sentence spoken-word summaries via Claude Haiku.
 *
 * Three rules, all from the plan, all load-bearing:
 *
 *  1. The input is already redacted. This module never receives a raw tool
 *     input — see redact.ts. Verify with a proxy, not by reading this file.
 *  2. This never blocks the decision path. The caller races it against a hard
 *     budget and ships the template summary if it loses.
 *  3. Failure is silent to the user and logged for `preymax stats`. An API
 *     outage degrades the wording of a notification, nothing more.
 *
 * Model choice: Haiku 4.5 (`claude-haiku-4-5`), $1/$5 per MTok, chosen for
 * latency per the plan. Thinking is left off — this is a sub-20-word rewrite
 * and thinking would blow the latency budget for no quality gain.
 */

const SYSTEM_PROMPT = [
  'You turn a developer tool call into one short sentence that will be SPOKEN ALOUD',
  'as a phone notification, so someone away from their desk can decide whether to',
  'approve it.',
  '',
  'Rules:',
  '- One sentence. Under twenty words. No preamble, no quotes, no markdown.',
  '- Write it to be heard, not read. Expand symbols: say "force push to main",',
  '  not "git push --force main". Avoid flags, paths with slashes, and jargon.',
  '- Name the risk if there is one ("this deletes the database", "this rewrites',
  '  published history"). If it is routine, say so plainly.',
  '- Do not add advice, do not ask questions, do not mention that you are an AI.',
  '- Some values may appear as [redacted]. That is expected; never comment on it.',
].join('\n');

export interface SummaryResult {
  text: string;
  source: 'model' | 'cache';
}

export class Summarizer {
  private client: Anthropic | null = null;
  private readonly cache = new Map<string, string>();
  private readonly maxCacheEntries = 500;

  /** Observability for `preymax stats`. */
  public stats = { hits: 0, misses: 0, errors: 0, timeouts: 0 };

  constructor(private readonly cfg: Config) {
    const apiKey = resolveApiKey(cfg);
    if (cfg.summarize.enabled && apiKey) {
      this.client = new Anthropic({ apiKey, maxRetries: 0 });
    }
  }

  get available(): boolean {
    return this.client !== null;
  }

  private remember(key: string, value: string): void {
    if (this.cache.size >= this.maxCacheEntries) {
      // Cheap FIFO eviction; the access pattern here is dominated by recency.
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(key, value);
  }

  /**
   * Returns null rather than throwing. Callers treat null as "use the template".
   * `fingerprint` is the cache key: you run the same commands constantly and
   * should pay for each summary once.
   */
  async summarize(
    fingerprint: string,
    toolName: string,
    redactedInput: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<SummaryResult | null> {
    const cached = this.cache.get(fingerprint);
    if (cached !== undefined) {
      this.stats.hits++;
      return { text: cached, source: 'cache' };
    }
    if (!this.client) return null;

    this.stats.misses++;
    try {
      const body = JSON.stringify(redactedInput, null, 1).slice(0, 4000);
      const res = await this.client.messages.create(
        {
          model: this.cfg.summarize.model,
          max_tokens: 100,
          system: SYSTEM_PROMPT,
          messages: [
            {
              role: 'user',
              content: `Tool: ${toolName}\nInput:\n${body}`,
            },
          ],
        },
        { signal },
      );

      if (res.stop_reason === 'refusal') {
        this.stats.errors++;
        return null;
      }

      const text = res.content
        .filter((b): b is Anthropic.TextBlock => b.type === 'text')
        .map((b) => b.text)
        .join(' ')
        .trim()
        .replace(/\s+/g, ' ');

      if (!text) {
        this.stats.errors++;
        return null;
      }

      this.remember(fingerprint, text);
      return { text, source: 'model' };
    } catch (err) {
      if ((err as Error).name === 'AbortError') this.stats.timeouts++;
      else this.stats.errors++;
      return null;
    }
  }

  /**
   * Race the model against a hard budget. Whatever the outcome, this resolves
   * within `budgetMs` and never rejects.
   *
   * Deviation from the plan, deliberate: the plan describes emitting the
   * template notification immediately and replacing its body in place once the
   * model returns. ntfy has no edit-message API, so an in-place replacement
   * would mean a second buzz for every escalation — exactly the notification
   * fatigue the plan names as the primary failure mode. Instead the model call
   * is capped at `summaryBudgetMs` (default 800ms, the plan's own ceiling) and
   * one notification is sent with whichever summary won. Cache hits resolve
   * instantly, so the steady state is the model wording at zero added latency.
   */
  async summarizeWithinBudget(
    fingerprint: string,
    toolName: string,
    redactedInput: Record<string, unknown>,
    budgetMs: number,
  ): Promise<SummaryResult | null> {
    if (this.cache.has(fingerprint)) {
      this.stats.hits++;
      return { text: this.cache.get(fingerprint)!, source: 'cache' };
    }
    if (!this.client) return null;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), budgetMs);
    try {
      return await this.summarize(fingerprint, toolName, redactedInput, controller.signal);
    } finally {
      clearTimeout(timer);
    }
  }
}
