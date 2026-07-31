> ## ⛔ Superseded — historical record only
>
> This is the v1 plan. **`PLANv2.md` replaces it** and is the document to read.
> Kept because its Phase 0 kill gate, its exit criteria, and its stop condition
> are what v2 was judged against — not because any of it is still the plan.
>
> Materially wrong here, corrected in v2: `auto_deny` (deleted, §3); Phase 5/6
> ordering (the phone is an optional layer, not a phase, §1); `defer` (settled,
> §6); "no third-party dependency" (never load-bearing, §6). Phase 0 itself was
> skipped during v1 and was finally written and resolved in `PLANv2 §1`.

# preymax

**Named, voice-summarized permission triage for parallel Claude Code sessions.**

Package: `preymax` · CLI: `preymax` · Daemon: `preymaxd` · Platform: macOS + iOS

---

## Table of contents

- [Problem statement](#problem-statement)
- [Why not terminal monitoring](#why-not-terminal-monitoring)
- [Architecture](#architecture)
- [Phase 0 — Kill gate](#phase-0--kill-gate)
- [Phase 1 — Capture](#phase-1--capture)
- [Phase 2 — Policy engine](#phase-2--policy-engine)
- [Phase 3 — Notify](#phase-3--notify)
- [Phase 4 — Summarize](#phase-4--summarize)
- [Phase 5 — Approve remotely](#phase-5--approve-remotely)
- [Phase 6 — Voice](#phase-6--voice)
- [Cross-cutting concerns](#cross-cutting-concerns)
- [Open questions](#open-questions)
- [Relationship to SessionLint](#relationship-to-sessionlint)

---

## Problem statement

Running several Claude Code sessions in parallel VS Code terminals means each one silently blocks on a permission prompt at an unpredictable moment. The cost is not the approval itself — it's the polling. You context-switch across terminals looking for which one stopped, and you lose the thread on whatever you were actually doing.

**preymax makes the blocked terminal announce itself, by name, in plain language, on your phone — and lets you unblock it from there.**

Non-goals:

- Not a full remote Claude Code client. You are not driving sessions from the phone.
- Not a security product. The policy engine reduces noise; it is not a sandbox and must never be described as one.
- Not cross-platform initially. macOS host, iOS phone.

---

## Why not terminal monitoring

The original instinct — install something into the terminal that watches output — is the wrong layer:

- Claude Code renders a TUI with ANSI escapes, spinners, and full-line redraws. Extracting semantic state from that byte stream means parsing a moving target.
- Prompt wording changes between releases. Any regex you write is a silent time bomb.
- VS Code's terminal data API is proposed/unstable and not available to published extensions.
- Even on a successful parse, you have text — not the structured tool name and tool input you need to summarize or gate.

Claude Code emits structured lifecycle events for exactly this purpose. A hook is a command (or HTTP endpoint) that receives JSON describing the event and signals back through exit codes or stdout JSON. That is the correct integration surface.

Two properties make it more than an observer:

1. `PreToolUse` returns `hookSpecificOutput.permissionDecision` of `allow` / `deny` / `ask`. There is also a `defer` decision that leaves the pending tool call preserved in the transcript and exits with a `tool_deferred` stop reason, so an external process can surface the question in its own UI and answer it on resume.
2. A hook returning `deny` blocks the tool **even under `--dangerously-skip-permissions`**. Bypass mode disables interactive prompts; it does not disable hooks.

So preymax does not watch a permission prompt. **preymax becomes the permission prompt.**

> The hook event set is actively expanding. Treat the official hooks reference as canonical and re-verify event names and payload shapes at the start of the build. Do not build on remembered API shapes.

---

## Architecture

```
┌─ VS Code ─────────────────────────────┐
│  terminal "api"    terminal "web"     │
│    $ claude          $ claude         │
│       │                  │            │
└───────┼──────────────────┼────────────┘
        │  PreToolUse hook │
        │  (HTTP POST)     │
        ▼                  ▼
   ┌────────────────────────────────┐
   │  preymaxd  (127.0.0.1 + tailnet)│
   │                                 │
   │  1. resolve session identity    │
   │  2. policy engine               │
   │       auto_allow → return allow │
   │       auto_deny  → return deny  │
   │       escalate   → continue     │
   │  3. redact                      │
   │  4. template summary (instant)  │
   │  5. Haiku summary (async, ≤800ms)│
   │  6. push notification           │
   │  7. block on pending decision   │
   │       timeout → return "ask"    │
   └───────┬─────────────────▲───────┘
           │ push            │ signed approval
           ▼                 │
    ┌──────────────────────────────┐
    │  iPhone: ntfy / Pushcut      │
    │  → Shortcuts → Speak Text    │
    │  → action buttons            │
    └──────────────────────────────┘
```

### Components

| Component | Responsibility |
|---|---|
| `preymaxd` | Long-lived HTTP server. Receives hook events, applies policy, holds pending-decision state, brokers approvals. Managed by `launchd`. |
| `preymax init` | Registers hooks in `~/.claude/settings.json`, allowlists env vars, installs the launchd plist, backs up prior config. |
| `preymax tail` | Live event stream, pretty-printed. Primary debugging surface. |
| `preymax pending` / `approve` / `deny` | Local escape hatch when the phone path fails. Non-optional. |
| `preymax stats` | Escalation rate, per-terminal volume, latency percentiles. |
| `preymax doctor` | Verifies hook registration, daemon health, tailnet reachability, push delivery. |

### Distribution

Shipped as an npm package, but note the mental model: it is **not** a per-terminal dependency. It is one global install plus a settings registration plus a background daemon. Documentation should say this explicitly, because the "add it to each terminal" intuition is common and wrong.

---

## Phase 0 — Kill gate

**Goal:** disprove the reason not to build this, before writing code.

### Work

- Install Happy Coder. Run two Claude Code sessions. Trigger permission prompts. Approve from the phone.
- Write down precisely what is unsatisfying. Latency? No per-session naming? Raw command text instead of a summary? No audio? No policy layer?
- Re-read the current hooks reference end to end. Determine which event carries the payload you want — `PreToolUse`, `PermissionRequest`, or `Notification` — and whether HTTP-transport hooks are stable enough to depend on.
- Sketch the notification format on paper. If you can't write a notification you'd act on without opening the laptop, the product doesn't exist yet.

### Exit criteria

- A written five-line diff between what Happy already does and what preymax will do.
- A named target hook event with its confirmed payload schema.
- A decision recorded: standalone repo, or a SessionLint module.

### Stop condition

If the five-line diff can't be written, build this as a SessionLint live module and stop here. That is a successful outcome, not a failure.

---

## Phase 1 — Capture

**Goal:** prove every permission event can be observed, structured and correctly attributed, across multiple named terminals — with zero behavior change.

### Work

- `preymaxd`: single endpoint `POST /hook` on `127.0.0.1:7717`. Logs raw JSON to a rotating JSONL file. Returns `permissionDecision: "ask"` unconditionally — pure passthrough.
- `preymax init`: writes the hooks block, backs up `~/.claude/settings.json` first, and is idempotent (re-running does not duplicate entries).
- Session identity resolver, in priority order:
  1. `PREYMAX_NAME` environment variable
  2. `basename(cwd)` + current git branch
  3. `session_id[:6]`
- Allowlist `PREYMAX_NAME` in `allowedEnvVars`. **Any `$VAR` not in the allowlist resolves to an empty string — silently, no warning, no error.** This will cost hours if missed.
- `preymax tail` with per-terminal colorization.
- launchd plist with `KeepAlive`, restart-on-crash, and log redirection.
- VS Code terminal profiles in `.vscode/settings.json` so naming is declarative per project rather than retyped per terminal.

### Exit criteria

- Three terminals named `api`, `web`, `infra`. Every Bash / Write / Edit event appears in `preymax tail` with correct attribution.
- Claude Code behaves identically to a no-hook install — no added latency perceptible, no changed prompts.
- Daemon survives a crash, a logout, and a reboot.

### Risks

- **HTTP hooks unavailable or flaky.** Fallback: a thin `preymax hook` shell shim that POSTs to the daemon. Budget for this discovery; the shim adds per-event process spawn cost, so measure it.
- **Hook latency budget.** A gate hook must be fast. Establish the ceiling here and treat it as a hard constraint for every later phase.

---

## Phase 2 — Policy engine

**Goal:** cut escalation volume by roughly an order of magnitude before a single notification exists. This phase is what determines whether the product is livable.

### Work

- `~/.preymax/policy.yaml` with three buckets:

```yaml
auto_allow:
  - tool: Bash
    command_matches: ['^git (status|diff|log|branch)', '^npm (test|run lint)', '^ls ', '^cat ']
  - tool: [Read, Glob, Grep]

auto_deny:
  - tool: Bash
    command_matches: ['\brm\b.*-rf', 'git\s+push.*--force.*\b(main|master)\b', '>\s*\.env', '--no-verify']
    reason: "destructive pattern — blocked by preymax policy"

escalate:
  - default: true
```

- Rule engine reusing SessionLint's matcher shape and test harness. Same rule format, same fixtures, same snapshot tests.
- `preymax stats`: escalations per hour, per terminal, per tool, and the top-10 escalating commands.
- Per-session temporary grants: an in-memory allow for a pattern with a TTL.

### Design principle

**Push everything you can into Claude Code's native `permissions.allow` so it never reaches preymax at all.** The policy engine should handle only the genuinely ambiguous middle. If preymax is deciding on `Read` calls, the configuration is wrong.

### Exit criteria

- A full normal working day logged.
- Escalation rate under roughly eight per hour.
- Zero false auto-denies (a legitimate command blocked) across that day.
- Rule set has test coverage in the SessionLint harness.

### Stop condition

If the escalation rate is forty per hour after tuning, the notification product is dead on arrival. Fix the policy layer or reconsider the concept. Do not proceed to Phase 3 and hope the notifications feel fine — they will not.

---

## Phase 3 — Notify

**Goal:** learn that a terminal is blocked, and which one, without looking at the screen. Approval still happens at the Mac.

### Work

- Push transport: ntfy (start with `ntfy.sh` and a high-entropy topic name; self-host later) or Pushcut. Evaluate both on delivery latency and action-button support, since Phase 5 depends on the latter.
- Notification format — **terminal name in the first three words**, because you will read this from a lock screen at a glance:

```
[api] run: npx prisma migrate reset
[infra] write: terraform/prod/main.tf
```

- Template-based descriptions only. No LLM in this phase.
- Coalescing: a short burst window so six rapid events become one grouped notification.
- Deduplication by `(session, tool, normalized_input)` hash.
- Distinct notification sound and high-priority delivery.

### Exit criteria

- Live with it unmodified for a full week of real work.
- Maintain a log of every notification you **ignored** and why. That log is the literal specification for Phase 4.
- Measure: did you stop polling terminals? If you still tab through them out of habit, the notification isn't trusted yet — find out why before adding more machinery.

---

## Phase 4 — Summarize

**Goal:** notifications become human-readable rather than command-readable.

### Work — in this order

1. **Redaction layer first.** Strip `.env` file contents, key-shaped strings, tokens, absolute home paths, and anything matching secret heuristics. Unit-test this thoroughly **before any outbound call is wired up.** Tool inputs routinely contain credentials and customer data.
2. Anthropic API call using Haiku for latency. System prompt pinned tight: *one sentence, under twenty words, written to be spoken aloud, no jargon, name the risk if there is one.*
3. **Never block on the API.** Emit the template notification immediately; if the model returns within the latency budget, replace the notification body in place. The API sits beside the critical path, never inside it.
4. Cache by hash of `(tool_name, normalized_input)`. You run the same commands constantly and should pay for each summary once.
5. Graceful degradation: API down, rate-limited, or slow → template summary, no user-visible error, log the miss.

### Exit criteria

- Added p95 latency under one second versus Phase 3.
- Zero secrets in outbound payloads, verified by inspecting an intercepting proxy log across a full day — not by reading the redaction code.
- Subjective test: you can decide approve-or-deny from the phone alone, without opening the laptop, for the large majority of escalations.

---

## Phase 5 — Approve remotely

**Goal:** close the loop. This phase carries the real security stakes. Move deliberately.

### Work

- **Network binding:** loopback plus the Tailscale interface only. Never `0.0.0.0`. Assert this at daemon startup and refuse to start otherwise.
- **Payload authentication:** HMAC-signed approvals with a shared secret, a single-use nonce per pending request, and a short TTL. An unsigned, replayed, or expired approval is rejected and logged loudly.
- **Blocking semantics:** the hook waits on the pending decision with a hard timeout. On timeout, return `ask` — **never** `allow`. The normal terminal prompt then appears and nothing is bypassed by failure. This is the single most important line of code in the project.
- **Action buttons:** Allow · Deny · Allow-this-pattern-for-30-minutes.
- **Local escape hatch:** `preymax pending` and `preymax approve <id>` must work even when the phone, the tailnet, and the push service are all unavailable.
- Pending-request state survives a daemon restart, or fails closed if it cannot.

### Red-team pass — write the results down

Each of these must fail safe:

| Attack / failure | Required behavior |
|---|---|
| Replay a captured approval webhook | Rejected — nonce consumed |
| Approval with a stale or expired nonce | Rejected |
| Daemon killed mid-decision | Hook times out, returns `ask`, terminal prompts normally |
| Tailscale drops mid-decision | Same — timeout to `ask` |
| Unsigned approval POST | Rejected and logged |
| Two approvals for the same pending ID | Second is a no-op |
| Push service delivers a duplicate | Idempotent — one decision only |

### Exit criteria

- All seven rows pass, with the test procedure and results committed to the repo.
- Do not publish this phase — not to npm, not to GitHub — until that document exists. A tool that lets a phone notification authorize a shell command needs its threat model written down before anyone else installs it.

---

## Phase 6 — Voice

Last, deliberately. It is the flashiest part and the most likely to disappoint.

### Work

- iOS Shortcuts personal automation triggered on notification receipt → `Speak Text` action.
- Alternatively Pushcut's speak action, which has the same underlying constraint.
- Tune the summary prompt separately for spoken output — spoken text wants different phrasing than read text.

### The honest constraint — document it prominently

An iPhone will not reliably speak aloud when locked and on silent. Reliable audio requires one of:

- AirPods connected (Announce Notifications)
- CarPlay
- Phone unlocked and not silenced

**Design the baseline as a rich notification with a distinct sound and haptic. Treat speech as the AirPods-connected upgrade.** If the real scenario is "across the room with AirPods in," this works well. If it is "phone in pocket on silent," it does not, and the README should say so rather than let users discover it.

### Exit criteria

- The actual target scenario tested end to end: you away from the desk, AirPods in, three sessions running, one blocks, you hear it, you approve, work resumes.

---

## Cross-cutting concerns

### Notification fatigue is the primary failure mode

More than any technical risk, this is what kills the tool. Every phase should be evaluated against escalations-per-hour. If that number rises, the feature was a mistake regardless of how well it works.

### Concurrency is the normal case

Two or more terminals blocked simultaneously is the expected state, not an edge case. Every notification needs a distinct pending ID, the terminal name up front, and an approval path that cannot cross-wire two requests.

### Fail-safe, always

Every failure mode in the system resolves to "the terminal prompts normally, as if preymax were not installed." Nothing about a failure should ever result in an auto-approval.

### Host availability

The daemon runs under `launchd` with restart-on-crash. To keep the Mac responsive while idle, run `caffeinate -dis` from the launchd job, and account for Power Nap behavior. Document the power cost honestly.

### Observability

Structured JSONL logs from the start, in a shape SessionLint can already parse. Every escalation records: session, tool, decision, decision source (policy / phone / timeout / local CLI), and end-to-end latency.

### Sequencing

**Phases 1–3 are the product. Phases 4–6 are amplifiers.** If the build stops after Phase 3, the result is still useful. There are two hard gates — Phase 0 and Phase 2 — and both are cheap. Either one can save weeks.

---

## Open questions

- Standalone repo, or `sessionlint live`? Shared rule engine, shared session-identity resolution, shared JSONL parsing all argue for merging. The main argument against is that `preymax` is the better name.
- ntfy versus Pushcut: decide on action-button ergonomics and delivery latency, not on price.
- Should the policy engine's `auto_deny` bucket exist at all, or does it overlap confusingly with Claude Code's native `permissions.deny`? Risk of two sources of truth.
- Does the `defer` decision offer a better model than blocking the hook? It preserves the pending call in the transcript rather than holding a process open — worth prototyping against the blocking approach in Phase 5.
- Multi-machine: one phone, several Macs. Out of scope initially, but the session identity scheme should not preclude it.

---

## Relationship to SessionLint

SessionLint audits Claude Code session transcripts after the fact. preymax operates on the same events as they happen. They share:

- Session identity resolution
- Rule engine and matcher format
- JSONL event schema and parsing
- Test fixture generation

The clean framing: **SessionLint is the post-hoc auditor, preymax is the live gate.** Whether that is one package with two entry points or two packages sharing a core library is a packaging decision, not an architectural one — and it should be settled in Phase 0, not discovered in Phase 4.