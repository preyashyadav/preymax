# preymax

**Named, voice-summarized permission triage for parallel Claude Code sessions.**

Package: `preymax` · CLI: `preymax` · Daemon: `preymaxd` (via `preymax daemon`) · Platform: macOS + iOS

---

Running several Claude Code sessions in parallel VS Code terminals means each
one silently blocks on a permission prompt at an unpredictable moment. The cost
is not the approval — it's the polling. You tab across terminals looking for
which one stopped, and you lose the thread on what you were actually doing.

preymax makes the blocked terminal announce itself, by name, in plain language,
on your phone — and lets you unblock it from there.

```
[api] run: npx prisma migrate reset
[infra] write: terraform/prod/main.tf
```

## How it works

preymax does not watch the terminal. Claude Code emits structured lifecycle
events, and a `PreToolUse` hook can return `allow` / `deny` / `ask`. **preymax
becomes the permission prompt** rather than observing one.

```
VS Code terminals "api" "web" "infra"
        │  PreToolUse hook (HTTP POST)
        ▼
   preymaxd  (127.0.0.1 + tailnet only)
     1. resolve session identity
     2. policy engine → allow / deny / escalate
     3. redact
     4. summarize (template, or Haiku within an 800ms budget)
     5. push notification
     6. block on the pending decision
          timeout → return "ask"
        │ push              ▲ signed approval
        ▼                   │
   iPhone: ntfy → action buttons
```

## Install

```sh
npm install          # from a clone; not yet published
npm run build
node dist/cli.js init
```

`preymax init` is idempotent. It:

- writes `~/.preymax/config.json` (mode `0600`) with a generated HMAC secret and
  a 128-bit ntfy topic — both preserved on re-run
- writes a default `~/.preymax/policy.yaml` (never overwrites a tuned one)
- **backs up** `~/.claude/settings.json`, then registers the `PreToolUse` hook
- installs and loads a launchd agent

Then:

```sh
preymax doctor        # verify hooks, daemon, tailnet, summaries
preymax doctor --push # also send a real test notification
preymax tail          # live, colorized event stream
```

## Naming your terminals

The whole product depends on knowing which terminal is which. Set `PREYMAX_NAME`
per VS Code terminal profile — declarative per project, rather than retyped per
terminal. See [`docs/vscode.md`](docs/vscode.md).

**The trap that will cost you hours:** Claude Code only interpolates `$VAR` into
hook *header* values, and only for variables listed in `allowedEnvVars`. A
variable that is not allowlisted resolves to an **empty string** — silently, no
warning, no error. `preymax init` writes the allowlist for you, and
`preymax doctor` checks it.

Without a name, preymax falls back to `basename(cwd)` + git branch, then to
`session_id[:6]`.

## Commands

| Command | What it does |
|---|---|
| `preymax init` | Register hooks, generate secrets, install the launch agent |
| `preymax daemon` | Run in the foreground (launchd normally does this) |
| `preymax tail` | Live event stream, colorized per terminal |
| `preymax pending` | List escalations awaiting a decision |
| `preymax approve <id> [--grant]` | Allow; `--grant` also allows the pattern for 30m |
| `preymax deny <id>` | Deny |
| `preymax grants` | List active temporary grants |
| `preymax stats [--hours N]` | Escalation rate, per-terminal volume, latency percentiles |
| `preymax doctor [--push]` | Verify the whole path end to end |

`preymax pending` / `approve` / `deny` are the **local escape hatch** and work
when the phone, the tailnet, and ntfy are all unavailable. That is not optional.

## It is one global install, not a per-terminal dependency

This is the most common wrong mental model. preymax is **one** npm install, one
settings registration, and one background daemon. You do not add it to each
terminal, each project, or each session. Naming terminals is configuration, not
installation.

## Tuning the escalation rate

This number decides whether the tool is livable. The plan's gate: **under ~8
escalations/hour**. At 40/hour the notification product is dead on arrival.

```sh
preymax stats --hours 24
```

The output ends with the top-10 escalating calls. Each one is a candidate rule
for `~/.preymax/policy.yaml`.

**Push everything you can into Claude Code's native `permissions.allow` so it
never reaches preymax at all.** The policy engine should only handle the
genuinely ambiguous middle. If preymax is deciding on `Read` calls, the
configuration is wrong.

## Phone approval

Action buttons need a URL your phone can reach:

```sh
preymax init --public-url https://<your-mac>.<your-tailnet>.ts.net:7717
```

Until you set this, notifications are **read-only** — you still learn which
terminal stopped and why, and you approve at the Mac. The daemon binds loopback
and the Tailscale interface only, and refuses to start if a configured address
is anything else.

Approvals are HMAC-signed with a single-use nonce and a 5-minute TTL. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## Voice — read this before you expect it to talk

Speech is the AirPods-connected upgrade, not the baseline.

**An iPhone will not reliably speak notifications aloud when locked and on
silent.** Reliable audio requires one of: AirPods connected with Announce
Notifications, CarPlay, or the phone unlocked and not silenced.

The baseline preymax ships is a rich notification with a distinct sound and
haptic. If your scenario is "across the room with AirPods in," this works well.
If it is "phone in pocket on silent," it does not. Setup:
[`docs/ios-shortcuts.md`](docs/ios-shortcuts.md).

## Honest costs

- **Battery.** The launch agent runs under `caffeinate -dis` so the Mac stays
  reachable — no display sleep, no idle sleep, no system sleep while the daemon
  runs. On battery this is significant. Set `"caffeinate": false` in
  `config.json` and re-run `preymax init` to disable it; the daemon then becomes
  unreachable when the Mac sleeps, and hooks fall through to normal prompts.
- **Tokens.** Summaries use Claude Haiku 4.5 ($1/$5 per MTok) with a
  fingerprint cache, so a repeated command is paid for once. Roughly 200 input
  and 30 output tokens per unique escalation. Set `summarize.enabled: false` for
  template-only summaries and zero cost.
- **Latency.** The model call is capped at `summaryBudgetMs` (800ms) and races
  the template. A cache hit is instant.
- **Privacy.** Redacted tool inputs go to ntfy and to the Anthropic API. On
  public ntfy.sh, **the topic name is the only access control** — anyone who
  knows it reads your notifications.

## What preymax is not

- **Not a sandbox, and not a security product.** The policy engine reduces
  noise. `auto_deny` is a regex filter that stops obvious footguns and nothing
  more. Real guarantees belong in Claude Code's native `permissions.deny`.
- **Not a remote Claude Code client.** You are not driving sessions from the
  phone; you are unblocking them.
- **Not cross-platform.** macOS host, iOS phone.

## Fail-safe, always

Every failure mode resolves to "the terminal prompts normally, as if preymax
were not installed":

| Failure | Outcome |
|---|---|
| Daemon not running | Connection failure is a non-blocking hook error → normal flow |
| Nobody answers in 60s | Returns `ask` → normal prompt |
| Daemon killed mid-decision | Waiters released as `ask` |
| ntfy or tailnet down | Escalation still resolvable via `preymax approve` |
| Anthropic API down | Template summary ships, no user-visible error |

**Nothing about a failure ever results in an auto-approval.** There is no code
path that returns `allow` without a policy match, a live grant, or a valid
signature.

## Development

```sh
npm run typecheck
npm test        # 151 tests, 21 suites
```

## Status against the plan

| Phase | State |
|---|---|
| 0 — Kill gate | **Not done.** Requires installing Happy Coder and writing the five-line diff. See below. |
| 1 — Capture | Built |
| 2 — Policy engine | Built; the exit criterion is a full day of real logs |
| 3 — Notify | Built; the exit criterion is a week of real use |
| 4 — Summarize | Built; the exit criterion is a proxy-log inspection |
| 5 — Approve remotely | Built; red-team table passes in tests |
| 6 — Voice | Documented, not verified on a physical device |

Phases 1–5 are code and are tested. The remaining exit criteria are all
*empirical* — they require you, a phone, and real working days. No amount of
implementation substitutes for them, and the two hard gates (Phase 0 and
Phase 2) are the ones that can still kill this.
