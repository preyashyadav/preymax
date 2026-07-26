# preymax threat model

preymax lets a notification tapped on a phone authorize a shell command on a
Mac. That deserves a written threat model before anyone else installs it.

**Status: this document must exist and its table must pass before Phase 5 is
published to npm or GitHub.** That is a gate from the plan, and it is why this
file is in the repo rather than in someone's notes.

---

## What preymax is not

- **Not a sandbox.** The policy engine's `auto_deny` bucket is a regex filter.
  It stops the obvious footguns; it does not stop a determined command. `rm -rf`
  is caught, `python -c "import shutil; shutil.rmtree('/')"` is not.
- **Not a security boundary.** Real guarantees belong in Claude Code's native
  `permissions.deny`, which preymax does not replace. Anything preymax denies,
  a differently-spelled command can evade.
- **Not an audit log you can rely on for forensics.** `events.jsonl` is a
  best-effort operational log. Write failures are swallowed on purpose, because
  the alternative is crashing on the permission-gate path.

What it *is*: a noise filter and a remote unblock button, whose every failure
mode degrades to stock Claude Code behavior.

---

## Trust boundaries

| Boundary | Trusted? | Notes |
|---|---|---|
| The Mac's local user account | Yes | Anyone with it can read `config.json` and forge approvals. preymax adds no protection here and does not claim to. |
| Loopback (`127.0.0.1`) | Partially | Any local process can reach `/hook` and `/pending`. Deciding still requires the HMAC secret, which is mode `0600`. |
| The tailnet | Partially | Every device on your tailnet can reach the daemon. Approvals still require the secret. Tailscale ACLs are the outer fence. |
| The public internet | No | The daemon never binds a public address. Asserted at startup; see `assertSafeBind`. |
| ntfy.sh | No | Treated as a hostile broadcast channel. It sees redacted summaries; it never sees the secret, and it cannot mint an approval. |
| The Anthropic API | No | Sees redacted tool inputs only. |

### What an attacker gets from each compromise

- **The ntfy topic**: they can read your notification summaries (redacted tool
  inputs — real information leakage) and can replay a captured action-button
  payload. Replay is defeated by the single-use nonce and the 5-minute TTL, so
  the practical loss is confidentiality, not authorization.
- **The tailnet, without the secret**: they can enumerate pending requests via
  `/pending` and observe the event stream. They cannot approve anything.
- **`config.json`**: full compromise. They can mint approvals at will. This is
  why the file is `0600` and why `preymax doctor` checks its mode.

---

## Red-team pass

Each row must fail safe. Every row is covered by an executable test; the test
file and case name are cited so the claim is checkable rather than asserted.

| # | Attack / failure | Required behavior | Result | Evidence |
|---|---|---|---|---|
| 1 | Replay a captured approval webhook | Rejected — nonce consumed | **PASS** | `security.test.ts` › "rejects a replayed nonce" |
| 2 | Approval with a stale or expired nonce | Rejected | **PASS** | `security.test.ts` › "rejects an expired approval", "rejects a decision after the request expired" |
| 3 | Daemon killed mid-decision | Hook times out, returns `ask`, terminal prompts normally | **PASS** | `security.test.ts` › "resolves to ask on shutdown, never allow"; `pending.ts` `releaseAll()` |
| 4 | Tailscale drops mid-decision | Same — timeout to `ask` | **PASS** | `integration.test.ts` › "escalates an unmatched command and falls through to ask on timeout" |
| 5 | Unsigned approval POST | Rejected and logged loudly | **PASS** | `integration.test.ts` › "rejects an unsigned approval with 401 and does not decide"; logged in `handleApprove` |
| 6 | Two approvals for the same pending ID | Second is a no-op | **PASS** | `security.test.ts` › "is idempotent…", "a later deny cannot override an allow…" |
| 7 | Push service delivers a duplicate | Idempotent — one decision only | **PASS** | Same as row 6: duplicate delivery is indistinguishable from a double-tap, and both are absorbed by `decide()`. |

### Additional cases tested beyond the required seven

| Attack | Required behavior | Result | Evidence |
|---|---|---|---|
| Approval signed with a different secret | Rejected | **PASS** | `integration.test.ts` › "rejects an approval signed with the wrong secret" |
| Flip `deny` → `allow` without re-signing | Rejected | **PASS** | `security.test.ts` › "rejects a flipped decision" |
| Swap the pending id onto a valid signature | Rejected | **PASS** | `security.test.ts` › "rejects a swapped pending id" |
| Smuggle `grant: true` onto an approval | Rejected | **PASS** | `security.test.ts` › "rejects a smuggled grant flag" |
| Backdate/postdate the timestamp | Rejected | **PASS** | `security.test.ts` › "rejects a timestamp from the future" |
| Malformed / non-object approval body | Rejected, no throw | **PASS** | `security.test.ts` › "rejects malformed payloads without throwing" |
| Malformed hook body | Returns `ask`, never `allow` | **PASS** | `integration.test.ts` › "returns ask (never allow) for a malformed hook body" |
| Daemon asked to bind `0.0.0.0` / LAN / public | Refuses to start | **PASS** | `security.test.ts` › "network binding" (6 cases) |
| Pending requests left by a dead daemon | Expired, not revived | **PASS** | `security.test.ts` › "expires rather than revives pending requests left by a dead daemon" |
| Secret-bearing file written (`.env`) | Body never transmitted | **PASS** | `redact.test.ts` › "withholds the body when writing a .env file" |
| `Authorization: Bearer <token>` in a command | Token redacted, not just the scheme | **PASS** | `redact.test.ts` › "redacts an Authorization header token…" (this case caught a real leak during development) |

### Reproducing

```
npm test
```

151 tests, 21 suites. The rows above are a subset; the suite also covers policy
precedence, hook-registration idempotency, and identity fallback.

---

## The single most important line of code

In `src/daemon/pending.ts`:

```ts
this.finalize(id, 'ask', 'timeout');
resolve({ decision: 'ask', source: 'timeout', ... });
```

On timeout the result is `ask` — never `allow`. Every other failure path in the
system routes here or to `releaseAll()`, which does the same thing. There is no
code path in preymax that returns `allow` without either a policy match, a live
grant, or a valid HMAC signature.

A related subtlety, worth stating because it was a real bug: this timer must not
be `unref()`d. An unref'd timer can be skipped when the event loop drains,
leaving the promise dangling and the hook without any response at all.

---

## Failure modes and their outcomes

| Failure | Outcome |
|---|---|
| Daemon not running | Claude Code treats a connection failure to an `http` hook as a **non-blocking error** and proceeds with the normal permission flow. Verified against the hooks reference. |
| Daemon hangs | Hook's own `timeout` (120s, set by `preymax init`) fires; non-blocking error; normal flow. |
| ntfy down or slow | Notification is skipped or fails; the escalation still exists and `preymax approve` still resolves it. Push is never awaited on the decision path. |
| Anthropic API down, slow, or rate-limited | Model summary loses its 800ms race; the template summary ships. No user-visible error. |
| Policy file corrupt | `loadPolicy()` throws at load; the daemon refuses to start with a message. A malformed regex is caught at parse time rather than silently never matching. |
| `pending.json` unwritable | Daemon operates in memory. A restart then loses pending state — the fail-closed direction. |
| Clock skew on the phone | Approvals more than 60s in the future are rejected; more than the TTL in the past are rejected. |

---

## Unresolved: `defer`

The hooks reference lists a fourth `permissionDecision` value, `defer`, but the
section describing its semantics was truncated in the copy retrieved on
2026-07-25. The plan assumed `defer` preserves the pending tool call in the
transcript and exits with a `tool_deferred` stop reason; the one-line
description actually retrieved says only "let the normal permission flow apply",
which is a materially different behavior.

**preymax never emits `defer`.** Until the semantics are confirmed against a
live Claude Code build, the blocking approach is what ships. If `defer` does
preserve the pending call, it is strictly better than holding a hook open for 60
seconds and should be prototyped — that is the open question the plan flags for
Phase 5, and it remains open.

---

## Known weaknesses, stated plainly

1. **The ntfy topic is a bearer secret with no rotation story.** Anyone who
   learns it reads your notifications forever. Rotating it means editing
   `config.json` and re-subscribing on the phone. There is no revocation.
2. **Redaction is heuristic.** It is written to over-redact and it is tested,
   but it is pattern matching. The plan's exit criterion — inspect an
   intercepting proxy log for a full day — has **not** been performed. Do that
   before trusting it with a customer-data-bearing repo.
3. **A tailnet device can enumerate pending requests.** `/pending` and
   `/health` require no authentication. They expose summaries, not secrets, but
   that is still information disclosure to every device on your tailnet.
4. **No rate limiting on `/approve`.** An attacker on the tailnet can brute
   force signatures. At HMAC-SHA256 with a 256-bit secret this is not a
   practical attack, but there is no lockout and failures are only logged.
5. **`caffeinate -dis` keeps the Mac awake.** This is a real battery cost, and
   it is on by default. See the README.
