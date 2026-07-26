# iOS setup: notifications, action buttons, and speech

## Read this first

**An iPhone will not reliably speak notifications aloud when it is locked and on
silent.** This is an iOS behavior, not a preymax limitation, and no amount of
configuration works around it.

Reliable spoken audio requires one of:

- **AirPods (or compatible headphones) connected**, with Announce Notifications
  enabled — the reliable path
- **CarPlay**, with Announce Notifications enabled
- **The phone unlocked and not silenced**

Design your expectations accordingly:

| Scenario | Works? |
|---|---|
| Across the room, AirPods in | Yes — this is the target scenario |
| At the desk, phone face up, not silenced | Yes |
| Phone in pocket, on silent, locked | **No speech.** You get the haptic and the sound only. |
| Phone in another room, on silent | No |

The baseline preymax ships is a rich notification with a distinct sound and a
haptic. Treat speech as the AirPods-connected upgrade.

---

## 1. Subscribe to your topic

Install [ntfy](https://ntfy.sh) from the App Store. Subscribe to the topic
printed by `preymax init` (also in `~/.preymax/config.json`).

> On public ntfy.sh, **the topic name is the access control**. Anyone who knows
> it can read every notification preymax sends. It is generated with 128 bits of
> entropy for this reason. Self-host or use an access-token-protected topic if
> that isn't good enough.

Verify delivery end to end:

```sh
preymax doctor --push
```

## 2. Make it cut through

In **iOS Settings → Notifications → ntfy**:

- Allow Notifications: on
- Lock Screen, Notification Centre, Banners: on
- Sounds: on
- **Time Sensitive Notifications: on** — this is what gets through a Focus mode
- Banner Style: Persistent

In the **ntfy app**, per subscription: set a distinct sound. A sound you use for
nothing else is worth more than any wording you put in the message — you want to
know it's preymax before you look.

## 3. Action buttons

Buttons appear when preymax knows a URL your phone can reach:

```sh
preymax init --public-url https://<your-mac>.<your-tailnet>.ts.net:7717
```

Each escalation then carries **Allow**, **Deny**, and **Allow 30m**. Long-press
(or pull down on) the notification to reveal them.

Each button POSTs an HMAC-signed, single-use, 5-minute-TTL approval directly to
your Mac over the tailnet. ntfy relays the notification; it never holds the
secret and cannot mint an approval.

If the buttons do nothing:

- Is Tailscale connected on **both** the phone and the Mac?
- Does `preymax doctor` report the tailnet bound?
- Is `publicBaseUrl` reachable from the phone's browser? Try loading
  `https://<mac>.<tailnet>.ts.net:7717/health`.

## 4. Speech (optional)

### Option A — Announce Notifications (simplest, recommended)

**Settings → Notifications → Announce Notifications** → on, and enable it for
ntfy. With AirPods connected, Siri reads the notification aloud. Nothing to
build.

This reads the title and body as written, which is why the summariser is
prompted for spoken phrasing — "force push to main" rather than
`git push --force main`.

### Option B — Shortcuts automation (more control)

**Shortcuts → Automation → New → App → ntfy → Is Opened**, or use a Personal
Automation triggered on notification receipt where your iOS version supports it.

Add a **Speak Text** action. Set rate and pitch to taste. Turn **Wait Until
Finished** on so overlapping escalations don't talk over each other.

Option B's real advantage is filtering — you can speak only escalations from
`[infra]`, and let the rest buzz silently.

### Tuning the wording

Spoken text wants different phrasing from read text. The system prompt in
`src/core/summarize.ts` already asks for it:

> One sentence. Under twenty words. Written to be spoken aloud. Expand symbols.
> Name the risk if there is one.

If summaries sound wrong through headphones, edit that prompt — it is the single
place spoken phrasing is controlled.

## 5. The end-to-end test that matters

The plan's Phase 6 exit criterion, and the only one that counts:

> You, away from the desk, AirPods in, three sessions running. One blocks. You
> hear it, you approve it from the phone, work resumes.

Run that literally before believing any of the above. Everything upstream can be
green while this still fails on a detail no configuration file predicts.
