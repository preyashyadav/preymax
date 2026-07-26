# Naming terminals in VS Code

preymax's whole value is that a notification says `[api]` and not
`[sess-8f3c…]`. Names come from the `PREYMAX_NAME` environment variable, set per
terminal profile so naming is declarative per project rather than retyped per
terminal.

## Per-project profiles

In your project's `.vscode/settings.json`:

```jsonc
{
  "terminal.integrated.profiles.osx": {
    "api": {
      "path": "/bin/zsh",
      "args": ["-l"],
      "env": { "PREYMAX_NAME": "api" },
      "icon": "server",
      "color": "terminal.ansiCyan"
    },
    "web": {
      "path": "/bin/zsh",
      "args": ["-l"],
      "env": { "PREYMAX_NAME": "web" },
      "icon": "browser",
      "color": "terminal.ansiGreen"
    },
    "infra": {
      "path": "/bin/zsh",
      "args": ["-l"],
      "env": { "PREYMAX_NAME": "infra" },
      "icon": "cloud",
      "color": "terminal.ansiYellow"
    }
  }
}
```

Open a named terminal with the dropdown next to the `+` in the terminal panel,
or bind **Terminal: Create New Terminal (With Profile)** to a key.

The `color` and `icon` are not decoration — matching the VS Code tab colour to
`preymax tail`'s output makes three sessions genuinely easier to keep apart.

## Ad hoc

```sh
PREYMAX_NAME=migration claude
```

## The allowlist trap

Claude Code interpolates `$VAR` into hook **header values** only, and only for
variables named in `allowedEnvVars`. A variable that is not allowlisted resolves
to an **empty string** — silently, with no warning and no error.

`preymax init` writes this for you:

```jsonc
{
  "type": "http",
  "url": "http://127.0.0.1:7717/hook",
  "timeout": 120,
  "headers": { "X-Preymax-Name": "$PREYMAX_NAME" },
  "allowedEnvVars": ["PREYMAX_NAME"]   // <- without this line, the header is ""
}
```

Verify with:

```sh
preymax doctor
```

It checks the allowlist explicitly and tells you when the name is silently
empty.

## Fallback naming

With no `PREYMAX_NAME`, preymax resolves, in order:

1. `PREYMAX_NAME` (the header)
2. `basename(cwd)` + git branch — e.g. `preymax:main`
3. `session_id[:6]` — e.g. `8f3c1a`

(2) is good enough that you can skip profiles entirely when one project means
one terminal. Profiles matter when several terminals share a working directory.

## Checking it worked

```sh
preymax tail
```

Run something trivial in each terminal. Every event should carry the right name,
in its own colour. If two terminals show the same name, they share a `cwd` and
neither has `PREYMAX_NAME` set.
