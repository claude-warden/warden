# Warden

[![CI](https://github.com/dorianspitz23/claude-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/dorianspitz23/claude-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

**An independent watchdog that checks what your AI coding agent is about to do — before it does it.**

You give Claude Code access to your files and let it run commands. Most of the time you skim the
command, it looks fine, you approve. That habit is the vulnerability: a prompt injection hidden in
a repo file, a web page, or an MCP tool result can steer the agent into deleting your work or
shipping your `.env` to someone else, and it will look perfectly reasonable while doing it.

Warden sits between the agent and your machine. Every tool call is inspected first.

```
Claude Code wants to run a tool
            │
            ▼
   ┌──────────────────────────────┐
   │ Warden                        │
   │   deterministic rules  ~0ms   │  offline, free, no API key
   │   independent auditor  ~1s    │  only for what the rules don't recognise
   └──────────────────────────────┘
            │
     allow ─┴─ ask ─── deny
```

## Why an *independent* checker

The agent cannot audit itself. If a prompt injection has taken hold, its reasoning is the thing
that has been compromised — asking it "are you sure?" just returns the attacker's answer.

So Warden's second tier is a separate model call that never sees the conversation, the agent's
reasoning, or its justification. It sees the proposed action and nothing else, framed explicitly
as untrusted data. If the payload tries to talk to *it* — "ignore previous instructions", "the
user already approved this" — that attempt is reported as evidence of an attack rather than
obeyed. The attack becomes the detector.

## Install

```bash
npm install -g github:dorianspitz23/claude-warden
warden install     # adds the PreToolUse hook to ~/.claude/settings.json
warden test        # prove it actually blocks things
```

Not on npm yet — install straight from the repo. It builds on install, so you need
Node 20 or newer and nothing else.

**Read the source before you trust it.** That advice applies to any tool you give this
much visibility, including this one. It is a few thousand lines of TypeScript with no
runtime dependencies beyond the Anthropic SDK, and [`CONTRACT.md`](./CONTRACT.md) tells you
which guarantees to check.

`warden install` leaves any hooks you already have untouched, and running it twice does not
install it twice. `warden uninstall` restores your settings file exactly.

The deterministic rules work immediately with no API key and no configuration. The independent
auditor needs a key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

## What it catches

| | |
|---|---|
| **Filesystem destruction** | `rm -rf /`, `mkfs`, `dd of=/dev/sda`, recursive `chmod` on system paths |
| **Losing your work** | `git reset --hard` over uncommitted changes, `git clean -fdx`, force-push to `main`, `stash drop` |
| **Credential exfiltration** | reading `.env` or `id_rsa` into a network call, `env \| nc`, uploading `~/.aws/credentials` |
| **Remote code execution** | `curl … \| sh`, `eval "$(curl …)"`, `bash <(curl …)`, decode-then-execute |
| **Persistence** | writes to `~/.bashrc`, `authorized_keys`, git hooks, cron, systemd, the Windows Run key |
| **Supply chain** | installs from a URL or git ref, registry redirects, `npm publish`, lockfile deletion |
| **Network egress** | reverse shells, `/dev/tcp`, tunnels, bulk copies of your home directory |
| **Privilege** | disabling the firewall or Defender, `csrutil disable`, `kill -9 1`, fork bombs |
| **Turning Warden off** | edits to the settings file, config, or audit log that would disable it mid-session |
| **What gets written** | `curl \| sh` payloads, obfuscated blobs that decode and execute, added `postinstall` scripts |

Two of these are things a pattern-matching blocklist structurally cannot do:

**It looks at your repository.** `git reset --hard` on a clean tree is routine and passes
silently. The identical command with uncommitted work stops and tells you how many files you are
about to lose.

**It reads what is being written.** A backdoor arrives as a `Write`, not as `rm -rf`. Warden
checks written content for a narrow set of high-signal patterns.

## What it does not do

Being honest about this matters more than sounding impressive.

- **It is not a sandbox.** It raises the bar considerably. It does not make it safe to point an
  agent at a hostile repository and walk away.
- **The rules are public, so an informed attacker can work around them.** That is what the second
  tier is for. Neither tier is a guarantee.
- **Obfuscated commands defeat tier 1.** `$(echo cm0K | base64 -d) -rf /` will not match a
  pattern. The auditor is the backstop, and it is not perfect either.
- **It can only see one tool call at a time.** An attack split across five innocuous-looking calls
  is not something Warden reconstructs.

## Privacy

**No telemetry, ever.** Warden does not phone home, count installs, or report what it
blocked. A tool that watches your commands and reports upstream would be self-defeating.

The deterministic rules are entirely local. Nothing leaves your machine.

**The auditor does not work that way.** When a tool call matches no rule, Warden sends the tool
name, its input, and the working directory to the Anthropic API. Before that happens the payload
is scrubbed of anything credential-shaped and truncated to a few thousand characters — but the
command itself, including file paths and arguments, is transmitted.

That is inherent to using a model as the judge. If you cannot allow it:

```json
{ "tier2": false }
```

You keep the rules and `warden status` will tell you plainly that the auditor is off.

## Three answers

- **allow** — nothing happens. You never see it.
- **ask** — Claude Code prompts you, with Warden's reason. Used for anything destructive but
  plausibly intentional.
- **deny** — blocked. Reserved for actions no legitimate development workflow performs.

That split is deliberate. A tool that interrupts real work gets uninstalled, and an uninstalled
tool protects nobody — so `rm -rf node_modules`, `git clean` in a scratch repo, and `npm install`
all pass without a word. In testing, 53 of 54 everyday commands are recognised outright.

## Escape hatch

If Warden is ever wrong, you are never stuck:

```bash
WARDEN_DISABLE=1 claude       # off for this session
```

Or turn off one rule permanently — the id is in the message Warden showed you:

```json
{ "disabledRules": ["supply.publish"] }
```

## Commands

```
warden install [path]     Add the hook to your Claude Code settings
warden uninstall [path]   Remove it
warden status             What is active right now, and why
warden log [n]            The last n decisions (only non-allowed calls are recorded)
warden test               Prove the rules still block known-bad commands
warden init               Write a default config file you can edit
```

## Configuration

`~/.claude/warden/config.json` — every key is optional.

| Key | Default | |
|---|---|---|
| `enabled` | `true` | Master switch |
| `tier2` | `true` | Whether the independent auditor runs |
| `model` | `claude-haiku-4-5` | Auditor model. Haiku because this fires per tool call; `claude-sonnet-5` for a sharper, pricier judge |
| `timeoutMs` | `5000` | Give up on the auditor and fall back to the rules |
| `failMode` | `open` | `open` keeps working from the rules alone if the auditor is unreachable; `closed` escalates instead |
| `apiKeyCommand` | `null` | Shell command that prints an API key, for keychain or vault storage |
| `logPath` | `~/.claude/warden/audit.jsonl` | Where decisions are recorded |
| `disabledRules` | `[]` | Rule ids to skip |

Key resolution order: `WARDEN_API_KEY` → `ANTHROPIC_API_KEY` → `apiKeyCommand`.

## How it fails

Failure behaviour is not uniform, and the asymmetry is intentional:

- A crash inside Warden's own rules escalates to **ask** — a broken guard should not wave things
  through.
- An unreachable auditor falls back to the rules and marks the entry `degraded` — a flaky network
  must never wedge your session. Set `failMode: "closed"` to invert that.
- The hook **always exits 0** and carries its verdict in JSON. A bug in Warden can never hard-block
  your work.

## Development

```bash
npm install
npm test          # 273 tests
npm run test:smoke
```

[`CONTRACT.md`](./CONTRACT.md) lists the eleven invariants that make Warden trustworthy and
names the test that locks each one. Read it before changing anything in `src/rules/` or
`src/auditor.ts` — several of those guarantees are easy to weaken by accident and hard to
notice afterwards.

## License

MIT
