# Warden — behaviour contract

The invariants below are what make Warden trustworthy. Each one names the test that
locks it. If you change code that breaks one of these, the test should go red — and if it
does not, the test is the thing that needs fixing.

This matters more here than in most projects: a security tool that has quietly stopped
protecting you is worse than no tool at all, because you have stopped watching.

---

## I1 — A Warden failure never costs the user their tool call

The hook always exits 0 and carries its verdict in JSON. Exit code 2 would block
unconditionally and cannot be overridden, so it is never used. Malformed input, an
unparseable payload, or a crash all resolve to silence.

*Locked by:* `hook.test.ts` — "exits 0 and stays quiet on malformed JSON", "exits 0 on
empty input", "handles a tool it has never heard of", and the exit-code assertion in
"blocks a catastrophic command".

## I2 — `deny` is reserved for actions with no legitimate use

Anything a developer might genuinely intend returns `ask`, which prompts rather than
blocks. This is a product requirement, not a preference: a tool that interrupts real work
gets uninstalled, and an uninstalled tool protects nobody.

*Locked by:* `corpus.test.ts` — 54 everyday commands must all return `allow`; and
`git.test.ts`, where every destructive-but-legitimate git operation asserts `ask`.

## I3 — The auditor never sees the conversation

Only the tool name, its input, and the working directory are sent. No transcript, no
prompt, no agent reasoning, no session history. If the agent has been prompt-injected, its
reasoning is precisely what must not reach the judge.

*Locked by:* `auditor.test.ts` — "carries no conversation history — that is the whole
design", plus the shape of `AuditRequest`, which has no field to put history in.

## I4 — The action reaches the auditor as data, never as instructions

The payload is wrapped in `<untrusted_action>`, and the system prompt states that
instruction-shaped text inside it is evidence of an attack rather than a command.

*Locked by:* `auditor.test.ts` — "an injected instruction lands inside the envelope, not
above it", "tells the auditor the payload is data, not instructions", "turns an attempt to
instruct the auditor into a deny signal".

## I5 — Nothing credential-shaped is written to disk or sent over the network

Redaction runs on both paths — the audit log and the auditor request — before anything
leaves memory.

*Locked by:* `audit-log.test.ts` "never writes a credential to disk" and
`auditor.test.ts` "redacts credentials before they leave the machine". Both assert the raw
secret is *absent*, not merely that redaction was called.

## I6 — A stronger verdict always wins

Findings merge by `strongest()`, so one `deny` inside a chain of allows still denies. A
command like `npm test && rm -rf /` cannot be laundered by its harmless first half.

*Locked by:* `rules.test.ts` — "lets the strongest verdict in a chain win", "still denies a
chain where only the second half is destructive".

## I7 — An unreachable auditor degrades, it does not wedge

Network failure falls back to the tier-1 verdict and marks the entry `degraded`. Users who
prefer the opposite set `failMode: "closed"` and get `ask` instead.

*Locked by:* `auditor.test.ts` — "falls back to tier 1 when the auditor is unreachable, and
says so", "escalates instead when the user has asked to fail closed".

## I8 — A crash inside Warden's own rules escalates rather than allows

A broken guard must not wave things through. The distinction from I1 is deliberate: we
could not *parse* the payload → allow silently; we parsed it and then our own analysis
crashed → ask.

*Locked by:* the `catch` in `pipeline.ts` that returns `ask`, and by `evaluate()` skipping
a single throwing rule rather than aborting the sweep.

## I9 — Install never damages an existing configuration

Other tools' hooks survive untouched, running install twice does not install twice, and
uninstall restores the file byte-for-byte.

*Locked by:* `cli.test.ts` — "leaves another tool's hook alone", "is idempotent — running
twice does not install twice", "restores the file to its original content", "survives
repeated cycles without drift".

## I10 — The user always has a way out

`WARDEN_DISABLE=1` short-circuits before any rule runs. A security tool with no escape
hatch gets uninstalled the first time it is wrong about something.

*Locked by:* `pipeline.test.ts` "honours the WARDEN_DISABLE escape hatch before anything
else runs" (asserts tier 0 even for `rm -rf /`) and `hook.test.ts` "honours WARDEN_DISABLE".

## I11 — Rules are tested through the pipeline, not in isolation

Every rule suite drives the real `decide()` path. The shell normalizer is a single point of
failure for nine rule families: a regression there would leave them dead while their own
unit tests still passed.

*Locked by:* `test/helpers.ts` — every rule assertion routes through `decideCommand()`.
Keep it that way.

---

## Deliberate non-guarantees

Stated so nobody builds on a promise that was never made:

- **Not a sandbox.** Warden raises the bar; it does not make an agent safe to run
  unattended on a hostile repository.
- **Tier 1 is defeatable by an informed attacker.** The rules are public. Tier 2 is the
  backstop, and it is not perfect either.
- **Obfuscation defeats tier 1.** `$(echo cm0K | base64 -d) -rf /` matches no pattern.
- **One call at a time.** An attack split across several innocuous-looking tool calls is not
  reconstructed.
