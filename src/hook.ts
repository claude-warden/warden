#!/usr/bin/env node
/**
 * The PreToolUse entrypoint — the only hot path in the project.
 *
 * Contract: Claude Code writes a JSON payload to stdin and reads a JSON decision
 * from stdout. We always exit 0 and carry the decision in the JSON, never via exit
 * code 2. Exit 2 blocks unconditionally and cannot be overridden, which makes it the
 * wrong tool for a decision that should be reviewable — and it would turn any bug in
 * Warden into a hard block on the user's real work.
 *
 * The overriding rule here: a failure inside Warden must never cost the user their
 * tool call. If we cannot even parse the payload, we allow and stay quiet.
 */

import { loadConfig } from './config.js';
import { record } from './audit-log.js';
import { decide } from './pipeline.js';
import type { Decision, HookOutput, PreToolUsePayload } from './types.js';

/** Read stdin fully, but never hang — a stalled hook would freeze the session. */
function readStdin(timeoutMs = 2000): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) return resolve('');

    let data = '';
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve(data);
    };

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', done);
    process.stdin.on('error', done);
    setTimeout(done, timeoutMs).unref?.();
  });
}

/** Map an internal verdict onto the three answers Claude Code understands. */
function toHookOutput(decision: Decision): HookOutput {
  const permissionDecision =
    decision.verdict === 'deny' ? 'deny' : decision.verdict === 'ask' ? 'escalate' : 'allow';

  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason:
        permissionDecision === 'allow' ? undefined : `Warden: ${decision.reason}`,
    },
  };
}

export async function run(): Promise<void> {
  const raw = await readStdin();
  if (!raw.trim()) return;

  let payload: PreToolUsePayload;
  try {
    payload = JSON.parse(raw) as PreToolUsePayload;
  } catch {
    // Unparseable input is Claude Code's problem, not the user's. Stay out of the way.
    return;
  }

  const config = loadConfig();
  const decision = await decide(payload, config);

  // Allowed calls are the overwhelming majority; logging them would bury the
  // handful of entries that actually matter.
  if (decision.verdict !== 'allow') {
    record(config.logPath, config.maxLogBytes, {
      tool: payload.tool_name ?? 'unknown',
      cwd: payload.cwd ?? '',
      verdict: decision.verdict,
      tier: decision.tier,
      reason: decision.reason,
      rules: decision.findings.map((f) => f.rule),
      input: payload.tool_input ?? {},
      ...(decision.degraded ? { degraded: true } : {}),
      ...(payload.session_id ? { sessionId: payload.session_id } : {}),
    });
  }

  if (decision.verdict === 'allow') return;
  process.stdout.write(JSON.stringify(toHookOutput(decision)));
}

// Exit 0 on every path. A Warden bug must not block a developer's work.
run()
  .then(() => process.exit(0))
  .catch(() => process.exit(0));
