/**
 * Tier orchestration — the decision path for one tool call.
 *
 * Ordered cheapest-first, because this runs before *every* tool call and a hook that
 * adds a visible pause to `Grep` is a hook people uninstall:
 *
 *   tier 0  triage        ~0ms   escape hatch, reentrancy, no-side-effect tools
 *   tier 1  rules         ~1ms   deterministic, offline, free
 *   tier 2  auditor       ~1s    only when tier 1 has no opinion
 *
 * The fail-safe policy is deliberately not uniform. A crash inside Warden's own
 * rules escalates to `ask`, because a broken guard should not wave things through.
 * An unreachable auditor falls back to the tier-1 verdict, because a flaky network
 * must never wedge someone's session.
 */

import { audit, type MessageSender } from './auditor.js';
import { activeTiers, resolveApiKey, type WardenConfig } from './config.js';
import { evaluate, primaryFinding, verdictOf } from './rules/index.js';
import { parseCommand } from './rules/shell.js';
import { ALL_RULES } from './rules/index.js';
import type { Decision, PreToolUsePayload, RuleContext } from './types.js';

/**
 * Tools that cannot change anything locally, so they never need inspecting.
 * `Read` is deliberately absent — reading a credential file is worth a prompt.
 */
const NO_SIDE_EFFECTS = new Set([
  'Glob', 'Grep', 'LS', 'TodoWrite', 'TodoRead', 'TaskList', 'TaskGet',
  'NotebookRead', 'WebSearch', 'ExitPlanMode', 'EnterPlanMode',
]);

/**
 * Tools whose blast radius is small enough that "no rule fired" is a good enough
 * answer. Without this, every ordinary `Read` would pay for an auditor call.
 */
const LOW_RISK = new Set(['Read', 'WebFetch', 'Task', 'Agent']);

/** Tools that carry a shell command we should parse. */
const COMMAND_TOOLS = new Set(['Bash', 'PowerShell', 'Shell', 'Terminal']);

/** Marks our own subprocesses so Warden can never end up auditing itself. */
export const REENTRANCY_ENV = 'WARDEN_AUDITOR';

function extractCommand(toolName: string, toolInput: Record<string, unknown>): string {
  if (!COMMAND_TOOLS.has(toolName)) return '';
  const value = toolInput.command ?? toolInput.script ?? toolInput.cmd;
  return typeof value === 'string' ? value : '';
}

function buildContext(payload: PreToolUsePayload): RuleContext {
  const toolName = payload.tool_name ?? '';
  const toolInput = payload.tool_input ?? {};
  const command = extractCommand(toolName, toolInput);

  return {
    toolName,
    toolInput,
    cwd: payload.cwd || process.cwd(),
    command,
    segments: command ? parseCommand(command) : [],
  };
}

const allow = (reason: string, tier: Decision['tier']): Decision => ({
  verdict: 'allow',
  reason,
  tier,
  findings: [],
});

/**
 * Decide what should happen to one proposed tool call.
 *
 * Never throws: every failure path resolves to a decision, because the caller's only
 * other option would be to crash and block the user's work.
 */
export async function decide(
  payload: PreToolUsePayload,
  config: WardenConfig,
  /** Test seam: lets the suite exercise the tier-2 path without a network call. */
  sender?: MessageSender,
): Promise<Decision> {
  // ---- Tier 0: triage -----------------------------------------------------
  if (process.env[REENTRANCY_ENV]) return allow('Warden does not audit its own calls', 0);
  if (process.env.WARDEN_DISABLE) return allow('WARDEN_DISABLE is set', 0);
  if (!config.enabled) return allow('Warden is disabled in config', 0);

  const toolName = payload.tool_name ?? '';
  if (!toolName) return allow('No tool name in payload', 0);
  if (NO_SIDE_EFFECTS.has(toolName)) return allow(`${toolName} has no local side effects`, 0);

  // ---- Tier 1: deterministic rules ----------------------------------------
  let ctx: RuleContext;
  let findings;
  try {
    ctx = buildContext(payload);
    // Rules are filtered after evaluation rather than before, so a disabled rule
    // still costs ~nothing and the list stays a simple string match on rule ids.
    findings = evaluate(ctx, ALL_RULES).filter((f) => !config.disabledRules.includes(f.rule));
  } catch {
    // A crash in our own analysis is not a reason to wave the action through.
    return {
      verdict: 'ask',
      reason: 'Warden could not analyse this action, so it is asking rather than assuming it is safe.',
      tier: 1,
      findings: [],
    };
  }

  const tier1 = verdictOf(findings);
  if (tier1 !== 'unknown') {
    const primary = primaryFinding(findings);
    return {
      verdict: tier1,
      reason: primary?.reason ?? 'Matched a Warden rule.',
      tier: 1,
      findings,
    };
  }

  // Nothing fired, and this tool cannot do much harm. Don't pay for an audit.
  if (LOW_RISK.has(toolName)) {
    return allow(`${toolName} is low risk and matched no rule`, 1);
  }

  // ---- Tier 2: the independent auditor ------------------------------------
  if (!config.tier2) {
    return allow('No rule matched; the independent auditor is switched off', 1);
  }

  const apiKey = resolveApiKey(config);
  if (!apiKey) {
    return {
      ...allow('No rule matched; the independent auditor has no API key', 1),
      degraded: true,
    };
  }

  const verdict = await audit(
    { toolName, toolInput: ctx.toolInput, cwd: ctx.cwd },
    config,
    apiKey,
    sender,
  );

  if (!verdict) {
    // Unreachable auditor. Fall back to tier 1 rather than guessing, unless the
    // user has explicitly asked to fail closed.
    if (config.failMode === 'closed') {
      return {
        verdict: 'ask',
        reason: 'The independent auditor could not be reached and Warden is set to fail closed.',
        tier: 2,
        findings,
        degraded: true,
      };
    }
    return { ...allow('No rule matched; the independent auditor was unreachable', 1), degraded: true };
  }

  return {
    verdict: verdict.verdict,
    reason: verdict.injectionSuspected
      ? `${verdict.reason} (Warden's auditor reports this payload tried to give *it* instructions, which is a hallmark of prompt injection.)`
      : verdict.reason,
    tier: 2,
    findings,
  };
}

export { activeTiers };
