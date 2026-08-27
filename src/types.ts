/**
 * The Claude Code PreToolUse hook contract, plus Warden's own verdict types.
 *
 * The hook shapes here were verified against the live Claude Code hook docs and
 * against a working PreToolUse hook, not written from memory. We deliberately type
 * the payload loosely and never validate it strictly: if Claude Code adds a field,
 * Warden must keep working rather than fail closed on an unknown key.
 */

/** What Claude Code writes to our stdin before running a tool. */
export interface PreToolUsePayload {
  hook_event_name?: string;
  session_id?: string;
  transcript_path?: string;
  cwd?: string;
  permission_mode?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_use_id?: string;
  /** Present only when the call came from a subagent. */
  agent_id?: string;
  agent_type?: string;
}

/** What we write to stdout. Exit code stays 0; this JSON carries the decision. */
export interface HookOutput {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse';
    permissionDecision: 'allow' | 'deny' | 'escalate';
    permissionDecisionReason?: string;
  };
}

/**
 * A rule's answer.
 *
 * `unknown` is load-bearing: it means "tier 1 has no opinion", which is the only
 * thing that escalates to the (slow, paid) LLM auditor. Rules must return `allow`
 * only when they positively recognise something as safe.
 */
export type Verdict = 'allow' | 'ask' | 'deny' | 'unknown';

/** Ordered weakest to strongest. A stronger verdict always wins a merge. */
const VERDICT_RANK: Record<Verdict, number> = {
  unknown: 0,
  allow: 1,
  ask: 2,
  deny: 3,
};

/**
 * Combine two verdicts. Strongest wins, so a single `deny` among a hundred
 * `allow`s still denies — which is what you want when a command chain like
 * `npm test && rm -rf /` is evaluated segment by segment.
 */
export function strongest(a: Verdict, b: Verdict): Verdict {
  return VERDICT_RANK[b] > VERDICT_RANK[a] ? b : a;
}

/** A rule's finding, with enough context for a human to judge it after the fact. */
export interface Finding {
  /** Stable identifier, e.g. `fs.rm-root`. Used in logs and tests. */
  rule: string;
  verdict: Verdict;
  /** One sentence a non-expert can act on. Shown to the user when we block. */
  reason: string;
  /** Which threat family this belongs to. */
  family: RuleFamily;
}

export type RuleFamily =
  | 'allowlist'
  | 'filesystem'
  | 'git'
  | 'secrets'
  | 'exec'
  | 'persistence'
  | 'self-defence'
  | 'supply-chain'
  | 'egress'
  | 'privilege'
  | 'content';

/** Everything a rule is allowed to look at. */
export interface RuleContext {
  toolName: string;
  toolInput: Record<string, unknown>;
  cwd: string;
  /** Parsed shell segments — empty for non-command tools. */
  segments: Segment[];
  /** Raw command string for command-bearing tools, else ''. */
  command: string;
}

/**
 * One command in a chain, with the operator that introduced it.
 *
 * Keeping the connector is what lets `curl x | sh` be distinguished from
 * `curl x; sh` — the first is remote code execution, the second is two
 * unrelated commands.
 */
export interface Segment {
  raw: string;
  /** argv-style tokens with quoting removed. */
  tokens: string[];
  /** tokens[0] after stripping wrappers like `sudo` and `env FOO=bar`. */
  argv0: string;
  /** Tokens after wrapper stripping. */
  argv: string[];
  /** The operator immediately before this segment, or null for the first. */
  connector: '|' | '&&' | '||' | ';' | '\n' | null;
  /** True when a wrapper such as `sudo` or `doas` was stripped. */
  elevated: boolean;
}

/** The final decision the pipeline reaches for one tool call. */
export interface Decision {
  verdict: Verdict;
  reason: string;
  /** Which tier decided: 0 triage, 1 rules, 2 the independent auditor. */
  tier: 0 | 1 | 2;
  findings: Finding[];
  /** True when tier 2 was wanted but unavailable, so we fell back to tier 1. */
  degraded?: boolean;
}

export type RuleFn = (ctx: RuleContext) => Finding | Finding[] | null;
