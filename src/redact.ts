/**
 * Secret scrubbing.
 *
 * This exists because of a hole found while red-teaming the design: Warden writes
 * denied tool calls to an audit log and sends unclassified ones to a model. Both
 * paths would happily persist or transmit whatever credential happened to be in the
 * command — so a tool built to stop exfiltration would itself be exfiltrating.
 *
 * Every string leaving Warden goes through `redact()` first. It runs on the hot
 * path, so the patterns are ordered cheapest-first and there is no backtracking.
 */

interface SecretPattern {
  kind: string;
  re: RegExp;
}

/**
 * Ordered specific-to-generic: a GitHub token should be labelled `github`, not
 * caught by the generic high-entropy rule. Each pattern is anchored on a literal
 * prefix where one exists, which keeps them fast and keeps false positives down.
 */
const PATTERNS: SecretPattern[] = [
  { kind: 'anthropic', re: /\bsk-ant-[A-Za-z0-9_-]{16,}/g },
  { kind: 'openai', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { kind: 'github', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g },
  { kind: 'github', re: /\bgithub_pat_[A-Za-z0-9_]{20,}/g },
  { kind: 'slack', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'aws', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { kind: 'google', re: /\bAIza[A-Za-z0-9_-]{35}\b/g },
  { kind: 'stripe', re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}/g },
  { kind: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { kind: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'bearer', re: /\b[Bb]earer\s+[A-Za-z0-9._~+/-]{16,}=*/g },
  // `DB_PASSWORD=hunter2`, `--api-key hunter2`, `"token": "hunter2"` and friends.
  // The bounded prefix is what catches `DB_PASSWORD` — an underscore is a word
  // character, so a leading `\b` would never match there.
  {
    kind: 'assigned',
    re: /[A-Za-z0-9_]{0,32}(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|auth)[A-Za-z0-9_]{0,32}["'\s]*[:=]\s*["']?([^\s"',;)&|]{6,})/gi,
  },
];

/** Value long enough that seeing it in a log would be a real leak. */
const HIGH_ENTROPY = /\b(?=[A-Za-z0-9+/_-]*[0-9])(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_-]{40,}={0,2}\b/g;

/**
 * Replace anything that looks like a credential with a labelled placeholder.
 *
 * Deliberately over-eager: a redacted value that turned out to be harmless costs a
 * little log readability, while a missed one is a leaked credential. The kind label
 * is preserved so an audit entry still says *what sort of* secret was involved.
 */
export function redact(input: string): string {
  if (!input) return input;
  let out = input;

  for (const { kind, re } of PATTERNS) {
    // `assigned` captures only the value so the key name stays readable.
    if (kind === 'assigned') {
      out = out.replace(re, (match, value: string) =>
        match.replace(value, '[REDACTED:assigned]'),
      );
      continue;
    }
    out = out.replace(re, `[REDACTED:${kind}]`);
  }

  return out.replace(HIGH_ENTROPY, '[REDACTED:high-entropy]');
}

/** Redact every string in an arbitrary structure, preserving its shape. */
export function redactDeep(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[truncated:depth]';
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactDeep(v, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Cap a string for transmission, keeping the head (where the dangerous part of a
 * command almost always is) and marking the cut so nobody mistakes it for the whole.
 */
export function truncate(input: string, limit: number): string {
  if (input.length <= limit) return input;
  return `${input.slice(0, limit)}\n…[truncated ${input.length - limit} chars]`;
}
