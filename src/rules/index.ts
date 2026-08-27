/**
 * The tier-1 rule engine.
 *
 * Deterministic, offline, and free. Every rule is a pure function over a
 * `RuleContext`; the engine runs them all and merges findings by taking the
 * strongest verdict, so a single `deny` inside `npm test && rm -rf /` still denies
 * the whole call.
 *
 * The calibration rule that governs every rule in this directory: `deny` is
 * reserved for actions no legitimate development workflow performs. Anything with a
 * plausible legitimate use returns `ask`, which prompts the user rather than
 * blocking them. A security tool that cries wolf gets uninstalled, and an
 * uninstalled tool has a 100% failure rate.
 */

import type { Finding, RuleContext, RuleFn, Verdict } from '../types.js';
import { strongest } from '../types.js';
import { allowlistRules } from './allowlist.js';
import { filesystemRules } from './filesystem.js';
import { gitRules } from './git.js';
import { secretsRules } from './secrets.js';
import { execRules } from './exec.js';
import { persistenceRules } from './persistence.js';
import { selfDefenceRules } from './self-defence.js';
import { supplyChainRules } from './supply-chain.js';
import { egressRules } from './egress.js';
import { privilegeRules } from './privilege.js';
import { contentRules } from './content.js';

/**
 * Blocklist families run before the allowlist purely for readability of the
 * findings array; merge order does not affect the outcome because `strongest`
 * is commutative.
 */
export const ALL_RULES: RuleFn[] = [
  ...filesystemRules,
  ...gitRules,
  ...secretsRules,
  ...execRules,
  ...persistenceRules,
  ...selfDefenceRules,
  ...supplyChainRules,
  ...egressRules,
  ...privilegeRules,
  ...contentRules,
  ...allowlistRules,
];

/** Run every rule and collect what fired. A rule that throws is skipped, not fatal. */
export function evaluate(ctx: RuleContext, rules: RuleFn[] = ALL_RULES): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    let result: Finding | Finding[] | null;
    try {
      result = rule(ctx);
    } catch {
      // A broken rule must never take down the hook. The pipeline's own
      // catch-all turns a total failure into `ask`; one bad rule just abstains.
      continue;
    }
    if (!result) continue;
    if (Array.isArray(result)) findings.push(...result);
    else findings.push(result);
  }

  return findings;
}

/** Merge findings into one verdict. No findings means tier 1 has no opinion. */
export function verdictOf(findings: Finding[]): Verdict {
  return findings.reduce<Verdict>((acc, f) => strongest(acc, f.verdict), 'unknown');
}

/**
 * The finding a human should be shown: the one that drove the verdict. Ties go to
 * the first, which is the most specific family because of the ordering above.
 */
export function primaryFinding(findings: Finding[]): Finding | null {
  const verdict = verdictOf(findings);
  return findings.find((f) => f.verdict === verdict) ?? null;
}
