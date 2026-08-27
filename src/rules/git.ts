/**
 * Git destruction — and the context-aware checks that are Warden's real edge.
 *
 * A blocklist can only ask "is this command in my list of bad commands". That is
 * the wrong question for git: `git reset --hard` on a clean tree is routine, and the
 * identical command with forty uncommitted files destroys a day's work. So these
 * rules actually look at the repository before deciding.
 *
 * Per the project's calibration rule, destructive-but-legitimate git operations
 * return `ask` rather than `deny`. Discarding uncommitted changes on purpose is a
 * real workflow; the user should be told what they are about to lose, not blocked.
 */

import { execFileSync } from 'node:child_process';
import type { Finding, RuleContext, RuleFn, Segment } from '../types.js';
import { hasFlag, operands } from './shell.js';

/** Branches where a history rewrite affects everyone, not just you. */
const SHARED_BRANCHES = new Set(['main', 'master', 'develop', 'release', 'production', 'prod']);

/**
 * How long we let git block before giving up.
 *
 * Measured rather than guessed: `git status --porcelain` on a trivial repo costs
 * 280–470ms on Windows, and comfortably exceeds a second when the machine is busy.
 * An earlier 1.5s budget meant the check degraded to "assume dirty" precisely when a
 * developer's machine was under load — which would quietly disable the clean-tree
 * pass-through, the main thing these rules exist to provide.
 *
 * Five seconds is affordable because this only runs for destructive git commands,
 * which are rare, and pausing before one is exactly when a pause is acceptable.
 */
const GIT_TIMEOUT_MS = 5000;

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'git' });

interface TreeState {
  /** Number of changed or untracked files, or null when we could not tell. */
  changedFiles: number | null;
  /** True when git did not answer in time — treated as dirty, which is fail-safe. */
  timedOut: boolean;
}

/**
 * Ask git what is uncommitted.
 *
 * A slow answer is treated as "dirty": on a huge repo we would rather prompt the
 * user unnecessarily than wave through a command that silently eats their work.
 */
export function inspectTree(cwd: string): TreeState {
  try {
    const out = execFileSync('git', ['-C', cwd, 'status', '--porcelain'], {
      encoding: 'utf8',
      timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    });
    const changedFiles = out.split('\n').filter((line) => line.trim().length > 0).length;
    return { changedFiles, timedOut: false };
  } catch (err) {
    const timedOut = Boolean(err && typeof err === 'object' && 'signal' in err && (err as { signal?: string }).signal);
    // Not a repository, or git is missing — no opinion either way.
    return { changedFiles: timedOut ? Number.POSITIVE_INFINITY : null, timedOut };
  }
}

/** Current branch name, or null when it cannot be determined cheaply. */
function currentBranch(cwd: string): string | null {
  try {
    return execFileSync('git', ['-C', cwd, 'rev-parse', '--abbrev-ref', 'HEAD'], {
      encoding: 'utf8',
      timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    }).trim();
  } catch {
    return null;
  }
}

/** Is this segment a git invocation, and if so which subcommand? */
function gitSub(segment: Segment): string | null {
  if (segment.argv0 !== 'git') return null;
  const sub = segment.argv.slice(1).find((t) => !t.startsWith('-'));
  return sub ?? null;
}

function describeLoss(state: TreeState): string {
  if (state.timedOut) return 'git did not respond in time, so Warden is assuming there is uncommitted work';
  if (state.changedFiles === null) return 'the working tree state is unknown';
  return `${state.changedFiles} uncommitted file${state.changedFiles === 1 ? '' : 's'} would be lost`;
}

/**
 * `git reset --hard` and `git checkout .` — routine on a clean tree, destructive on
 * a dirty one. This is the check a regex ruleset cannot make.
 */
const discardsUncommittedWork: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    const sub = gitSub(segment);
    if (!sub) continue;

    const isHardReset = sub === 'reset' && hasFlag(segment.argv, { long: ['hard'] });
    const targets = operands(segment.argv).slice(1);
    const sweepsEverything = targets.some((t) => t === '.' || t === '*' || t === './');
    const isBulkCheckout = (sub === 'checkout' || sub === 'restore') && sweepsEverything;

    if (!isHardReset && !isBulkCheckout) continue;

    const state = inspectTree(ctx.cwd);
    if (state.changedFiles === null) continue;

    if (state.changedFiles === 0) {
      findings.push(
        finding('git.reset-clean', 'allow', 'The working tree is clean, so nothing is lost'),
      );
      continue;
    }

    findings.push(
      finding(
        isHardReset ? 'git.reset-hard-dirty' : 'git.checkout-dirty',
        'ask',
        `\`${segment.raw}\` discards uncommitted changes — ${describeLoss(state)}.`,
      ),
    );
  }

  return findings;
};

/** `git clean -fdx` deletes untracked files, which routinely includes `.env`. */
const cleanUntracked: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    if (gitSub(segment) !== 'clean') continue;
    if (!hasFlag(segment.argv, { short: ['f'], long: ['force'] })) continue;

    const alsoIgnored = hasFlag(segment.argv, { short: ['x', 'X'] });
    findings.push(
      finding(
        'git.clean-force',
        'ask',
        alsoIgnored
          ? 'This deletes untracked *and* git-ignored files — local `.env` files and credentials are usually ignored.'
          : 'This permanently deletes untracked files.',
      ),
    );
  }

  return findings;
};

/** Force-pushing a shared branch rewrites history for everyone on the team. */
const forcePush: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    if (gitSub(segment) !== 'push') continue;

    const forced = hasFlag(segment.argv, { short: ['f'], long: ['force'] });
    if (!forced) continue;

    // `--force-with-lease` refuses to clobber work you have not seen. That is the
    // safe variant and does not deserve a prompt.
    if (segment.argv.some((t) => t.startsWith('--force-with-lease'))) continue;

    const named = operands(segment.argv).slice(1);
    const branch = named.find((t) => SHARED_BRANCHES.has(t)) ?? (named.length === 0 ? currentBranch(ctx.cwd) : null);
    const targetsShared = Boolean(branch && SHARED_BRANCHES.has(branch));

    findings.push(
      finding(
        targetsShared ? 'git.force-push-shared' : 'git.force-push',
        'ask',
        targetsShared
          ? `Force-pushing \`${branch}\` rewrites shared history and can destroy other people's commits.`
          : 'Force-pushing overwrites remote history — use `--force-with-lease` if you can.',
      ),
    );
  }

  return findings;
};

/** Operations that quietly discard recoverable work. */
const destroysRecovery: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    const sub = gitSub(segment);
    if (!sub) continue;
    const rest = segment.argv.slice(segment.argv.indexOf(sub) + 1);

    if (sub === 'stash' && (rest.includes('drop') || rest.includes('clear'))) {
      findings.push(finding('git.stash-drop', 'ask', 'This permanently discards stashed work.'));
    }

    if (sub === 'branch' && segment.argv.includes('-D')) {
      findings.push(
        finding('git.branch-force-delete', 'ask', 'This force-deletes a branch, including unmerged commits on it.'),
      );
    }

    if (sub === 'filter-branch' || sub === 'filter-repo') {
      findings.push(finding('git.filter-branch', 'ask', 'This rewrites the entire repository history.'));
    }

    if (sub === 'reflog' && rest.includes('expire') && rest.some((t) => t.includes('--expire=now'))) {
      findings.push(
        finding('git.reflog-expire', 'ask', 'Expiring the reflog removes git’s safety net for recovering lost commits.'),
      );
    }

    if (sub === 'gc' && rest.some((t) => t.startsWith('--prune=now') || t === '--aggressive')) {
      findings.push(
        finding('git.gc-prune', 'ask', 'Pruning now makes unreferenced commits unrecoverable.'),
      );
    }

    if (sub === 'update-ref' && rest.includes('-d')) {
      findings.push(finding('git.update-ref-delete', 'ask', 'This deletes a git ref directly.'));
    }
  }

  return findings;
};

export const gitRules: RuleFn[] = [discardsUncommittedWork, cleanUntracked, forcePush, destroysRecovery];
