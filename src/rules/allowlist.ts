/**
 * The positive allowlist — ordinary development commands that are recognised as
 * safe so they never reach the paid, slower auditor.
 *
 * This half of tier 1 matters as much as the blocklist. Red-teaming the design
 * surfaced two failure modes that a blocklist alone walks straight into: a latency
 * tax on every unrecognised command, and users disabling the tool because it keeps
 * asking about `ls`. Recognising safe work explicitly is what keeps Warden quiet.
 *
 * An `allow` here is never the last word — `strongest()` lets any blocklist finding
 * override it, so `npm test && rm -rf /` still denies.
 */

import type { Finding, RuleContext, RuleFn } from '../types.js';
import { hasFlag } from './shell.js';

/** Commands that cannot destroy or exfiltrate anything on their own. */
const SAFE_COMMANDS = new Set([
  // Inspection
  'ls', 'dir', 'pwd', 'cd', 'echo', 'cat', 'bat', 'head', 'tail', 'less', 'more',
  'wc', 'sort', 'uniq', 'diff', 'tree', 'file', 'stat', 'du', 'df', 'which',
  'where', 'whoami', 'hostname', 'date', 'uptime', 'env', 'printenv', 'type',
  'basename', 'dirname', 'realpath', 'readlink', 'cksum', 'md5sum', 'sha256sum',
  // Search
  'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'fd',
  // Text processing (they write to stdout unless redirected)
  'jq', 'yq', 'awk', 'cut', 'tr', 'column', 'tee',
  // Creating things is not destroying things
  'mkdir', 'touch', 'cp', 'ln',
  // Toolchains
  'node', 'deno', 'bun', 'tsc', 'tsx', 'ts-node', 'eslint', 'prettier', 'biome',
  'jest', 'vitest', 'mocha', 'ava', 'playwright', 'cypress',
  'python', 'python3', 'pytest', 'ruff', 'black', 'mypy', 'poetry',
  'go', 'gofmt', 'cargo', 'rustc', 'rustfmt', 'clippy',
  'javac', 'java', 'mvn', 'gradle', 'dotnet', 'ruby', 'rake', 'bundle',
  'php', 'composer', 'swift', 'kotlin', 'elixir', 'mix',
  'make', 'cmake', 'ninja', 'bazel', 'npx',
  // Process inspection
  'ps', 'top', 'htop', 'lsof', 'netstat', 'ss',
]);

/*
 * `curl` and `wget` are deliberately absent.
 *
 * Their dangerous uses are covered by specific rules that would override an allow,
 * so listing them would be *safe* — but it would also mean a novel abuse nobody has
 * written a rule for (say, posting `/etc/passwd` to a pastebin) never reaches the
 * auditor. Leaving downloaders unrecognised is what keeps that path open, at the
 * cost of a handful of audit calls.
 */

/**
 * Commands whose safety depends on the subcommand. Only the listed subcommands are
 * recognised as safe; anything else falls through so the blocklist families (or the
 * auditor) can weigh in.
 */
const SAFE_SUBCOMMANDS: Record<string, Set<string>> = {
  // The destructive git subcommands each have a rule of their own, and a rule's
  // `ask`/`deny` always beats an allowlist `allow` — so listing `branch` here still
  // leaves `git branch -D` prompting.
  git: new Set([
    'status', 'log', 'diff', 'show', 'blame', 'describe', 'rev-parse', 'rev-list',
    'ls-files', 'ls-remote', 'shortlog', 'config', 'remote', 'fetch', 'add', 'branch',
    'commit', 'switch', 'restore', 'merge-base', 'cherry', 'grep', 'worktree',
    'bisect', 'notes', 'whatchanged', 'reflog', 'apply', 'format-patch', 'stash',
  ]),
  // Likewise `install` — the supply-chain rules cover off-registry sources.
  npm: new Set(['test', 'run', 'run-script', 'ci', 'install', 'i', 'add', 'list', 'ls', 'why', 'outdated', 'view', 'audit', 'version', 'exec', 'start', 'build']),
  pnpm: new Set(['test', 'run', 'install', 'i', 'add', 'list', 'why', 'outdated', 'build', 'start']),
  yarn: new Set(['test', 'run', 'install', 'add', 'list', 'why', 'outdated', 'build', 'start']),
  docker: new Set(['ps', 'images', 'logs', 'inspect', 'version', 'info', 'build', 'compose']),
  kubectl: new Set(['get', 'describe', 'logs', 'top', 'explain', 'version', 'config']),
  gh: new Set(['pr', 'issue', 'repo', 'run', 'workflow', 'auth', 'api', 'release']),
  cargo: new Set(['build', 'test', 'run', 'check', 'clippy', 'fmt', 'doc', 'tree']),
};

/** `git worktree remove --force` and `gh repo delete` are not routine. */
const UNSAFE_SUB_SUBCOMMANDS = new Set(['delete', 'remove', 'prune', 'destroy']);

const safe = (rule: string, reason: string): Finding => ({
  rule,
  verdict: 'allow',
  reason,
  family: 'allowlist',
});

/** Recognise plainly safe commands so they never reach tier 2. */
const recogniseSafeCommands: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    const cmd = segment.argv0;
    if (!cmd) continue;

    // Redirection can turn a harmless reader into a file-clobberer, so any
    // segment containing `>` is left for other rules to judge.
    if (/[^0-9]>>?/.test(segment.raw)) continue;

    if (SAFE_COMMANDS.has(cmd)) {
      // `find` is only safe while it is finding rather than deleting or executing.
      if (cmd === 'find' || cmd === 'fd') continue;
      findings.push(safe(`allow.${cmd}`, `${cmd} is a routine, non-destructive command`));
      continue;
    }

    const subcommands = SAFE_SUBCOMMANDS[cmd];
    if (!subcommands) continue;

    const sub = segment.argv.slice(1).find((t) => !t.startsWith('-'));
    if (!sub || !subcommands.has(sub)) continue;

    const rest = segment.argv.slice(segment.argv.indexOf(sub) + 1);
    if (rest.some((t) => UNSAFE_SUB_SUBCOMMANDS.has(t))) continue;
    if (cmd === 'git' && sub === 'config' && rest.includes('--global')) continue;

    findings.push(safe(`allow.${cmd}.${sub}`, `\`${cmd} ${sub}\` is routine development work`));
  }

  return findings;
};

/** `find` without `-delete` or `-exec` only reads the filesystem. */
const recogniseReadOnlyFind: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    if (segment.argv0 !== 'find' && segment.argv0 !== 'fd') continue;
    if (hasFlag(segment.argv, { long: ['delete', 'exec', 'execdir', 'ok', 'okdir'] })) continue;
    if (segment.argv.some((t) => t === '-delete' || t === '-exec' || t === '-execdir')) continue;
    if (segment.argv0 === 'fd' && hasFlag(segment.argv, { short: ['x', 'X'], long: ['exec', 'exec-batch'] })) continue;
    findings.push(safe('allow.find', 'find is only reading the filesystem here'));
  }

  return findings;
};

export const allowlistRules: RuleFn[] = [recogniseSafeCommands, recogniseReadOnlyFind];
