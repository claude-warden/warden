/**
 * Supply chain — pulling code from somewhere other than the registry.
 *
 * Installing from a registry is normal and stays silent. Installing straight from a
 * URL, a git ref, or a local tarball bypasses every check the registry provides, and
 * a `postinstall` script runs before anyone reads a line of the package.
 */

import type { Finding, RuleContext, RuleFn, Segment } from '../types.js';
import { operands } from './shell.js';

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'supply-chain' });

const INSTALLERS: Record<string, string[]> = {
  npm: ['install', 'i', 'add'],
  pnpm: ['install', 'i', 'add'],
  yarn: ['add', 'install'],
  bun: ['install', 'add'],
  pip: ['install'],
  pip3: ['install'],
  gem: ['install'],
  cargo: ['install'],
  go: ['install', 'get'],
  composer: ['require'],
};

/** A dependency source that is not the package registry. */
const NON_REGISTRY = /^(?:https?:\/\/|git\+|git:\/\/|ssh:\/\/|github:|gitlab:|bitbucket:|file:|\.\/|\.\.\/|\/)/i;

/** Package names that look like a source rather than a name. */
function offRegistrySources(segment: Segment): string[] {
  const cmd = segment.argv0;
  const subs = INSTALLERS[cmd];
  if (!subs) return [];

  const sub = segment.argv.slice(1).find((t) => !t.startsWith('-'));
  if (!sub || !subs.includes(sub)) return [];

  const args = operands(segment.argv).slice(1);
  return args.filter((a) => NON_REGISTRY.test(a) || /\.(?:tgz|tar\.gz|whl|zip)$/i.test(a));
}

const installsFromOffRegistry: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    const sources = offRegistrySources(segment);
    if (sources.length === 0) continue;

    findings.push(
      finding(
        'supply.off-registry',
        'ask',
        `This installs from ${sources.join(', ')} rather than the package registry, so it skips the registry's checks and can run install scripts.`,
      ),
    );
  }

  return findings;
};

/** Pointing the installer at a different registry redirects every future install. */
const redirectsRegistry: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    if (!INSTALLERS[segment.argv0] && segment.argv0 !== 'npm' && segment.argv0 !== 'pip') continue;

    const redirect = segment.argv.find(
      (t) => t.startsWith('--registry') || t.startsWith('--index-url') || t.startsWith('--extra-index-url'),
    );
    if (!redirect) continue;

    findings.push(
      finding(
        'supply.registry-redirect',
        'ask',
        `This installs from a non-default registry (\`${redirect}\`), which can serve different code than the official one.`,
      ),
    );
  }

  return findings;
};

/** Publishing is outward-facing and irreversible once it lands. */
const publishesPackage: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    const sub = segment.argv.slice(1).find((t) => !t.startsWith('-'));
    const publishing =
      (['npm', 'pnpm', 'yarn', 'bun'].includes(segment.argv0) && sub === 'publish') ||
      (segment.argv0 === 'cargo' && sub === 'publish') ||
      (segment.argv0 === 'gem' && sub === 'push') ||
      (segment.argv0 === 'twine' && sub === 'upload');

    if (!publishing) continue;

    findings.push(
      finding(
        'supply.publish',
        'ask',
        `\`${segment.raw}\` publishes a package publicly. That is hard to undo.`,
      ),
    );
  }

  return findings;
};

/** Deleting a lockfile discards the pinned, reviewed dependency set. */
const removesLockfile: RuleFn = (ctx: RuleContext) => {
  const LOCKFILES = /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|Cargo\.lock|poetry\.lock|Gemfile\.lock|composer\.lock)$/i;

  for (const segment of ctx.segments) {
    if (!['rm', 'del', 'unlink'].includes(segment.argv0)) continue;
    const targets = operands(segment.argv).filter((t) => LOCKFILES.test(t));
    if (targets.length === 0) continue;

    return finding(
      'supply.remove-lockfile',
      'ask',
      `Deleting ${targets.join(', ')} discards the pinned dependency versions, so the next install can pull different code.`,
    );
  }

  return null;
};

export const supplyChainRules: RuleFn[] = [
  installsFromOffRegistry,
  redirectsRegistry,
  publishesPackage,
  removesLockfile,
];
