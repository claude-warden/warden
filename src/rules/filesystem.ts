/**
 * Filesystem destruction — the "fatal mistake" half of the threat model.
 *
 * The hard part here is not catching `rm -rf /`; it is *not* catching
 * `rm -rf node_modules`, which is the most common legitimate destructive command in
 * the ecosystem. Blocking that once is enough for someone to uninstall Warden, so
 * build artifacts are recognised explicitly before anything else runs.
 */

import type { Finding, RuleContext, RuleFn, Segment } from '../types.js';
import { hasFlag, operands } from './shell.js';
import {
  isCatastrophicPath,
  isFilesystemRoot,
  isWorkingDirectorySweep,
  normalizeTarget,
} from './paths.js';

const REMOVERS = new Set(['rm', 'rmdir', 'unlink', 'del', 'erase', 'shred', 'srm']);
const PS_REMOVERS = new Set(['remove-item', 'ri', 'rd', 'rmdir']);

/** Directories that are cheap to regenerate and routinely deleted on purpose. */
const REGENERABLE = new Set([
  'node_modules', 'dist', 'build', 'out', 'target', 'coverage', '.next', '.nuxt',
  '.turbo', '.cache', '.parcel-cache', '__pycache__', '.pytest_cache', '.venv',
  'venv', 'vendor', 'bin', 'obj', '.gradle', '.mypy_cache', '.ruff_cache',
  'tmp', 'temp', '.tmp', 'logs', '.output', '.svelte-kit', '.astro',
]);

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'filesystem' });

/**
 * True when the last path component is a well-known build artifact.
 *
 * Checked before anything else, because `rm -rf node_modules` is the most common
 * legitimate destructive command there is and prompting on it would be the fastest
 * way to get Warden uninstalled.
 */
function isRegenerable(target: string): boolean {
  const parts = normalizeTarget(target).split('/').filter(Boolean);
  const last = parts[parts.length - 1];
  return Boolean(last && REGENERABLE.has(last.toLowerCase()));
}

function recursiveDelete(segment: Segment): Finding | null {
  const isUnixRemover = REMOVERS.has(segment.argv0);
  const isPsRemover = PS_REMOVERS.has(segment.argv0);
  if (!isUnixRemover && !isPsRemover) return null;

  const recursive =
    segment.argv0 === 'rmdir' ||
    segment.argv0 === 'rd' ||
    // `/s` is how Windows spells recursive for `del` and `rd`.
    hasFlag(segment.argv, { short: ['r', 'R', 's'], long: ['recursive', 'Recurse'] });

  // `operands()` only strips `-`-style flags, so Windows `/s` `/q` would otherwise
  // be read as paths. Bounded to one or two letters, which keeps `/` and `/etc`.
  const targets = operands(segment.argv).filter((t) => !/^\/[A-Za-z]{1,2}$/.test(t));

  for (const target of targets) {
    if (isCatastrophicPath(target)) {
      return finding(
        'fs.destroy-root',
        'deny',
        `This deletes \`${target}\` — a system or home root. No development task needs that.`,
      );
    }
    if (recursive && isWorkingDirectorySweep(target)) {
      return finding(
        'fs.wildcard-sweep',
        'ask',
        `This recursively deletes everything in the current directory (\`${target}\`).`,
      );
    }
  }

  if (!recursive) return null;

  // Recursive delete of a known build artifact is normal and stays silent.
  if (targets.length > 0 && targets.every(isRegenerable)) {
    return finding(
      'fs.regenerable',
      'allow',
      'Deleting a regenerable build directory is routine',
    );
  }

  if (targets.length === 0) return null;

  const force = hasFlag(segment.argv, { short: ['f'], long: ['force'] });
  if (force && segment.elevated) {
    return finding(
      'fs.sudo-force-delete',
      'ask',
      `Elevated recursive delete of \`${targets.join(', ')}\`.`,
    );
  }

  return null;
}

/** `mkfs`, `dd of=/dev/sda`, `format` — these end a disk. */
function diskDestruction(segment: Segment): Finding | null {
  if (/^mkfs(\.|$)/.test(segment.argv0)) {
    return finding('fs.mkfs', 'deny', 'This formats a filesystem, destroying every file on it.');
  }

  if (segment.argv0 === 'dd') {
    const out = segment.argv.find((t) => t.startsWith('of='));
    if (out && /of=\/dev\/(?:sd|nvme|hd|disk|vd)/.test(out)) {
      return finding('fs.dd-device', 'deny', `\`${out}\` writes directly to a raw disk, destroying its contents.`);
    }
  }

  if (segment.argv0 === 'format' && segment.argv.some((t) => /^[A-Za-z]:$/.test(t))) {
    return finding('fs.format', 'deny', 'This formats a drive, destroying every file on it.');
  }

  if (segment.argv0 === 'diskpart' || segment.argv0 === 'mkswap') {
    return finding('fs.disk-tool', 'ask', `\`${segment.argv0}\` operates on raw disks.`);
  }

  return null;
}

/** Redirecting into a block device or a system binary is never routine. */
function dangerousRedirect(segment: Segment): Finding | null {
  const match = segment.raw.match(/>\s*(\/dev\/(?:sd|nvme|hd|disk)[a-z0-9]*)/i);
  if (match) {
    return finding('fs.redirect-device', 'deny', `Writing to \`${match[1]}\` corrupts a raw disk.`);
  }
  return null;
}

/** `find / -delete` and `find . -exec rm` sweep far more than people expect. */
function findDelete(segment: Segment): Finding | null {
  if (segment.argv0 !== 'find') return null;

  const deletes = segment.argv.includes('-delete');
  const execs = segment.argv.includes('-exec') || segment.argv.includes('-execdir');
  if (!deletes && !execs) return null;

  const root = operands(segment.argv)[0] ?? '.';
  if (isFilesystemRoot(root)) {
    return finding('fs.find-delete-root', 'deny', `\`find ${root}\` with deletion would sweep the whole system.`);
  }

  return finding(
    'fs.find-delete',
    'ask',
    `This find deletes or executes across \`${root}\` — worth a look before it runs.`,
  );
}

/** `chmod -R 777 /` and `chown -R` on system paths break a machine's permissions. */
function permissionSweep(segment: Segment): Finding | null {
  if (segment.argv0 !== 'chmod' && segment.argv0 !== 'chown' && segment.argv0 !== 'chgrp') return null;
  if (!hasFlag(segment.argv, { short: ['R'], long: ['recursive'] })) return null;

  const targets = operands(segment.argv);
  for (const target of targets) {
    if (isCatastrophicPath(target)) {
      return finding(
        'fs.permission-sweep',
        'deny',
        `Recursive \`${segment.argv0}\` on \`${target}\` would break system permissions.`,
      );
    }
  }
  return null;
}

const scan = (fn: (s: Segment) => Finding | null): RuleFn => (ctx: RuleContext) => {
  const findings: Finding[] = [];
  for (const segment of ctx.segments) {
    const result = fn(segment);
    if (result) findings.push(result);
  }
  return findings;
};

export const filesystemRules: RuleFn[] = [
  scan(recursiveDelete),
  scan(diskDestruction),
  scan(dangerousRedirect),
  scan(findDelete),
  scan(permissionSweep),
];
