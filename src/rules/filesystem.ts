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

const REMOVERS = new Set(['rm', 'rmdir', 'unlink', 'del', 'erase', 'shred', 'srm']);
const PS_REMOVERS = new Set(['remove-item', 'ri', 'rd', 'rmdir']);

/** Paths whose loss ends the machine, not just the project. */
const CATASTROPHIC = [
  /^\/$/,
  /^\/\*$/,
  /^~\/?$/,
  /^\$HOME\/?$/,
  /^\/(?:bin|boot|dev|etc|lib|lib64|proc|root|sbin|sys|usr|var|home|opt|srv)\/?$/,
  /^[A-Za-z]:[\\/]?$/,
  /^[A-Za-z]:[\\/]\*$/,
  /^[\\/](?:windows|program files(?: \(x86\))?|users)[\\/]?$/i,
];

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

/** Strip trailing slashes and quotes so `"/"` and `/` compare equal. */
function normalizePath(target: string): string {
  return target.replace(/["']/g, '').replace(/\/+$/, '') || '/';
}

/** True when the last path component is a well-known build artifact. */
function isRegenerable(target: string): boolean {
  const clean = normalizePath(target);
  const parts = clean.split(/[\\/]/).filter(Boolean);
  const last = parts[parts.length - 1];
  return Boolean(last && REGENERABLE.has(last.toLowerCase()));
}

function isCatastrophic(target: string): boolean {
  const clean = normalizePath(target);
  return CATASTROPHIC.some((re) => re.test(clean)) || clean === '';
}

/**
 * The narrower question: is this the top of the whole filesystem?
 *
 * `rm -rf /var` deserves a hard deny, but `find /var -name '*.log' -delete` is a
 * real sysadmin task. Sweeping operations are judged against this stricter root
 * check so they prompt instead of blocking.
 */
function isFilesystemRoot(target: string): boolean {
  const clean = normalizePath(target);
  return /^(?:\/|~|\$HOME|[A-Za-z]:[\\/]?)$/.test(clean) || clean === '/*' || clean === '';
}

/** A bare `*` or `.` with recursion wipes the working directory. */
function isWildcardSweep(target: string): boolean {
  const clean = normalizePath(target);
  return clean === '*' || clean === '.' || clean === './*' || clean === '.*';
}

function recursiveDelete(segment: Segment): Finding | null {
  const isUnixRemover = REMOVERS.has(segment.argv0);
  const isPsRemover = PS_REMOVERS.has(segment.argv0);
  if (!isUnixRemover && !isPsRemover) return null;

  const recursive =
    segment.argv0 === 'rmdir' ||
    hasFlag(segment.argv, { short: ['r', 'R'], long: ['recursive', 'Recurse'] }) ||
    segment.argv.some((t) => /^-Recurse$/i.test(t));

  const targets = operands(segment.argv).filter((t) => !/^-/.test(t));

  for (const target of targets) {
    if (isCatastrophic(target)) {
      return finding(
        'fs.destroy-root',
        'deny',
        `This deletes \`${target}\` — a system or home root. No development task needs that.`,
      );
    }
    if (recursive && isWildcardSweep(target)) {
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
    if (isCatastrophic(target)) {
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
