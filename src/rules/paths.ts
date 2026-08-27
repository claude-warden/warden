/**
 * Path normalization.
 *
 * This exists because adversarial probing found the rules were matching *spellings*
 * rather than *destinations*. `rm -rf /` was caught, while `rm -rf /.`, `rm -rf /..`,
 * `rm -rf //` and `rm -rf ${HOME}` all sailed through — the same catastrophic action,
 * written four other ways.
 *
 * Everything that compares a path against a dangerous location resolves it here
 * first, so a rule asks "where does this actually point" instead of "does this string
 * look like the one I remembered".
 */

/** Environment variables that expand to a user's home directory. */
const HOME_VARS = ['HOME', 'USERPROFILE', 'HOMEPATH'];

/**
 * Reduce a path to a canonical comparable form.
 *
 * Deliberately *logical*, not filesystem-backed: it never touches disk, so it is safe
 * on the hot path and gives the same answer for a path that does not exist yet.
 */
export function normalizeTarget(input: string): string {
  if (!input) return '';

  // Strip quoting the tokenizer may have left, then expand home references so
  // `~`, `$HOME` and `${USERPROFILE}` all collapse to the same marker.
  let path = input.replace(/["']/g, '').trim();
  if (!path) return '';

  for (const name of HOME_VARS) {
    path = path.replace(new RegExp(`\\$\\{${name}\\}|\\$${name}\\b`, 'g'), '~');
  }

  const isWindowsAbsolute = /^[A-Za-z]:[\\/]/.test(path);
  const driveLetter = isWindowsAbsolute ? path.slice(0, 2) : '';
  if (isWindowsAbsolute) path = path.slice(2);

  const startsAtRoot = /^[\\/]/.test(path);
  const startsAtHome = path === '~' || /^~[\\/]/.test(path);
  if (startsAtHome) path = path.slice(1);

  // Resolve `.` and `..` logically. `/..` is still the root — you cannot climb
  // above it — which is exactly the case that was slipping past the old check.
  const resolved: string[] = [];
  for (const part of path.split(/[\\/]+/)) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (resolved.length > 0) resolved.pop();
      else if (startsAtHome) return '~/..';
      continue;
    }
    resolved.push(part);
  }

  const body = resolved.join('/');
  if (isWindowsAbsolute) return `${driveLetter}${body ? `/${body}` : '/'}`;
  if (startsAtHome) return body ? `~/${body}` : '~';
  if (startsAtRoot) return `/${body}`;
  return body;
}

/**
 * The top of the whole filesystem, or a user's entire home.
 *
 * Losing either of these ends the machine or the person's data, so nothing routine
 * ever targets them.
 */
export function isFilesystemRoot(target: string): boolean {
  const path = normalizeTarget(target);
  return path === '/' || path === '~' || path === '' || /^[A-Za-z]:\/$/.test(path);
}

/** Directories whose removal breaks the operating system. */
const SYSTEM_DIRS = new Set([
  'bin', 'boot', 'dev', 'etc', 'lib', 'lib64', 'proc', 'root', 'sbin', 'sys',
  'usr', 'var', 'home', 'opt', 'srv', 'windows', 'system32', 'users',
  'program files', 'program files (x86)', 'applications', 'library',
]);

/** A path no development task legitimately destroys. */
export function isCatastrophicPath(target: string): boolean {
  const path = normalizeTarget(target);
  if (isFilesystemRoot(path)) return true;

  // A wildcard directly under a root sweeps everything beneath it.
  if (/^(?:\/|~\/|[A-Za-z]:\/)\*$/.test(path)) return true;

  const windowsMatch = path.match(/^[A-Za-z]:\/([^/]+)\/?$/);
  if (windowsMatch?.[1]) return SYSTEM_DIRS.has(windowsMatch[1].toLowerCase());

  const unixMatch = path.match(/^\/([^/]+)\/?$/);
  if (unixMatch?.[1]) return SYSTEM_DIRS.has(unixMatch[1].toLowerCase());

  return false;
}

/** A bare wildcard or `.` — recursive deletion of the working directory. */
export function isWorkingDirectorySweep(target: string): boolean {
  const cleaned = target.replace(/["']/g, '').trim();
  if (cleaned === '*' || cleaned === '.' || cleaned === './*' || cleaned === '.*') return true;
  return normalizeTarget(cleaned) === '';
}

/**
 * True when a token's meaning depends on runtime state we cannot see.
 *
 * `$X -rf /` and `$CMD` are unanalyzable by construction — the honest response is to
 * say so and ask, rather than to report a confident `allow` about a command whose
 * identity is unknown.
 */
export function isDynamic(token: string): boolean {
  if (!token) return false;
  const withoutHome = HOME_VARS.reduce(
    (acc, name) => acc.replace(new RegExp(`\\$\\{${name}\\}|\\$${name}\\b`, 'g'), '~'),
    token,
  );
  return /\$\{?\w+\}?|`|\$\(/.test(withoutHome);
}
