/**
 * The audit trail.
 *
 * Two constraints shape this file. Hooks run in parallel, so every entry is written
 * as one complete line in a single append — never read-modify-write, which would
 * interleave and corrupt under concurrency. And nothing reaches disk unredacted,
 * because a log of blocked commands is exactly where a leaked credential would sit
 * forever.
 *
 * A logging failure never changes a verdict. Being unable to record a denial is bad;
 * failing to deny because recording failed would be much worse.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import { redact, redactDeep } from './redact.js';
import type { Decision } from './types.js';

export interface AuditEntry {
  ts: string;
  tool: string;
  cwd: string;
  verdict: Decision['verdict'];
  tier: Decision['tier'];
  reason: string;
  rules: string[];
  input: unknown;
  degraded?: boolean;
  sessionId?: string;
}

/** Keep the record readable — the full payload belongs in the transcript, not here. */
const MAX_INPUT_CHARS = 2000;

/** Rename the log aside once it gets large, keeping exactly one previous generation. */
function rotateIfNeeded(path: string, maxBytes: number): void {
  try {
    if (!existsSync(path)) return;
    if (statSync(path).size < maxBytes) return;
    renameSync(path, `${path}.1`);
  } catch {
    // Rotation is housekeeping; failing it must not stop the entry being written.
  }
}

/**
 * Append one decision. Everything is best-effort — a full disk or a read-only home
 * directory must not break the session.
 */
export function record(
  path: string,
  maxBytes: number,
  entry: Omit<AuditEntry, 'ts'>,
): void {
  try {
    mkdirSync(dirname(path), { recursive: true });
    rotateIfNeeded(path, maxBytes);

    const safe: AuditEntry = {
      ts: new Date().toISOString(),
      ...entry,
      reason: redact(entry.reason),
      input: redactDeep(entry.input),
    };

    let line = JSON.stringify(safe);
    if (line.length > MAX_INPUT_CHARS * 2) {
      safe.input = `${JSON.stringify(safe.input).slice(0, MAX_INPUT_CHARS)}…[truncated]`;
      line = JSON.stringify(safe);
    }

    // One complete line, one syscall — safe against parallel hook processes.
    appendFileSync(path, `${line}\n`, 'utf8');
  } catch {
    // Deliberately silent: stderr from a hook can surface as noise in the session.
  }
}

/** Read back the most recent entries, newest last. Malformed lines are skipped. */
export function readEntries(path: string, limit = 50): AuditEntry[] {
  try {
    if (!existsSync(path)) return [];
    const lines = readFileSync(path, 'utf8').split('\n').filter((l) => l.trim());
    return lines
      .slice(-limit)
      .map((line) => {
        try {
          return JSON.parse(line) as AuditEntry;
        } catch {
          return null;
        }
      })
      .filter((e): e is AuditEntry => e !== null);
  } catch {
    return [];
  }
}
