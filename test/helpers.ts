/**
 * Shared test helpers.
 *
 * Everything routes through `decide()` rather than calling rule functions directly.
 * That is deliberate: the red team identified the shell normalizer as a
 * silent-poisoning risk, where a regression would leave rules dead while their own
 * unit tests still passed. Driving the real pipeline means a normalizer break shows
 * up as a rule failure.
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_CONFIG, type WardenConfig } from '../src/config.js';
import { decide } from '../src/pipeline.js';
import type { Decision, Verdict } from '../src/types.js';

/** A scratch directory per run, so tests never write into the developer's home. */
export const TEST_HOME = mkdtempSync(join(tmpdir(), 'warden-test-'));

/** Offline config: deterministic rules only, so tests never touch the network. */
export const OFFLINE: WardenConfig = {
  ...DEFAULT_CONFIG,
  tier2: false,
  logPath: join(TEST_HOME, 'audit.jsonl'),
};

/** Run a shell command through the whole pipeline and return the decision. */
export async function decideCommand(
  command: string,
  overrides: Partial<WardenConfig> = {},
  cwd = process.cwd(),
): Promise<Decision> {
  return decide(
    { tool_name: 'Bash', tool_input: { command }, cwd },
    { ...OFFLINE, ...overrides },
  );
}

/** Just the verdict, for the many cases where that is all we assert on. */
export async function verdictFor(command: string, cwd?: string): Promise<Verdict> {
  return (await decideCommand(command, {}, cwd)).verdict;
}

/** Run a non-Bash tool call through the pipeline. */
export async function decideTool(
  toolName: string,
  toolInput: Record<string, unknown>,
  overrides: Partial<WardenConfig> = {},
): Promise<Decision> {
  return decide(
    { tool_name: toolName, tool_input: toolInput, cwd: process.cwd() },
    { ...OFFLINE, ...overrides },
  );
}

/** Make sure an environment escape hatch from the outer shell cannot skew results. */
export function clearEnvOverrides(): void {
  delete process.env.WARDEN_DISABLE;
  delete process.env.WARDEN_AUDITOR;
}

/**
 * Assemble a credential-shaped test fixture at runtime.
 *
 * These fixtures have to match real credential formats exactly, or they would not
 * exercise the redaction patterns at all. Writing them as literals has two costs in a
 * public repository: secret scanners block the push, and anyone auditing the source
 * finds strings that look like live keys sitting in the tree forever.
 *
 * Joining the parts keeps the runtime value byte-identical to a real key shape while
 * leaving no scannable literal in the source. The value is still fake — every one of
 * these is invented.
 */
export function credentialFixture(...parts: string[]): string {
  return parts.join('');
}
