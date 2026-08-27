/**
 * Tier orchestration: which tier answers, and what happens when something breaks.
 *
 * The behaviour under test is mostly about *not* getting in the way — the escape
 * hatch, the no-side-effect short circuit, and the rule that a Warden bug must never
 * cost a developer their tool call.
 */

import { strict as assert } from 'node:assert';
import { afterEach, before, describe, it } from 'node:test';
import { decide, REENTRANCY_ENV } from '../src/pipeline.js';
import { activeTiers, DEFAULT_CONFIG } from '../src/config.js';
import { clearEnvOverrides, OFFLINE } from './helpers.js';

before(clearEnvOverrides);
afterEach(clearEnvOverrides);

const call = (toolName: string, toolInput: Record<string, unknown> = {}) =>
  decide({ tool_name: toolName, tool_input: toolInput, cwd: process.cwd() }, OFFLINE);

describe('tier 0 — triage', () => {
  it('honours the WARDEN_DISABLE escape hatch before anything else runs', async () => {
    process.env.WARDEN_DISABLE = '1';
    const decision = await decide(
      { tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, cwd: process.cwd() },
      OFFLINE,
    );
    assert.equal(decision.verdict, 'allow');
    assert.equal(decision.tier, 0);
  });

  it('never audits its own calls', async () => {
    process.env[REENTRANCY_ENV] = '1';
    const decision = await decide(
      { tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, cwd: process.cwd() },
      OFFLINE,
    );
    assert.equal(decision.tier, 0);
  });

  it('respects the config master switch', async () => {
    const decision = await decide(
      { tool_name: 'Bash', tool_input: { command: 'rm -rf /' }, cwd: process.cwd() },
      { ...OFFLINE, enabled: false },
    );
    assert.equal(decision.verdict, 'allow');
  });

  it('short-circuits tools with no local side effects', async () => {
    for (const tool of ['Glob', 'Grep', 'TodoWrite', 'WebSearch']) {
      const decision = await call(tool, { pattern: '**/*.ts' });
      assert.equal(decision.tier, 0, `${tool} should not reach the rule engine`);
    }
  });

  it('does not short-circuit Read, because credential files matter', async () => {
    const decision = await call('Read', { file_path: '/project/.env' });
    assert.equal(decision.verdict, 'ask');
  });

  it('allows a payload with no tool name instead of failing', async () => {
    const decision = await decide({ cwd: process.cwd() }, OFFLINE);
    assert.equal(decision.verdict, 'allow');
  });
});

describe('tier 1 — rules', () => {
  it('answers destructive commands without any network call', async () => {
    const decision = await call('Bash', { command: 'rm -rf /' });
    assert.equal(decision.verdict, 'deny');
    assert.equal(decision.tier, 1);
  });

  it('does not pay for an audit on a low-risk tool that matched no rule', async () => {
    const decision = await call('Read', { file_path: '/project/src/app.ts' });
    assert.equal(decision.verdict, 'allow');
    assert.equal(decision.tier, 1);
  });

  it('respects disabled rules', async () => {
    const decision = await decide(
      { tool_name: 'Bash', tool_input: { command: 'npm publish' }, cwd: process.cwd() },
      { ...OFFLINE, disabledRules: ['supply.publish'] },
    );
    assert.equal(decision.verdict, 'allow');
  });

  it('handles a Bash call with no command field', async () => {
    const decision = await call('Bash', {});
    assert.equal(decision.verdict, 'allow');
  });

  it('handles an empty command string', async () => {
    const decision = await call('Bash', { command: '' });
    assert.equal(decision.verdict, 'allow');
  });
});

describe('tier 2 gating', () => {
  it('allows an unrecognised command when the auditor is switched off', async () => {
    const decision = await call('Bash', { command: 'obscure-internal-tool --run' });
    assert.equal(decision.verdict, 'allow');
    assert.equal(decision.tier, 1);
  });

  it('marks the decision degraded when the auditor is on but has no key', async () => {
    const decision = await decide(
      { tool_name: 'Bash', tool_input: { command: 'obscure-tool-two --run' }, cwd: process.cwd() },
      { ...OFFLINE, tier2: true, apiKeyCommand: null },
    );
    assert.equal(decision.degraded, true);
  });
});

describe('activeTiers reports honestly', () => {
  it('says why the auditor is inactive rather than implying protection', () => {
    const state = activeTiers({ ...DEFAULT_CONFIG, tier2: false });
    assert.equal(state.tier1, true);
    assert.equal(state.tier2, false);
    assert.match(state.reason, /switched off/i);
  });

  it('reports everything inactive when disabled', () => {
    const state = activeTiers({ ...DEFAULT_CONFIG, enabled: false });
    assert.equal(state.tier1, false);
    assert.match(state.reason, /disabled/i);
  });
});
