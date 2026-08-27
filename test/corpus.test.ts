/**
 * The false-positive guard.
 *
 * The red team's top-ranked failure mode was not "Warden misses an attack" — it was
 * "Warden interrupts ordinary work until someone uninstalls it". An uninstalled tool
 * protects nobody, so this corpus of everyday commands is treated as a hard
 * requirement: every one must pass without a prompt.
 *
 * It also measures how often tier 1 has no opinion, because that number is what
 * decides whether the auditor fires constantly (slow and costly) or rarely.
 */

import { strict as assert } from 'node:assert';
import { before, describe, it } from 'node:test';
import { evaluate, verdictOf } from '../src/rules/index.js';
import { parseCommand } from '../src/rules/shell.js';
import { clearEnvOverrides, decideCommand } from './helpers.js';

before(clearEnvOverrides);

/** Commands a developer or agent runs constantly. None may prompt or block. */
export const ORDINARY_COMMANDS = [
  'ls -la',
  'pwd',
  'cat README.md',
  'head -n 20 src/index.ts',
  'grep -rn "TODO" src/',
  'rg "useEffect" --type ts',
  'find src -name "*.test.ts"',
  'wc -l src/*.ts',
  'diff a.txt b.txt',
  'echo "hello"',
  'mkdir -p src/components',
  'touch src/components/Button.tsx',
  'cp src/a.ts src/b.ts',
  'npm install',
  'npm install lodash',
  'npm ci',
  'npm test',
  'npm run build',
  'npm run lint -- --fix',
  'npx tsc --noEmit',
  'pnpm install',
  'yarn build',
  'node dist/index.js',
  'node --test',
  'pytest tests/ -v',
  'python -m pytest',
  'go test ./...',
  'cargo build --release',
  'make build',
  'git status',
  'git diff --staged',
  'git log --oneline -20',
  'git add src/index.ts',
  'git commit -m "fix: handle empty input"',
  'git fetch origin',
  'git branch -a',
  'git show HEAD',
  'git rev-parse --abbrev-ref HEAD',
  'docker ps',
  'docker build -t app .',
  'kubectl get pods',
  'curl -s https://api.github.com/repos/x/y',
  'curl -s https://api.example.com/v1/data | jq ".items[0]"',
  'rm -rf node_modules',
  'rm -rf dist build',
  'tsc --watch',
  'eslint src --ext .ts',
  'prettier --write "src/**/*.ts"',
  'ps aux',
  'df -h',
  'which node',
  'NODE_ENV=production npm run build',
  'cd packages/api && npm test',
  'npm test && npm run build',
];

describe('ordinary development commands are never interrupted', () => {
  for (const command of ORDINARY_COMMANDS) {
    it(`allows \`${command}\``, async () => {
      const decision = await decideCommand(command);
      assert.equal(
        decision.verdict,
        'allow',
        `False positive on ordinary work.\n  command:  ${command}\n  verdict:  ${decision.verdict}\n  reason:   ${decision.reason}`,
      );
    });
  }
});

describe('tier-1 coverage', () => {
  it('recognises most ordinary commands outright, so the auditor stays idle', () => {
    let recognised = 0;
    const unrecognised: string[] = [];

    for (const command of ORDINARY_COMMANDS) {
      const ctx = {
        toolName: 'Bash',
        toolInput: { command },
        cwd: process.cwd(),
        command,
        segments: parseCommand(command),
      };
      const verdict = verdictOf(evaluate(ctx));
      if (verdict === 'unknown') unrecognised.push(command);
      else recognised++;
    }

    const rate = recognised / ORDINARY_COMMANDS.length;
    // Reported so the number is visible in test output, not just asserted on.
    console.log(
      `    tier-1 recognised ${recognised}/${ORDINARY_COMMANDS.length} (${Math.round(rate * 100)}%); ` +
        `would reach the auditor: ${unrecognised.length ? unrecognised.join(', ') : 'none'}`,
    );

    assert.ok(
      rate >= 0.85,
      `Only ${Math.round(rate * 100)}% of ordinary commands were recognised by tier 1. ` +
        `Everything else pays for an auditor call. Unrecognised: ${unrecognised.join(', ')}`,
    );
  });
});
