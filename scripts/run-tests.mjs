#!/usr/bin/env node
/**
 * Test runner entry point.
 *
 * This exists because `node --test dist-test/test/*.test.js` is not portable, in two
 * separate ways that only show up together:
 *
 *   - The glob is expanded by the *shell*. bash does it; PowerShell does not, so on
 *     Windows the literal `*.test.js` reaches node and matches nothing.
 *   - Node only learned to expand globs itself in v21, so on Node 20 quoting the
 *     pattern does not rescue it either.
 *
 * Passing a directory instead is documented to work, but does not reliably do so
 * across versions and platforms. Listing the files here removes all of it: no shell
 * involvement, no version-dependent glob support, same behaviour everywhere.
 *
 * Optional argument filters by substring, e.g. `node scripts/run-tests.mjs smoke`.
 */

import { spawn } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const testDir = join(root, 'dist-test', 'test');

if (!existsSync(testDir)) {
  console.error(`No compiled tests at ${testDir}. Run \`npm run pretest\` (or \`npm test\`, which does it for you).`);
  process.exit(1);
}

const filter = process.argv[2];
const files = readdirSync(testDir)
  .filter((name) => name.endsWith('.test.js'))
  .filter((name) => !filter || name.includes(filter))
  .map((name) => join(testDir, name))
  .sort();

if (files.length === 0) {
  console.error(filter ? `No test files matching "${filter}".` : 'No test files found.');
  process.exit(1);
}

const child = spawn(process.execPath, ['--test', ...files], { stdio: 'inherit' });
child.on('exit', (code, signal) => process.exit(signal ? 1 : (code ?? 1)));
child.on('error', (err) => {
  console.error(`Could not start the test runner: ${err.message}`);
  process.exit(1);
});
