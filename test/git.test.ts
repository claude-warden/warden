/**
 * The context-aware git checks, tested against real repositories.
 *
 * These use actual `git init` temp repos rather than mocks, because the whole claim
 * being tested is "Warden looks at the repository instead of pattern-matching the
 * command". A mock would test the mock.
 */

import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { clearEnvOverrides, decideCommand } from './helpers.js';

const repos: string[] = [];

function git(dir: string, ...args: string[]): void {
  execFileSync('git', ['-C', dir, ...args], { stdio: 'ignore', windowsHide: true });
}

/** A real repository with one commit, optionally left dirty. */
function makeRepo(dirty: boolean): string {
  const dir = mkdtempSync(join(tmpdir(), 'warden-git-'));
  repos.push(dir);

  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'test@example.com');
  git(dir, 'config', 'user.name', 'Warden Test');
  writeFileSync(join(dir, 'file.txt'), 'original\n');
  git(dir, 'add', 'file.txt');
  git(dir, 'commit', '-q', '-m', 'initial');

  if (dirty) {
    writeFileSync(join(dir, 'file.txt'), 'uncommitted change\n');
    writeFileSync(join(dir, 'another.txt'), 'new untracked file\n');
  }

  return dir;
}

before(clearEnvOverrides);

after(() => {
  for (const dir of repos) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Temp cleanup only; a leftover directory is not a test failure.
    }
  }
});

describe('git reset --hard is judged by what would be lost', () => {
  it('allows it when the working tree is clean', async () => {
    const decision = await decideCommand('git reset --hard HEAD', {}, makeRepo(false));
    assert.equal(decision.verdict, 'allow', `expected allow on a clean tree, got: ${decision.reason}`);
  });

  it('asks when there is uncommitted work to lose', async () => {
    const decision = await decideCommand('git reset --hard HEAD', {}, makeRepo(true));
    assert.equal(decision.verdict, 'ask', `expected ask on a dirty tree, got: ${decision.reason}`);
  });

  it('says how much would be lost, so the developer can judge', async () => {
    const decision = await decideCommand('git reset --hard', {}, makeRepo(true));
    assert.match(decision.reason, /\d+ uncommitted file/);
  });

  it('has no opinion outside a git repository', async () => {
    const notARepo = mkdtempSync(join(tmpdir(), 'warden-plain-'));
    repos.push(notARepo);
    const decision = await decideCommand('git reset --hard', {}, notARepo);
    assert.notEqual(decision.verdict, 'deny');
  });
});

describe('bulk checkout discards changes too', () => {
  it('asks before `git checkout .` on a dirty tree', async () => {
    const decision = await decideCommand('git checkout .', {}, makeRepo(true));
    assert.equal(decision.verdict, 'ask');
  });

  it('allows `git checkout .` when nothing would be lost', async () => {
    const decision = await decideCommand('git checkout .', {}, makeRepo(false));
    assert.equal(decision.verdict, 'allow');
  });
});

describe('other destructive git operations', () => {
  const clean = () => makeRepo(false);

  it('asks before `git clean -fdx` and explains the ignored-files risk', async () => {
    const decision = await decideCommand('git clean -fdx', {}, clean());
    assert.equal(decision.verdict, 'ask');
    assert.match(decision.reason, /ignored/i);
  });

  it('asks before force-pushing', async () => {
    const decision = await decideCommand('git push --force origin main', {}, clean());
    assert.equal(decision.verdict, 'ask');
    assert.match(decision.reason, /shared history/i);
  });

  it('does not prompt for the safe --force-with-lease variant', async () => {
    const decision = await decideCommand('git push --force-with-lease origin feature', {}, clean());
    assert.equal(decision.verdict, 'allow');
  });

  it('asks before dropping a stash', async () => {
    assert.equal((await decideCommand('git stash drop', {}, clean())).verdict, 'ask');
  });

  it('asks before force-deleting a branch', async () => {
    assert.equal((await decideCommand('git branch -D feature', {}, clean())).verdict, 'ask');
  });

  it('asks before rewriting history', async () => {
    assert.equal((await decideCommand('git filter-branch --tree-filter x HEAD', {}, clean())).verdict, 'ask');
  });

  it('asks before expiring the reflog, which is the recovery net', async () => {
    assert.equal(
      (await decideCommand('git reflog expire --expire=now --all', {}, clean())).verdict,
      'ask',
    );
  });

  it('leaves everyday git commands alone', async () => {
    const dir = clean();
    for (const command of ['git status', 'git log', 'git diff', 'git add .', 'git fetch origin']) {
      assert.equal((await decideCommand(command, {}, dir)).verdict, 'allow', `${command} should be silent`);
    }
  });
});
