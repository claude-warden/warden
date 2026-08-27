/**
 * Install and uninstall.
 *
 * These edit the file that controls whether Warden runs at all, so the bar is high:
 * never clobber someone else's hook, never duplicate on a second run, and leave the
 * file byte-for-byte restorable. Every case runs against a temp fixture — the real
 * `~/.claude/settings.json` is never touched by the suite.
 */

import { strict as assert } from 'node:assert';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { install, uninstall } from '../src/cli.js';

function fixture(contents?: unknown): string {
  const path = join(mkdtempSync(join(tmpdir(), 'warden-cli-')), 'settings.json');
  if (contents !== undefined) writeFileSync(path, `${JSON.stringify(contents, null, 2)}\n`);
  return path;
}

const read = (path: string) => JSON.parse(readFileSync(path, 'utf8'));

/** A pre-existing hook from another tool, which must survive untouched. */
const OTHER_HOOK = {
  matcher: 'Bash|Edit',
  hooks: [{ type: 'command', command: 'node /some/other/guardrails.mjs', timeout: 15 }],
};

describe('install', () => {
  it('creates the settings file when there is none', () => {
    const path = fixture();
    install(path);

    const settings = read(path);
    assert.equal(settings.hooks.PreToolUse.length, 1);

    // Assert on what the entry has to be to work — it must run this package's hook
    // module through node. The previous version of this test matched /warden/i
    // against the command, which only ever passed because the checkout directory
    // happened to be called "warden"; it went red the moment the repo was cloned
    // under any other name.
    const [entry] = settings.hooks.PreToolUse;
    assert.equal(entry.hooks[0].type, 'command');
    assert.match(entry.hooks[0].command, /^node ".*hook\.js"$/);
    assert.equal(entry.wardenManaged, true, 'our entry must be identifiable without reading the path');
  });

  it('matches every tool, since any tool can be dangerous', () => {
    const path = fixture();
    install(path);
    assert.equal(read(path).hooks.PreToolUse[0].matcher, '*');
  });

  it('leaves another tool’s hook alone', () => {
    const path = fixture({ hooks: { PreToolUse: [OTHER_HOOK] } });
    install(path);

    const entries = read(path).hooks.PreToolUse;
    assert.equal(entries.length, 2);
    assert.deepEqual(entries[0], OTHER_HOOK, 'the existing hook must survive verbatim');
  });

  it('preserves unrelated settings', () => {
    const path = fixture({ theme: 'dark', enabledPlugins: { x: true } });
    install(path);

    const settings = read(path);
    assert.equal(settings.theme, 'dark');
    assert.deepEqual(settings.enabledPlugins, { x: true });
  });

  it('preserves other hook events', () => {
    const path = fixture({ hooks: { PostToolUse: [OTHER_HOOK] } });
    install(path);

    const settings = read(path);
    assert.equal(settings.hooks.PostToolUse.length, 1);
    assert.equal(settings.hooks.PreToolUse.length, 1);
  });

  it('is idempotent — running twice does not install twice', () => {
    const path = fixture();
    install(path);
    install(path);

    assert.equal(read(path).hooks.PreToolUse.length, 1);
  });

  it('refuses to guess at a corrupted settings file', () => {
    const path = fixture();
    writeFileSync(path, '{ this is not json');

    assert.throws(() => install(path), /not valid JSON/);
  });
});

describe('uninstall', () => {
  it('restores the file to its original content', () => {
    const original = { theme: 'dark', hooks: { PreToolUse: [OTHER_HOOK] } };
    const path = fixture(original);
    const before = readFileSync(path, 'utf8');

    install(path);
    uninstall(path);

    assert.equal(readFileSync(path, 'utf8'), before, 'uninstall must be a clean reversal');
  });

  it('removes the hooks key entirely when we created it', () => {
    const path = fixture({ theme: 'dark' });
    install(path);
    uninstall(path);

    const settings = read(path);
    assert.equal(settings.hooks, undefined, 'no empty scaffolding should be left behind');
    assert.equal(settings.theme, 'dark');
  });

  it('says so plainly when Warden was not installed', () => {
    const path = fixture({ theme: 'dark' });
    const message = uninstall(path);

    assert.match(message, /not installed/i);
    assert.deepEqual(read(path), { theme: 'dark' });
  });

  it('never removes another tool’s hook', () => {
    const path = fixture({ hooks: { PreToolUse: [OTHER_HOOK] } });
    install(path);
    uninstall(path);

    assert.deepEqual(read(path).hooks.PreToolUse, [OTHER_HOOK]);
  });

  it('never removes a foreign hook that merely has "warden" in its path', () => {
    // Identifying our entry by looking for the word "warden" inside the command
    // silently deleted anything that lived under a path containing it — someone
    // whose user account or project is named warden would lose their own hook.
    const IMPOSTOR = {
      matcher: 'Bash',
      hooks: [{ type: 'command', command: 'node /home/warden/tools/other-guard.mjs', timeout: 10 }],
    };
    const path = fixture({ hooks: { PreToolUse: [IMPOSTOR] } });

    install(path);
    uninstall(path);

    assert.deepEqual(read(path).hooks.PreToolUse, [IMPOSTOR], 'a foreign hook must survive verbatim');
  });

  it('removes an entry installed from a different checkout', () => {
    // Uninstalling from a second clone must still find the first one's entry,
    // which is exactly what the marker is for — the paths will not match.
    const FROM_ELSEWHERE = {
      matcher: '*',
      wardenManaged: true,
      hooks: [{ type: 'command', command: 'node "/opt/somewhere/else/hook.js"', timeout: 15 }],
    };
    const path = fixture({ theme: 'dark', hooks: { PreToolUse: [FROM_ELSEWHERE] } });

    const message = uninstall(path);

    assert.match(message, /removed/i);
    assert.equal(read(path).hooks, undefined);
  });

  it('replaces rather than duplicates an entry from a different checkout', () => {
    const FROM_ELSEWHERE = {
      matcher: '*',
      wardenManaged: true,
      hooks: [{ type: 'command', command: 'node "/opt/somewhere/else/hook.js"', timeout: 15 }],
    };
    const path = fixture({ hooks: { PreToolUse: [FROM_ELSEWHERE] } });

    install(path);

    assert.equal(read(path).hooks.PreToolUse.length, 1, 'upgrading must not stack a second hook');
  });
});

describe('install and uninstall round-trip', () => {
  it('survives repeated cycles without drift', () => {
    const path = fixture({ hooks: { PreToolUse: [OTHER_HOOK] } });
    const before = readFileSync(path, 'utf8');

    for (let i = 0; i < 3; i++) {
      install(path);
      uninstall(path);
    }

    assert.equal(readFileSync(path, 'utf8'), before);
    assert.ok(existsSync(path));
  });
});
