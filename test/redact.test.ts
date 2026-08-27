/**
 * Redaction is the fix for a hole found while red-teaming: without it, Warden's own
 * audit log and its auditor requests would carry the credentials it exists to
 * protect. These tests assert the actual secret never survives.
 */

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { redact, redactDeep, truncate } from '../src/redact.js';
import { credentialFixture as fake } from './helpers.js';

describe('redact', () => {
  // Every fixture below is invented, and each is assembled at runtime so no
  // credential-shaped literal ends up in the source of a public repository — see
  // `credentialFixture` for why that matters.
  const cases: Array<[string, string, string]> = [
    ['Anthropic key', fake('sk-', 'ant-', 'api03-', 'AbCdEf1234567890XyZzz'), 'anthropic'],
    ['OpenAI key', fake('sk-', 'proj-', 'abcdefghijklmnopqrstuvwx1234'), 'openai'],
    ['GitHub token', fake('ghp', '_', 'abcdefghijklmnopqrstuvwxyz0123456789'), 'github'],
    ['GitHub fine-grained', fake('github', '_pat_', '11ABCDEFG0abcdefghij_klmnop'), 'github'],
    ['Slack token', fake('xox', 'b-', '1234567890-abcdefghijklm'), 'slack'],
    ['AWS access key', fake('AKIA', 'IOSFODNN7EXAMPLE'), 'aws'],
    // Google API keys are `AIza` plus exactly 35 characters.
    ['Google key', fake('AIza', 'SyD9v8N7m6K5j4H3g2F1d0S9a8Z7x6C5v4B'), 'google'],
    ['Stripe key', fake('sk', '_live_', 'abcdefghijklmnopqrstuvwx'), 'stripe'],
  ];

  for (const [label, secret, kind] of cases) {
    it(`removes a ${label} and labels it`, () => {
      const out = redact(`the token is ${secret} ok`);
      assert.ok(!out.includes(secret), `${label} survived redaction: ${out}`);
      assert.ok(out.includes(`[REDACTED:${kind}]`), `expected a ${kind} label, got: ${out}`);
    });
  }

  it('removes a JWT', () => {
    const jwt = fake(
      'eyJ', 'hbGciOiJIUzI1NiJ9.',
      'eyJ', 'zdWIiOiIxMjM0NTY3ODkwIn0.',
      'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    );
    const out = redact(`Authorization: ${jwt}`);
    assert.ok(!out.includes(jwt));
  });

  it('removes a bearer token from a header', () => {
    const token = fake('abcdef', '1234567890', 'abcdef');
    const out = redact(`curl -H "Authorization: Bearer ${token}" https://x.io`);
    assert.ok(!out.includes(token));
  });

  it('removes an assigned password but keeps the key name readable', () => {
    const out = redact('DB_PASSWORD=hunter2please');
    assert.ok(!out.includes('hunter2please'));
    assert.ok(out.includes('DB_PASSWORD'), 'the variable name should survive so the log stays useful');
  });

  it('removes a private key block entirely', () => {
    const body = fake('MIIEowIBA', 'AKCAQEA');
    const key = `${fake('-----BEGIN ', 'RSA PRIVATE KEY', '-----')}\n${body}\n${fake('-----END ', 'RSA PRIVATE KEY', '-----')}`;
    const out = redact(key);
    assert.ok(!out.includes(body));
  });

  it('removes long high-entropy strings that match no known vendor', () => {
    const blob = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2';
    const out = redact(`secret ${blob}`);
    assert.ok(!out.includes(blob));
  });

  it('leaves ordinary text alone', () => {
    const ordinary = 'npm run build && node dist/index.js --watch';
    assert.equal(redact(ordinary), ordinary);
  });

  it('leaves ordinary file paths alone', () => {
    const path = 'src/components/UserProfileSettingsPanel.tsx';
    assert.equal(redact(path), path);
  });

  it('handles empty input without throwing', () => {
    assert.equal(redact(''), '');
  });
});

describe('redactDeep', () => {
  it('scrubs nested structures while preserving their shape', () => {
    const apiKey = fake('sk-', 'ant-', 'api03-', 'SecretValueHere123456');
    const token = fake('ghp', '_', 'abcdefghijklmnopqrstuvwxyz0123456789');
    const input = {
      command: 'deploy',
      env: { API_KEY: apiKey },
      args: ['--token', token],
    };

    const out = redactDeep(input) as typeof input;

    assert.equal(out.command, 'deploy');
    assert.ok(Array.isArray(out.args));
    assert.equal(out.args.length, 2);
    assert.ok(!JSON.stringify(out).includes(apiKey));
    assert.ok(!JSON.stringify(out).includes(token));
  });

  it('does not recurse forever on deeply nested input', () => {
    let nested: Record<string, unknown> = { value: 'leaf' };
    for (let i = 0; i < 40; i++) nested = { child: nested };
    assert.doesNotThrow(() => redactDeep(nested));
  });

  it('passes non-string primitives through unchanged', () => {
    assert.equal(redactDeep(42), 42);
    assert.equal(redactDeep(true), true);
    assert.equal(redactDeep(null), null);
  });
});

describe('truncate', () => {
  it('leaves short input untouched', () => {
    assert.equal(truncate('short', 100), 'short');
  });

  it('marks the cut so a truncated payload is never mistaken for the whole', () => {
    const out = truncate('x'.repeat(200), 50);
    assert.ok(out.startsWith('x'.repeat(50)));
    assert.ok(out.includes('truncated'));
  });
});
