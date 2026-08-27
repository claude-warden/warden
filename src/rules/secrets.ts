/**
 * Credential access and exfiltration.
 *
 * The distinction that matters: *reading* a credential file is sometimes legitimate
 * (debugging a misconfigured `.env` is real work), so it prompts. Reading one in the
 * same breath as a network call is not something a development task does, so it is
 * denied outright.
 */

import type { Finding, RuleContext, RuleFn } from '../types.js';
import { isCredentialPath, NETWORK_TOOLS, READERS, targetPath } from './patterns.js';
import { operands } from './shell.js';

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'secrets' });

/** Every credential file mentioned anywhere in the command. */
function credentialTargets(ctx: RuleContext): string[] {
  const hits = new Set<string>();

  for (const segment of ctx.segments) {
    for (const token of segment.tokens) {
      const clean = token.replace(/^@/, '');
      if (isCredentialPath(clean)) hits.add(clean);
    }
  }

  return [...hits];
}

/** Does this command talk to the network at all? */
function networkSegments(ctx: RuleContext) {
  return ctx.segments.filter((s) => NETWORK_TOOLS.has(s.argv0));
}

/**
 * The exfiltration shape: a credential is read and a network tool appears in the
 * same command. Denied — there is no benign version of this.
 */
const exfiltratesCredentials: RuleFn = (ctx: RuleContext) => {
  const creds = credentialTargets(ctx);
  if (creds.length === 0) return null;

  const network = networkSegments(ctx);
  if (network.length === 0) return null;

  return finding(
    'secrets.exfiltrate',
    'deny',
    `This reads ${creds.join(', ')} and sends data over the network in the same command — that is credential exfiltration.`,
  );
};

/** `env | curl …` and `printenv | nc …` ship the whole environment off-box. */
const exfiltratesEnvironment: RuleFn = (ctx: RuleContext) => {
  const dumpsEnv = ctx.segments.some(
    (s) => (s.argv0 === 'env' || s.argv0 === 'printenv' || s.argv0 === 'set') && s.argv.length <= 2,
  );
  if (!dumpsEnv) return null;

  const piped = ctx.segments.some((s) => s.connector === '|' && NETWORK_TOOLS.has(s.argv0));
  if (!piped) return null;

  return finding(
    'secrets.env-exfiltrate',
    'deny',
    'This pipes the entire environment — including every API key in it — to a network tool.',
  );
};

/** Reading a credential file on its own: legitimate sometimes, worth a prompt always. */
const readsCredentials: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    if (!READERS.has(segment.argv0)) continue;
    const targets = operands(segment.argv).filter(isCredentialPath);
    if (targets.length === 0) continue;

    findings.push(
      finding(
        'secrets.read',
        'ask',
        `This reads ${targets.join(', ')}, which holds credentials.`,
      ),
    );
  }

  return findings;
};

/** The `Read` tool pointed straight at a credential file. */
const readToolOnCredentials: RuleFn = (ctx: RuleContext) => {
  if (ctx.toolName !== 'Read') return null;
  const target = targetPath(ctx.toolInput);
  if (!target || !isCredentialPath(target)) return null;

  return finding(
    'secrets.read-tool',
    'ask',
    `This reads \`${target}\`, which holds credentials.`,
  );
};

/** Writing a credential file into a place git will happily commit. */
const writesCredentialsIntoRepo: RuleFn = (ctx: RuleContext) => {
  if (ctx.toolName !== 'Write' && ctx.toolName !== 'Edit') return null;
  const target = targetPath(ctx.toolInput);
  if (!target) return null;

  const content = typeof ctx.toolInput.content === 'string' ? ctx.toolInput.content : '';
  if (!content) return null;

  const looksLikeKey = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk-ant-[A-Za-z0-9_-]{16,}|\bAKIA[A-Z0-9]{16}\b/.test(content);
  if (!looksLikeKey) return null;
  if (isCredentialPath(target)) return null; // A key belongs in a key file.

  return finding(
    'secrets.write-into-source',
    'ask',
    `This writes what looks like a real private key or API key into \`${target}\`, which is not a credential file.`,
  );
};

export const secretsRules: RuleFn[] = [
  exfiltratesCredentials,
  exfiltratesEnvironment,
  readsCredentials,
  readToolOnCredentials,
  writesCredentialsIntoRepo,
];
