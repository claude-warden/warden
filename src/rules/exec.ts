/**
 * Remote code execution — running code fetched from the internet.
 *
 * `curl … | sh` is the canonical prompt-injection payload: it turns one poisoned
 * instruction into arbitrary code on the machine. There is no version of this that a
 * careful engineer does by accident, so it is denied rather than prompted.
 */

import type { Finding, RuleContext, RuleFn } from '../types.js';
import { DOWNLOADERS, INTERPRETERS } from './patterns.js';

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'exec' });

/** The classic: something downloads, and its output is piped into a shell. */
const pipeToShell: RuleFn = (ctx: RuleContext) => {
  for (let i = 1; i < ctx.segments.length; i++) {
    const current = ctx.segments[i]!;
    const previous = ctx.segments[i - 1]!;

    if (current.connector !== '|') continue;
    if (!INTERPRETERS.has(current.argv0)) continue;
    if (!DOWNLOADERS.has(previous.argv0)) continue;

    return finding(
      'exec.pipe-to-shell',
      'deny',
      `This downloads a script and executes it immediately (\`${previous.argv0} … | ${current.argv0}\`). Whatever that URL serves runs with your permissions.`,
    );
  }

  return null;
};

/**
 * `eval "$(curl …)"` and `iex (iwr …)` — the same attack wearing a different hat.
 * The shell parser lifts command substitutions into their own segments, so we look
 * for a downloader and an evaluator coexisting in one command.
 */
const evalOfDownload: RuleFn = (ctx: RuleContext) => {
  const evaluates = ctx.segments.some(
    (s) => s.argv0 === 'eval' || s.argv0 === 'iex' || s.argv0 === 'invoke-expression',
  );
  if (!evaluates) return null;

  const downloads = ctx.segments.find((s) => DOWNLOADERS.has(s.argv0));
  if (!downloads) return null;

  return finding(
    'exec.eval-download',
    'deny',
    'This evaluates the output of a network download as code — the same risk as `curl | sh`, just written differently.',
  );
};

/** `bash <(curl …)` — process substitution instead of a pipe. */
const processSubstitution: RuleFn = (ctx: RuleContext) => {
  if (!/<\(\s*(?:curl|wget|fetch)\b/i.test(ctx.command)) return null;

  return finding(
    'exec.process-substitution',
    'deny',
    'This executes a downloaded script through process substitution — remote code execution.',
  );
};

/** Decoding an opaque blob straight into a shell hides what is being run. */
const decodeToShell: RuleFn = (ctx: RuleContext) => {
  for (let i = 1; i < ctx.segments.length; i++) {
    const current = ctx.segments[i]!;
    const previous = ctx.segments[i - 1]!;

    if (current.connector !== '|') continue;
    if (!INTERPRETERS.has(current.argv0)) continue;

    const decodes =
      (previous.argv0 === 'base64' && previous.argv.some((t) => /^-{1,2}(d|D|decode)$/.test(t))) ||
      previous.argv0 === 'xxd' ||
      (previous.argv0 === 'openssl' && previous.argv.includes('enc'));

    if (!decodes) continue;

    return finding(
      'exec.decode-to-shell',
      'deny',
      'This decodes an encoded payload and pipes it directly into a shell, which hides what is actually being executed.',
    );
  }

  return null;
};

/** Interpreters given inline code that then reaches out to the network. */
const inlineScriptWithNetwork: RuleFn = (ctx: RuleContext) => {
  for (const segment of ctx.segments) {
    if (!INTERPRETERS.has(segment.argv0)) continue;

    const inlineFlag = segment.argv.findIndex((t) => t === '-c' || t === '-e' || t === '--eval' || t === '--command');
    if (inlineFlag === -1) continue;

    const code = segment.argv[inlineFlag + 1] ?? '';
    if (!code) continue;

    const reachesOut = /\b(?:urllib|requests\.(?:get|post)|http\.client|socket\.|fetch\(|axios|net\.connect|Net::HTTP|LWP)/.test(code);
    const touchesSecrets = /\.env\b|id_rsa|credentials|SECRET|API_KEY|TOKEN/i.test(code);

    if (reachesOut && touchesSecrets) {
      return finding(
        'exec.inline-exfil',
        'deny',
        'This runs inline code that reads secrets and makes a network call.',
      );
    }

    if (reachesOut) {
      return finding(
        'exec.inline-network',
        'ask',
        `This runs an inline ${segment.argv0} script that makes network calls.`,
      );
    }
  }

  return null;
};

export const execRules: RuleFn[] = [
  pipeToShell,
  evalOfDownload,
  processSubstitution,
  decodeToShell,
  inlineScriptWithNetwork,
];
