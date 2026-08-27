/**
 * Content inspection for file writes.
 *
 * The original design only watched *commands*, which left the obvious gap: the
 * request that started this project asks for a check on the agent's **work**, and a
 * backdoor arrives as a `Write`, not as `rm -rf`. This is deliberately narrow — a
 * handful of high-signal patterns, not a code review. Broad heuristics here would
 * flag ordinary code and get the whole tool switched off.
 */

import type { Finding, RuleContext, RuleFn } from '../types.js';
import { targetPath, WRITE_TOOLS } from './patterns.js';

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'content' });

/** The text this write would put on disk, whichever tool is doing the writing. */
function writtenText(ctx: RuleContext): string {
  if (!WRITE_TOOLS.has(ctx.toolName)) return '';

  const direct = ctx.toolInput.content ?? ctx.toolInput.new_string ?? ctx.toolInput.new_source;
  if (typeof direct === 'string') return direct;

  // MultiEdit hands over a list of replacements rather than one string.
  const edits = ctx.toolInput.edits;
  if (Array.isArray(edits)) {
    return edits
      .map((e) => (e && typeof e === 'object' ? String((e as Record<string, unknown>).new_string ?? '') : ''))
      .join('\n');
  }

  return '';
}

/** An install script runs on `npm install`, before anyone reads the package. */
const addsInstallScript: RuleFn = (ctx: RuleContext) => {
  const target = targetPath(ctx.toolInput);
  if (!/package\.json$/i.test(target)) return null;

  const text = writtenText(ctx);
  if (!/"(?:pre|post)install"\s*:/.test(text)) return null;

  return finding(
    'content.install-script',
    'ask',
    'This adds a `postinstall`/`preinstall` script to package.json — it will run automatically on the next install.',
  );
};

/** A shell payload embedded in a source file is not a coding pattern. */
const embedsShellPayload: RuleFn = (ctx: RuleContext) => {
  const text = writtenText(ctx);
  if (!text) return null;

  if (/(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b/.test(text)) {
    return finding(
      'content.embedded-pipe-to-shell',
      'deny',
      'This writes a `curl … | sh` payload into a file, which will execute remote code whenever it runs.',
    );
  }

  if (/\/dev\/tcp\/|nc\s+-e\s|socat\s+.*EXEC:/.test(text)) {
    return finding(
      'content.embedded-reverse-shell',
      'deny',
      'This writes reverse-shell code into a file.',
    );
  }

  return null;
};

/** Code that reads secrets and posts them somewhere is the exfiltration shape. */
const exfiltratingCode: RuleFn = (ctx: RuleContext) => {
  const text = writtenText(ctx);
  if (!text) return null;

  const readsSecrets = /process\.env|os\.environ|ENV\[|getenv\(|readFileSync\([^)]*\.env|\.aws[\\/]credentials|id_rsa/.test(text);
  if (!readsSecrets) return null;

  // A hardcoded external destination — not a configured one, which is normal.
  const hardcodedRemote =
    /(?:fetch|axios|requests\.post|urlopen|http\.request|XMLHttpRequest)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(text) ||
    /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/.test(text);

  if (!hardcodedRemote) return null;

  return finding(
    'content.exfiltrating-code',
    'ask',
    'This writes code that reads environment secrets and sends them to a hardcoded external address.',
  );
};

/** A large opaque blob that gets decoded and executed hides its own intent. */
const obfuscatedPayload: RuleFn = (ctx: RuleContext) => {
  const text = writtenText(ctx);
  if (!text) return null;

  const hasBlob = /['"`][A-Za-z0-9+/]{200,}={0,2}['"`]/.test(text);
  if (!hasBlob) return null;

  const decodesAndRuns =
    /(?:eval|new\s+Function|exec|execSync|spawnSync|child_process)/.test(text) &&
    /(?:atob|Buffer\.from|base64\.b64decode|fromCharCode)/.test(text);

  if (!decodesAndRuns) return null;

  return finding(
    'content.obfuscated-payload',
    'deny',
    'This writes an encoded blob that is decoded and executed at runtime — a standard way to hide malicious code from review.',
  );
};

export const contentRules: RuleFn[] = [
  addsInstallScript,
  embedsShellPayload,
  exfiltratingCode,
  obfuscatedPayload,
];
