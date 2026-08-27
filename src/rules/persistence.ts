/**
 * Persistence — code that arranges to run again later.
 *
 * An attacker's goal after landing is to survive a reboot. Shell startup files,
 * cron, systemd units, launch agents, git hooks, and the Windows Run key are how
 * that is done, and none of them are things an agent edits during ordinary
 * development. These prompt rather than deny because dotfile editing is a real, if
 * uncommon, request.
 */

import type { Finding, RuleContext, RuleFn } from '../types.js';
import { isStartupFile, targetPath, WRITE_TOOLS } from './patterns.js';
import { operands } from './shell.js';

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'persistence' });

/** Appending to a shell rc file makes code run on every future session. */
const writesStartupFile: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  if (WRITE_TOOLS.has(ctx.toolName)) {
    const target = targetPath(ctx.toolInput);
    if (target && isStartupFile(target)) {
      findings.push(
        finding(
          'persist.write-startup',
          'ask',
          `\`${target}\` runs automatically — anything written there executes on every new session.`,
        ),
      );
    }
  }

  for (const segment of ctx.segments) {
    // Shell redirection into a startup file, e.g. `echo evil >> ~/.bashrc`.
    const redirect = segment.raw.match(/>>?\s*("?[^\s"']+"?)/);
    if (redirect?.[1] && isStartupFile(redirect[1])) {
      findings.push(
        finding(
          'persist.append-startup',
          'ask',
          `This appends to \`${redirect[1].replace(/"/g, '')}\`, which runs on every new shell session.`,
        ),
      );
    }

    for (const target of operands(segment.argv)) {
      if (isStartupFile(target) && ['tee', 'cp', 'mv', 'ln', 'install'].includes(segment.argv0)) {
        findings.push(
          finding('persist.replace-startup', 'ask', `This modifies \`${target}\`, a shell startup file.`),
        );
      }
    }
  }

  return findings;
};

/** Scheduled execution: cron, at, systemd timers, launchd, Windows tasks. */
const schedulesExecution: RuleFn = (ctx: RuleContext) => {
  const findings: Finding[] = [];

  for (const segment of ctx.segments) {
    if (segment.argv0 === 'crontab' && !segment.argv.includes('-l')) {
      findings.push(finding('persist.crontab', 'ask', 'This modifies the crontab, scheduling code to run automatically.'));
    }

    if (segment.argv0 === 'at' || segment.argv0 === 'batch') {
      findings.push(finding('persist.at', 'ask', `\`${segment.argv0}\` schedules a command to run later.`));
    }

    if (segment.argv0 === 'schtasks' && segment.argv.some((t) => /^\/create$/i.test(t))) {
      findings.push(finding('persist.schtasks', 'ask', 'This creates a Windows scheduled task.'));
    }

    if (segment.argv0 === 'launchctl' && segment.argv.some((t) => ['load', 'bootstrap', 'enable'].includes(t))) {
      findings.push(finding('persist.launchctl', 'ask', 'This registers a macOS launch agent, which runs automatically.'));
    }

    if (segment.argv0 === 'systemctl' && segment.argv.some((t) => ['enable', 'link'].includes(t))) {
      findings.push(finding('persist.systemd', 'ask', 'This enables a systemd unit, which runs on boot.'));
    }

    // Windows Run keys are the classic autostart location.
    if ((segment.argv0 === 'reg' || segment.argv0 === 'new-itemproperty' || segment.argv0 === 'set-itemproperty') &&
        /currentversion[\\/]+run/i.test(segment.raw)) {
      findings.push(finding('persist.run-key', 'ask', 'This writes a Windows autostart registry key.'));
    }
  }

  return findings;
};

/** Git hooks execute on ordinary git commands, which makes them a quiet foothold. */
const writesGitHook: RuleFn = (ctx: RuleContext) => {
  const isHookPath = (p: string) => /[\\/]\.git[\\/]hooks[\\/][a-z-]+$/i.test(p.replace(/["']/g, ''));

  if (WRITE_TOOLS.has(ctx.toolName)) {
    const target = targetPath(ctx.toolInput);
    if (target && isHookPath(target)) {
      return finding(
        'persist.git-hook',
        'ask',
        `\`${target}\` is a git hook — it will execute automatically on future git commands.`,
      );
    }
  }

  for (const segment of ctx.segments) {
    if (segment.tokens.some(isHookPath) && segment.argv0 !== 'cat' && segment.argv0 !== 'ls') {
      return finding('persist.git-hook-shell', 'ask', 'This modifies a git hook, which runs automatically on git commands.');
    }
  }

  return null;
};

/** Adding an SSH key grants durable remote access. */
const addsAuthorizedKey: RuleFn = (ctx: RuleContext) => {
  if (!/authorized_keys/i.test(ctx.command) && !/authorized_keys/i.test(targetPath(ctx.toolInput))) return null;

  const writing =
    WRITE_TOOLS.has(ctx.toolName) ||
    ctx.segments.some((s) => />>?/.test(s.raw) || ['tee', 'cp', 'mv'].includes(s.argv0));

  if (!writing) return null;

  return finding(
    'persist.authorized-keys',
    'deny',
    'This adds an SSH key to `authorized_keys`, granting permanent remote login to this machine.',
  );
};

export const persistenceRules: RuleFn[] = [
  writesStartupFile,
  schedulesExecution,
  writesGitHook,
  addsAuthorizedKey,
];
