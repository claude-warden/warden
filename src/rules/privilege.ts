/**
 * Privilege and system integrity.
 *
 * Turning off a firewall or a malware scanner is the step that makes everything
 * after it easier, and it is never part of writing software. Adding users and
 * editing sudoers are prompted rather than denied because infrastructure work is a
 * legitimate, if narrow, use case.
 */

import type { Finding, RuleContext, RuleFn, Segment } from '../types.js';
import { hasFlag, operands } from './shell.js';

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'privilege' });

/** Security software being switched off. */
function disablesProtection(segment: Segment): Finding | null {
  const raw = segment.raw.toLowerCase();

  if (segment.argv0 === 'set-mppreference' && /disablerealtimemonitoring\s+\$?true/i.test(raw)) {
    return finding('priv.disable-defender', 'deny', 'This turns off Windows Defender real-time protection.');
  }

  if (segment.argv0 === 'csrutil' && segment.argv.includes('disable')) {
    return finding('priv.disable-sip', 'deny', 'This disables macOS System Integrity Protection.');
  }

  if (segment.argv0 === 'spctl' && raw.includes('--master-disable')) {
    return finding('priv.disable-gatekeeper', 'deny', 'This disables macOS Gatekeeper, allowing unsigned code to run.');
  }

  if ((segment.argv0 === 'ufw' || segment.argv0 === 'firewall-cmd') && raw.includes('disable')) {
    return finding('priv.disable-firewall', 'deny', 'This disables the system firewall.');
  }

  if (segment.argv0 === 'netsh' && /advfirewall.*state\s+off/i.test(raw)) {
    return finding('priv.disable-firewall', 'deny', 'This turns the Windows firewall off.');
  }

  if (segment.argv0 === 'setenforce' && segment.argv.includes('0')) {
    return finding('priv.disable-selinux', 'ask', 'This puts SELinux into permissive mode.');
  }

  if (segment.argv0 === 'systemctl' && segment.argv.includes('stop') &&
      segment.argv.some((t) => /firewalld|ufw|apparmor|auditd/i.test(t))) {
    return finding('priv.stop-security-service', 'deny', 'This stops a running security service.');
  }

  return null;
}

/** Creating accounts or widening sudo rights. */
function grantsAccess(segment: Segment): Finding | null {
  if (['useradd', 'adduser', 'net'].includes(segment.argv0)) {
    const addingUser = segment.argv0 !== 'net' || /user\s+\S+\s+.*\/add/i.test(segment.raw);
    if (addingUser) {
      return finding('priv.add-user', 'ask', 'This creates a new system user account.');
    }
  }

  if (['usermod', 'gpasswd'].includes(segment.argv0) &&
      segment.argv.some((t) => /^(?:sudo|wheel|admin|root|Administrators)$/i.test(t))) {
    return finding('priv.grant-admin', 'ask', 'This adds an account to an administrative group.');
  }

  if (segment.argv0 === 'visudo' || segment.tokens.some((t) => /[\\/]etc[\\/]sudoers/.test(t))) {
    return finding('priv.edit-sudoers', 'ask', 'This edits sudo permissions.');
  }

  // A setuid-root binary runs as root no matter who launches it.
  if (segment.argv0 === 'chmod' && operands(segment.argv).some((t) => /^[+ ]?[u]?\+s$/.test(t) || /^[24][0-7]{3}$/.test(t))) {
    return finding('priv.setuid', 'ask', 'This sets the setuid bit, letting the file run with its owner’s privileges.');
  }

  return null;
}

/** Killing PID 1 or halting the box mid-session. */
function haltsSystem(segment: Segment): Finding | null {
  if (segment.argv0 === 'kill' && hasFlag(segment.argv, { short: ['9'] }) && operands(segment.argv).includes('1')) {
    return finding('priv.kill-init', 'deny', 'This kills PID 1, which takes the whole system down.');
  }

  if (['shutdown', 'reboot', 'halt', 'poweroff'].includes(segment.argv0)) {
    return finding('priv.shutdown', 'ask', `\`${segment.argv0}\` restarts or powers off this machine.`);
  }

  return null;
}

/**
 * The classic fork bomb.
 *
 * Checked against the whole command rather than a segment, because the payload is
 * built out of the very characters the parser splits on — by the time it is
 * segmented, the shape is gone.
 */
const forkBomb: RuleFn = (ctx: RuleContext) => {
  const compact = ctx.command.replace(/\s+/g, '');

  // Cheap literal gate before the regex. Every bomb of this shape defines a
  // function, so a command without `(){` cannot be one — and this skips the
  // pattern entirely for the ~100% of real commands that are not fork bombs.
  if (!compact.includes('(){')) return null;
  if (!FORK_BOMB.test(compact)) return null;

  return finding('priv.fork-bomb', 'deny', 'This is a fork bomb — it will exhaust the machine’s process table.');
};

/**
 * `name(){name|name&};` — the recursive self-pipe, with `:` as its classic name.
 *
 * Every quantifier is bounded. An unbounded `\w+` here backtracked quadratically:
 * a 40 KB command took 2.4 s and a 1 MB one hung the hook outright, which stalls
 * the user's session — a denial of service against the tool meant to prevent one.
 * Function names in real bombs are a couple of characters; 64 is already generous,
 * and the independent auditor covers shapes this deliberately narrow rule will not.
 */
const FORK_BOMB = /[\w:.]{1,64}\(\)\{[\w:.]{1,64}\|[\w:.]{1,64}&\};/;

const scan = (fn: (s: Segment) => Finding | null): RuleFn => (ctx: RuleContext) => {
  const findings: Finding[] = [];
  for (const segment of ctx.segments) {
    const result = fn(segment);
    if (result) findings.push(result);
  }
  return findings;
};

export const privilegeRules: RuleFn[] = [
  scan(disablesProtection),
  scan(grantsAccess),
  scan(haltsSystem),
  forkBomb,
];
