/**
 * Configuration and credential resolution.
 *
 * Two rules govern this file. It must never throw — a hand-broken config file
 * should degrade to defaults with a warning, never wedge someone's session. And it
 * must never put a resolved API key anywhere but the request it was fetched for.
 */

import { execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface WardenConfig {
  /** Master switch. */
  enabled: boolean;
  /** Whether the independent LLM auditor runs at all. */
  tier2: boolean;
  /** Auditor model. Haiku is the default because this runs per tool call. */
  model: string;
  /** Give up on the auditor after this long and fall back to tier 1. */
  timeoutMs: number;
  /**
   * What to do when the auditor cannot be reached.
   * `open` keeps working from tier 1 alone; `closed` escalates everything unknown.
   */
  failMode: 'open' | 'closed';
  /** Shell command that prints an API key — mirrors Claude Code's apiKeyHelper. */
  apiKeyCommand: string | null;
  /** Where decisions are recorded. */
  logPath: string;
  /** Rotate the log once it passes this size. */
  maxLogBytes: number;
  /** Rule ids to skip, for when a rule is wrong about your workflow. */
  disabledRules: string[];
}

/**
 * Both locations are overridable by environment variable. That is what lets the
 * integration tests run the real hook binary end to end without writing anything
 * into the developer's actual home directory.
 */
export const WARDEN_HOME = process.env.WARDEN_HOME || join(homedir(), '.claude', 'warden');
export const CONFIG_PATH = process.env.WARDEN_CONFIG || join(WARDEN_HOME, 'config.json');

export const DEFAULT_CONFIG: WardenConfig = {
  enabled: true,
  tier2: true,
  // Fires on every unclassified tool call, so it has to be fast and cheap.
  // Swap to `claude-sonnet-5` or `claude-opus-5` for a sharper, pricier auditor.
  model: 'claude-haiku-4-5',
  timeoutMs: 5000,
  failMode: 'open',
  apiKeyCommand: null,
  logPath: join(WARDEN_HOME, 'audit.jsonl'),
  maxLogBytes: 5 * 1024 * 1024,
  disabledRules: [],
};

/** Only these keys are honored; anything else in the file is ignored. */
function coerce(raw: Record<string, unknown>): Partial<WardenConfig> {
  const out: Partial<WardenConfig> = {};

  if (typeof raw.enabled === 'boolean') out.enabled = raw.enabled;
  if (typeof raw.tier2 === 'boolean') out.tier2 = raw.tier2;
  if (typeof raw.model === 'string' && raw.model) out.model = raw.model;
  if (typeof raw.timeoutMs === 'number' && raw.timeoutMs > 0) out.timeoutMs = raw.timeoutMs;
  if (raw.failMode === 'open' || raw.failMode === 'closed') out.failMode = raw.failMode;
  if (typeof raw.apiKeyCommand === 'string' && raw.apiKeyCommand) out.apiKeyCommand = raw.apiKeyCommand;
  if (typeof raw.logPath === 'string' && raw.logPath) out.logPath = raw.logPath;
  if (typeof raw.maxLogBytes === 'number' && raw.maxLogBytes > 0) out.maxLogBytes = raw.maxLogBytes;
  if (Array.isArray(raw.disabledRules)) {
    out.disabledRules = raw.disabledRules.filter((r): r is string => typeof r === 'string');
  }

  return out;
}

/**
 * Load config, falling back to defaults for anything missing or malformed.
 * A broken file costs you your customisations, not your session.
 */
export function loadConfig(path: string = CONFIG_PATH): WardenConfig {
  if (!existsSync(path)) return { ...DEFAULT_CONFIG };

  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ...DEFAULT_CONFIG };
    return { ...DEFAULT_CONFIG, ...coerce(parsed as Record<string, unknown>) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

/**
 * Find an API key, cheapest source first.
 *
 * The `apiKeyCommand` rung exists so a key can live in an OS keychain or secret
 * vault rather than an environment variable — the same idea as Claude Code's own
 * `apiKeyHelper`. The value is returned, never logged.
 */
export function resolveApiKey(config: WardenConfig): string | null {
  const fromEnv = process.env.WARDEN_API_KEY || process.env.ANTHROPIC_API_KEY;
  if (fromEnv) return fromEnv.trim();

  if (!config.apiKeyCommand) return null;

  try {
    const out = execSync(config.apiKeyCommand, {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    });
    return out.trim() || null;
  } catch {
    return null;
  }
}

/** Which tiers can actually run right now — used by `warden status` to be honest. */
export function activeTiers(config: WardenConfig): { tier1: boolean; tier2: boolean; reason: string } {
  if (!config.enabled) return { tier1: false, tier2: false, reason: 'Warden is disabled in config' };
  if (process.env.WARDEN_DISABLE) return { tier1: false, tier2: false, reason: 'WARDEN_DISABLE is set in this environment' };
  if (!config.tier2) return { tier1: true, tier2: false, reason: 'the auditor is switched off in config (tier2: false)' };
  if (!resolveApiKey(config)) {
    return { tier1: true, tier2: false, reason: 'no API key found — set ANTHROPIC_API_KEY or configure apiKeyCommand' };
  }
  return { tier1: true, tier2: true, reason: 'both tiers active' };
}
