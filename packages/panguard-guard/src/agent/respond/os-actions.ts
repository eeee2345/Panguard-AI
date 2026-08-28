/**
 * OS-level response actions: IP blocking, process killing, account disabling, file isolation.
 * Uses execFile (never exec) for all system commands to prevent command injection.
 *
 * @module @panguard-ai/panguard-guard/agent/respond/os-actions
 */

import { execFile } from 'node:child_process';
import { platform, homedir } from 'node:os';
import { appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type { ThreatVerdict, ResponseResult, EnforcementPolicy } from '../../types.js';
import { SAFETY_RULES, matchesFilePathAllowlist } from './safety-rules.js';
import {
  extractIP,
  extractPID,
  extractProcessName,
  extractUsername,
  extractFilePath,
} from './evidence-extractor.js';
import type { ActionManifest } from './action-manifest.js';
import type { EscalationTracker } from './escalation-tracker.js';

const logger = createLogger('panguard-guard:os-actions');

/** Promise wrapper for execFile */
export function execFilePromise(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 10000, windowsHide: true }, (error, stdout) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

/** Wait for a process to exit, return true if still alive after timeout */
async function waitForProcessExit(pid: number, timeoutMs: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      process.kill(pid, 0);
      await new Promise((resolve) => setTimeout(resolve, 500));
    } catch {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Block / Unblock IP
// ---------------------------------------------------------------------------

export interface BlockIPDeps {
  readonly additionalWhitelistedIPs: ReadonlySet<string>;
  readonly manifest: ActionManifest;
  readonly escalation: EscalationTracker;
  readonly unblockTimers: Map<string, ReturnType<typeof setTimeout>>;
  readonly policy: EnforcementPolicy;
}

export async function blockIP(verdict: ThreatVerdict, deps: BlockIPDeps): Promise<ResponseResult> {
  // Enforcement-policy gate: IP blocking must be explicitly enabled
  if (!deps.policy.blockIPs.enabled) {
    return {
      action: 'block_ip',
      success: false,
      details: 'IP blocking is disabled in enforcementPolicy.blockIPs.enabled',
      timestamp: new Date().toISOString(),
    };
  }

  const ip = extractIP(verdict);
  if (!ip) {
    return {
      action: 'block_ip',
      success: false,
      details: 'No IP address found in verdict evidence',
      timestamp: new Date().toISOString(),
    };
  }

  if (SAFETY_RULES.whitelistedIPs.has(ip) || deps.additionalWhitelistedIPs.has(ip)) {
    logger.warn(`Refusing to block whitelisted IP: ${ip}`);
    return {
      action: 'block_ip',
      success: false,
      details: `IP ${ip} is whitelisted and cannot be blocked`,
      timestamp: new Date().toISOString(),
      target: ip,
    };
  }

  if (!/^[\d.]+$/.test(ip) && !/^[a-fA-F\d:]+$/.test(ip)) {
    return {
      action: 'block_ip',
      success: false,
      details: `Invalid IP format: ${ip}`,
      timestamp: new Date().toISOString(),
      target: ip,
    };
  }

  const isRepeat = deps.escalation.isRepeatOffender(ip, SAFETY_RULES.escalationThreshold);
  const blockDuration = isRepeat
    ? SAFETY_RULES.repeatOffenderBlockDurationMs
    : SAFETY_RULES.defaultBlockDurationMs;

  const os = platform();
  try {
    if (os === 'darwin') {
      await execFilePromise('/sbin/pfctl', ['-t', 'panguard-guard_blocked', '-T', 'add', ip]);
    } else if (os === 'linux') {
      await execFilePromise('/sbin/iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
    } else if (os === 'win32') {
      await execFilePromise('netsh', [
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=PanguardGuard_Block_${ip}`,
        'dir=in',
        'action=block',
        `remoteip=${ip}`,
      ]);
    }

    const expiresAt = new Date(Date.now() + blockDuration).toISOString();
    const entry = deps.manifest.record('block_ip', ip, verdict, expiresAt);
    scheduleUnblock(ip, blockDuration, entry.id, deps);

    const durationStr = isRepeat ? '24h (repeat offender)' : '1h';
    logger.info(`Blocked IP: ${ip} for ${durationStr} (auto-unblock scheduled)`);

    return {
      action: 'block_ip',
      success: true,
      details: `IP ${ip} blocked via ${os} firewall for ${durationStr}. Auto-unblock at ${expiresAt}`,
      timestamp: new Date().toISOString(),
      target: ip,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to block IP ${ip}: ${msg}`);
    return {
      action: 'block_ip',
      success: false,
      details: `Failed to block IP ${ip}: ${msg}`,
      timestamp: new Date().toISOString(),
      target: ip,
    };
  }
}

export async function unblockIP(
  ip: string,
  unblockTimers: Map<string, ReturnType<typeof setTimeout>>
): Promise<ResponseResult> {
  const os = platform();
  try {
    if (os === 'darwin') {
      await execFilePromise('/sbin/pfctl', ['-t', 'panguard-guard_blocked', '-T', 'delete', ip]);
    } else if (os === 'linux') {
      await execFilePromise('/sbin/iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
    } else if (os === 'win32') {
      await execFilePromise('netsh', [
        'advfirewall',
        'firewall',
        'delete',
        'rule',
        `name=PanguardGuard_Block_${ip}`,
      ]);
    }

    const timer = unblockTimers.get(ip);
    if (timer) {
      clearTimeout(timer);
      unblockTimers.delete(ip);
    }

    logger.info(`Unblocked IP: ${ip}`);
    return {
      action: 'block_ip',
      success: true,
      details: `IP ${ip} unblocked`,
      timestamp: new Date().toISOString(),
      target: ip,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to unblock IP ${ip}: ${msg}`);
    return {
      action: 'block_ip',
      success: false,
      details: `Failed to unblock IP ${ip}: ${msg}`,
      timestamp: new Date().toISOString(),
      target: ip,
    };
  }
}

function scheduleUnblock(ip: string, durationMs: number, entryId: string, deps: BlockIPDeps): void {
  const existing = deps.unblockTimers.get(ip);
  if (existing) clearTimeout(existing);

  const timer = setTimeout(async () => {
    logger.info(`Auto-unblock timer expired for IP: ${ip}`);
    const result = await unblockIP(ip, deps.unblockTimers);
    if (result.success) {
      deps.manifest.markRolledBack(entryId);
    }
    deps.unblockTimers.delete(ip);
  }, durationMs);

  if (timer.unref) timer.unref();
  deps.unblockTimers.set(ip, timer);
}

// ---------------------------------------------------------------------------
// Kill Process
// ---------------------------------------------------------------------------

export interface KillProcessDeps {
  readonly manifest: ActionManifest;
  readonly policy: EnforcementPolicy;
}

export async function killProcess(
  verdict: ThreatVerdict,
  deps: KillProcessDeps
): Promise<ResponseResult> {
  const { manifest, policy } = deps;

  // Enforcement-policy gate: process killing must be explicitly enabled
  if (!policy.killProcesses.enabled) {
    return {
      action: 'kill_process',
      success: false,
      details: 'Process killing is disabled in enforcementPolicy.killProcesses.enabled',
      timestamp: new Date().toISOString(),
    };
  }

  const pid = extractPID(verdict);
  if (!pid) {
    return {
      action: 'kill_process',
      success: false,
      details: 'No PID found in verdict evidence',
      timestamp: new Date().toISOString(),
    };
  }

  const processName = extractProcessName(verdict);

  // Process-name allowlist: even with enabled=true, only processes matching
  // the operator's allowlist may be killed. Defence against LLM-driven evidence
  // claiming an unrelated process (e.g. customer's prod server) is the target.
  if (processName) {
    const { matchesProcessAllowlist } = await import('./safety-rules.js');
    if (!matchesProcessAllowlist(processName, policy.killProcesses.allowedProcessNames)) {
      logger.warn(
        `Refusing to kill ${processName} (PID ${pid}): not in enforcementPolicy.killProcesses.allowedProcessNames`
      );
      return {
        action: 'kill_process',
        success: false,
        details:
          `Process "${processName}" is not in killProcesses.allowedProcessNames. ` +
          `Operators must explicitly allowlist process name patterns.`,
        timestamp: new Date().toISOString(),
        target: String(pid),
      };
    }
  } else if (policy.killProcesses.allowedProcessNames.length > 0) {
    // Allowlist is configured but evidence omits process name — refuse rather than
    // risk killing an unknown process.
    logger.warn(`Refusing to kill PID ${pid}: process name unknown, allowlist configured`);
    return {
      action: 'kill_process',
      success: false,
      details: 'Process name missing from verdict evidence; allowlist is configured',
      timestamp: new Date().toISOString(),
      target: String(pid),
    };
  }

  if (processName && SAFETY_RULES.protectedProcesses.has(processName)) {
    logger.warn(`Refusing to kill protected process: ${processName} (PID ${pid})`);
    return {
      action: 'kill_process',
      success: false,
      details: `Process ${processName} is protected and cannot be killed`,
      timestamp: new Date().toISOString(),
      target: String(pid),
    };
  }

  if (pid === process.pid) {
    logger.warn('Refusing to kill own process');
    return {
      action: 'kill_process',
      success: false,
      details: 'Cannot kill own process',
      timestamp: new Date().toISOString(),
      target: String(pid),
    };
  }

  try {
    process.kill(pid, 'SIGTERM');
    logger.info(`Sent SIGTERM to PID ${pid}`);

    const isAlive = await waitForProcessExit(pid, SAFETY_RULES.sigkillTimeoutMs);
    if (isAlive) {
      try {
        process.kill(pid, 'SIGKILL');
        logger.warn(`SIGTERM failed, sent SIGKILL to PID ${pid}`);
      } catch {
        // Process may have exited between check and kill
      }
    }

    manifest.record('kill_process', String(pid), verdict);

    return {
      action: 'kill_process',
      success: true,
      details: `Process PID ${pid} terminated${isAlive ? ' (SIGKILL required)' : ''}`,
      timestamp: new Date().toISOString(),
      target: String(pid),
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to kill process ${pid}: ${msg}`);
    return {
      action: 'kill_process',
      success: false,
      details: `Failed to kill process ${pid}: ${msg}`,
      timestamp: new Date().toISOString(),
      target: String(pid),
    };
  }
}

// ---------------------------------------------------------------------------
// Disable Account
// ---------------------------------------------------------------------------

export interface DisableAccountDeps {
  readonly manifest: ActionManifest;
  readonly policy: EnforcementPolicy;
}

export async function disableAccount(
  verdict: ThreatVerdict,
  deps: DisableAccountDeps
): Promise<ResponseResult> {
  const { manifest, policy } = deps;

  // Enforcement-policy gate: account disabling must be explicitly enabled.
  // Default OFF — too destructive for autonomous response.
  if (!policy.disableAccounts.enabled) {
    return {
      action: 'disable_account',
      success: false,
      details:
        'Account disabling is disabled in enforcementPolicy.disableAccounts.enabled ' +
        '(default OFF — too destructive for autonomous response)',
      timestamp: new Date().toISOString(),
    };
  }

  const username = extractUsername(verdict);
  if (!username) {
    return {
      action: 'disable_account',
      success: false,
      details: 'No username found in verdict evidence',
      timestamp: new Date().toISOString(),
    };
  }

  if (SAFETY_RULES.protectedAccounts.has(username)) {
    logger.warn(`Refusing to disable protected account: ${username}`);
    return {
      action: 'disable_account',
      success: false,
      details: `Account ${username} is protected and cannot be disabled`,
      timestamp: new Date().toISOString(),
      target: username,
    };
  }

  if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
    return {
      action: 'disable_account',
      success: false,
      details: `Invalid username format: ${username}`,
      timestamp: new Date().toISOString(),
      target: username,
    };
  }

  const os = platform();
  try {
    if (os === 'darwin') {
      await execFilePromise('/usr/bin/dscl', [
        '.',
        '-create',
        `/Users/${username}`,
        'AuthenticationAuthority',
        ';DisabledUser;',
      ]);
    } else if (os === 'linux') {
      await execFilePromise('/usr/sbin/usermod', ['-L', username]);
    } else if (os === 'win32') {
      await execFilePromise('net', ['user', username, '/active:no']);
    }

    manifest.record('disable_account', username, verdict);

    logger.info(`Disabled account: ${username}`);
    return {
      action: 'disable_account',
      success: true,
      details: `Account ${username} disabled`,
      timestamp: new Date().toISOString(),
      target: username,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to disable account ${username}: ${msg}`);
    return {
      action: 'disable_account',
      success: false,
      details: `Failed to disable account: ${msg}`,
      timestamp: new Date().toISOString(),
      target: username,
    };
  }
}

// ---------------------------------------------------------------------------
// Isolate File
// ---------------------------------------------------------------------------

/**
 * System-critical paths that must never be touched, regardless of operator
 * allowlist. Defence-in-depth: even if `enforcementPolicy.isolateFiles.allowedPaths`
 * is misconfigured to include one of these, the action still refuses.
 */
const DENY_PATHS = [
  '/etc',
  '/usr',
  '/bin',
  '/sbin',
  '/lib',
  '/boot',
  '/System',
  '/Library',
  // Credential / config directories under home that must never be quarantined
];

/** Subdirectories under any user's home that are unconditionally protected. */
const HOME_DENY_SUFFIXES = [
  '/.ssh',
  '/.gnupg',
  '/.aws',
  '/.kube',
  '/.docker',
  '/.npmrc',
  '/.pypirc',
  '/.gitconfig',
  '/.git-credentials',
];

/**
 * Check if a file path is safe to isolate.
 * Must be within the configured `allowedPaths` allowlist (explicit subdirs,
 * never `$HOME`-wide), and NOT within DENY_PATHS or credential subdirectories.
 */
function isPathSafeToIsolate(
  filePath: string,
  allowedPaths: ReadonlyArray<string>
): { safe: boolean; reason?: string } {
  const resolved = resolve(filePath);
  const home = homedir();

  // Deny list takes precedence over allowlist (defence-in-depth)
  for (const denied of DENY_PATHS) {
    if (resolved.startsWith(denied + '/') || resolved === denied) {
      return { safe: false, reason: `Path "${resolved}" is in deny list (${denied})` };
    }
  }
  for (const suffix of HOME_DENY_SUFFIXES) {
    const credentialPath = home + suffix;
    if (resolved === credentialPath || resolved.startsWith(credentialPath + '/')) {
      return {
        safe: false,
        reason: `Path "${resolved}" is a credential / config file and cannot be quarantined`,
      };
    }
  }

  // Must be within configured allowlist
  if (!matchesFilePathAllowlist(resolved, allowedPaths, home)) {
    return {
      safe: false,
      reason:
        `Path "${resolved}" is not within configured isolateFiles.allowedPaths. ` +
        `Operators must explicitly opt in to specific subdirectories.`,
    };
  }

  return { safe: true };
}

export interface IsolateFileDeps {
  readonly manifest: ActionManifest;
  readonly policy: EnforcementPolicy;
}

export async function isolateFile(
  verdict: ThreatVerdict,
  deps: IsolateFileDeps
): Promise<ResponseResult> {
  const { manifest, policy } = deps;

  // Enforcement-policy gate: isolation must be explicitly enabled
  if (!policy.isolateFiles.enabled) {
    return {
      action: 'isolate_file',
      success: false,
      details: 'File isolation is disabled in enforcementPolicy.isolateFiles.enabled',
      timestamp: new Date().toISOString(),
    };
  }

  const filePath = extractFilePath(verdict);
  if (!filePath) {
    return {
      action: 'isolate_file',
      success: false,
      details: 'No file path found in verdict evidence',
      timestamp: new Date().toISOString(),
    };
  }

  // Validate path is safe to isolate
  const pathCheck = isPathSafeToIsolate(filePath, policy.isolateFiles.allowedPaths);
  if (!pathCheck.safe) {
    logger.warn(`Refused to isolate file: ${pathCheck.reason}`);
    return {
      action: 'isolate_file',
      success: false,
      details: `Refused: ${pathCheck.reason}`,
      timestamp: new Date().toISOString(),
      target: filePath,
    };
  }

  try {
    const quarantineDir = '/var/panguard-guard/quarantine';
    const os = platform();
    const mvCmd = os === 'win32' ? 'move' : '/bin/mv';
    const fileName = filePath.split(/[/\\]/).pop() ?? 'unknown';
    const dest = `${quarantineDir}/${Date.now()}_${fileName}`;

    if (os !== 'win32') {
      await execFilePromise('/bin/mkdir', ['-p', quarantineDir]);
    }

    await execFilePromise(mvCmd, [filePath, dest]);

    manifest.record('isolate_file', filePath, verdict);

    try {
      const metadata = {
        originalPath: filePath,
        quarantinedAt: new Date().toISOString(),
        verdict: { conclusion: verdict.conclusion, confidence: verdict.confidence },
        reasoning: verdict.reasoning,
      };
      appendFileSync(`${dest}.meta.json`, JSON.stringify(metadata, null, 2), 'utf-8');
    } catch {
      // Non-critical: metadata write failure
    }

    logger.info(`Isolated file: ${filePath} -> ${dest}`);
    return {
      action: 'isolate_file',
      success: true,
      details: `File isolated: ${filePath} -> ${dest}`,
      timestamp: new Date().toISOString(),
      target: filePath,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to isolate file: ${msg}`);
    return {
      action: 'isolate_file',
      success: false,
      details: `Failed to isolate file: ${msg}`,
      timestamp: new Date().toISOString(),
      target: filePath,
    };
  }
}
