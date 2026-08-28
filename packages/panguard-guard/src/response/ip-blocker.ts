/**
 * IP Blocker - Cross-platform firewall rule management with auto-unblock
 * IP 封鎖器 - 跨平台防火牆規則管理與自動解封
 *
 * Features:
 * - Platform-aware blocking (pfctl / iptables / netsh)
 * - Auto-unblock timer (default 24h)
 * - Persistent whitelist
 * - Block manifest tracking
 *
 * @module @panguard-ai/panguard-guard/response/ip-blocker
 */

import { execFile } from 'node:child_process';
import { platform } from 'node:os';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:ip-blocker');

/** Record of a blocked IP / 封鎖 IP 紀錄 */
export interface BlockRecord {
  ip: string;
  blockedAt: string;
  expiresAt: string;
  reason: string;
  autoUnblock: boolean;
}

/** IP Blocker configuration / IP 封鎖器設定 */
export interface IPBlockerConfig {
  /** Default block duration in ms (default 24h) / 預設封鎖時長 */
  defaultBlockDurationMs: number;
  /** IPs that can never be blocked / 永不封鎖的 IP */
  whitelist: string[];
  /** Enable auto-unblock timer / 啟用自動解封 */
  autoUnblockEnabled: boolean;
}

const DEFAULT_CONFIG: IPBlockerConfig = {
  defaultBlockDurationMs: 24 * 60 * 60 * 1000, // 24h
  whitelist: ['127.0.0.1', '::1', '0.0.0.0', 'localhost'],
  autoUnblockEnabled: true,
};

/**
 * Manages IP blocking with auto-unblock timers
 * 管理 IP 封鎖與自動解封計時器
 */
export class IPBlocker {
  private readonly config: IPBlockerConfig;
  private readonly blocked: Map<string, BlockRecord> = new Map();
  private readonly whitelist: Set<string>;
  private unblockTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  constructor(config: Partial<IPBlockerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.whitelist = new Set([...DEFAULT_CONFIG.whitelist, ...(config.whitelist ?? [])]);
  }

  /** Check if IP is whitelisted / 檢查 IP 是否在白名單 */
  isWhitelisted(ip: string): boolean {
    return this.whitelist.has(ip);
  }

  /** Check if IP is currently blocked / 檢查 IP 是否已封鎖 */
  isBlocked(ip: string): boolean {
    return this.blocked.has(ip);
  }

  /** Get all currently blocked IPs / 取得所有已封鎖的 IP */
  getBlockedIPs(): BlockRecord[] {
    return Array.from(this.blocked.values());
  }

  /**
   * Block an IP address
   * 封鎖 IP 位址
   */
  async block(
    ip: string,
    reason: string,
    durationMs?: number
  ): Promise<{ success: boolean; message: string }> {
    // Whitelist check
    if (this.whitelist.has(ip)) {
      logger.warn(`Refusing to block whitelisted IP: ${ip}`);
      return { success: false, message: `IP ${ip} is whitelisted` };
    }

    // Already blocked check
    if (this.blocked.has(ip)) {
      return { success: true, message: `IP ${ip} is already blocked` };
    }

    // Validate IP format
    if (!isValidIP(ip)) {
      return { success: false, message: `Invalid IP format: ${ip}` };
    }

    const duration = durationMs ?? this.config.defaultBlockDurationMs;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + duration);

    // Execute platform firewall command
    try {
      await this.addFirewallRule(ip);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to block IP ${ip}: ${msg}`);
      return { success: false, message: `Firewall error: ${msg}` };
    }

    // Record block
    const record: BlockRecord = {
      ip,
      blockedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      reason,
      autoUnblock: this.config.autoUnblockEnabled,
    };
    this.blocked.set(ip, record);

    // Set auto-unblock timer
    if (this.config.autoUnblockEnabled) {
      const timer = setTimeout(() => {
        void this.unblock(ip, 'auto-unblock: duration expired');
      }, duration);
      // Don't prevent process exit
      if (timer.unref) timer.unref();
      this.unblockTimers.set(ip, timer);
    }

    logger.info(`Blocked IP ${ip} for ${Math.round(duration / 60000)} minutes. Reason: ${reason}`);
    return { success: true, message: `IP ${ip} blocked until ${expiresAt.toISOString()}` };
  }

  /**
   * Unblock an IP address
   * 解封 IP 位址
   */
  async unblock(ip: string, reason: string): Promise<{ success: boolean; message: string }> {
    if (!this.blocked.has(ip)) {
      return { success: true, message: `IP ${ip} is not blocked` };
    }

    try {
      await this.removeFirewallRule(ip);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to unblock IP ${ip}: ${msg}`);
      return { success: false, message: `Firewall error: ${msg}` };
    }

    this.blocked.delete(ip);

    // Clear timer
    const timer = this.unblockTimers.get(ip);
    if (timer) {
      clearTimeout(timer);
      this.unblockTimers.delete(ip);
    }

    logger.info(`Unblocked IP ${ip}. Reason: ${reason}`);
    return { success: true, message: `IP ${ip} unblocked` };
  }

  /** Add whitelist entry / 新增白名單條目 */
  addToWhitelist(ip: string): void {
    this.whitelist.add(ip);
  }

  /** Clean up all timers / 清理所有計時器 */
  destroy(): void {
    for (const timer of this.unblockTimers.values()) {
      clearTimeout(timer);
    }
    this.unblockTimers.clear();
  }

  // -- Platform firewall commands --

  private async addFirewallRule(ip: string): Promise<void> {
    const os = platform();
    if (os === 'darwin') {
      await execFilePromise('/sbin/pfctl', ['-t', 'panguard_blocked', '-T', 'add', ip]);
    } else if (os === 'linux') {
      await execFilePromise('/sbin/iptables', ['-A', 'INPUT', '-s', ip, '-j', 'DROP']);
    } else if (os === 'win32') {
      await execFilePromise('netsh', [
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=Panguard_Block_${ip}`,
        'dir=in',
        'action=block',
        `remoteip=${ip}`,
      ]);
    }
  }

  private async removeFirewallRule(ip: string): Promise<void> {
    const os = platform();
    if (os === 'darwin') {
      await execFilePromise('/sbin/pfctl', ['-t', 'panguard_blocked', '-T', 'delete', ip]);
    } else if (os === 'linux') {
      await execFilePromise('/sbin/iptables', ['-D', 'INPUT', '-s', ip, '-j', 'DROP']);
    } else if (os === 'win32') {
      await execFilePromise('netsh', [
        'advfirewall',
        'firewall',
        'delete',
        'rule',
        `name=Panguard_Block_${ip}`,
      ]);
    }
  }
}

/** Validate IPv4 or IPv6 format / 驗證 IPv4 或 IPv6 格式 */
function isValidIP(ip: string): boolean {
  return /^[\d.]+$/.test(ip) || /^[a-fA-F\d:]+$/.test(ip);
}

function execFilePromise(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 10000, windowsHide: true }, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}
