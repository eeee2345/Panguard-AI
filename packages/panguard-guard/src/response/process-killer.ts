/**
 * Process Killer - Terminate processes with child cleanup and safety checks
 * 程序終止器 - 終止程序（含子程序清理與安全檢查）
 *
 * Features:
 * - Kill process and all child processes (process tree)
 * - Protected process list (never kill system-critical processes)
 * - SIGTERM first, SIGKILL after timeout
 * - Cross-platform support
 *
 * @module @panguard-ai/panguard-guard/response/process-killer
 */

import { execFile } from 'node:child_process';
import { platform } from 'node:os';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:process-killer');

/** Process kill result / 程序終止結果 */
export interface KillResult {
  pid: number;
  processName?: string;
  success: boolean;
  message: string;
  childrenKilled: number;
}

/** Protected system processes that must never be killed / 不可終止的系統程序 */
const PROTECTED_PROCESSES = new Set([
  // Unix/Linux
  'init',
  'systemd',
  'launchd',
  'sshd',
  'cron',
  'atd',
  'journald',
  'udevd',
  'dbus-daemon',
  'NetworkManager',
  'login',
  'getty',
  // macOS
  'loginwindow',
  'WindowServer',
  'kernel_task',
  'mds',
  'mds_stores',
  'coreaudiod',
  'diskarbitrationd',
  'configd',
  // Windows
  'explorer.exe',
  'svchost.exe',
  'csrss.exe',
  'lsass.exe',
  'services.exe',
  'winlogon.exe',
  'wininit.exe',
  'smss.exe',
  'System',
  'dwm.exe',
  // Self
  'panguard-guard',
  'node',
]);

/** Protected PIDs / 受保護的 PID */
const PROTECTED_PIDS = new Set([0, 1]);

/**
 * Process Killer with safety checks and tree killing
 * 程序終止器（含安全檢查與程序樹終止）
 */
export class ProcessKiller {
  private readonly additionalProtected: Set<string>;

  constructor(additionalProtectedProcesses: string[] = []) {
    this.additionalProtected = new Set(additionalProtectedProcesses);
  }

  /** Check if process name is protected / 檢查程序名稱是否受保護 */
  isProtected(nameOrPid: string | number): boolean {
    if (typeof nameOrPid === 'number') {
      return PROTECTED_PIDS.has(nameOrPid) || nameOrPid === process.pid;
    }
    return PROTECTED_PROCESSES.has(nameOrPid) || this.additionalProtected.has(nameOrPid);
  }

  /**
   * Kill a process and optionally its children
   * 終止程序（可選終止子程序）
   */
  async kill(
    pid: number,
    options: { processName?: string; killChildren?: boolean; gracePeriodMs?: number } = {}
  ): Promise<KillResult> {
    const { processName, killChildren = true, gracePeriodMs = 3000 } = options;

    // Safety: protected PID check
    if (PROTECTED_PIDS.has(pid) || pid === process.pid) {
      return {
        pid,
        processName,
        success: false,
        message: `PID ${pid} is protected and cannot be killed`,
        childrenKilled: 0,
      };
    }

    // Safety: protected process name check
    if (
      processName &&
      (PROTECTED_PROCESSES.has(processName) || this.additionalProtected.has(processName))
    ) {
      return {
        pid,
        processName,
        success: false,
        message: `Process "${processName}" is protected`,
        childrenKilled: 0,
      };
    }

    let childrenKilled = 0;

    // Kill children first if requested
    if (killChildren) {
      try {
        const children = await this.getChildPIDs(pid);
        for (const childPid of children) {
          try {
            process.kill(childPid, 'SIGTERM');
            childrenKilled++;
          } catch {
            // Child may have already exited
          }
        }
      } catch {
        // Failed to get children, continue with parent
      }
    }

    // SIGTERM first (graceful)
    try {
      process.kill(pid, 'SIGTERM');
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if ((err as NodeJS.ErrnoException).code === 'ESRCH') {
        return {
          pid,
          processName,
          success: true,
          message: 'Process already exited',
          childrenKilled,
        };
      }
      return {
        pid,
        processName,
        success: false,
        message: `SIGTERM failed: ${msg}`,
        childrenKilled,
      };
    }

    // Wait for graceful exit, then SIGKILL if still alive
    const isAlive = await this.waitForExit(pid, gracePeriodMs);
    if (isAlive) {
      try {
        process.kill(pid, 'SIGKILL');
        logger.info(`SIGKILL sent to PID ${pid} after grace period`);
      } catch {
        // Process may have exited between check and kill
      }
    }

    logger.info(
      `Killed process PID ${pid}${processName ? ` (${processName})` : ''}, ${childrenKilled} children terminated`
    );
    return {
      pid,
      processName,
      success: true,
      message: `Process PID ${pid} terminated (${childrenKilled} children also killed)`,
      childrenKilled,
    };
  }

  /**
   * Get child PIDs of a process / 取得程序的子 PID
   */
  private async getChildPIDs(parentPid: number): Promise<number[]> {
    const os = platform();
    try {
      if (os === 'win32') {
        const stdout = await execFilePromise('wmic', [
          'process',
          'where',
          `(ParentProcessId=${parentPid})`,
          'get',
          'ProcessId',
        ]);
        return stdout
          .split('\n')
          .map((line) => parseInt(line.trim(), 10))
          .filter((pid) => !isNaN(pid) && pid !== parentPid);
      } else {
        // Unix/macOS: use pgrep
        const stdout = await execFilePromise('/usr/bin/pgrep', ['-P', String(parentPid)]);
        return stdout
          .split('\n')
          .map((line) => parseInt(line.trim(), 10))
          .filter((pid) => !isNaN(pid));
      }
    } catch {
      return []; // No children or pgrep not available
    }
  }

  /**
   * Wait for process to exit, return true if still alive
   * 等待程序退出，如果仍存活則回傳 true
   */
  private waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
    return new Promise((resolve) => {
      const start = Date.now();
      const check = () => {
        try {
          process.kill(pid, 0); // Signal 0 checks existence
          if (Date.now() - start >= timeoutMs) {
            resolve(true); // Still alive after timeout
          } else {
            setTimeout(check, 200);
          }
        } catch {
          resolve(false); // Process exited
        }
      };
      check();
    });
  }
}

function execFilePromise(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 5000, windowsHide: true }, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}
