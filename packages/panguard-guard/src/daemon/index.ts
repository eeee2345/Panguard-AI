/**
 * Daemon / Service Management
 * Daemon / 服務管理
 *
 * Cross-platform daemon support:
 * - macOS: launchd plist
 * - Linux: systemd unit file
 * - Windows: sc.exe service
 * Includes PID file management and watchdog functionality.
 *
 * 跨平台 daemon 支援：
 * - macOS: launchd plist
 * - Linux: systemd unit 檔案
 * - Windows: sc.exe 服務
 * 包含 PID 檔案管理和看門狗功能。
 *
 * @module @panguard-ai/panguard-guard/daemon
 */

import { writeFileSync, readFileSync, unlinkSync, existsSync, mkdirSync, lstatSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { platform, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:daemon');

/** Service name constants / 服務名稱常數 */
const SERVICE_NAME = 'com.panguard.panguard-guard';
const SERVICE_DISPLAY_NAME = 'PanguardGuard Security Monitor';

/**
 * PID file management / PID 檔案管理
 */
export class PidFile {
  private readonly pidPath: string;

  constructor(dataDir: string) {
    this.pidPath = join(dataDir, 'panguard-guard.pid');
  }

  /** Write current PID to file / 將目前 PID 寫入檔案 */
  write(): void {
    mkdirSync(dirname(this.pidPath), { recursive: true, mode: 0o700 });
    // Reject symlinks to prevent symlink-following file overwrite attacks
    if (existsSync(this.pidPath)) {
      const stat = lstatSync(this.pidPath);
      if (stat.isSymbolicLink()) {
        unlinkSync(this.pidPath);
        logger.warn('PID file was a symlink — removed for safety');
      }
    }
    writeFileSync(this.pidPath, String(process.pid), { encoding: 'utf-8', mode: 0o600 });
    logger.info(`PID file written: ${this.pidPath} (PID: ${process.pid}) / PID 檔案已寫入`);
  }

  /** Read PID from file / 從檔案讀取 PID */
  read(): number | null {
    try {
      if (!existsSync(this.pidPath)) return null;
      // Reject symlinks
      const stat = lstatSync(this.pidPath);
      if (stat.isSymbolicLink()) return null;
      const pid = parseInt(readFileSync(this.pidPath, 'utf-8').trim(), 10);
      // Validate PID range (2–4194304 on Linux, reasonable upper bound)
      if (isNaN(pid) || pid < 2 || pid > 4194304) return null;
      return pid;
    } catch {
      return null;
    }
  }

  /** Remove PID file / 移除 PID 檔案 */
  remove(): void {
    try {
      if (existsSync(this.pidPath)) {
        unlinkSync(this.pidPath);
        logger.info('PID file removed / PID 檔案已移除');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to remove PID file: ${msg} / 移除 PID 檔案失敗`);
    }
  }

  /** Check if process with stored PID is running / 檢查儲存的 PID 程序是否執行中 */
  isRunning(): boolean {
    const pid = this.read();
    if (pid === null) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Watchdog - monitors the guard engine and restarts if needed
 * 看門狗 - 監控守護引擎，需要時重新啟動
 */
export class Watchdog {
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly intervalMs: number;
  private lastHeartbeat: number = Date.now();
  private readonly onFailure: () => void;

  /**
   * @param intervalMs - Check interval in milliseconds / 檢查間隔（毫秒）
   * @param onFailure - Callback when engine appears unresponsive / 引擎無回應時的回呼
   */
  constructor(intervalMs: number, onFailure: () => void) {
    this.intervalMs = intervalMs;
    this.onFailure = onFailure;
  }

  /** Start watchdog monitoring / 啟動看門狗監控 */
  start(): void {
    if (this.timer) return;

    this.lastHeartbeat = Date.now();
    this.timer = setInterval(() => {
      const elapsed = Date.now() - this.lastHeartbeat;
      // If no heartbeat for 3x the interval, trigger failure
      // 如果超過 3 倍間隔無心跳，觸發失敗
      if (elapsed > this.intervalMs * 3) {
        logger.error(
          `Watchdog: no heartbeat for ${elapsed}ms, triggering restart / ` +
            `看門狗: ${elapsed}ms 無心跳，觸發重啟`
        );
        this.onFailure();
      }
    }, this.intervalMs);

    logger.info(
      `Watchdog started with ${this.intervalMs}ms interval / ` +
        `看門狗已啟動，間隔 ${this.intervalMs}ms`
    );
  }

  /** Record a heartbeat / 記錄心跳 */
  heartbeat(): void {
    this.lastHeartbeat = Date.now();
  }

  /** Stop watchdog / 停止看門狗 */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      logger.info('Watchdog stopped / 看門狗已停止');
    }
  }
}

/**
 * Install as a system service / 安裝為系統服務
 *
 * @param execArgv - Executable + script as discrete argv parts, e.g.
 *   [nodePath, scriptPath]. Never a space-joined string — paths contain spaces.
 * @param dataDir - Data directory path / 資料目錄路徑
 */
export async function installService(execArgv: string[], dataDir: string): Promise<string> {
  const os = platform();

  switch (os) {
    case 'darwin':
      return installLaunchd(execArgv, dataDir);
    case 'linux':
      return installSystemd(execArgv, dataDir);
    case 'win32':
      return installWindowsService(execArgv);
    default:
      throw new Error(`Unsupported platform: ${os} / 不支援的平台: ${os}`);
  }
}

/**
 * Uninstall system service / 解除安裝系統服務
 */
export async function uninstallService(): Promise<string> {
  const os = platform();

  switch (os) {
    case 'darwin':
      return uninstallLaunchd();
    case 'linux':
      return uninstallSystemd();
    case 'win32':
      return uninstallWindowsService();
    default:
      throw new Error(`Unsupported platform: ${os} / 不支援的平台: ${os}`);
  }
}

// ---------------------------------------------------------------------------
// macOS launchd / macOS launchd
// ---------------------------------------------------------------------------

/** Escape a value for safe inclusion in plist XML text. */
function xmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Quote a value as a single systemd ExecStart token (handles spaces + specials). */
function systemdQuote(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

async function installLaunchd(execArgv: string[], dataDir: string): Promise<string> {
  const plistPath = join(homedir(), 'Library', 'LaunchAgents', `${SERVICE_NAME}.plist`);

  // execArgv is already split into discrete parts (e.g. [nodePath, scriptPath]).
  // Never split on whitespace — paths legitimately contain spaces.
  const programArgs = execArgv
    .concat(['start', '--data-dir', dataDir])
    .map((arg) => `    <string>${xmlEscape(arg)}</string>`)
    .join('\n');

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_NAME}</string>
  <key>ProgramArguments</key>
  <array>
${programArgs}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${xmlEscape(join(dataDir, 'panguard-guard.log'))}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(join(dataDir, 'panguard-guard-error.log'))}</string>
</dict>
</plist>`;

  mkdirSync(dirname(plistPath), { recursive: true });
  writeFileSync(plistPath, plist, 'utf-8');

  await execFileAsync('/bin/launchctl', ['load', plistPath]);

  logger.info(`launchd service installed at ${plistPath} / launchd 服務已安裝`);
  return plistPath;
}

async function uninstallLaunchd(): Promise<string> {
  const plistPath = join(homedir(), 'Library', 'LaunchAgents', `${SERVICE_NAME}.plist`);

  if (existsSync(plistPath)) {
    await execFileAsync('/bin/launchctl', ['unload', plistPath]);
    unlinkSync(plistPath);
    logger.info('launchd service uninstalled / launchd 服務已解除安裝');
  }

  return plistPath;
}

// ---------------------------------------------------------------------------
// Linux systemd / Linux systemd
// ---------------------------------------------------------------------------

async function installSystemd(execArgv: string[], dataDir: string): Promise<string> {
  // Rootless `systemctl --user` unit — written to the per-user systemd dir, NOT
  // the root-only /etc/systemd/system. This mirrors the macOS user-LaunchAgent
  // philosophy: a security daemon must not be a root-level attack surface, it
  // monitors *this user's* agents, and it must install without sudo so the
  // "survives reboot" status reflects reality. (For survival across logout the
  // user can enable lingering with `loginctl enable-linger`.)
  const unitDir = join(homedir(), '.config', 'systemd', 'user');
  const unitPath = join(unitDir, `${SERVICE_NAME}.service`);

  const unit = `[Unit]
Description=${SERVICE_DISPLAY_NAME}
After=network.target

[Service]
Type=simple
NoNewPrivileges=true
PrivateTmp=true
ExecStart=${[...execArgv, 'start', '--data-dir', dataDir].map(systemdQuote).join(' ')}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
`;

  mkdirSync(unitDir, { recursive: true });
  writeFileSync(unitPath, unit, 'utf-8');
  await execFileAsync('/bin/systemctl', ['--user', 'daemon-reload']);
  await execFileAsync('/bin/systemctl', ['--user', 'enable', SERVICE_NAME]);
  await execFileAsync('/bin/systemctl', ['--user', 'start', SERVICE_NAME]);

  logger.info(`systemd --user service installed at ${unitPath} / systemd --user 服務已安裝`);
  return unitPath;
}

async function uninstallSystemd(): Promise<string> {
  const unitPath = join(homedir(), '.config', 'systemd', 'user', `${SERVICE_NAME}.service`);

  await execFileAsync('/bin/systemctl', ['--user', 'stop', SERVICE_NAME]);
  await execFileAsync('/bin/systemctl', ['--user', 'disable', SERVICE_NAME]);

  if (existsSync(unitPath)) {
    unlinkSync(unitPath);
    await execFileAsync('/bin/systemctl', ['--user', 'daemon-reload']);
  }

  logger.info('systemd --user service uninstalled / systemd --user 服務已解除安裝');
  return unitPath;
}

// ---------------------------------------------------------------------------
// Windows sc.exe / Windows sc.exe
// ---------------------------------------------------------------------------

async function installWindowsService(execArgv: string[]): Promise<string> {
  // Quote each argv part so paths with spaces survive sc.exe / schtasks parsing.
  const quoted = execArgv.map((p) => `"${p}"`).join(' ');
  // Try sc create (requires admin), fall back to Task Scheduler (no admin needed)
  try {
    await execFileAsync('sc', [
      'create',
      SERVICE_NAME,
      `binpath=${quoted} start`,
      `displayname=${SERVICE_DISPLAY_NAME}`,
      'start=auto',
    ]);
    await execFileAsync('sc', ['start', SERVICE_NAME]);
    logger.info('Windows service installed via sc.exe / Windows 服務已透過 sc.exe 安裝');
    return SERVICE_NAME;
  } catch (scErr) {
    const msg = scErr instanceof Error ? scErr.message : String(scErr);
    if (msg.includes('Access') || msg.includes('denied') || msg.includes('5')) {
      // No admin — use Task Scheduler (schtasks) which works without elevation
      logger.info('sc.exe requires admin, falling back to Task Scheduler / 嘗試使用工作排程器');
      const taskName = 'PanguardGuard';
      await execFileAsync('schtasks', [
        '/Create',
        '/TN',
        taskName,
        '/TR',
        `${quoted} start`,
        '/SC',
        'ONLOGON',
        '/RL',
        'LIMITED',
        '/F',
      ]);
      // Start it now
      await execFileAsync('schtasks', ['/Run', '/TN', taskName]).catch(() => {
        // May fail if already running
      });
      logger.info('Windows task installed via schtasks / Windows 排程工作已安裝');
      return taskName;
    }
    throw scErr;
  }
}

async function uninstallWindowsService(): Promise<string> {
  try {
    execFileAsync('sc', ['stop', SERVICE_NAME]);
  } catch {
    // Service may not be running / 服務可能未執行
  }
  await execFileAsync('sc', ['delete', SERVICE_NAME]);

  logger.info('Windows service uninstalled / Windows 服務已解除安裝');
  return SERVICE_NAME;
}

// ---------------------------------------------------------------------------
// Async execFile helper / 非同步 execFile 輔助函數
// ---------------------------------------------------------------------------

function execFileAsync(command: string, args: string[]): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    execFile(command, args, { timeout: 15000, windowsHide: true }, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
