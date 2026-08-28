/**
 * System log monitoring via native OS log streams
 * 透過原生作業系統日誌串流進行系統日誌監控
 *
 * Supports macOS (log stream), Linux (tail -F), and Windows (wevtutil).
 * 支援 macOS (log stream)、Linux (tail -F) 和 Windows (wevtutil)。
 *
 * @module @panguard-ai/core/monitor/log-monitor
 */

import { EventEmitter } from 'node:events';
import { type ChildProcess, spawn } from 'node:child_process';
import { platform } from 'node:os';
import { createInterface } from 'node:readline';

import { createLogger } from '../utils/index.js';
import { normalizeLogEvent } from './event-normalizer.js';

const logger = createLogger('log-monitor');

/**
 * Log monitor configuration
 * 日誌監控配置
 */
interface LogMonitorConfig {
  /** Custom log paths to monitor (Linux only) / 自訂要監控的日誌路徑（僅 Linux） */
  logPaths?: string[];
}

/**
 * LogMonitor - monitors system logs in real-time using OS-native tools
 * LogMonitor - 使用作業系統原生工具即時監控系統日誌
 *
 * Events emitted:
 * - 'event': SecurityEvent - when a log line is captured / 當擷取到日誌行時
 * - 'error': Error - when the monitoring process encounters an error / 當監控程序遇到錯誤時
 *
 * @example
 * ```typescript
 * const monitor = new LogMonitor();
 * monitor.on('event', (event) => console.log(event));
 * monitor.start();
 * ```
 */
export class LogMonitor extends EventEmitter {
  /** Whether the monitor is currently running / 監控器是否正在執行 */
  private running = false;
  /** Child process for log streaming / 用於日誌串流的子程序 */
  private childProcess?: ChildProcess;
  /** Monitor configuration / 監控配置 */
  private config: LogMonitorConfig;

  /**
   * Create a new LogMonitor instance
   * 建立新的 LogMonitor 實例
   *
   * @param config - Optional configuration / 可選配置
   */
  constructor(config?: LogMonitorConfig) {
    super();
    this.config = config ?? {};
  }

  /**
   * Start monitoring system logs
   * 開始監控系統日誌
   *
   * Spawns the appropriate OS-level log monitoring process:
   * 產生適當的作業系統級日誌監控程序：
   * - macOS: `log stream --style json --predicate 'eventType == logEvent'`
   * - Linux: `tail -F /var/log/auth.log /var/log/syslog`
   * - Windows: `wevtutil qe Security /f:text /rd:true /c:1`
   */
  start(): void {
    if (this.running) {
      logger.warn('LogMonitor is already running');
      return;
    }

    const os = platform();
    logger.info(`Starting log monitor on platform: ${os}`);

    try {
      if (os === 'darwin') {
        this.startMacOS();
      } else if (os === 'linux') {
        this.startLinux();
      } else if (os === 'win32') {
        this.startWindows();
      } else {
        logger.error(`Unsupported platform: ${os}`);
        this.emit('error', new Error(`Unsupported platform: ${os}`));
        return;
      }

      this.running = true;
      logger.info('LogMonitor started successfully');
    } catch (err) {
      logger.error('Failed to start LogMonitor', { error: String(err) });
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
    }
  }

  /**
   * Stop monitoring system logs and clean up child processes
   * 停止監控系統日誌並清理子程序
   */
  stop(): void {
    if (!this.running) {
      logger.warn('LogMonitor is not running');
      return;
    }

    if (this.childProcess) {
      this.childProcess.removeAllListeners();

      if (this.childProcess.stdout) {
        this.childProcess.stdout.removeAllListeners();
      }
      if (this.childProcess.stderr) {
        this.childProcess.stderr.removeAllListeners();
      }

      this.childProcess.kill('SIGTERM');

      // Force kill after 3 seconds if still alive
      // 如果仍在執行，3 秒後強制終止
      const forceKillTimeout = setTimeout(() => {
        if (this.childProcess && !this.childProcess.killed) {
          this.childProcess.kill('SIGKILL');
        }
      }, 3000);

      this.childProcess.once('exit', () => {
        clearTimeout(forceKillTimeout);
      });

      this.childProcess = undefined;
    }

    this.running = false;
    logger.info('LogMonitor stopped');
  }

  /**
   * Check if the monitor is currently running
   * 檢查監控器是否正在執行
   *
   * @returns True if running / 如果正在執行則為 true
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Start macOS log stream monitoring
   * 啟動 macOS 日誌串流監控
   */
  private startMacOS(): void {
    this.childProcess = spawn('log', [
      'stream',
      '--style',
      'json',
      '--predicate',
      'eventType == logEvent',
    ]);

    this.attachProcessHandlers('macOS-log-stream');
    this.parseOutputStream((line: string) => {
      // macOS log stream JSON output: try to parse each line
      // macOS 日誌串流 JSON 輸出：嘗試解析每一行
      try {
        const parsed = JSON.parse(line) as Record<string, unknown>;
        const message = typeof parsed['eventMessage'] === 'string' ? parsed['eventMessage'] : line;
        const source =
          typeof parsed['senderImagePath'] === 'string' ? parsed['senderImagePath'] : 'macOS';
        const timestamp =
          typeof parsed['timestamp'] === 'string' ? new Date(parsed['timestamp']) : new Date();

        const event = normalizeLogEvent({ message, source, timestamp });
        this.emit('event', event);
      } catch {
        // Non-JSON line (e.g., header line), treat as plain text
        // 非 JSON 行（例如標頭行），視為純文字處理
        if (line.trim().length > 0 && !line.startsWith('Filtering')) {
          const event = normalizeLogEvent({
            message: line,
            source: 'macOS-log-stream',
          });
          this.emit('event', event);
        }
      }
    });
  }

  /**
   * Start Linux log tail monitoring
   * 啟動 Linux 日誌尾部監控
   */
  private startLinux(): void {
    const logPaths = this.config.logPaths ?? ['/var/log/auth.log', '/var/log/syslog'];

    this.childProcess = spawn('tail', ['-F', ...logPaths]);

    this.attachProcessHandlers('linux-tail');
    this.parseOutputStream((line: string) => {
      if (line.trim().length > 0) {
        const event = normalizeLogEvent({
          message: line,
          source: 'syslog',
        });
        this.emit('event', event);
      }
    });
  }

  /**
   * Start Windows event log monitoring
   * 啟動 Windows 事件日誌監控
   */
  private startWindows(): void {
    this.childProcess = spawn('wevtutil', ['qe', 'Security', '/f:text', '/rd:true', '/c:1'], {
      windowsHide: true,
    });

    this.attachProcessHandlers('windows-wevtutil');
    this.parseOutputStream((line: string) => {
      if (line.trim().length > 0) {
        const event = normalizeLogEvent({
          message: line,
          source: 'windows-event',
        });
        this.emit('event', event);
      }
    });
  }

  /**
   * Attach error and exit handlers to the child process
   * 將錯誤和退出處理器附加到子程序
   *
   * @param label - Label for logging / 用於日誌記錄的標籤
   */
  private attachProcessHandlers(label: string): void {
    if (!this.childProcess) return;

    this.childProcess.on('error', (err: Error) => {
      logger.warn(`${label} process error (non-fatal): ${err.message}`);
      this.running = false;
      // Graceful fallback — don't crash the app if log monitoring fails
      // Common: wevtutil Access Denied on Windows without admin privileges
    });

    this.childProcess.on('exit', (code: number | null, signal: string | null) => {
      logger.info(`${label} process exited`, { code, signal });
      if (this.running) {
        // Unexpected exit — log but don't crash (graceful degradation)
        this.running = false;
        logger.warn(
          `${label} process exited unexpectedly (code: ${code}, signal: ${signal}). Log monitoring disabled.`
        );
      }
    });
  }

  /**
   * Parse stdout from the child process line by line
   * 逐行解析子程序的標準輸出
   *
   * @param handler - Callback for each line / 每行的回呼函式
   */
  private parseOutputStream(handler: (line: string) => void): void {
    if (!this.childProcess?.stdout) return;

    const rl = createInterface({
      input: this.childProcess.stdout,
      crlfDelay: Infinity,
    });

    rl.on('line', handler);

    rl.on('error', (err: Error) => {
      logger.error(`Readline error: ${err.message}`);
    });
  }
}
