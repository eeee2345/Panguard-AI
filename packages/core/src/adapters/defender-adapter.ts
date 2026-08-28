/**
 * Windows Defender adapter
 * Windows Defender 對接器
 *
 * Integrates with Microsoft Windows Defender / Microsoft Defender Antivirus
 * via PowerShell commands and MpCmdRun.exe for threat detection and scanning.
 * Gracefully handles non-Windows platforms by returning empty results.
 * 透過 PowerShell 命令和 MpCmdRun.exe 與 Microsoft Windows Defender /
 * Microsoft Defender Antivirus 整合，進行威脅偵測和掃描。
 * 在非 Windows 平台上優雅地處理並回傳空結果。
 *
 * @module @panguard-ai/core/adapters/defender-adapter
 */

import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';

import type { AdapterConfig, AdapterAlert } from './types.js';
import { BaseAdapter } from './base-adapter.js';

/**
 * Default path to the Windows Defender command-line utility
 * Windows Defender 命令列工具的預設路徑
 */
const MPCMDRUN_PATH = 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe';

/**
 * Promisified wrapper around execFile
 * execFile 的 Promise 化包裝器
 *
 * @param cmd - Command to execute / 要執行的命令
 * @param args - Command arguments / 命令參數
 * @returns Promise resolving to stdout/stderr / 解析為 stdout/stderr 的 Promise
 */
function execFileAsync(cmd: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 60000, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      resolve({ stdout: stdout ?? '', stderr: stderr ?? '' });
    });
  });
}

/**
 * Parsed threat detection entry from PowerShell Get-MpThreatDetection
 * 從 PowerShell Get-MpThreatDetection 解析的威脅偵測條目
 */
interface DefenderThreat {
  /** Threat detection ID / 威脅偵測 ID */
  detectionId: string;
  /** Threat name / 威脅名稱 */
  threatName: string;
  /** Severity ID (1-5) / 嚴重等級 ID (1-5) */
  severityId: string;
  /** Detection time (ISO string) / 偵測時間（ISO 字串） */
  initialDetectionTime: string;
  /** Last threat status change time / 最後威脅狀態變更時間 */
  lastThreatStatusChangeTime: string;
  /** Action taken / 採取的動作 */
  actionSuccess: string;
  /** Additional status info / 額外狀態資訊 */
  additionalActionsBitMask: string;
  /** Resources affected / 受影響的資源 */
  resources: string;
}

/**
 * Map Windows Defender severity ID to severity string
 * 將 Windows Defender 嚴重等級 ID 映射為嚴重等級字串
 *
 * @param severityId - Defender severity ID (1-5) / Defender 嚴重等級 ID (1-5)
 * @returns Severity string for use in AdapterAlert / 用於 AdapterAlert 的嚴重等級字串
 */
function mapDefenderSeverity(severityId: string): string {
  switch (severityId) {
    case '5':
      return 'critical';
    case '4':
      return 'high';
    case '3':
      return 'medium';
    case '2':
      return 'low';
    case '1':
    default:
      return 'info';
  }
}

/**
 * Windows Defender security adapter
 * Windows Defender 安全對接器
 *
 * Provides integration with Windows Defender through:
 * - Threat detection retrieval via PowerShell `Get-MpThreatDetection`
 * - Quick and full scans via `MpCmdRun.exe`
 * - Graceful handling on non-Windows platforms
 *
 * 透過以下方式提供與 Windows Defender 的整合：
 * - 透過 PowerShell `Get-MpThreatDetection` 取得威脅偵測
 * - 透過 `MpCmdRun.exe` 進行快速和完整掃描
 * - 在非 Windows 平台上優雅處理
 *
 * @example
 * ```typescript
 * const adapter = new DefenderAdapter({ enabled: true });
 * if (await adapter.isAvailable()) {
 *   const alerts = await adapter.getAlerts();
 *   const events = adapter.toSecurityEvents(alerts);
 * }
 * ```
 */
export class DefenderAdapter extends BaseAdapter {
  /** @inheritdoc */
  readonly name = 'Windows Defender';

  /** @inheritdoc */
  readonly type = 'antivirus';

  /**
   * Create a new DefenderAdapter instance
   * 建立新的 DefenderAdapter 實例
   *
   * @param config - Adapter configuration / 對接器配置
   */
  constructor(config: AdapterConfig = { enabled: true }) {
    super('adapter-defender', config);
  }

  /**
   * Check if Windows Defender is available on this system
   * 檢查 Windows Defender 在此系統上是否可用
   *
   * Returns false immediately on non-Windows platforms.
   * On Windows, attempts to run MpCmdRun.exe to verify availability.
   * 在非 Windows 平台上立即回傳 false。
   * 在 Windows 上，嘗試執行 MpCmdRun.exe 來驗證可用性。
   *
   * @returns True if Defender is available / 若 Defender 可用則回傳 true
   */
  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'win32') {
      this.logger.debug('Not a Windows platform, Defender unavailable');
      return false;
    }

    try {
      await execFileAsync(MPCMDRUN_PATH, ['-h']);
      this.logger.info('Windows Defender is available');
      return true;
    } catch (err) {
      this.logger.warn('Windows Defender MpCmdRun.exe not accessible', {
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  /**
   * Retrieve threat detections from Windows Defender
   * 從 Windows Defender 取得威脅偵測
   *
   * Uses PowerShell `Get-MpThreatDetection` to retrieve recent threats.
   * Returns an empty array on non-Windows platforms or on failure.
   * 使用 PowerShell `Get-MpThreatDetection` 取得最近的威脅。
   * 在非 Windows 平台上或失敗時回傳空陣列。
   *
   * @param since - Optional cutoff date / 可選截止日期
   * @returns Array of adapter alerts from Defender / 來自 Defender 的對接器告警陣列
   */
  async getAlerts(since?: Date): Promise<AdapterAlert[]> {
    if (process.platform !== 'win32') {
      return [];
    }

    try {
      const psCommand = 'Get-MpThreatDetection | ConvertTo-Json -Depth 3';
      const { stdout } = await execFileAsync('powershell', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        psCommand,
      ]);

      if (!stdout.trim()) {
        this.logger.debug('No threat detections returned from Defender');
        return [];
      }

      const parsed: DefenderThreat | DefenderThreat[] = JSON.parse(stdout);
      const threats = Array.isArray(parsed) ? parsed : [parsed];

      const alerts: AdapterAlert[] = [];

      for (const threat of threats) {
        const detectionTime = threat.initialDetectionTime || new Date().toISOString();

        // Filter by since date if provided / 若提供截止日期則過濾
        if (since) {
          const detectionDate = new Date(detectionTime);
          if (detectionDate < since) {
            continue;
          }
        }

        alerts.push({
          id: threat.detectionId || randomUUID(),
          timestamp: detectionTime,
          severity: mapDefenderSeverity(threat.severityId || '1'),
          title: `Defender Threat: ${threat.threatName || 'Unknown'}`,
          description: [
            `Threat: ${threat.threatName || 'Unknown'}`,
            `Action: ${threat.actionSuccess || 'Unknown'}`,
            `Resources: ${threat.resources || 'N/A'}`,
          ].join(' | '),
          source: 'defender',
          raw: threat,
        });
      }

      this.logger.info(`Retrieved ${alerts.length} alerts from Defender`, {
        total: threats.length,
        filtered: alerts.length,
      });

      return alerts;
    } catch (err) {
      this.logger.warn('Failed to retrieve Defender threat detections', {
        error: err instanceof Error ? err.message : String(err),
      });
      return [];
    }
  }

  /**
   * Trigger a Windows Defender scan
   * 觸發 Windows Defender 掃描
   *
   * Runs MpCmdRun.exe with the specified scan type.
   * Returns false on non-Windows platforms or on failure.
   * 以指定的掃描類型執行 MpCmdRun.exe。
   * 在非 Windows 平台上或失敗時回傳 false。
   *
   * @param scanType - Scan type: 1 = Quick, 2 = Full (default: 1) / 掃描類型：1 = 快速，2 = 完整（預設：1）
   * @returns True if scan started successfully / 若掃描成功啟動則回傳 true
   */
  async triggerScan(scanType: 1 | 2 = 1): Promise<boolean> {
    if (process.platform !== 'win32') {
      this.logger.warn('Cannot trigger scan on non-Windows platform');
      return false;
    }

    const scanTypeLabel = scanType === 1 ? 'Quick' : 'Full';
    this.logger.info(`Triggering ${scanTypeLabel} scan`);

    try {
      await execFileAsync(MPCMDRUN_PATH, ['-Scan', '-ScanType', String(scanType)]);
      this.logger.info(`${scanTypeLabel} scan completed successfully`);
      return true;
    } catch (err) {
      this.logger.error(`${scanTypeLabel} scan failed`, {
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }
}
