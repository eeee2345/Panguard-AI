/**
 * Windows console-window invariant for core monitors and adapters
 * 核心監控器與對接器的 Windows 主控台視窗不變條件
 *
 * These run inside the unattended Guard process, which owns no console. On
 * Windows a console child launched from such a process is given a new console
 * window unless the launch passes `windowsHide: true` (Node defaults it to
 * false). The Defender adapter shells out to `powershell`, and the log monitor
 * to `wevtutil`, so without the flag both paint a window on the desktop every
 * time they run. The flag is ignored on macOS and Linux.
 *
 * 這些元件在無主控台的 Guard 程序中執行；Windows 上若未傳入
 * `windowsHide: true`，每次呼叫都會在桌面上畫出一個主控台視窗。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { execFileMock, spawnMock, platformMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  spawnMock: vi.fn(),
  platformMock: vi.fn(() => 'win32'),
}));

vi.mock('node:child_process', () => ({
  execFile: execFileMock,
  spawn: spawnMock,
}));

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, platform: platformMock };
});

import { DefenderAdapter } from '../src/adapters/defender-adapter.js';
import { LogMonitor } from '../src/monitor/log-monitor.js';

/** Minimal stub of the ChildProcess surface LogMonitor touches */
function stubChildProcess(): Record<string, unknown> {
  return {
    stdout: null,
    stderr: null,
    killed: false,
    on: vi.fn(),
    once: vi.fn(),
    removeAllListeners: vi.fn(),
    kill: vi.fn(),
    unref: vi.fn(),
  };
}

describe('core subprocesses never paint a Windows console window', () => {
  const realPlatform = process.platform;

  beforeEach(() => {
    execFileMock.mockReset();
    spawnMock.mockReset();
    platformMock.mockReturnValue('win32');
    spawnMock.mockImplementation(() => stubChildProcess());
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  });

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: realPlatform, configurable: true });
    vi.clearAllMocks();
  });

  describe('DefenderAdapter', () => {
    it('hides the console window for the MpCmdRun availability probe', async () => {
      execFileMock.mockImplementation(
        (
          _cmd: string,
          _args: readonly string[],
          _opts: unknown,
          cb?: (err: Error | null, stdout: string, stderr: string) => void
        ) => {
          cb?.(null, '', '');
        }
      );

      await new DefenderAdapter({ enabled: true }).isAvailable();

      const call = execFileMock.mock.calls[0];
      expect(call?.[0]).toContain('MpCmdRun.exe');
      expect((call?.[2] as Record<string, unknown>)['windowsHide']).toBe(true);
    });

    it('hides the console window for the Get-MpThreatDetection PowerShell call', async () => {
      execFileMock.mockImplementation(
        (
          _cmd: string,
          _args: readonly string[],
          _opts: unknown,
          cb?: (err: Error | null, stdout: string, stderr: string) => void
        ) => {
          cb?.(null, '[]', '');
        }
      );

      await new DefenderAdapter({ enabled: true }).getAlerts();

      const call = execFileMock.mock.calls.find((c) => c[0] === 'powershell');
      expect(call, 'expected a powershell invocation').toBeDefined();
      const opts = call?.[2] as Record<string, unknown>;
      expect(opts['windowsHide']).toBe(true);
      // The pre-existing timeout must survive.
      expect(opts['timeout']).toBe(60000);
    });
  });

  describe('LogMonitor', () => {
    it('hides the console window for the wevtutil event-log reader', () => {
      const monitor = new LogMonitor();

      monitor.start();
      monitor.stop();

      const call = spawnMock.mock.calls.find((c) => c[0] === 'wevtutil');
      expect(call, 'expected a wevtutil spawn on win32').toBeDefined();
      expect(call?.[1]).toEqual(['qe', 'Security', '/f:text', '/rd:true', '/c:1']);
      expect((call?.[2] as Record<string, unknown>)['windowsHide']).toBe(true);
    });

    it('leaves the POSIX readers exactly as they were', () => {
      platformMock.mockReturnValue('linux');
      const monitor = new LogMonitor();

      monitor.start();
      monitor.stop();

      // `tail` cannot run on Windows, so the flag has no business there; the
      // POSIX branch must keep behaving identically.
      const call = spawnMock.mock.calls.find((c) => c[0] === 'tail');
      expect(call, 'expected a tail spawn on linux').toBeDefined();
      expect(call?.[1]).toEqual(['-F', '/var/log/auth.log', '/var/log/syslog']);
      expect(call?.[2]).toBeUndefined();
    });
  });
});
