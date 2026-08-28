/**
 * Windows console-window invariant for Guard subprocesses
 * Guard 子程序的 Windows 主控台視窗不變條件
 *
 * Guard is meant to run unattended (Windows service, Task Scheduler, or a
 * detached `pga guard start`), so it owns no console of its own. On Windows a
 * console child launched from such a process does not inherit a console -- it
 * is given a brand new one, and the window is painted on the desktop for as
 * long as the child lives. Node only suppresses that with `windowsHide: true`,
 * which defaults to false.
 *
 * ProcessWatcher polls `tasklist` every 5 seconds, so without the flag Guard
 * flashes a console window twelve times a minute for as long as protection is
 * on. Hiding the launcher does not help: the flag has to be set on each child.
 * It is a no-op on macOS and Linux.
 *
 * Guard 需在無人值守下執行，本身沒有主控台。Windows 上這類程序啟動的子程序
 * 會取得全新的主控台視窗，除非傳入 `windowsHide: true`（預設為 false）。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { execFileMock, execFileSyncMock, spawnMock, platformMock } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  execFileSyncMock: vi.fn(),
  spawnMock: vi.fn(),
  platformMock: vi.fn(() => 'win32'),
}));

vi.mock('node:child_process', () => ({
  execFile: execFileMock,
  execFileSync: execFileSyncMock,
  spawn: spawnMock,
}));

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, platform: platformMock };
});

import { ProcessWatcher } from '../src/watchers/process-watcher.js';
import { runNpmAudit } from '../src/watchers/dependency-watcher.js';
import { execFilePromise } from '../src/agent/respond/os-actions.js';

/** Options object handed to the child_process call at `index` */
function optionsOfCall(index: number): Record<string, unknown> {
  const call = execFileMock.mock.calls[index];
  expect(call, `expected an execFile call at index ${index}`).toBeDefined();
  return (call?.[2] ?? {}) as Record<string, unknown>;
}

/** Commands passed to every execFile call so far */
function commandsCalled(): string[] {
  return execFileMock.mock.calls.map((c) => String(c[0]));
}

describe('Guard subprocesses never paint a Windows console window', () => {
  beforeEach(() => {
    execFileMock.mockReset();
    execFileSyncMock.mockReset();
    spawnMock.mockReset();
    platformMock.mockReturnValue('win32');

    // Every launch site takes a (cmd, args, options, callback) shape; answer the
    // callback so the promisified wrappers settle.
    execFileMock.mockImplementation(
      (
        _cmd: string,
        _args: readonly string[],
        _opts: unknown,
        cb?: (err: Error | null, stdout: unknown, stderr?: unknown) => void
      ) => {
        cb?.(null, { stdout: '', stderr: '' }, '');
      }
    );
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('ProcessWatcher', () => {
    it('hides the console window when probing tasklist availability', async () => {
      const watcher = new ProcessWatcher();

      await watcher.checkAvailability();

      expect(commandsCalled()).toContain('tasklist');
      expect(optionsOfCall(0)['windowsHide']).toBe(true);
    });

    it('hides the console window on the tasklist poll that runs every 5 seconds', async () => {
      const watcher = new ProcessWatcher();

      // start() takes the baseline snapshot through the same code path the
      // interval later polls with.
      await watcher.start();
      watcher.stop();

      const tasklistCalls = execFileMock.mock.calls.filter((c) => c[0] === 'tasklist');
      expect(tasklistCalls.length).toBeGreaterThan(0);
      for (const call of tasklistCalls) {
        expect((call[2] as Record<string, unknown>)['windowsHide']).toBe(true);
      }
    });

    it('keeps the existing tasklist arguments and timeout', async () => {
      const watcher = new ProcessWatcher();

      await watcher.start();
      watcher.stop();

      const call = execFileMock.mock.calls.find((c) => c[0] === 'tasklist');
      expect(call?.[1]).toEqual(['/FO', 'CSV', '/V']);
      expect((call?.[2] as Record<string, unknown>)['timeout']).toBe(5000);
      expect((call?.[2] as Record<string, unknown>)['maxBuffer']).toBe(10 * 1024 * 1024);
    });

    it('leaves the POSIX ps path exactly as it was', async () => {
      platformMock.mockReturnValue('linux');
      const watcher = new ProcessWatcher();

      await watcher.start();
      watcher.stop();

      // `ps` cannot run on Windows, so the flag has no business there; the
      // POSIX branch must keep behaving identically.
      const call = execFileMock.mock.calls.find((c) => c[0] === 'ps');
      expect(call?.[1]).toEqual(['-eo', 'pid,ppid,user,comm,args']);
      expect(call?.[2]).toEqual({ timeout: 5000, maxBuffer: 10 * 1024 * 1024 });
    });
  });

  describe('dependency watcher', () => {
    it('hides the console window for npm audit', async () => {
      execFileMock.mockImplementation(
        (
          _cmd: string,
          _args: readonly string[],
          _opts: unknown,
          cb?: (err: Error | null, stdout: string) => void
        ) => {
          cb?.(null, '{"vulnerabilities":{}}');
        }
      );

      await runNpmAudit('/tmp/project');

      expect(commandsCalled()).toContain('npm');
      const opts = optionsOfCall(0);
      expect(opts['windowsHide']).toBe(true);
      // The pre-existing options must survive.
      expect(opts['cwd']).toBe('/tmp/project');
      expect(opts['timeout']).toBe(30_000);
    });
  });

  describe('response actions', () => {
    it('hides the console window for OS response commands (taskkill, netsh)', async () => {
      execFileMock.mockImplementation(
        (
          _cmd: string,
          _args: readonly string[],
          _opts: unknown,
          cb?: (err: Error | null, stdout: string) => void
        ) => {
          cb?.(null, '');
        }
      );

      await execFilePromise('taskkill', ['/PID', '1234', '/F']);

      const opts = optionsOfCall(0);
      expect(opts['windowsHide']).toBe(true);
      expect(opts['timeout']).toBe(10000);
    });
  });
});
