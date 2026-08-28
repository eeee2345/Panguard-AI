/**
 * Platform Sandbox Tests
 * 平台沙盒測試
 *
 * Tests platform detection and config path resolution for all 13 platforms
 * using isolated temp directories as sandboxed home environments.
 *
 * @module @panguard-ai/panguard-mcp/tests/platform-sandbox
 */

import { describe, it, expect, vi, afterAll } from 'vitest';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ─── Sandbox Setup ──────────────────────────────────────────────────────────

const SANDBOX_ROOT = join(tmpdir(), `panguard-sandbox-${Date.now()}`);
const FAKE_HOME = join(SANDBOX_ROOT, 'home');

// Mock os.homedir() and platform()
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => FAKE_HOME,
  };
});

// Mock child_process to prevent actual command lookups.
// execFile's callback is always the last argument, with or without an options
// object in between — read it positionally so the stub matches either shape.
vi.mock('node:child_process', () => ({
  execFile: (...args: unknown[]) => {
    const cb = args[args.length - 1] as (err: Error | null) => void;
    cb(new Error('not found'));
  },
  execFileSync: () => {
    throw new Error('not found');
  },
}));

// Mock @panguard-ai/core
vi.mock('@panguard-ai/core', () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

// Import after mocks
import { detectPlatforms, getConfigPath } from '../src/config/platform-detector.js';
import type { PlatformId } from '../src/config/platform-detector.js';

// ─── Cleanup ────────────────────────────────────────────────────────────────

afterAll(() => {
  rmSync(SANDBOX_ROOT, { recursive: true, force: true });
});

// ─── All 13 Platform IDs ────────────────────────────────────────────────────

const ALL_PLATFORM_IDS: PlatformId[] = [
  'claude-code',
  'claude-desktop',
  'cursor',
  'openclaw',
  'codex',
  'workbuddy',
  'windsurf',
  'cline',
  'vscode-copilot',
  'zed',
  'gemini-cli',
  'continue',
  'roo-code',
];

// ═══════════════════════════════════════════════════════════════════════════
// 1. All platforms registered (no detection, just existence)
// ═══════════════════════════════════════════════════════════════════════════

describe('All supported platforms registered', () => {
  it('detectPlatforms returns all 13 platforms', async () => {
    const platforms = await detectPlatforms();
    expect(platforms.length).toBeGreaterThanOrEqual(13);
  });

  it('includes all expected platform IDs', async () => {
    const platforms = await detectPlatforms();
    const ids = platforms.map((p) => p.id);

    for (const id of ALL_PLATFORM_IDS) {
      expect(ids, `missing platform: ${id}`).toContain(id);
    }
  });

  it('getConfigPath returns valid path for all platforms', () => {
    for (const id of ALL_PLATFORM_IDS) {
      const configPath = getConfigPath(id);
      expect(configPath, `getConfigPath('${id}') returned falsy`).toBeTruthy();
      expect(typeof configPath).toBe('string');
      expect(configPath!.length).toBeGreaterThan(0);
    }
  });

  it('no two platforms share the same config path', () => {
    const paths = ALL_PLATFORM_IDS.map((id) => getConfigPath(id));
    const unique = new Set(paths);
    // vscode-copilot and cline/roo-code are in the same VS Code dir but different files
    // Just check no exact duplicates
    expect(unique.size).toBe(paths.length);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Detection via directory existence
// ═══════════════════════════════════════════════════════════════════════════

describe('Platform detection via directory', () => {
  const dirDetectionTests: Array<{ id: PlatformId; name: string; dir: string }> = [
    { id: 'claude-code', name: 'Claude Code', dir: '.claude' },
    { id: 'cursor', name: 'Cursor', dir: '.cursor' },
    { id: 'openclaw', name: 'OpenClaw', dir: '.openclaw' },
    { id: 'codex', name: 'Codex CLI', dir: '.codex' },
    { id: 'workbuddy', name: 'WorkBuddy', dir: '.workbuddy' },
    { id: 'gemini-cli', name: 'Gemini CLI', dir: '.gemini' },
    { id: 'continue', name: 'Continue', dir: '.continue' },
  ];

  for (const { id, name, dir } of dirDetectionTests) {
    it(`detects ${name} when ~/${dir}/ exists`, async () => {
      mkdirSync(join(FAKE_HOME, dir), { recursive: true });
      const platforms = await detectPlatforms();
      const platform = platforms.find((p) => p.id === id);
      expect(platform, `platform ${id} not found`).toBeDefined();
      expect(platform!.detected, `${name} should be detected via ~/${dir}/`).toBe(true);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. alreadyConfigured detection
// ═══════════════════════════════════════════════════════════════════════════

describe('alreadyConfigured detection', () => {
  it('detects existing panguard MCP entry in cursor config', async () => {
    const cursorDir = join(FAKE_HOME, '.cursor');
    mkdirSync(cursorDir, { recursive: true });
    writeFileSync(
      join(cursorDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: { panguard: { command: 'npx', args: ['-y', '@panguard-ai/panguard-mcp'] } },
      })
    );

    const platforms = await detectPlatforms();
    const cursor = platforms.find((p) => p.id === 'cursor');
    expect(cursor!.alreadyConfigured).toBe(true);
  });

  it('detects existing panguard MCP entry in gemini config', async () => {
    const geminiDir = join(FAKE_HOME, '.gemini');
    mkdirSync(geminiDir, { recursive: true });
    writeFileSync(
      join(geminiDir, 'settings.json'),
      JSON.stringify({
        mcpServers: { panguard: { command: 'npx', args: ['-y', '@panguard-ai/panguard-mcp'] } },
      })
    );

    const platforms = await detectPlatforms();
    const gemini = platforms.find((p) => p.id === 'gemini-cli');
    expect(gemini!.alreadyConfigured).toBe(true);
  });
});
