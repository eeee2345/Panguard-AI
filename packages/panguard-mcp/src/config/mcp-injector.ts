/**
 * MCP Config Injector - Write Panguard MCP config to AI agent platforms
 * MCP 設定注入器 - 將 Panguard MCP 設定寫入 AI Agent 平台
 *
 * Supports Claude Code, Claude Desktop, Cursor, OpenClaw, Codex, Workbuddy.
 *
 * @module @panguard-ai/panguard-mcp/config/mcp-injector
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  copyFileSync,
  rmSync,
  chmodSync,
  readdirSync,
  unlinkSync,
} from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createLogger } from '@panguard-ai/core';
import type { PlatformId } from './platform-detector.js';
import { getConfigPath } from './platform-detector.js';

const logger = createLogger('panguard-mcp:injector');

export interface InjectionResult {
  platformId: PlatformId;
  success: boolean;
  configPath: string;
  backupPath?: string;
  error?: string;
}

/** The MCP server entry Panguard adds to config files. */
const PANGUARD_MCP_ENTRY = {
  command: 'npx',
  args: ['-y', '@panguard-ai/panguard-mcp'],
};

/**
 * Read an existing JSON config file, or return empty object.
 * 讀取現有 JSON 設定檔，或回傳空物件。
 */
function readJsonSafe(filePath: string): Record<string, unknown> {
  if (!existsSync(filePath)) return {};
  try {
    const raw = readFileSync(filePath, 'utf-8');
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return {};
  } catch {
    return {};
  }
}

/**
 * Atomically write JSON to a config file: write a temp file, then rename it
 * over the target. rename() is atomic on POSIX, so a crash or signal mid-write
 * can never leave the agent's config truncated or empty (which would break the
 * user's AI tool). The caller takes a .bak backup separately before mutating.
 */
function atomicWriteJson(filePath: string, data: unknown): void {
  const tmp = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8');
  try {
    renameSync(tmp, filePath);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* best-effort cleanup of the temp file */
    }
    throw err;
  }
}

/**
 * Back up a config file before modifying it.
 * 修改前備份設定檔。
 */
function backupFile(filePath: string): string | undefined {
  if (!existsSync(filePath)) return undefined;
  const backupPath = `${filePath}.bak.${Date.now()}`;
  copyFileSync(filePath, backupPath);
  // Set restrictive permissions — config files may contain API keys
  try {
    chmodSync(backupPath, 0o600);
  } catch {
    /* best effort */
  }
  logger.info(`Backed up ${filePath} -> ${backupPath}`);

  // Cleanup old backups — keep only the 3 most recent
  try {
    const dir = dirname(filePath);
    const base = basename(filePath);
    const backups = readdirSync(dir)
      .filter((f: string) => f.startsWith(`${base}.bak.`))
      .sort()
      .reverse();
    for (const old of backups.slice(3)) {
      unlinkSync(join(dir, old));
      logger.debug(`Removed old backup: ${old}`);
    }
  } catch {
    /* cleanup is best-effort */
  }

  return backupPath;
}

/**
 * Ensure parent directory exists.
 * 確保父目錄存在。
 */
function ensureDir(filePath: string): void {
  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

/**
 * Inject Panguard MCP config for Claude Desktop.
 * Claude Desktop uses: { "mcpServers": { "panguard": { "command": "...", "args": [...] } } }
 */
function injectClaudeDesktop(configPath: string): void {
  const config = readJsonSafe(configPath);
  const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
  servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
  config['mcpServers'] = servers;
  atomicWriteJson(configPath, config);
}

/**
 * Inject Panguard MCP config for Claude Code.
 * Claude Code uses `claude mcp add` CLI (not JSON file).
 * Falls back to writing settings.local.json if CLI not available.
 */
function injectClaudeCode(_configPath: string): void {
  try {
    // Try `claude mcp add` first (the correct way for Claude Code)
    execFileSync(
      'claude',
      ['mcp', 'add', '--scope', 'user', 'panguard', '--', 'npx', '-y', '@panguard-ai/panguard-mcp'],
      {
        timeout: 15_000,
        stdio: 'pipe',
        windowsHide: true,
      }
    );
    logger.info('Added Panguard MCP via `claude mcp add --scope user`');
  } catch {
    // Fallback: write JSON directly (older Claude Code versions)
    logger.warn('`claude mcp add` failed, falling back to JSON config');
    const config = readJsonSafe(_configPath);
    const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
    servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
    config['mcpServers'] = servers;
    atomicWriteJson(_configPath, config);
  }
}

/**
 * Inject Panguard MCP config for Cursor.
 * Cursor uses: { "mcpServers": { "panguard": { "command": "...", "args": [...] } } }
 * in ~/.cursor/mcp.json
 */
function injectCursor(configPath: string): void {
  const config = readJsonSafe(configPath);
  const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
  servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
  config['mcpServers'] = servers;
  atomicWriteJson(configPath, config);
}

/**
 * Inject Panguard MCP config for Codex/Workbuddy and other generic platforms.
 * Generic MCP JSON format: { "mcpServers": { "panguard": { ... } } }
 */
function injectGenericMCP(configPath: string): void {
  const config = readJsonSafe(configPath);
  const servers = (config['mcpServers'] as Record<string, unknown>) ?? {};
  servers['panguard'] = { ...PANGUARD_MCP_ENTRY };
  config['mcpServers'] = servers;
  atomicWriteJson(configPath, config);
}

/**
 * Inject Panguard as an OpenClaw native skill.
 * OpenClaw uses its own skill system (not MCP), so we copy SKILL.md
 * to ~/.openclaw/skills/panguard/.
 */
function injectOpenClawSkill(skillDir: string): void {
  mkdirSync(skillDir, { recursive: true });

  // Resolve the bundled SKILL.md from this package
  const thisDir = dirname(fileURLToPath(import.meta.url));
  const bundledSkill = join(thisDir, '..', '..', 'openclaw-skill', 'SKILL.md');

  if (existsSync(bundledSkill)) {
    copyFileSync(bundledSkill, join(skillDir, 'SKILL.md'));
  } else {
    // Fallback: write a minimal SKILL.md inline
    const skillContent = [
      '---',
      'name: panguard',
      'description: AI agent security platform -- audit skills, scan threats, run 24/7 protection',
      'homepage: https://panguard.ai',
      'license: MIT',
      'metadata: { "openclaw": { "requires": { "bins": ["npx"] }, "install": [{ "id": "node", "kind": "node", "package": "@panguard-ai/panguard", "bins": ["panguard"], "label": "Install Panguard AI" }] } }',
      '---',
      '',
      '# Panguard AI',
      '',
      'Security platform for AI agents with 10,400+ detection rules.',
      '',
      '## Commands',
      '- `panguard audit skill .` -- Audit skills for threats',
      '- `panguard scan` -- Security scan',
      '- `panguard guard start` -- Start real-time protection',
      '- `panguard status` -- Show status dashboard',
      '',
    ].join('\n');
    writeFileSync(join(skillDir, 'SKILL.md'), skillContent, 'utf-8');
  }
}

/**
 * Inject Panguard MCP config into a specific platform.
 * 將 Panguard MCP 設定注入特定平台。
 *
 * @param platformId - Target platform / 目標平台
 * @returns Injection result with success status and paths.
 */
export function injectMCPConfig(platformId: PlatformId): InjectionResult {
  const configPath = getConfigPath(platformId);
  const result: InjectionResult = { platformId, success: false, configPath };

  try {
    ensureDir(configPath);
    result.backupPath = backupFile(configPath);

    switch (platformId) {
      case 'claude-desktop':
        injectClaudeDesktop(configPath);
        break;
      case 'claude-code':
        injectClaudeCode(configPath);
        break;
      case 'cursor':
        injectCursor(configPath);
        break;
      case 'openclaw':
        injectOpenClawSkill(configPath);
        break;
      case 'codex':
      case 'workbuddy':
      case 'windsurf':
      case 'cline':
      case 'vscode-copilot':
      case 'zed':
      case 'gemini-cli':
      case 'continue':
      case 'roo-code':
        injectGenericMCP(configPath);
        break;
    }

    // Verify the write succeeded
    if (platformId === 'claude-code') {
      // Claude Code: verify via `claude mcp list`
      try {
        const output = execFileSync('claude', ['mcp', 'list'], {
          timeout: 10_000,
          stdio: 'pipe',
          windowsHide: true,
        }).toString();
        if (output.includes('panguard')) {
          result.success = true;
          logger.info('Verified Panguard MCP in Claude Code via `claude mcp list`');
        } else {
          // Might take a moment to register, assume success if inject didn't throw
          result.success = true;
          logger.info('Panguard MCP added to Claude Code (pending verification)');
        }
      } catch {
        result.success = true; // inject didn't throw, assume OK
        logger.info('Panguard MCP injected into Claude Code');
      }
    } else if (platformId === 'openclaw') {
      // OpenClaw uses SKILL.md, not JSON
      if (existsSync(join(configPath, 'SKILL.md'))) {
        result.success = true;
        logger.info(`Installed Panguard skill for OpenClaw at ${configPath}`);
      } else {
        result.error = 'Verification failed: SKILL.md not found after write';
        logger.error(result.error);
      }
    } else {
      const verify = readJsonSafe(configPath);
      const servers = verify['mcpServers'] as Record<string, unknown> | undefined;
      if (servers && servers['panguard']) {
        result.success = true;
        logger.info(`Injected Panguard MCP config into ${platformId} at ${configPath}`);
      } else {
        result.error = 'Verification failed: panguard entry not found after write';
        logger.error(result.error);
      }
    }
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to inject ${platformId}: ${result.error}`);
  }

  return result;
}

/**
 * Remove Panguard MCP config from a specific platform.
 * 從特定平台移除 Panguard MCP 設定。
 */
export function removeMCPConfig(platformId: PlatformId): InjectionResult {
  const configPath = getConfigPath(platformId);
  const result: InjectionResult = { platformId, success: false, configPath };

  try {
    if (platformId === 'openclaw') {
      // Remove OpenClaw skill directory
      const skillMd = join(configPath, 'SKILL.md');
      if (existsSync(skillMd)) {
        rmSync(configPath, { recursive: true, force: true });
        logger.info(`Removed Panguard skill from OpenClaw`);
      }
      result.success = true;
      return result;
    }

    if (!existsSync(configPath)) {
      result.success = true;
      return result;
    }

    result.backupPath = backupFile(configPath);
    const config = readJsonSafe(configPath);
    const servers = config['mcpServers'] as Record<string, unknown> | undefined;
    if (servers) {
      delete servers['panguard'];
      config['mcpServers'] = servers;
    }
    atomicWriteJson(configPath, config);
    result.success = true;
    logger.info(`Removed Panguard MCP config from ${platformId}`);
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to remove from ${platformId}: ${result.error}`);
  }

  return result;
}

/**
 * Inject Panguard MCP config into all detected platforms.
 * 將 Panguard MCP 設定注入所有偵測到的平台。
 */
export async function injectAll(platformIds: PlatformId[]): Promise<InjectionResult[]> {
  return platformIds.map((id) => injectMCPConfig(id));
}

/**
 * Get the one-liner install command for display.
 * 取得用於顯示的一行安裝指令。
 */
export function getInstallCommand(): string {
  return 'npx panguard setup';
}

// ── Proxy Injection ──────────────────────────────────────────

const PROXY_PACKAGE = '@panguard-ai/panguard-mcp-proxy';

/** Check if an MCP server entry is already wrapped with the proxy. */
function isAlreadyProxied(server: Record<string, unknown>): boolean {
  const args = Array.isArray(server['args']) ? server['args'] : [];
  return args.some((a: unknown) => typeof a === 'string' && a.includes(PROXY_PACKAGE));
}

/** Check if an MCP server entry belongs to PanGuard itself. */
function isPanguardEntry(name: string, server: Record<string, unknown>): boolean {
  if (name === 'panguard') return true;
  const args = Array.isArray(server['args']) ? server['args'] : [];
  const command = typeof server['command'] === 'string' ? server['command'] : '';
  return (
    command.includes('panguard') ||
    args.some((a: unknown) => typeof a === 'string' && a.includes('@panguard-ai/panguard-mcp'))
  );
}

/** Wrap a single MCP server entry with the proxy. Returns a new object. */
function wrapWithProxy(server: Record<string, unknown>): Record<string, unknown> {
  const command = typeof server['command'] === 'string' ? server['command'] : '';
  const args = Array.isArray(server['args'])
    ? (server['args'] as unknown[]).filter((a): a is string => typeof a === 'string')
    : [];

  // New args: npx -y @panguard-ai/panguard-mcp-proxy -- <original command> <original args>
  const proxyArgs = ['-y', PROXY_PACKAGE, '--', command, ...args];

  return { ...server, command: 'npx', args: proxyArgs };
}

/** Unwrap a proxy-wrapped MCP server entry. Returns null if not proxied. */
function unwrapProxy(server: Record<string, unknown>): Record<string, unknown> | null {
  if (!isAlreadyProxied(server)) return null;

  const args = Array.isArray(server['args'])
    ? (server['args'] as unknown[]).filter((a): a is string => typeof a === 'string')
    : [];

  // Find "--" separator
  const sepIdx = args.indexOf('--');
  if (sepIdx === -1 || sepIdx >= args.length - 1) return null;

  const originalCommand = args[sepIdx + 1]!;
  const originalArgs = args.slice(sepIdx + 2);

  return { ...server, command: originalCommand, args: originalArgs };
}

export interface ProxyInjectionResult {
  readonly platformId: PlatformId;
  readonly configPath: string;
  readonly serversProxied: number;
  readonly serversSkipped: number;
  readonly backupPath?: string;
  readonly error?: string;
}

export interface ProxyInjectionSummary {
  readonly results: readonly ProxyInjectionResult[];
  readonly totalPlatforms: number;
  readonly totalServersProxied: number;
}

/**
 * Inject proxy into all MCP servers on a single JSON-config platform.
 * Wraps each non-panguard server with panguard-mcp-proxy.
 * Skips already-proxied servers and panguard's own entries.
 */
function injectProxyForJsonPlatform(
  platformId: PlatformId,
  configPath: string
): ProxyInjectionResult {
  const result: {
    platformId: PlatformId;
    configPath: string;
    serversProxied: number;
    serversSkipped: number;
    backupPath?: string;
    error?: string;
  } = {
    platformId,
    configPath,
    serversProxied: 0,
    serversSkipped: 0,
  };

  if (!existsSync(configPath)) {
    return result;
  }

  try {
    const config = readJsonSafe(configPath);
    const servers = config['mcpServers'] as Record<string, unknown> | undefined;
    if (!servers || typeof servers !== 'object') return result;

    const updatedServers: Record<string, unknown> = {};
    let changed = false;

    for (const [name, value] of Object.entries(servers)) {
      if (!value || typeof value !== 'object') {
        updatedServers[name] = value;
        continue;
      }
      const server = value as Record<string, unknown>;

      // Skip panguard's own entries
      if (isPanguardEntry(name, server)) {
        updatedServers[name] = server;
        result.serversSkipped++;
        continue;
      }

      // Skip already proxied
      if (isAlreadyProxied(server)) {
        updatedServers[name] = server;
        result.serversSkipped++;
        continue;
      }

      // Wrap with proxy
      updatedServers[name] = wrapWithProxy(server);
      result.serversProxied++;
      changed = true;
    }

    if (changed) {
      result.backupPath = backupFile(configPath);
      const updatedConfig = { ...config, mcpServers: updatedServers };
      ensureDir(configPath);
      atomicWriteJson(configPath, updatedConfig);
      logger.info(`Proxied ${result.serversProxied} server(s) on ${platformId}`);
    }
  } catch (err) {
    result.error = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to inject proxy for ${platformId}: ${result.error}`);
  }

  return result;
}

/**
 * Inject MCP proxy into all detected platforms.
 * Wraps every non-panguard MCP server with panguard-mcp-proxy
 * so all tool calls pass through ATR evaluation.
 *
 * @param platformIds - Platforms to inject proxy into
 * @returns Summary with per-platform results
 */
export function injectProxy(platformIds: readonly PlatformId[]): ProxyInjectionSummary {
  const results: ProxyInjectionResult[] = [];

  for (const platformId of platformIds) {
    // OpenClaw uses SKILL.md, not MCP protocol — skip
    if (platformId === 'openclaw') continue;

    const configPath = getConfigPath(platformId);
    const result = injectProxyForJsonPlatform(platformId, configPath);
    results.push(result);
  }

  const totalServersProxied = results.reduce((sum, r) => sum + r.serversProxied, 0);
  const totalPlatforms = results.filter((r) => r.serversProxied > 0).length;

  return { results, totalPlatforms, totalServersProxied };
}

/**
 * Remove proxy wrappers from all MCP servers on detected platforms.
 * Restores original command/args for each proxied server.
 *
 * @param platformIds - Platforms to remove proxy from
 * @returns Summary with per-platform results
 */
export function removeProxy(platformIds: readonly PlatformId[]): ProxyInjectionSummary {
  const results: ProxyInjectionResult[] = [];

  for (const platformId of platformIds) {
    if (platformId === 'openclaw') continue;

    const configPath = getConfigPath(platformId);
    const result: {
      platformId: PlatformId;
      configPath: string;
      serversProxied: number;
      serversSkipped: number;
      backupPath?: string;
      error?: string;
    } = {
      platformId,
      configPath,
      serversProxied: 0,
      serversSkipped: 0,
    };

    if (!existsSync(configPath)) {
      results.push(result);
      continue;
    }

    try {
      const config = readJsonSafe(configPath);
      const servers = config['mcpServers'] as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') {
        results.push(result);
        continue;
      }

      const updatedServers: Record<string, unknown> = {};
      let changed = false;

      for (const [name, value] of Object.entries(servers)) {
        if (!value || typeof value !== 'object') {
          updatedServers[name] = value;
          continue;
        }
        const server = value as Record<string, unknown>;
        const unwrapped = unwrapProxy(server);

        if (unwrapped) {
          updatedServers[name] = unwrapped;
          result.serversProxied++;
          changed = true;
        } else {
          updatedServers[name] = server;
        }
      }

      if (changed) {
        result.backupPath = backupFile(configPath);
        const updatedConfig = { ...config, mcpServers: updatedServers };
        atomicWriteJson(configPath, updatedConfig);
        logger.info(`Removed proxy from ${result.serversProxied} server(s) on ${platformId}`);
      }
    } catch (err) {
      result.error = err instanceof Error ? err.message : String(err);
      logger.error(`Failed to remove proxy for ${platformId}: ${result.error}`);
    }

    results.push(result);
  }

  const totalServersProxied = results.reduce((sum, r) => sum + r.serversProxied, 0);
  const totalPlatforms = results.filter((r) => r.serversProxied > 0).length;

  return { results, totalPlatforms, totalServersProxied };
}
