/**
 * Platform Detector - Detect installed AI agent runtimes
 * 平台偵測器 - 偵測已安裝的 AI Agent 執行環境
 *
 * Detects 13 platforms: Claude Code, Claude Desktop, Cursor, OpenClaw,
 * Codex, WorkBuddy, Windsurf, Cline, VS Code Copilot, Zed, Gemini CLI,
 * Continue, Roo Code.
 *
 * @module @panguard-ai/panguard-mcp/config/platform-detector
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { execFile, execFileSync } from 'node:child_process';
import { createLogger } from '@panguard-ai/core';

const logger = createLogger('panguard-mcp:platform-detector');

export type PlatformId =
  | 'claude-code'
  | 'claude-desktop'
  | 'cursor'
  | 'openclaw'
  | 'codex'
  | 'workbuddy'
  | 'windsurf'
  | 'cline'
  | 'vscode-copilot'
  | 'zed'
  | 'gemini-cli'
  | 'continue'
  | 'roo-code';

export interface DetectedPlatform {
  id: PlatformId;
  name: string;
  configPath: string;
  detected: boolean;
  alreadyConfigured: boolean;
}

/** Check if a command exists on PATH. */
function commandExists(cmd: string): Promise<boolean> {
  if (!/^[a-zA-Z0-9_.-]+$/.test(cmd)) return Promise.resolve(false);
  return new Promise((resolve) => {
    const bin = platform() === 'win32' ? 'where' : 'which';
    execFile(bin, [cmd], { windowsHide: true }, (err) => resolve(!err));
  });
}

/** Check if a JSON config file has a panguard MCP server entry. */
function hasPanguardMCPEntry(filePath: string): boolean {
  if (!existsSync(filePath)) return false;
  try {
    const parsed: unknown = JSON.parse(readFileSync(filePath, 'utf-8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const servers = (parsed as Record<string, unknown>)['mcpServers'];
      if (servers && typeof servers === 'object' && !Array.isArray(servers)) {
        return 'panguard' in (servers as Record<string, unknown>);
      }
    }
    return false;
  } catch {
    return false;
  }
}

/** Check if Claude Code has panguard MCP configured via `claude mcp list`. */
function hasClaudeCodePanguard(): boolean {
  try {
    const output = execFileSync('claude', ['mcp', 'list'], {
      timeout: 10_000,
      stdio: 'pipe',
      windowsHide: true,
    }).toString();
    return output.includes('panguard');
  } catch {
    // Fallback: check JSON config
    return hasPanguardMCPEntry(getClaudeCodeConfigPath());
  }
}

/** Check if OpenClaw has the panguard skill installed. */
function hasOpenClawSkill(): boolean {
  return existsSync(getOpenClawSkillPath());
}

/** Get the MCP config path for Claude Desktop based on OS. */
function getClaudeDesktopConfigPath(): string {
  const home = homedir();
  switch (platform()) {
    case 'darwin':
      return join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
    case 'win32':
      return join(
        process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'),
        'Claude',
        'claude_desktop_config.json'
      );
    default:
      return join(home, '.config', 'claude', 'claude_desktop_config.json');
  }
}

/** Get the MCP settings path for Claude Code. */
function getClaudeCodeConfigPath(): string {
  return join(homedir(), '.claude', 'settings.local.json');
}

/** Get the MCP config path for Cursor. */
function getCursorConfigPath(): string {
  return join(homedir(), '.cursor', 'mcp.json');
}

/** Get the OpenClaw skill installation path for Panguard. */
function getOpenClawSkillPath(): string {
  return join(homedir(), '.openclaw', 'skills', 'panguard', 'SKILL.md');
}

/** Get the OpenClaw skills directory for Panguard. */
function getOpenClawSkillDir(): string {
  return join(homedir(), '.openclaw', 'skills', 'panguard');
}

/** Get the MCP config path for Codex. */
function getCodexConfigPath(): string {
  return join(homedir(), '.codex', 'mcp.json');
}

/** Get the MCP config path for WorkBuddy. */
function getWorkbuddyConfigPath(): string {
  return join(homedir(), '.workbuddy', '.mcp.json');
}

/** Get the MCP config path for Windsurf (Codeium). */
function getWindsurfConfigPath(): string {
  return join(homedir(), '.codeium', 'windsurf', 'mcp_config.json');
}

/** Get the MCP settings path for Cline (VS Code extension). */
function getClineConfigPath(): string {
  const home = homedir();
  switch (platform()) {
    case 'darwin':
      return join(
        home,
        'Library',
        'Application Support',
        'Code',
        'User',
        'globalStorage',
        'saoudrizwan.claude-dev',
        'settings',
        'cline_mcp_settings.json'
      );
    case 'win32':
      return join(
        process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'),
        'Code',
        'User',
        'globalStorage',
        'saoudrizwan.claude-dev',
        'settings',
        'cline_mcp_settings.json'
      );
    default:
      return join(
        home,
        '.config',
        'Code',
        'User',
        'globalStorage',
        'saoudrizwan.claude-dev',
        'settings',
        'cline_mcp_settings.json'
      );
  }
}

/** Get the MCP config path for VS Code Copilot. */
function getVSCodeCopilotConfigPath(): string {
  const home = homedir();
  switch (platform()) {
    case 'darwin':
      return join(home, 'Library', 'Application Support', 'Code', 'User', 'settings.json');
    case 'win32':
      return join(
        process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'),
        'Code',
        'User',
        'settings.json'
      );
    default:
      return join(home, '.config', 'Code', 'User', 'settings.json');
  }
}

/** Get the MCP config path for Zed editor. */
function getZedConfigPath(): string {
  const home = homedir();
  switch (platform()) {
    case 'win32':
      return join(
        process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'),
        'Zed',
        'settings.json'
      );
    default:
      return join(home, '.config', 'zed', 'settings.json');
  }
}

/** Get the MCP config path for Gemini CLI. */
function getGeminiCliConfigPath(): string {
  return join(homedir(), '.gemini', 'settings.json');
}

/** Get the MCP config path for Continue.dev. */
function getContinueConfigPath(): string {
  return join(homedir(), '.continue', 'mcp.json');
}

/** Get the MCP settings path for Roo Code (VS Code extension). */
function getRooCodeConfigPath(): string {
  const home = homedir();
  switch (platform()) {
    case 'darwin':
      return join(
        home,
        'Library',
        'Application Support',
        'Code',
        'User',
        'globalStorage',
        'rooveterinaryinc.roo-cline',
        'settings',
        'cline_mcp_settings.json'
      );
    case 'win32':
      return join(
        process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'),
        'Code',
        'User',
        'globalStorage',
        'rooveterinaryinc.roo-cline',
        'settings',
        'cline_mcp_settings.json'
      );
    default:
      return join(
        home,
        '.config',
        'Code',
        'User',
        'globalStorage',
        'rooveterinaryinc.roo-cline',
        'settings',
        'cline_mcp_settings.json'
      );
  }
}

/**
 * Detect all supported AI agent platforms.
 * 偵測所有支援的 AI Agent 平台。
 *
 * @returns Array of detected platforms with their config paths and status.
 */
export async function detectPlatforms(): Promise<DetectedPlatform[]> {
  const platforms: DetectedPlatform[] = [];

  // Claude Code (uses `claude mcp add` CLI, not JSON config)
  const claudeCodePath = getClaudeCodeConfigPath();
  const claudeCodeDetected =
    (await commandExists('claude')) || existsSync(join(homedir(), '.claude'));
  platforms.push({
    id: 'claude-code',
    name: 'Claude Code',
    configPath: claudeCodePath,
    detected: claudeCodeDetected,
    alreadyConfigured: hasClaudeCodePanguard(),
  });

  // Claude Desktop
  const claudeDesktopPath = getClaudeDesktopConfigPath();
  const claudeDesktopDetected =
    existsSync(claudeDesktopPath) ||
    (platform() === 'darwin' && existsSync('/Applications/Claude.app'));
  platforms.push({
    id: 'claude-desktop',
    name: 'Claude Desktop',
    configPath: claudeDesktopPath,
    detected: claudeDesktopDetected,
    alreadyConfigured: hasPanguardMCPEntry(claudeDesktopPath),
  });

  // Cursor
  const cursorPath = getCursorConfigPath();
  const cursorDetected =
    (await commandExists('cursor')) ||
    existsSync(join(homedir(), '.cursor')) ||
    (platform() === 'darwin' && existsSync('/Applications/Cursor.app'));
  platforms.push({
    id: 'cursor',
    name: 'Cursor',
    configPath: cursorPath,
    detected: cursorDetected,
    alreadyConfigured: hasPanguardMCPEntry(cursorPath),
  });

  // OpenClaw (uses native skill system, not MCP)
  const openclawSkillDir = getOpenClawSkillDir();
  const openclawDetected =
    (await commandExists('openclaw')) || existsSync(join(homedir(), '.openclaw'));
  platforms.push({
    id: 'openclaw',
    name: 'OpenClaw',
    configPath: openclawSkillDir,
    detected: openclawDetected,
    alreadyConfigured: hasOpenClawSkill(),
  });

  // Codex
  const codexPath = getCodexConfigPath();
  const codexDetected = (await commandExists('codex')) || existsSync(join(homedir(), '.codex'));
  platforms.push({
    id: 'codex',
    name: 'Codex CLI',
    configPath: codexPath,
    detected: codexDetected,
    alreadyConfigured: hasPanguardMCPEntry(codexPath),
  });

  // WorkBuddy
  const wbPath = getWorkbuddyConfigPath();
  const wbDetected =
    (await commandExists('workbuddy')) || existsSync(join(homedir(), '.workbuddy'));
  platforms.push({
    id: 'workbuddy',
    name: 'WorkBuddy',
    configPath: wbPath,
    detected: wbDetected,
    alreadyConfigured: hasPanguardMCPEntry(wbPath),
  });

  // Windsurf (Codeium)
  const wsPath = getWindsurfConfigPath();
  const wsDetected =
    (await commandExists('windsurf')) || existsSync(join(homedir(), '.codeium', 'windsurf'));
  platforms.push({
    id: 'windsurf',
    name: 'Windsurf',
    configPath: wsPath,
    detected: wsDetected,
    alreadyConfigured: hasPanguardMCPEntry(wsPath),
  });

  // Cline (VS Code extension)
  const clinePath = getClineConfigPath();
  const clineDetected =
    existsSync(clinePath) ||
    existsSync(
      join(
        homedir(),
        'Library',
        'Application Support',
        'Code',
        'User',
        'globalStorage',
        'saoudrizwan.claude-dev'
      )
    );
  platforms.push({
    id: 'cline',
    name: 'Cline',
    configPath: clinePath,
    detected: clineDetected,
    alreadyConfigured: hasPanguardMCPEntry(clinePath),
  });

  // VS Code Copilot (via .vscode/mcp.json or user settings)
  const vscodePath = getVSCodeCopilotConfigPath();
  const vscodeDetected =
    (await commandExists('code')) ||
    (platform() === 'darwin' && existsSync('/Applications/Visual Studio Code.app'));
  platforms.push({
    id: 'vscode-copilot',
    name: 'VS Code Copilot',
    configPath: vscodePath,
    detected: vscodeDetected,
    alreadyConfigured: false, // VS Code uses different config structure
  });

  // Zed
  const zedPath = getZedConfigPath();
  const zedDetected =
    (await commandExists('zed')) ||
    existsSync(join(homedir(), '.config', 'zed')) ||
    (platform() === 'darwin' && existsSync('/Applications/Zed.app'));
  platforms.push({
    id: 'zed',
    name: 'Zed',
    configPath: zedPath,
    detected: zedDetected,
    alreadyConfigured: false, // Zed uses context_servers, not mcpServers
  });

  // Gemini CLI
  const geminiPath = getGeminiCliConfigPath();
  const geminiDetected = (await commandExists('gemini')) || existsSync(join(homedir(), '.gemini'));
  platforms.push({
    id: 'gemini-cli',
    name: 'Gemini CLI',
    configPath: geminiPath,
    detected: geminiDetected,
    alreadyConfigured: hasPanguardMCPEntry(geminiPath),
  });

  // Continue.dev
  const continuePath = getContinueConfigPath();
  const continueDetected = existsSync(join(homedir(), '.continue'));
  platforms.push({
    id: 'continue',
    name: 'Continue',
    configPath: continuePath,
    detected: continueDetected,
    alreadyConfigured: hasPanguardMCPEntry(continuePath),
  });

  // Roo Code (VS Code extension)
  const rooPath = getRooCodeConfigPath();
  const rooDetected =
    existsSync(rooPath) ||
    existsSync(
      join(
        homedir(),
        'Library',
        'Application Support',
        'Code',
        'User',
        'globalStorage',
        'rooveterinaryinc.roo-cline'
      )
    );
  platforms.push({
    id: 'roo-code',
    name: 'Roo Code',
    configPath: rooPath,
    detected: rooDetected,
    alreadyConfigured: hasPanguardMCPEntry(rooPath),
  });

  const detected = platforms.filter((p) => p.detected);
  logger.info(
    `Detected ${detected.length} platform(s): ${detected.map((p) => p.name).join(', ') || 'none'}`
  );
  return platforms;
}

/**
 * Get the MCP config path for a specific platform.
 * 取得特定平台的 MCP 設定路徑。
 */
export function getConfigPath(platformId: PlatformId): string {
  switch (platformId) {
    case 'claude-code':
      return getClaudeCodeConfigPath();
    case 'claude-desktop':
      return getClaudeDesktopConfigPath();
    case 'cursor':
      return getCursorConfigPath();
    case 'openclaw':
      return getOpenClawSkillDir();
    case 'codex':
      return getCodexConfigPath();
    case 'workbuddy':
      return getWorkbuddyConfigPath();
    case 'windsurf':
      return getWindsurfConfigPath();
    case 'cline':
      return getClineConfigPath();
    case 'vscode-copilot':
      return getVSCodeCopilotConfigPath();
    case 'zed':
      return getZedConfigPath();
    case 'gemini-cli':
      return getGeminiCliConfigPath();
    case 'continue':
      return getContinueConfigPath();
    case 'roo-code':
      return getRooCodeConfigPath();
  }
}
