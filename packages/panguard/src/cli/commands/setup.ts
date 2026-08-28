/**
 * panguard setup - One-command platform setup with skill scanning
 * panguard setup - 一行指令平台安裝並掃描技能
 *
 * Detects installed AI agent platforms, injects MCP config,
 * scans and audits all installed skills, and optionally starts Guard.
 * 偵測已安裝的 AI Agent 平台，注入 MCP 設定，掃描審核所有已安裝技能，可選啟動 Guard。
 */

import { Command } from 'commander';
import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';
import { createRequire } from 'node:module';
import { c, banner, divider, symbols, promptConfirm } from '@panguard-ai/core';
import { PANGUARD_VERSION } from '../../index.js';
import {
  scanInstalledSkills,
  renderSkillScanResults,
  reviewFlaggedSkills,
} from './setup-skill-scan.js';
import { markInitialized } from '../first-run.js';
import { readAuthenticatedDashboardUrl, dashboardBaseUrl } from '../dashboard-url.js';
import { recordScanResults, toEvidence, type RiskLevel } from '../flagged-skills.js';

/** Open URL in the default browser (cross-platform) */
function openBrowser(url: string): void {
  const os = platform();
  if (os === 'win32') {
    const systemRoot = process.env['SystemRoot'] || 'C:\\Windows';
    const cmd = `${systemRoot}\\System32\\cmd.exe`;
    execFile(cmd, ['/c', 'start', '', url], () => {});
  } else if (os === 'darwin') {
    execFile('open', [url], () => {});
  } else {
    execFile('xdg-open', [url], () => {});
  }
}

/** Persist skill names into the Guard whitelist JSON file */
function persistToWhitelist(skillNames: readonly string[], source: 'manual' | 'static'): void {
  const guardDir = join(homedir(), '.panguard-guard');
  const whitelistPath = join(guardDir, 'skill-whitelist.json');

  // Trust-critical store: the whitelist decides which skills are ALLOWED, so it
  // must be owner-only (0700 dir / 0600 file). A world-readable trust store is an
  // information leak and inconsistent with the rest of ~/.panguard-guard.
  if (!existsSync(guardDir)) {
    mkdirSync(guardDir, { recursive: true, mode: 0o700 });
  }
  try {
    chmodSync(guardDir, 0o700);
  } catch {
    /* best-effort: non-POSIX filesystems (e.g. Windows) ignore modes */
  }

  // Load existing whitelist if present
  let existing: {
    whitelist: Array<{
      name: string;
      normalizedName: string;
      source: string;
      addedAt: string;
      fingerprintHash?: string;
      reason?: string;
    }>;
    revoked: string[];
  } = { whitelist: [], revoked: [] };

  if (existsSync(whitelistPath)) {
    try {
      existing = JSON.parse(readFileSync(whitelistPath, 'utf-8')) as typeof existing;
    } catch {
      console.warn(c.yellow(`  ${symbols.warn} Whitelist file was corrupt and has been reset.`));
    }
  }

  const existingNames = new Set(existing.whitelist.map((e) => e.normalizedName));
  const now = new Date().toISOString();

  for (const name of skillNames) {
    const normalized = name.toLowerCase().trim().replace(/\s+/g, '-');
    if (existingNames.has(normalized)) continue;

    existing.whitelist.push({
      name,
      normalizedName: normalized,
      source,
      addedAt: now,
      reason:
        source === 'manual' ? 'User-approved during setup' : 'Auto-whitelisted during setup (safe)',
    });
    existingNames.add(normalized);
  }

  writeFileSync(whitelistPath, JSON.stringify(existing, null, 2), {
    encoding: 'utf-8',
    mode: 0o600,
  });
  try {
    // writeFileSync's mode only applies on CREATE; chmod an existing file too.
    chmodSync(whitelistPath, 0o600);
  } catch {
    /* best-effort */
  }
}

/** Platform-specific restart instructions */
const PLATFORM_RESTART_HINTS: Record<string, string> = {
  'claude-code': 'Close and reopen your terminal',
  'claude-desktop': 'Quit and reopen Claude Desktop',
  cursor: 'Cmd+Shift+P (or Ctrl+Shift+P) > "Reload Window"',
  openclaw: 'Close and reopen OpenClaw',
  codex: 'Restart the Codex CLI session',
  workbuddy: 'Close and reopen WorkBuddy',
};

export function setupCommand(): Command {
  const cmd = new Command('setup')
    .description('Auto-detect AI agent platforms and configure Panguard MCP')
    .option(
      '--platform <name>',
      'Target a specific platform (claude-code, cursor, openclaw, codex, workbuddy, claude-desktop)'
    )
    .option('--remove', 'Remove Panguard MCP config from platforms', false)
    .option('--json', 'Output as JSON', false)
    .option('--yes', 'Skip confirmation prompts', false)
    .option('--skip-scan', 'Skip skill scanning', false)
    .option('--skip-guard', 'Skip guard start prompt', false)
    .option('--skip-service', 'Do not install the reboot-surviving system service', false)
    .option('--lang <lang>', 'UI language: en or zh-TW (auto-detect if omitted)')
    .action(
      async (options: {
        platform?: string;
        remove: boolean;
        json: boolean;
        yes: boolean;
        skipScan: boolean;
        skipGuard: boolean;
        skipService: boolean;
        lang?: string;
      }) => {
        // Detect UI language: --lang flag > system locale > default zh-TW
        const sysLang = (process.env['LANG'] ?? process.env['LC_ALL'] ?? '').toLowerCase();
        const isSystemChinese = sysLang.includes('zh') || sysLang.includes('chinese');
        const detectedLang: 'en' | 'zh-TW' =
          options.lang === 'en'
            ? 'en'
            : options.lang === 'zh-TW'
              ? 'zh-TW'
              : isSystemChinese
                ? 'zh-TW'
                : 'en';
        const L = detectedLang;

        /**
         * Open + print the Guard dashboard once it is reachable. The daemon mints
         * the dashboard auth cookie ONLY for a URL carrying its launch token
         * (/?token=…); a bare http://127.0.0.1:PORT lands on a 401 "Invalid token"
         * page. The daemon persists that token to ~/.panguard-guard/dashboard-token
         * shortly after its dashboard starts listening, so we poll briefly (~3s)
         * for it. If it never appears (daemon still starting / headless), we print
         * actionable guidance instead of opening a dead bare URL.
         */
        const openDashboard = async (): Promise<void> => {
          let url: string | null = null;
          for (let i = 0; i < 30; i++) {
            url = readAuthenticatedDashboardUrl();
            if (url) break;
            await new Promise((r) => setTimeout(r, 100));
          }
          console.log();
          if (url) {
            console.log(c.green(`  ${symbols.pass} Opening Guard Dashboard...`));
            console.log(c.dim(`    ${url}`));
            openBrowser(url);
          } else {
            console.log(
              c.yellow(
                `  ${symbols.warn} Dashboard is still starting. Run "pga status" for the link.`
              )
            );
            console.log(c.dim(`    It will be served at ${dashboardBaseUrl()}`));
          }
        };

        const mcpConfig = await (import('@panguard-ai/panguard-mcp/config' as string) as Promise<{
          detectPlatforms: () => Promise<
            Array<{ id: string; name: string; detected: boolean; alreadyConfigured: boolean }>
          >;
          injectMCPConfig: (platformId: string) => {
            success: boolean;
            platformId: string;
            configPath?: string;
            error?: string;
          };
          removeMCPConfig: (platformId: string) => {
            success: boolean;
            platformId: string;
            configPath?: string;
            error?: string;
          };
        }>);
        const { detectPlatforms, injectMCPConfig, removeMCPConfig } = mcpConfig;

        // Silence structured logs for both human and json modes. Human mode
        // owns the screen via hand-crafted console.log() output; json mode
        // needs a pure JSON object on stdout so consumers can pipe to jq.
        // The comment used to read the opposite — in --json mode the
        // platform-detector / injector / mcp-config logs were polluting
        // stdout and breaking parsing.
        const { setLogLevel } = await import('@panguard-ai/core');
        setLogLevel('silent');

        if (!options.json) {
          banner('Panguard Setup');
          console.log();
        }

        // 1. Detect platforms
        if (!options.json) {
          console.log(c.dim('  Scanning for AI agent platforms...'));
          console.log();
        }

        const allPlatforms = await detectPlatforms();

        // Filter to target platform if specified
        const validIds = [
          'claude-code',
          'claude-desktop',
          'cursor',
          'openclaw',
          'codex',
          'workbuddy',
        ];
        let targets = allPlatforms;
        if (options.platform) {
          if (!validIds.includes(options.platform)) {
            console.error(c.red(`  Unknown platform: ${options.platform}`));
            console.error(c.dim(`  Valid platforms: ${validIds.join(', ')}`));
            process.exitCode = 1;
            return;
          }
          targets = allPlatforms.filter((p) => p.id === options.platform);
        }

        // 2. Show detection results
        if (!options.json) {
          console.log(c.bold('  Detected Platforms:'));
          console.log();
          for (const p of allPlatforms) {
            const status = p.detected
              ? p.alreadyConfigured
                ? c.green(`${symbols.pass} configured`)
                : c.yellow(`${symbols.warn} not configured`)
              : c.dim(`${symbols.dot} not found`);
            console.log(`    ${p.detected ? c.bold(p.name) : c.dim(p.name)}  ${status}`);
          }
          console.log();
          divider();
          console.log();
        }

        // Determine which platforms to act on
        const actionable = options.remove
          ? targets.filter((p) => p.alreadyConfigured)
          : targets.filter((p) => p.detected && !p.alreadyConfigured);

        // JSON mode: collect all data, output at the end (don't return early)
        const jsonOutput: Record<string, unknown> = {
          action: options.remove ? 'remove' : 'setup',
          version: PANGUARD_VERSION,
          timestamp: new Date().toISOString(),
          platforms: [],
        };

        if (actionable.length === 0) {
          if (!options.json) {
            const msg = options.remove
              ? 'No platforms have Panguard configured.'
              : 'All detected platforms are already configured, or no platforms found.';
            console.log(c.green(`  ${symbols.pass} ${msg}`));
            console.log();
            console.log(c.dim('  Run with --platform <name> to target a specific platform.'));
          }

          // Include already-configured platforms in JSON output
          jsonOutput['platforms'] = allPlatforms
            .filter((p) => p.detected)
            .map((p) => ({
              platform: p.id,
              success: true,
              already_configured: p.alreadyConfigured,
            }));

          // Continue to skill scan + guard install even if platforms already configured
        }

        // 3. Execute injection or removal
        if (!options.json) {
          const action = options.remove ? 'Removing from' : 'Configuring';
          console.log(c.bold(`  ${action} ${actionable.length} platform(s):`));
          console.log();
        }

        const results: Array<{
          success: boolean;
          platformId: string;
          configPath?: string;
          error?: string;
        }> = [];
        for (const p of actionable) {
          const result = options.remove ? removeMCPConfig(p.id) : injectMCPConfig(p.id);
          results.push(result);

          if (!options.json) {
            const icon = result.success ? c.green(symbols.pass) : c.red(symbols.fail);
            console.log(`    ${icon} ${p.name}`);
            if (result.success) {
              console.log(c.dim(`      ${result.configPath}`));
            } else {
              console.log(c.red(`      Error: ${result.error}`));
            }
          }
        }

        // Update jsonOutput with actual platform results (only if there were actionable platforms)
        if (results.length > 0) {
          jsonOutput['platforms'] = results.map((r) => ({
            platform: r.platformId,
            success: r.success,
            configPath: r.configPath,
            error: r.error,
          }));
        }

        if (options.json && options.remove) {
          jsonOutput['agent_friendly'] = true;
          console.log(JSON.stringify(jsonOutput, null, 2));
          return;
        }

        console.log();
        divider();
        console.log();

        const succeeded = results.filter((r) => r.success).length;
        const failed = results.filter((r) => !r.success).length;

        if (!options.json) {
          if (failed === 0) {
            console.log(
              c.green(`  ${symbols.pass} All ${succeeded} platform(s) configured successfully.`)
            );
          } else {
            console.log(c.yellow(`  ${succeeded} succeeded, ${failed} failed.`));
          }
        }

        // ── 4. Scan installed skills ──────────────────────────────────
        if (!options.remove && !options.skipScan) {
          if (!options.json) {
            console.log();
            divider('Skill Security Scan');
            console.log();
            console.log(c.dim('  Scanning installed MCP skills across all platforms...'));
            console.log();
          }

          try {
            const { discoverAllSkills } = await (import(
              '@panguard-ai/panguard-mcp/config' as string
            ) as Promise<{
              discoverAllSkills: () => Promise<import('./setup-skill-scan.js').MCPServerEntry[]>;
            }>);
            const skills = await discoverAllSkills();

            if (skills.length > 0) {
              const scanResults = await scanInstalledSkills(skills, {
                silent: options.json,
              });
              if (!options.json) renderSkillScanResults(scanResults);

              // Collect skill scan data for JSON output
              const safe = scanResults.filter((r) => r.status === 'safe');
              const cautionResults = scanResults.filter((r) => r.status === 'caution');
              const flaggedResults = scanResults.filter((r) => r.status === 'flagged');
              jsonOutput['skill_scan'] = {
                total: scanResults.length,
                safe: safe.length,
                caution: cautionResults.length,
                flagged: flaggedResults.length,
                skills: scanResults.map((r) => ({
                  name: r.entry.name,
                  platform: r.entry.platformId,
                  status: r.status,
                  risk_level: r.audit?.riskLevel ?? null,
                  risk_score: r.audit?.riskScore ?? null,
                })),
              };

              // Persist the scan verdict so `pga status` / `pga doctor` show real
              // severities, and so `pga up` can skip a redundant re-scan on first
              // run (setup owns the first-run scan).
              recordScanResults({
                scannedNames: scanResults.map((r) => r.entry.name),
                flagged: flaggedResults.map((r) => ({
                  name: r.entry.name,
                  platform: r.entry.platformId,
                  riskLevel: (r.audit?.riskLevel ?? 'HIGH') as RiskLevel,
                  // First run is where a user first meets a flag; carry the rules
                  // that fired so status can explain it instead of just asserting.
                  evidence: toEvidence(r.audit?.findings ?? []),
                })),
                scannedAt: new Date().toISOString(),
              });

              // Whitelist only safe (LOW risk) skills — caution (MEDIUM) needs review
              const safeOnly = scanResults
                .filter((r) => r.status === 'safe')
                .map((r) => r.entry.name);
              if (safeOnly.length > 0) {
                persistToWhitelist(safeOnly, 'static');
                if (!options.json) {
                  console.log();
                  console.log(
                    c.green(`  ${symbols.pass} ${safeOnly.length} safe skill(s) auto-whitelisted.`)
                  );
                  console.log(c.dim(`    Saved to ~/.panguard-guard/skill-whitelist.json`));
                }
              }

              const caution = scanResults.filter((r) => r.status === 'caution');
              if (caution.length > 0 && !options.json) {
                console.log(
                  c.yellow(
                    `  ${symbols.warn} ${caution.length} skill(s) at MEDIUM risk — monitored but not whitelisted.`
                  )
                );
              }

              // Separate CRITICAL (auto-block) from HIGH (interactive review)
              const flagged = scanResults.filter((r) => r.status === 'flagged');
              const critical = flagged.filter((r) => r.audit?.riskLevel === 'CRITICAL');
              const high = flagged.filter((r) => r.audit?.riskLevel === 'HIGH');

              // Auto-block CRITICAL skills -- no user choice offered
              if (critical.length > 0) {
                const { removeServer } = await (import(
                  '@panguard-ai/panguard-mcp/config' as string
                ) as Promise<{
                  removeServer: (platformId: string, serverName: string) => boolean;
                }>);

                for (const result of critical) {
                  const removed = removeServer(result.entry.platformId, result.entry.name);
                  if (!options.json) {
                    if (removed) {
                      console.log(
                        c.red(
                          `  ${symbols.fail} BLOCKED: ${c.bold(result.entry.name)} is critically dangerous and has been disabled.`
                        )
                      );
                      console.log(
                        c.dim(
                          `    Risk score: ${result.audit?.riskScore ?? 0}/100 | Platform: ${result.entry.platformId}`
                        )
                      );
                    } else {
                      // We flag but never delete a user's files. Give a concrete,
                      // safe removal path instead of a dead-end "manually disable".
                      console.log(
                        c.red(
                          `  ${symbols.fail} CRITICAL: ${c.bold(result.entry.name)} (${result.entry.platformId}) is dangerous.`
                        )
                      );
                      console.log(
                        c.dim(
                          `    PanGuard does not delete your files. Inspect it: pga audit skill ${result.entry.name}`
                        )
                      );
                      console.log(
                        c.dim(
                          `    Then remove the skill folder from ${result.entry.platformId} to disable it.`
                        )
                      );
                    }
                  }
                }
              }

              // Review HIGH skills interactively (not CRITICAL)
              if (high.length > 0 && !options.yes && !options.json) {
                const userWhitelisted = await reviewFlaggedSkills(high);
                if (userWhitelisted.length > 0) {
                  persistToWhitelist(userWhitelisted, 'manual');
                }
              } else if (high.length > 0 && !options.json) {
                console.log(
                  c.yellow(
                    `  ${symbols.warn} ${high.length} HIGH-risk skill(s) -- run "pga guard --watch" to review.`
                  )
                );
              }
            } else {
              jsonOutput['skill_scan'] = { total: 0, safe: 0, caution: 0, flagged: 0, skills: [] };
              if (!options.json) {
                console.log(
                  c.dim(
                    `  ${symbols.info} No MCP skills found. Skills will be audited as you install them.`
                  )
                );
              }
            }
          } catch {
            if (!options.json) {
              console.log(
                c.dim(`  ${symbols.info} Skill scanning skipped (auditor not available).`)
              );
            }
          }

          if (!options.json) {
            console.log();
            divider();
          }
        }

        // ── 5. Install guard as system service (auto-start on boot) ───
        if (!options.remove && !options.skipGuard) {
          if (!options.json) console.log();
          const installGuard =
            !options.skipService &&
            (options.yes ||
              options.json ||
              (await promptConfirm({
                message: {
                  en: 'Install Panguard Guard as system service? (recommended, auto-start on boot)',
                  'zh-TW': '安裝 Panguard Guard 為系統服務？（建議安裝，開機自動啟動）',
                },
                defaultValue: true,
                lang: L,
              })));

          if (installGuard) {
            if (!options.json) {
              console.log();
              console.log(c.dim('  Installing Panguard Guard as system service...'));
            }

            // Resolve the guard CLI binary path
            let guardBin: string | undefined;
            try {
              const require = createRequire(import.meta.url);
              // The package's exports map only defines "." — resolving the deep
              // subpath "@panguard-ai/panguard-guard/dist/cli/index.js" (or even
              // "/package.json") directly throws ERR_PACKAGE_PATH_NOT_EXPORTED.
              // Resolve the exported package root ("." → dist/index.js) instead,
              // then derive the CLI entry: dist/index.js → dist → dist/cli/index.js.
              const { join: rjoin } = await import('node:path');
              const { existsSync: feMain } = await import('node:fs');
              // The package's exports map exposes no resolvable "." for
              // require.resolve (it throws ERR_PACKAGE_PATH_NOT_EXPORTED), so
              // locate the package directory by walking the node resolution
              // paths. Covers hoisted (npm/pnpm sibling), nested, and global
              // layouts — the previous require.resolve threw on every layout,
              // which is why `pga up` never auto-started the guard daemon.
              let resolvedBin: string | null = null;
              for (const base of require.resolve.paths('@panguard-ai/panguard-guard') ?? []) {
                const cand = rjoin(
                  base,
                  '@panguard-ai',
                  'panguard-guard',
                  'dist',
                  'cli',
                  'index.js'
                );
                if (feMain(cand)) {
                  resolvedBin = cand;
                  break;
                }
              }
              if (!resolvedBin) throw new Error('panguard-guard not found in resolution paths');
              guardBin = resolvedBin;
            } catch {
              // Fallback: search common paths for npm global / local installs
              const { existsSync: fe } = await import('node:fs');
              const { join: pjoin } = await import('node:path');
              const { fileURLToPath } = await import('node:url');
              const { dirname: pdirname } = await import('node:path');
              // Relative to this panguard package's own node_modules — covers a
              // plain local `npm install @panguard-ai/panguard` that hoists the
              // guard dependency under the panguard package. This compiled file is
              // dist/cli/commands/setup.js, so the package root is four dirs up
              // (commands -> cli -> dist -> package root).
              const panguardPkgDir = pdirname(
                pdirname(pdirname(pdirname(fileURLToPath(import.meta.url))))
              );
              const candidates = [
                pjoin(
                  panguardPkgDir,
                  'node_modules',
                  '@panguard-ai',
                  'panguard-guard',
                  'dist',
                  'cli',
                  'index.js'
                ),
                pjoin(
                  homedir(),
                  '.panguard',
                  'node_modules',
                  '@panguard-ai',
                  'panguard-guard',
                  'dist',
                  'cli',
                  'index.js'
                ),
                pjoin(
                  process.execPath,
                  '..',
                  '..',
                  'lib',
                  'node_modules',
                  '@panguard-ai',
                  'panguard',
                  'node_modules',
                  '@panguard-ai',
                  'panguard-guard',
                  'dist',
                  'cli',
                  'index.js'
                ),
                pjoin(
                  process.execPath,
                  '..',
                  '..',
                  'lib',
                  'node_modules',
                  '@panguard-ai',
                  'panguard-guard',
                  'dist',
                  'cli',
                  'index.js'
                ),
              ];
              for (const c of candidates) {
                if (fe(c)) {
                  guardBin = c;
                  break;
                }
              }
            }

            // Human-readable base URL for JSON metadata / last-resort hints only.
            // The page the user actually opens must carry the daemon's auth token
            // (resolved at open time via openDashboard) — a bare URL 401s.
            const dashUrl = dashboardBaseUrl();

            if (!guardBin) {
              if (!options.json) {
                console.log(c.yellow(`  ${symbols.warn} Could not locate panguard-guard binary.`));
                console.log(c.dim('    Run manually: pga guard install'));
              }
              jsonOutput['guard'] = {
                installed: false,
                running: false,
                error: 'guard binary not found',
              };
            } else {
              try {
                // Discrete argv parts, never a space-joined string — the binary
                // path legitimately contains spaces (e.g. "Application Support")
                // which would otherwise split into broken service arguments.
                const guardExec = [process.execPath, guardBin];
                const dataDir = join(homedir(), '.panguard-guard');

                const { installService } = await import('@panguard-ai/panguard-guard');
                const servicePath = await installService(guardExec, dataDir);

                const osPlatform = process.platform;
                const serviceType =
                  osPlatform === 'darwin'
                    ? 'launchd'
                    : osPlatform === 'linux'
                      ? 'systemd'
                      : osPlatform === 'win32'
                        ? 'Windows Service'
                        : 'system service';

                // The service is installed, but verify the daemon actually CAME UP
                // before claiming it runs — RunAtLoad can succeed while the daemon
                // then fails to bind (bad ruleset / port held / crash on start).
                // Poll the PID file briefly instead of reporting running:true blind.
                const guardPidPath = join(dataDir, 'panguard-guard.pid');
                const daemonUp = (): boolean => {
                  try {
                    const p = parseInt(readFileSync(guardPidPath, 'utf-8').trim(), 10);
                    process.kill(p, 0);
                    return true;
                  } catch {
                    return false;
                  }
                };
                let guardRunning = false;
                for (let i = 0; i < 120 && !guardRunning; i++) {
                  guardRunning = daemonUp();
                  if (!guardRunning) await new Promise((r) => setTimeout(r, 100));
                }

                if (!options.json) {
                  console.log(
                    c.green(`  ${symbols.pass} Guard installed as ${serviceType} service.`)
                  );
                  console.log(c.dim(`    ${servicePath}`));
                  if (guardRunning) {
                    console.log(
                      c.green(`  ${symbols.pass} Guard is running and will auto-start on boot.`)
                    );
                  } else {
                    console.log(
                      c.yellow(
                        `  ${symbols.warn} Service installed, but the daemon has not come up yet.`
                      )
                    );
                    console.log(
                      c.dim(
                        '    Run "pga doctor" or see ~/.panguard-guard/panguard-guard.log — it may still be starting.'
                      )
                    );
                  }
                  console.log(c.dim('    Run "pga guard status" to check.'));
                  console.log(c.dim('    Run "pga guard uninstall" to remove.'));
                }

                jsonOutput['guard'] = {
                  installed: true,
                  running: guardRunning,
                  service_type: serviceType,
                  service_path: servicePath,
                  dashboard_url: dashUrl,
                };

                // Open Dashboard in browser only once the daemon is actually up
                // (skip in JSON mode — the agent shows the URL).
                if (!options.json && guardRunning) {
                  await openDashboard();
                }
              } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                if (!options.json) {
                  if (msg.includes('EACCES') || msg.includes('permission')) {
                    console.log(
                      c.yellow(
                        `  ${symbols.warn} Needs elevated privileges to install system service.`
                      )
                    );
                    console.log(c.dim('    Run: sudo pga guard install'));
                  } else {
                    console.log(
                      c.yellow(`  ${symbols.warn} Could not install as system service: ${msg}`)
                    );
                    console.log(c.dim('    Run manually: pga guard install'));
                  }
                  // Fallback: start Guard for this session only
                  console.log();
                  console.log(c.dim('  Starting Guard for this session instead...'));
                }
                try {
                  const child = spawn(process.execPath, [guardBin, 'start', '--dashboard'], {
                    detached: true,
                    stdio: 'ignore',
                    windowsHide: true,
                  });
                  child.unref();

                  jsonOutput['guard'] = {
                    installed: false,
                    running: true,
                    pid: child.pid,
                    dashboard_url: dashUrl,
                    error: `service install failed: ${msg}`,
                  };

                  if (!options.json) {
                    console.log(
                      c.green(
                        `  ${symbols.pass} Guard started (PID: ${child.pid}). Will stop when system restarts.`
                      )
                    );
                    await openDashboard();
                  }
                } catch {
                  jsonOutput['guard'] = { installed: false, running: false, error: msg };
                  if (!options.json) {
                    console.log(c.dim('    Run manually: pga guard start --dashboard'));
                  }
                }
              }
            }
          }
        }

        // ── 6. Threat Cloud opt-in (always runs, independent of guard install) ──
        // OPT-IN, default OFF. Non-interactive runs (-y / --json) must NOT silently
        // enable collective-defense sharing — that would be an implicit opt-out, the
        // exact pattern we are removing. They stay OFF; the user enables it later
        // with `pga config set telemetry true`. The interactive prompt defaults to
        // NO so a bare Enter declines.
        //
        // This is the SINGLE consent point: the answer here drives BOTH
        // threatCloudUploadEnabled AND telemetryEnabled, and we mark consent as
        // asked so the trailing ensureTelemetryConsent() sees hasConsentBeenAsked()
        // === true and does not re-prompt (which previously asked a second time,
        // defaulted to NO, and silently overwrote a first-prompt opt-in).
        // Tracks the explicit opt-in decision so the post-setup usage ping below
        // (outside this block) only fires when the user turned sharing ON.
        let tcUploadOptedIn = false;
        if (!options.remove && !options.skipGuard) {
          const dataDir = join(homedir(), '.panguard-guard');
          // Honest agreement shown before the opt-in. States exactly what joining
          // does (contribute anonymized signatures incl. UNKNOWN threats + auto-
          // receive community rules), and is precise about encryption: anonymized
          // on-device, then end-to-end sealed (JWE to the ingest key) so only the
          // Threat Cloud backend can read it — verified live 2026-07-07.
          if (!options.yes && !options.json) {
            console.log();
            console.log(`  ${c.bold('Join Collective Defense (your choice, reversible anytime)')}`);
            console.log(c.dim('    If you agree, PanGuard connects to Threat Cloud and will:'));
            console.log(
              c.dim('    · share minimal ANONYMIZED threat signatures (matched rule ID, attack')
            );
            console.log(c.dim('      category + MITRE, coarse region, truncated IP),'));
            console.log(
              c.dim('    · with the local AI layer on (free — pga guard setup-ai), ALSO report')
            );
            console.log(
              c.dim('      UNKNOWN suspicious behavior it can’t yet match to a rule, so the')
            );
            console.log(c.dim('      community can turn a novel attack into a new rule,'));
            console.log(
              c.dim('    · anonymize it on your machine, then END-TO-END SEAL the threat')
            );
            console.log(
              c.dim('      signatures (only the Threat Cloud backend can read them, not the')
            );
            console.log(
              c.dim('      network); skill-audit findings & rule proposals go over TLS,')
            );
            console.log(c.dim('    · auto-update your detection rules from the community.'));
            console.log(
              c.dim('    NEVER shared: prompts, code, file contents, secrets, paths, hostname.')
            );
            console.log();
          }
          const enableTC =
            !options.yes &&
            !options.json &&
            (await promptConfirm({
              message: {
                en: 'Agree and join Collective Defense? (auto-connect + auto-update rules)',
                'zh-TW': '同意並加入集體防禦？（自動連線 + 規則自動更新）',
              },
              defaultValue: false,
              lang: L,
            }));
          tcUploadOptedIn = enableTC;

          try {
            const tcConfigPath = join(dataDir, 'config.json');
            const { loadConfig, saveConfig } = await import('@panguard-ai/panguard-guard');
            const guardConfig = loadConfig(tcConfigPath);
            const updatedConfig = {
              ...guardConfig,
              // One consent answer wires the whole collective-defense loop:
              // contribute (upload + telemetry) AND receive (rule sync auto-updates).
              // The upload gate checks threatCloudUploadEnabled; telemetryEnabled is
              // what ensureTelemetryConsent() reads back; threatCloudRuleSyncEnabled
              // turns on automatic community rule updates. All follow the one answer.
              threatCloudUploadEnabled: enableTC,
              telemetryEnabled: enableTC,
              threatCloudRuleSyncEnabled: enableTC,
              threatCloudEndpoint: enableTC
                ? (guardConfig.threatCloudEndpoint ?? 'https://tc.panguard.ai/api')
                : guardConfig.threatCloudEndpoint,
            };
            saveConfig(updatedConfig, tcConfigPath);

            // Record that consent has been asked HERE, so the trailing
            // ensureTelemetryConsent() does not prompt again and clobber this
            // answer with its default-NO.
            const { markConsentAsked } = await import('../consent.js');
            markConsentAsked();

            if (!options.json) {
              if (enableTC) {
                console.log(
                  c.green(
                    `  ${symbols.pass} Connected to Threat Cloud: ${updatedConfig.threatCloudEndpoint ?? 'https://tc.panguard.ai/api'}`
                  )
                );
                console.log(
                  c.dim(
                    '    Sharing anonymized signatures (incl. unknown threats); rules auto-update.'
                  )
                );
              } else {
                console.log(
                  c.dim(
                    `  ${symbols.info} Threat Cloud disabled. Enable later: pga guard config --set threatCloudUploadEnabled=true`
                  )
                );
              }
            }

            // Add TC status to guard JSON output
            if (jsonOutput['guard'] && typeof jsonOutput['guard'] === 'object') {
              (jsonOutput['guard'] as Record<string, unknown>)['threat_cloud'] = enableTC;
            }
          } catch {
            // Config save failed — non-fatal
          }
        }

        // ── Report setup event to Threat Cloud — OPT-IN only ────────
        // Only fire when the user explicitly enabled collective defense above
        // (enableTC). Default OFF: no phone-home on a plain `pga setup`.
        if (tcUploadOptedIn) {
          void fetch('https://tc.panguard.ai/api/usage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              event_type: 'cli_setup',
              source: 'cli-user',
              metadata: {
                version: PANGUARD_VERSION,
                platforms: results.filter((r) => r.success).map((r) => r.platformId),
                skillsScanned:
                  (jsonOutput['skill_scan'] as { total?: number } | undefined)?.total ?? 0,
              },
            }),
            signal: AbortSignal.timeout(3000),
          }).catch(() => {});
        }

        // ── JSON output (all data collected) ─────────────────────────
        if (options.json) {
          jsonOutput['agent_friendly'] = true;
          console.log(JSON.stringify(jsonOutput, null, 2));
          return;
        }

        // ── Telemetry consent (opt-in, first-run only) ─────────────
        const { ensureTelemetryConsent } = await import('../consent.js');
        await ensureTelemetryConsent();

        // ── Next steps (human-readable only) ─────────────────────────
        console.log();
        console.log(c.sage(c.bold('  Setup complete! Here are your quick commands:')));
        console.log();
        console.log(`    ${c.sage('pga')}              Open interactive menu`);
        console.log(`    ${c.sage('pga up')}           Start protection + dashboard`);
        console.log(`    ${c.sage('pga status')}       Check protection status`);
        console.log(`    ${c.sage('pga scan')}         Scan all installed skills`);
        console.log(`    ${c.sage('pga audit skill <url>')}  Audit a skill before installing`);
        console.log();
        console.log(c.dim('  Open source (MIT). If PanGuard helps you, star us on GitHub:'));
        console.log(c.sage('  https://github.com/panguard-ai/panguard-ai'));
        console.log();

        const configuredPlatforms = actionable.filter((_, i) => results[i]?.success);
        if (configuredPlatforms.length > 0) {
          console.log(c.dim('  Restart your AI agent to activate MCP:'));
          for (const p of configuredPlatforms) {
            const restartHint = PLATFORM_RESTART_HINTS[p.id] ?? 'Restart the application';
            console.log(c.dim(`    ${p.name}: ${restartHint}`));
          }
          console.log();
        }

        // Setup finished interactively: record the durable first-run marker so a
        // later `pga up` / bare `pga` skips the welcome + this wizard. Writing it
        // here (not only in the bare-`pga` path) makes a direct `pga setup` also
        // count as completing first-run.
        markInitialized();
      }
    );

  return cmd;
}
