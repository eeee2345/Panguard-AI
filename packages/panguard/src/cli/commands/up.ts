/**
 * panguard up - One-command start: scan → protect → dashboard
 *
 * Flow: scan installed skills → warn about threats → start Guard → open dashboard
 */

import { existsSync, readFileSync, readdirSync, statSync, mkdirSync, openSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir, platform } from 'node:os';
import { execFile, spawn } from 'node:child_process';
import { Command } from 'commander';
import { runCLI } from '@panguard-ai/panguard-guard';
import { c, setLogLevel } from '@panguard-ai/core';
import { ok, warn, arrow, shield, brandTagline } from '../theme.js';
import { detectLang } from '../interactive/lang.js';
import { ensureTelemetryConsent } from '../consent.js';
import { installFor, toHookPlatform } from './hook.js';
import { ensurePersistentService, type PersistResult } from './persist.js';
import { buildSkillAuditProposal } from './atr-proposal.js';
import { isFirstRun, markInitialized } from '../first-run.js';
import {
  readAuthenticatedDashboardUrl,
  dashboardBaseUrl,
  isDashboardHealthy,
} from '../dashboard-url.js';
import {
  recordScanResults,
  readFlaggedSkills,
  toEvidence,
  type RiskLevel,
} from '../flagged-skills.js';

type Lang = 'en' | 'zh-TW';

/** Minimal i18n for key user-facing strings */
const t = (lang: Lang, en: string, zh: string): string => (lang === 'zh-TW' ? zh : en);

const TC_ENDPOINT = 'https://tc.panguard.ai';

function openBrowser(url: string): void {
  const os = platform();
  if (os === 'win32') {
    // Hardcode cmd.exe path — never trust COMSPEC env var (attacker-controllable)
    const systemRoot = process.env['SystemRoot'] || 'C:\\Windows';
    const cmd = `${systemRoot}\\System32\\cmd.exe`;
    execFile(cmd, ['/c', 'start', '', url], () => {});
  } else if (os === 'darwin') {
    execFile('open', [url], () => {});
  } else {
    execFile('xdg-open', [url], () => {});
  }
}

function isGuardRunning(): boolean {
  const pidPath = join(homedir(), '.panguard-guard', 'panguard-guard.pid');
  if (!existsSync(pidPath)) return false;
  try {
    const pid = parseInt(readFileSync(pidPath, 'utf-8').trim(), 10);
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * SIGTERM a running Guard daemon by its PID file so `pga up` can REPLACE a daemon
 * whose dashboard cannot authenticate (stale/tokenless instance, or a pre-upgrade
 * daemon). The daemon removes its own launch token in its graceful SIGTERM
 * shutdown and releases the dashboard port before exiting; the replacement
 * (launchd KeepAlive respawn, or a fresh ephemeral spawn by the caller) then binds
 * the freed port and writes a new token. Best-effort: a missing/dead PID is a
 * no-op — the caller re-checks isGuardRunning() afterwards.
 */
function stopGuardDaemon(): void {
  const pidPath = join(homedir(), '.panguard-guard', 'panguard-guard.pid');
  try {
    const pid = parseInt(readFileSync(pidPath, 'utf-8').trim(), 10);
    if (pid > 0) process.kill(pid, 'SIGTERM');
  } catch {
    /* no pid file / already gone — nothing to stop */
  }
}

/**
 * Whether Guard is installed as a persistent OS service (launchd/systemd). `pga up`
 * starts a background daemon but does NOT install the service — so monitoring stops
 * at the next reboot unless the user ran `pga guard install`. Used to keep the
 * summary panel honest about persistence (a security tool must not overclaim it).
 */
function isServiceInstalled(): boolean {
  try {
    const os = platform();
    if (os === 'darwin') {
      const dir = join(homedir(), 'Library', 'LaunchAgents');
      return existsSync(dir) && readdirSync(dir).some((f) => /panguard.*guard.*\.plist$/i.test(f));
    }
    if (os === 'linux') {
      const dir = join(homedir(), '.config', 'systemd', 'user');
      return existsSync(dir) && readdirSync(dir).some((f) => /panguard.*guard/i.test(f));
    }
  } catch {
    /* best-effort */
  }
  return false;
}

/**
 * Read the real rule count loaded by Guard from its TC cache, falling back to
 * the count actually bundled with THIS install (never a hardcoded guess — the
 * ATR rule count changes daily, so we read it from the shipped package).
 */
function readRuleCountFromCache(): number {
  // The Guard always loads the rules BUNDLED with this install; Threat Cloud
  // sync can only ADD more on top. So the honest "active" count is at least the
  // bundled count — never the (often smaller) TC cache figure alone, which would
  // understate what the engine is really running and disagree with the dashboard.
  const bundled = readBundledRuleCount();
  try {
    const cachePath = join(homedir(), '.panguard-guard', 'threat-cloud-cache.json');
    if (existsSync(cachePath)) {
      const cache = JSON.parse(readFileSync(cachePath, 'utf-8')) as {
        uniqueRulesCount?: number;
      };
      if (typeof cache.uniqueRulesCount === 'number' && cache.uniqueRulesCount > 0) {
        return Math.max(bundled, cache.uniqueRulesCount);
      }
    }
  } catch {
    /* fall through to the bundled count */
  }
  return bundled;
}

/**
 * Count the detection rules actually bundled with this install by reading the
 * shipped agent-threat-rules package (stats.json if present, else counting the
 * rule YAML files). Returns 0 if it cannot be determined so the caller can omit
 * the line rather than print a wrong number.
 */
function readBundledRuleCount(): number {
  try {
    const pkgDir = resolveBundledAtrDir();
    if (!pkgDir) return 0;
    const statsPath = join(pkgDir, 'data', 'stats.json');
    if (existsSync(statsPath)) {
      const stats = JSON.parse(readFileSync(statsPath, 'utf-8')) as {
        rules?: { total?: number };
      };
      if (typeof stats.rules?.total === 'number' && stats.rules.total > 0) {
        return stats.rules.total;
      }
    }
    // Fallback: count rule YAML files on disk
    const rulesDir = join(pkgDir, 'rules');
    let count = 0;
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walk(full);
        else if (entry.endsWith('.yaml') || entry.endsWith('.yml')) count++;
      }
    };
    if (existsSync(rulesDir)) walk(rulesDir);
    return count;
  } catch {
    return 0;
  }
}

/**
 * Locate the bundled agent-threat-rules package directory by walking up the
 * module tree (filesystem lookup, immune to the package's ESM `exports` map
 * which blocks require.resolve of its package.json).
 */
function resolveBundledAtrDir(): string | null {
  try {
    let dir = dirname(fileURLToPath(import.meta.url));
    for (let i = 0; i < 12; i++) {
      const cand = join(dir, 'node_modules', 'agent-threat-rules');
      if (existsSync(join(cand, 'package.json'))) return cand;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Read the anonymous client ID provisioned during first `pga up`.
 * This is the sensor identity used by Threat Cloud for per-device aggregation
 * (no email, no hostname, no raw PII — just a random UUID).
 */
function readSensorId(): string | null {
  try {
    const idPath = join(homedir(), '.panguard', 'client-id');
    if (existsSync(idPath)) {
      return readFileSync(idPath, 'utf-8').trim();
    }
  } catch {
    /* no identity yet */
  }
  return null;
}

export function upCommand(): Command {
  return new Command('up')
    .description('Scan skills → start protection → open dashboard')
    .option('--no-dashboard', 'Skip opening dashboard in browser')
    .option('--no-proxy', 'Scan only — do not inject runtime protection into agent configs')
    .option('--verbose', 'Verbose output', false)
    .option('--skip-scan', 'Skip initial skill scan', false)
    .option('--no-persist', 'Do not install the reboot-surviving service (run only until reboot)')
    .option('-y, --yes', 'Skip confirmation prompts', false)
    .action(
      async (opts: {
        dashboard: boolean;
        proxy: boolean;
        verbose: boolean;
        skipScan: boolean;
        persist: boolean;
        yes: boolean;
      }) => {
        // Suppress JSON logs for clean output — set env var BEFORE any dynamic imports
        // so all child modules (panguard-mcp, panguard-scan, etc.) also respect it
        if (!opts.verbose) {
          process.env['PANGUARD_LOG_LEVEL'] = 'silent';
          setLogLevel('silent');
        }
        const startTime = Date.now();
        const lang = detectLang();

        console.log(
          `\n  ${c.sage(c.bold('PanGuard'))}  ${c.dim(t(lang, 'Your AI Security Guard', '你的 AI 安全防護'))}`
        );
        console.log(`  ${c.dim(brandTagline(lang))}\n`);
        console.log(`  ${c.dim('─'.repeat(50))}\n`);

        // First-run detection uses a durable, telemetry-independent marker
        // (~/.panguard/.initialized) so the welcome + interactive setup run ONCE.
        // The old ~/.panguard/activated marker was written only by the opt-in
        // Threat Cloud ping, so an opt-out user (the default) saw the welcome +
        // setup on every single `pga up`.
        const firstRun = isFirstRun();

        if (firstRun) {
          console.log('');
          console.log(
            `  ${c.sage(c.bold(t(lang, 'Welcome to PanGuard AI!', '歡迎使用 PanGuard AI！')))}`
          );
          console.log('');
          console.log(
            `  ${t(lang, 'PanGuard protects your AI agents in 3 steps:', 'PanGuard 三步驟保護你的 AI 代理：')}`
          );
          console.log(
            `  ${c.dim('1.')} ${t(lang, 'Scan — check installed skills against threat rules', '掃描 — 用威脅規則檢查已安裝技能')}`
          );
          console.log(
            `  ${c.dim('2.')} ${t(lang, 'Watch — guard your agents as they run', '守護 — 在 agent 執行時即時守護')}`
          );
          console.log(
            `  ${c.dim('3.')} ${t(lang, 'Monitor — Guard engine watches for attacks', '監控 — Guard 引擎持續監控攻擊')}`
          );
          console.log('');
          console.log(`  ${c.dim(t(lang, 'Running initial setup...', '正在執行初始設定...'))}`);
          console.log('');
          const { execFileSync } = await import('node:child_process');
          try {
            // Forward the flags that must not be lost across the shell boundary:
            // --yes keeps it non-interactive, and --no-persist must reach setup's
            // service install (otherwise setup installs a launchd service the user
            // explicitly opted out of).
            const setupArgs = [process.argv[1] ?? 'panguard', 'setup'];
            if (opts.yes) setupArgs.push('--yes');
            if (opts.persist === false) setupArgs.push('--skip-service');
            execFileSync(process.execPath, setupArgs, {
              stdio: 'inherit',
            });
          } catch (err) {
            // Setup can fail or be interrupted (e.g. Ctrl-C during the
            // interactive skill review, a platform-detection error). Whatever
            // completed before the failure stays in place, but no MCP platforms
            // may be configured and the whitelist may be empty — surface that
            // plainly instead of a bracketed stderr line the user can miss, since
            // we fall through into the rest of `pga up` regardless.
            console.log('');
            console.log(
              `  ${c.caution(
                t(
                  lang,
                  'Setup was interrupted — some platforms may not be configured.',
                  '設定被中斷 — 部分平台可能尚未設定。'
                )
              )}`
            );
            console.log(
              `  ${c.dim(
                t(
                  lang,
                  `Run ${c.sage('pga setup')} to finish, or continue below for whatever completed.`,
                  `執行 ${c.sage('pga setup')} 完成設定，或繼續以下已完成的部分。`
                )
              )}`
            );
            console.log('');
            if (opts.verbose) {
              process.stderr.write(
                `[panguard up] Setup error detail: ${err instanceof Error ? err.message : String(err)}\n`
              );
            }
          }
        }

        // ── Threat Cloud policy + consent (BEFORE we scan or deploy anything) ──
        // Discloses exactly what is shared — anonymized threat signatures + one-way
        // hashes, never code/prompts/PII — and asks once. OPT-IN, default OFF: a
        // bare Enter declines and nothing leaves the machine. This gates all TC
        // upload, and is changeable anytime (pga config set telemetry true / the
        // dashboard Settings + Threat Cloud toggle). Non-interactive (CI) stays OFF.
        const telemetryConsented = await ensureTelemetryConsent();

        // Whether the scan flywheel may upload to Threat Cloud. OPT-IN, default
        // OFF: requires an affirmative consent (telemetryConsented) AND that TC
        // upload is EXPLICITLY enabled in config (threatCloudUploadEnabled ===
        // true). Absent/unset config => OFF (gate is `=== true`, never `!== false`).
        // Nothing leaves the machine unless the user opted in via the first-run
        // prompt / `pga config set telemetry true` / the dashboard toggle.
        const tcUploadAllowed = (() => {
          if (!telemetryConsented) return false;
          try {
            const cfgPath = join(homedir(), '.panguard-guard', 'config.json');
            if (existsSync(cfgPath)) {
              const cfg = JSON.parse(readFileSync(cfgPath, 'utf-8')) as {
                telemetryEnabled?: boolean;
                threatCloudUploadEnabled?: boolean;
              };
              return cfg.threatCloudUploadEnabled === true;
            }
          } catch {
            // On any read error, fail closed — do not upload.
            return false;
          }
          // No config on disk yet => not opted in => OFF.
          return false;
        })();

        // ── Step 1: Detect AI platforms (we SCAN before deploying) ──
        let platformCount = 0;
        let serverCount = 0;
        let threatCount = 0;
        type DetectFn = () => Promise<Array<{ id: string; name: string; detected: boolean }>>;
        type InjectFn = (ids: readonly string[]) => {
          totalPlatforms: number;
          totalServersProxied: number;
          results: ReadonlyArray<{ platformId: string; serversProxied: number; error?: string }>;
        };
        // Captured during detection, used to inject AFTER the scan completes.
        let detectedPlatforms: Array<{ id: string; name: string; detected: boolean }> = [];
        let injectProxyFn: InjectFn | null = null;
        try {
          let detectPlatforms: DetectFn;
          try {
            // Published package: import from /config subpath
            const mcp = (await import('@panguard-ai/panguard-mcp/config' as string)) as {
              detectPlatforms: DetectFn;
              injectProxy: InjectFn;
            };
            detectPlatforms = mcp.detectPlatforms;
            injectProxyFn = mcp.injectProxy;
          } catch {
            // Monorepo fallback: resolve from cwd
            const { resolve } = await import('node:path');
            const { pathToFileURL } = await import('node:url');
            const mcpDist = resolve(process.cwd(), 'packages/panguard-mcp/dist/config/index.js');
            const mcp = (await import(pathToFileURL(mcpDist).href)) as {
              detectPlatforms: DetectFn;
              injectProxy: InjectFn;
            };
            detectPlatforms = mcp.detectPlatforms;
            injectProxyFn = mcp.injectProxy;
          }

          console.log(
            `  ${shield()} ${c.bold(t(lang, 'Looking at your setup...', '看看你的環境...'))}\n`
          );
          const platforms = await detectPlatforms();
          detectedPlatforms = platforms.filter((p) => p.detected);

          for (const p of detectedPlatforms) {
            console.log(`    ${ok()} ${c.safe(p.name)}  ${c.dim(t(lang, 'found', '已找到'))}`);
          }
          if (detectedPlatforms.length === 0) {
            console.log(`    ${c.dim(t(lang, 'No AI tools found yet.', '尚未找到 AI 工具。'))}`);
            console.log(
              `    ${c.dim(
                t(
                  lang,
                  'Supported: Claude Code, Claude Desktop, Cursor, OpenClaw, Codex, WorkBuddy.',
                  '支援：Claude Code、Claude Desktop、Cursor、OpenClaw、Codex、WorkBuddy。'
                )
              )}`
            );
            console.log(
              `    ${c.dim(
                t(
                  lang,
                  'Guard is still running in the background and will pick up newly installed tools automatically.',
                  'Guard 仍在背景執行，安裝新工具後會自動偵測。'
                )
              )}`
            );
          }
          console.log();
        } catch {
          console.log(
            `  ${c.dim('Platform detection skipped (install @panguard-ai/panguard-mcp for full detection).')}\n`
          );
        }

        // ── Step 2: Scan installed skills (BEFORE deploying protection) ──
        // On first run `pga setup` (shelled above) already scanned every skill and
        // recorded verdicts — re-scanning here would double the work (~2x wall
        // clock) and print the same threats twice under a second UI. Reuse setup's
        // verdict from the flagged store instead.
        if (firstRun && !opts.skipScan) {
          threatCount = readFlaggedSkills().length;
          if (threatCount > 0) {
            console.log(
              `  ${warn()} ${c.bold(
                t(
                  lang,
                  `${threatCount} skill(s) flagged during setup (shown above) — review with "pga status".`,
                  `設定時標記了 ${threatCount} 個技能(如上）— 用「pga status」檢視。`
                )
              )}\n`
            );
          }
        }
        if (!opts.skipScan && !firstRun) {
          console.log(
            `\n  ${arrow()} ${c.bold(t(lang, 'Scanning installed skills...', '掃描已安裝技能...'))}\n`
          );

          try {
            let skills: ReadonlyArray<{ name: string; platformId: string }> = [];
            try {
              const mcp = (await import('@panguard-ai/panguard-mcp/config' as string)) as {
                discoverAllSkills: () => Promise<typeof skills>;
              };
              skills = await mcp.discoverAllSkills();
            } catch {
              // Monorepo fallback
              const { resolve } = await import('node:path');
              const { pathToFileURL } = await import('node:url');
              const mcpDist = resolve(process.cwd(), 'packages/panguard-mcp/dist/config/index.js');
              const mcp = (await import(pathToFileURL(mcpDist).href)) as {
                discoverAllSkills: () => Promise<typeof skills>;
              };
              skills = await mcp.discoverAllSkills();
            }

            if (skills.length === 0) {
              // Be precise about SCOPE: `pga up` scans skills already INSTALLED
              // across your AI platforms (~/.claude/skills + MCP server configs).
              // A project folder of SKILL.md files is a different thing — point at
              // `pga scan <path>` for that so "no skills" doesn't read as "nothing
              // is installed" when the user has a ./skills dir right there.
              console.log(
                `  ${c.dim('No installed skills found across your AI platforms. ("pga up" scans ~/.claude/skills and your MCP server configs — to scan a project folder instead, run "pga scan ./skills" or "pga scan <path>".)')}\n`
              );
              console.log(
                `  ${c.dim('Guard is still running in the background and will pick up newly installed skills automatically.')}\n`
              );
            } else {
              // Load whitelist
              const whitelistPath = join(homedir(), '.panguard-guard', 'skill-whitelist.json');
              const safeNames = new Set<string>();
              if (existsSync(whitelistPath)) {
                try {
                  const wl = JSON.parse(readFileSync(whitelistPath, 'utf-8')) as {
                    whitelist?: Array<{ name: string; normalizedName?: string }>;
                  };
                  for (const s of wl.whitelist ?? []) {
                    safeNames.add(s.name.toLowerCase());
                    if (s.normalizedName) safeNames.add(s.normalizedName.toLowerCase());
                  }
                } catch (err) {
                  process.stderr.write(
                    `[panguard up] Failed to load whitelist: ${err instanceof Error ? err.message : String(err)}\n`
                  );
                }
              }

              const safe = skills.filter((s) => safeNames.has(s.name.toLowerCase()));
              const unknown = skills.filter((s) => !safeNames.has(s.name.toLowerCase()));

              console.log(
                `  ${c.safe(String(safe.length))} safe  ${c.dim('|')}  ${unknown.length > 0 ? c.caution(String(unknown.length)) : c.dim('0')} unscanned`
              );

              // If there are unscanned skills, run audit on them
              if (unknown.length > 0) {
                console.log(
                  `\n  ${warn()} ${c.bold(`${unknown.length} unscanned skill(s) found. Auditing...`)}\n`
                );

                const threats: Array<{
                  name: string;
                  platform: string;
                  riskLevel: string;
                  riskScore: number;
                  /** Which rules fired — so status can say WHY, not just THAT. */
                  evidence: ReturnType<typeof toEvidence>;
                }> = [];

                try {
                  const { auditSkill } = await import('@panguard-ai/panguard-skill-auditor');

                  const toScan = unknown;
                  let scanned = 0;
                  for (const skill of toScan) {
                    try {
                      scanned++;
                      process.stdout.write(
                        `\r  ${c.dim(`[${scanned}/${toScan.length}]`)} Auditing ${c.bold(skill.name)}...`
                      );

                      // Find skill directory
                      const skillDir = join(homedir(), '.claude', 'skills', skill.name);
                      if (!existsSync(skillDir)) continue;

                      // Fast path: ATR regex only for `pga up` — skip both the AI
                      // layer AND the code scan (semgrep's ~3-4s per-skill startup
                      // times the number of installed skills turns `pga up` into a
                      // multi-minute hang). Users run `pga audit --deep <skill>` for
                      // the full SAST + secrets + AI analysis.
                      const report = await auditSkill(skillDir, {
                        skipAI: true,
                        skipCode: true,
                      });
                      if (report.riskLevel === 'HIGH' || report.riskLevel === 'CRITICAL') {
                        threats.push({
                          name: skill.name,
                          platform: skill.platformId,
                          riskLevel: report.riskLevel,
                          riskScore: report.riskScore,
                          evidence: toEvidence(report.findings),
                        });
                      }

                      // ── Flywheel: submit scan results to TC (consent-gated) ──
                      // Never upload anything when the user has not consented or
                      // has opted out of Threat Cloud.
                      if (tcUploadAllowed && report.riskScore > 0) {
                        submitToTC(skill.name, skillDir, report).catch(() => {});
                      }
                    } catch (err) {
                      process.stderr.write(
                        `[panguard up] Skill audit failed for ${skill.name}: ${err instanceof Error ? err.message : String(err)}\n`
                      );
                    }
                  }
                } catch (err) {
                  process.stderr.write(
                    `[panguard up] Skill auditor unavailable: ${err instanceof Error ? err.message : String(err)}\n`
                  );
                }

                // Clear progress line
                process.stdout.write('\r' + ' '.repeat(80) + '\r');

                threatCount = threats.length;
                // Persist the scan verdict so `pga status` / `pga doctor` show the
                // real severity of a flagged skill (not "UNKNOWN"/"No scan result").
                recordScanResults({
                  scannedNames: unknown.map((s) => s.name),
                  flagged: threats.map((t) => ({
                    name: t.name,
                    platform: t.platform,
                    riskLevel: t.riskLevel as RiskLevel,
                    evidence: t.evidence,
                  })),
                  scannedAt: new Date().toISOString(),
                });
                if (threats.length > 0) {
                  console.log(`  ${c.critical(c.bold(`${threats.length} skill(s) flagged:`))}\n`);
                  for (const threat of threats) {
                    const icon =
                      threat.riskLevel === 'CRITICAL' ? c.critical('!!') : c.caution('!');
                    const action =
                      threat.riskLevel === 'CRITICAL'
                        ? c.critical('remove or replace this skill')
                        : c.caution('review with: pga scan ~/.claude/skills/' + threat.name);
                    console.log(
                      `    ${icon} ${c.bold(threat.name)} ${c.dim(`(${threat.platform}) \u2014 ${threat.riskLevel}`)}`
                    );
                    console.log(`      ${c.dim('\u2192')} ${action}`);
                  }

                  // Auto-revoke CRITICAL skills from whitelist
                  const criticalNames = new Set(
                    threats
                      .filter((t) => t.riskLevel === 'CRITICAL')
                      .map((t) => t.name.toLowerCase())
                  );
                  if (criticalNames.size > 0 && existsSync(whitelistPath)) {
                    try {
                      const wlRaw = JSON.parse(readFileSync(whitelistPath, 'utf-8')) as {
                        whitelist?: Array<{ name: string; [k: string]: unknown }>;
                      };
                      const before = wlRaw.whitelist?.length ?? 0;
                      wlRaw.whitelist = (wlRaw.whitelist ?? []).filter(
                        (s) => !criticalNames.has(s.name.toLowerCase())
                      );
                      const revoked = before - (wlRaw.whitelist?.length ?? 0);
                      if (revoked > 0) {
                        const { writeFileSync, renameSync } = await import('node:fs');
                        const tmpPath = `${whitelistPath}.tmp.${process.pid}`;
                        writeFileSync(tmpPath, JSON.stringify(wlRaw, null, 2), 'utf-8');
                        renameSync(tmpPath, whitelistPath);
                        console.log(
                          `\n  ${c.critical(c.bold(`${revoked} CRITICAL skill(s) auto-revoked from whitelist.`))}`
                        );
                      }
                    } catch (err) {
                      process.stderr.write(
                        `[panguard up] Whitelist revocation failed: ${err instanceof Error ? err.message : String(err)}\n`
                      );
                    }
                  }
                  console.log('');
                } else {
                  console.log(`  ${c.safe(`${ok()} No threats found in unscanned skills.`)}\n`);
                }
              } else {
                console.log(`  ${c.safe(`${ok()} All ${skills.length} skills verified safe.`)}\n`);
                // Every installed skill is whitelisted-safe: record a clean scan so
                // doctor shows a real timestamp and any stale flag is cleared.
                recordScanResults({
                  scannedNames: skills.map((s) => s.name),
                  flagged: [],
                  scannedAt: new Date().toISOString(),
                });
              }
            }
          } catch {
            console.log(`  ${c.dim('Skill scan skipped (discovery unavailable).')}\n`);
          }
        }

        // ── Step 3: Deploy runtime protection (AFTER the scan) ──
        // Build runtime protection by DEFAULT. `pga up` should stand up
        // protection out of the box; --no-proxy opts out (scan only). In an
        // interactive TTY we confirm, but the prompt defaults to YES so the
        // common path (just run `pga up`) actually protects. Non-TTY
        // (CI / unattended) injects by default too — configs are backed up.
        if (detectedPlatforms.length > 0 && injectProxyFn) {
          let shouldInject = opts.proxy !== false;
          if (shouldInject && !opts.yes && process.stdin.isTTY) {
            const { createInterface } = await import('node:readline');
            const rl = createInterface({ input: process.stdin, output: process.stdout });
            const answer = await new Promise<string>((resolve) => {
              rl.question(
                `\n  Inject runtime protection into ${detectedPlatforms.length} platform(s)? ` +
                  `${c.dim('(configs backed up to *.bak)')} [Y/n] `,
                resolve
              );
            });
            rl.close();
            shouldInject = answer.trim().toLowerCase() !== 'n';
          }

          if (!shouldInject) {
            console.log(
              `\n    ${c.dim('Scan only — runtime protection not injected (--no-proxy).')}`
            );
          } else {
            console.log(`\n  ${shield()} ${c.bold('Watching your agents...')}\n`);
            const proxySummary = injectProxyFn(detectedPlatforms.map((p) => p.id));
            platformCount = proxySummary.totalPlatforms;
            serverCount = proxySummary.totalServersProxied;

            if (serverCount > 0) {
              console.log(
                `    ${c.safe(`${serverCount} MCP server(s)`)} proxied across ${c.sage(`${platformCount} platform(s)`)}`
              );
              console.log(`    ${c.dim('Config backed up to *.bak files')}`);
            } else {
              console.log(`    ${c.dim('All detected tools are already protected.')}`);
            }

            for (const r of proxySummary.results) {
              if (r.error) {
                console.log(`    ${c.critical(`${r.platformId}: ${r.error}`)}`);
              }
            }

            // The MCP proxy only covers MCP tool servers. An agent's BUILT-IN
            // tools (Bash/Edit/Write/WebFetch) bypass it — the most dangerous
            // surface. Register the per-platform tool-call hook on EVERY detected
            // platform that exposes one, so built-in tools are evaluated too.
            const hookable = detectedPlatforms
              .map((p) => toHookPlatform(p.id))
              .filter((p): p is NonNullable<typeof p> => p !== null);
            if (hookable.length) {
              const done: string[] = [];
              for (const hp of hookable) {
                try {
                  if (installFor(hp) !== 'error') done.push(hp);
                } catch {
                  /* best-effort; pga hook install can retry */
                }
              }
              if (done.length) {
                // The hook is written to disk but not yet loaded by the running
                // agent process — built-in tools are NOT protected until the
                // agent restarts. Lead with that so the user doesn't read a
                // green line and assume protection is already active.
                console.log(
                  `    ${c.caution(`Built-in tools will be guarded on ${done.length} platform(s) after you restart the agent`)} ` +
                    `${c.dim(`(${done.join(', ')})`)}`
                );
                // The agent only reads its hook config at startup, so tell the
                // user the EXACT restart action per platform — "restart the
                // agent" alone leaves them guessing which key/menu to press.
                const RESTART_HINTS: Record<string, string> = {
                  'claude-code': 'quit and relaunch Claude Code (a new session loads the hook)',
                  'claude-desktop': 'quit and reopen Claude Desktop',
                  cursor: 'Reload Window — Cmd/Ctrl+Shift+P → "Reload Window" — or restart Cursor',
                  codex: 'restart the Codex CLI',
                  gemini: 'restart the Gemini CLI',
                  continue: 'Reload Window in VS Code — Cmd/Ctrl+Shift+P → "Reload Window"',
                  cline: 'Reload Window in VS Code — Cmd/Ctrl+Shift+P → "Reload Window"',
                  'vscode-copilot': 'Reload Window in VS Code — Cmd/Ctrl+Shift+P → "Reload Window"',
                  'roo-code': 'Reload Window in VS Code — Cmd/Ctrl+Shift+P → "Reload Window"',
                  windsurf: 'Reload Window, or restart Windsurf',
                  zed: 'restart Zed',
                };
                console.log(`    ${c.dim('To activate now:')}`);
                for (const hp of done) {
                  console.log(
                    `      ${c.dim('•')} ${c.bold(hp)} — ${c.dim(RESTART_HINTS[hp] ?? 'restart the agent')}`
                  );
                }
                console.log(
                  `    ${c.dim('Guarded = critical/high-confidence threats blocked, the rest advisory. `pga hook install --enforce` blocks everything. Verify anytime: `pga doctor`.')}`
                );
              }
            }
          }
          console.log();
        }

        // ── Activation tracking (one-time, OPT-IN) ──
        // The activation ping is non-essential collective telemetry, so it only
        // fires when the user has EXPLICITLY opted in (threatCloudUploadEnabled
        // === true). Default OFF: absent/unset config or any read error => no ping.
        const telemetryDisabled = !tcUploadAllowed;
        if (tcUploadAllowed) {
          reportActivation().catch(() => {});
        }

        // ── Summary + Start Guard ─────────────────────────────
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        let guardAlreadyRunning = isGuardRunning();

        // Self-heal an unauthenticated dashboard (GA hardening). A daemon can be
        // alive and holding the dashboard port yet serve only 401s — a stale
        // instance that never persisted a launch token, or one still running from
        // before an upgrade. `pga up` used to leave such a daemon untouched and
        // then poll forever for a token that never lands, so the dashboard 401'd
        // on every visit. If the running daemon's dashboard cannot authenticate,
        // stop it here so the start logic below (launchd KeepAlive respawn, or a
        // fresh ephemeral spawn) re-mints the token and the dashboard becomes
        // reachable. Only when a dashboard is expected (opts.dashboard).
        if (guardAlreadyRunning && opts.dashboard && !(await isDashboardHealthy())) {
          console.log(
            `  ${c.dim(t(lang, 'Refreshing the dashboard (restarting Guard)…', '重新整理儀表板(重啟 Guard)…'))}`
          );
          stopGuardDaemon();
          // Wait for the old daemon to exit and release the port (up to ~4s) so
          // the replacement can bind cleanly and write a fresh token.
          for (let i = 0; i < 40 && isGuardRunning(); i++) {
            await new Promise((r) => setTimeout(r, 100));
          }
          guardAlreadyRunning = isGuardRunning();
        }

        // Persistence: on macOS install a user-level LaunchAgent (no sudo) so
        // protection survives reboot like an antivirus. The service IS the daemon
        // (RunAtLoad), so when we install it we do NOT also spawn an ephemeral one
        // — two daemons would fight over the dashboard port. Linux/Windows keep
        // the ephemeral daemon plus the honest "pga guard install" hint.
        let persistResult: PersistResult = isServiceInstalled() ? 'already' : 'unsupported';
        if (!guardAlreadyRunning) {
          if (opts.persist !== false && platform() === 'darwin' && persistResult !== 'already') {
            persistResult = ensurePersistentService();
          }
          const serviceManages = persistResult === 'installed' || persistResult === 'already';
          if (serviceManages) {
            // launchctl starts the daemon asynchronously — wait briefly (up to
            // ~3s for the PID file) so the summary reflects reality.
            for (let i = 0; i < 30 && !isGuardRunning(); i++) {
              await new Promise((r) => setTimeout(r, 100));
            }
          } else {
            // Ephemeral fallback (no reboot-surviving service, e.g. --no-persist
            // or a non-macOS host without an installed service): spawn a DETACHED
            // background daemon so protection actually runs until reboot. Running
            // the guard in-process (runCLI('start')) would die the moment `pga up`
            // returns — commandStart is a foreground daemon, so it must be its own
            // process, exactly like the launchd/systemd path. spawn + detached +
            // unref() is what keeps it alive after this process exits.
            // Re-launch THIS CLI entry running `guard --watch` — the exact command
            // the launchd/systemd service runs — as a detached process. Resolving
            // the guard package would fail here: its exports map defines only an
            // `import` condition, so require.resolve (CJS) throws "No exports main".
            // process.argv[1] is the running CLI entry and needs no resolution.
            const watchArgs = ['guard', '--watch'];
            if (opts.dashboard) watchArgs.push('--dashboard');
            if (opts.verbose) watchArgs.push('--verbose');
            // Resolve to an absolute path: when invoked as `node ./dist/...` the
            // entry is relative, and a detached child must not depend on inheriting
            // the right cwd to find it.
            const cliEntry = process.argv[1] ? resolve(process.argv[1]) : '';
            try {
              if (cliEntry && existsSync(cliEntry)) {
                // Send the daemon's console output to its own log (like launchd),
                // not /dev/null, so a failed background start is diagnosable.
                let outFd: number | 'ignore' = 'ignore';
                try {
                  const gdir = join(homedir(), '.panguard-guard');
                  if (!existsSync(gdir)) mkdirSync(gdir, { recursive: true, mode: 0o700 });
                  outFd = openSync(join(gdir, 'panguard-guard.log'), 'a');
                } catch {
                  outFd = 'ignore';
                }
                const child = spawn(process.execPath, [cliEntry, ...watchArgs], {
                  detached: true,
                  stdio: ['ignore', outFd, outFd],
                  env: { ...process.env, PANGUARD_QUIET_GUARD: '1' },
                  windowsHide: true,
                });
                child.unref();
                // Wait briefly for the detached daemon to come up so the summary
                // + authenticated-URL step below reflect a running guard.
                for (let i = 0; i < 30 && !isGuardRunning(); i++) {
                  await new Promise((r) => setTimeout(r, 100));
                }
              } else {
                // Last-resort fallback (no resolvable CLI entry): in-process start.
                // Protection lasts only while this process lives — degraded, but
                // better than no daemon at all.
                process.env['PANGUARD_QUIET_GUARD'] = '1';
                const inProc = ['start'];
                if (opts.dashboard) inProc.push('--dashboard');
                if (opts.verbose) inProc.push('--verbose');
                await runCLI(inProc);
              }
            } catch (err) {
              process.stderr.write(
                `  ${c.caution('Guard start failed:')} ${err instanceof Error ? err.message : String(err)}\n`
              );
            }
          }
        }

        // ── Resolve the AUTHENTICATED dashboard URL ──────────────────
        // The daemon persists its launch token once the dashboard is listening.
        // The launchd path writes the PID file before the dashboard token, so
        // there can be a brief window where the daemon is up but the token is
        // not yet on disk. The dashboard server starts INSIDE the just-launched
        // guard daemon and needs a few seconds to load rules, bind its port, and
        // write its auth token. 2s (then 15s) was too short — on a first run the
        // daemon also loads the full ruleset before binding, so the token can
        // take longer than 15s to land and `pga up` fell to the "re-run" path
        // (which re-runs the whole scan). Poll up to ~40s so the common AND the
        // slow-first-run paths actually open the dashboard; only a pathological
        // start falls back (to `pga status`, not a full re-scan).
        let dashboardUrl: string | null = null;
        if (opts.dashboard) {
          // Do NOT gate on an early isGuardRunning() snapshot: a first-run daemon
          // loads the full ruleset before writing its PID, so it can be up seconds
          // later. Poll for the daemon AND its token inside the loop, so a slow
          // start is 'still starting', not a false 'Guard is not running'.
          for (let i = 0; i < 400; i++) {
            if (isGuardRunning()) {
              dashboardUrl = readAuthenticatedDashboardUrl();
              if (dashboardUrl) break;
            }
            if (i === 10) {
              console.log(`  ${c.dim(t(lang, 'Starting dashboard...', '正在啟動儀表板...'))}`);
            }
            await new Promise((r) => setTimeout(r, 100));
          }
        }

        // ── Open dashboard (after Guard is up so the server is listening) ──
        // Open + print the AUTHENTICATED URL so it works on rerun, headless, or
        // when copied. If the token is unavailable, print guidance instead of a
        // dead bare URL that would land on a 401 "Invalid token" page.
        if (opts.dashboard) {
          if (dashboardUrl) {
            console.log(`\n  ${c.sage(`Opening dashboard: ${dashboardBaseUrl()}`)}\n`);
            openBrowser(dashboardUrl);
          } else if (isGuardRunning()) {
            const base = dashboardBaseUrl();
            console.log(
              `\n  ${c.caution(
                t(
                  lang,
                  `Dashboard is starting at ${base} — run "pga status" for the ready link (no re-scan needed).`,
                  `儀表板正在啟動：${base} — 執行「pga status」取得就緒連結(不需重新掃描)。`
                )
              )}\n`
            );
          } else {
            // Guard did not come up. Never tell the user to re-run the command
            // they are already running — point them at the log + doctor + a
            // foreground start so the failure is self-debuggable.
            console.log(
              `\n  ${c.caution(
                t(
                  lang,
                  `Dashboard not available — Guard did not start. See ~/.panguard-guard/panguard-guard.log, run "pga doctor", or "pga guard --watch" to start it in the foreground and see the error.`,
                  `儀表板無法使用 — Guard 未啟動。請查看 ~/.panguard-guard/panguard-guard.log,執行「pga doctor」,或用「pga guard --watch」在前景啟動以查看錯誤。`
                )
              )}\n`
            );
          }
        }

        // ── Read rule count + TC status ──────────
        const ruleCount = readRuleCountFromCache();
        const sensorId = readSensorId();
        const sensorShortId = sensorId ? sensorId.slice(0, 8) : null;

        let tcStatus = 'disconnected';
        try {
          const cachePath = join(homedir(), '.panguard-guard', 'threat-cloud-cache.json');
          if (existsSync(cachePath)) {
            const cache = JSON.parse(readFileSync(cachePath, 'utf-8')) as {
              lastSync?: string;
            };
            if (cache.lastSync) {
              tcStatus = 'connected';
            }
          }
        } catch {
          /* best-effort: TC cache may not exist on first run */
        }

        // ── Clean summary panel ────────────────────────────────
        const guardRunning = isGuardRunning();
        const hasProxy = serverCount > 0;
        const statusLabel =
          guardRunning && hasProxy
            ? c.safe(c.bold(t(lang, 'MONITORING + PROXY ACTIVE', '監控中 + 代理已啟動')))
            : guardRunning
              ? c.sage(c.bold(t(lang, 'MONITORING', '監控中')))
              : c.caution(c.bold(t(lang, 'SCAN COMPLETE', '掃描完成')));

        console.log(`\n  ${c.dim('\u2500'.repeat(50))}`);
        console.log(`  ${statusLabel} ${c.dim(`\u2014 ${elapsed}s`)}`);
        console.log(`  ${c.dim('\u2500'.repeat(50))}`);
        // Honest persistence framing: say plainly whether protection survives a
        // reboot \u2014 never imply always-on when it's only a until-reboot daemon.
        const persisted =
          persistResult === 'installed' || persistResult === 'already' || isServiceInstalled();
        if (guardRunning && persisted) {
          console.log(
            `  ${c.dim(t(lang, 'Always-on: protection restarts after reboot (launchd).', '\u5e38\u99d0:\u91cd\u958b\u6a5f\u5f8c\u81ea\u52d5\u6062\u5fa9\u9632\u8b77(launchd)\u3002'))}`
          );
        } else if (guardRunning) {
          console.log(
            `  ${c.dim(t(lang, 'Runs until reboot. For always-on monitoring: pga guard install', '\u6301\u7e8c\u5230\u91cd\u958b\u6a5f\u70ba\u6b62\u3002\u8981\u958b\u6a5f\u5f8c\u4ecd\u6301\u7e8c\u76e3\u63a7:pga guard install'))}`
          );
        }
        console.log('');
        if (opts.dashboard) {
          // Reflect real state — never print a bare URL that 401s. Only show a
          // link when we have the AUTHENTICATED (token) URL; otherwise say where
          // to get it (running) or where to debug (not started). This keeps the
          // summary consistent with the dashboard-status branch above.
          if (dashboardUrl) {
            console.log(`  ${c.sage('Dashboard')}     ${dashboardUrl}`);
          } else if (guardRunning) {
            console.log(
              `  ${c.sage('Dashboard')}     ${c.dim(t(lang, 'run "pga status" for the link', '執行「pga status」取得連結'))}`
            );
          } else {
            console.log(
              `  ${c.sage('Dashboard')}     ${c.dim(t(lang, 'not started — see ~/.panguard-guard/panguard-guard.log', '未啟動 — 見 ~/.panguard-guard/panguard-guard.log'))}`
            );
          }
        }
        console.log(
          `  ${c.sage(t(lang, 'Rules', '規則'))}         ${ruleCount} ${t(lang, 'detection rules active', '條偵測規則運作中')}`
        );
        if (platformCount > 0) {
          console.log(
            `  ${c.sage(t(lang, 'Platforms', '平台'))}     ${platformCount} ${t(lang, 'detected', '已偵測')}, ${hasProxy ? `${serverCount} ${t(lang, 'server(s) proxied', '個伺服器已代理')}` : t(lang, 'proxy not injected', '代理未注入')}`
          );
        }
        if (threatCount > 0) {
          console.log(
            `  ${c.sage(t(lang, 'Threats', '威脅'))}       ${c.critical(`${threatCount} ${t(lang, 'flagged', '個標記')}`)}`
          );
        }
        // `tcStatus === 'connected'` only means rules were pulled IN (rule-sync);
        // it does NOT mean anything is shared OUT. Sharing is the opt-in
        // (threatCloudUploadEnabled, i.e. !telemetryDisabled). Gate the label on
        // the SHARING state first so a receive-only default install never reads as
        // "connected" next to "nothing leaves this machine".
        const synced = tcStatus === 'connected';
        const tcStatusLine = telemetryDisabled
          ? synced
            ? t(lang, 'receive-only · rules synced, nothing shared', '僅接收 · 規則已同步,不分享')
            : t(lang, 'off · not sharing', '關閉 · 不分享')
          : synced
            ? `${t(lang, 'sharing on', '分享中')}${sensorShortId ? ` · ${t(lang, 'sensor', '感測器')} ${c.sage(sensorShortId)}` : ''}`
            : t(
                lang,
                'sharing on · offline (will sync when online)',
                '分享中 · 離線(上線時自動同步)'
              );
        console.log(`  ${c.sage('Threat Cloud')}  ${tcStatusLine}`);
        console.log('');

        // ── Sensor confirmation: user knows they are now part of the defense network
        if (tcStatus === 'connected' && !telemetryDisabled && sensorShortId) {
          console.log(
            `  ${c.safe(ok())} ${c.bold(t(lang, 'You are now a Threat Cloud sensor.', '你已成為威脅雲感測器。'))}`
          );
          console.log(
            `  ${c.dim(t(lang, `This machine contributes anonymous detections to the community defense network.`, `這台機器正在為社群防禦網路貢獻匿名偵測。`))}`
          );
          console.log(
            `  ${c.dim(t(lang, `Check status: pga sensor status · Opt out: pga config set telemetry false`, `查看狀態:pga sensor status · 停用:pga config set telemetry false`))}`
          );
          console.log('');
        }

        // ── Next steps ─────────────────────────────────────────
        console.log(`  ${c.bold(t(lang, 'NEXT STEPS', '下一步'))}`);
        if (dashboardUrl) {
          console.log(
            `  ${c.dim('1.')} ${t(lang, 'Open dashboard', '開啟儀表板')}     ${c.sage(dashboardUrl)}`
          );
        } else {
          // No live token yet (daemon still writing it). Point at `pga status`,
          // which prints the authenticated dashboard link once it lands — never
          // back at `pga up` (the command they just ran → a confusing loop).
          console.log(
            `  ${c.dim('1.')} ${t(lang, 'Open dashboard', '開啟儀表板')}     ${c.dim(t(lang, 'run "pga status" for the dashboard link', '執行「pga status」取得儀表板連結'))}`
          );
        }
        if (threatCount > 0) {
          console.log(
            `  ${c.dim('2.')} ${t(lang, 'Review threats', '檢視威脅')}     ${c.caution(`${threatCount} ${t(lang, 'flagged', '個標記')}`)} ${c.dim('\u2014 pga audit skill <name>')}`
          );
          console.log(
            `  ${c.dim('3.')} ${t(lang, 'Upgrade detection', '升級偵測')}  ${c.dim('pga guard setup-ai')}`
          );
        } else {
          console.log(
            `  ${c.dim('2.')} ${t(lang, 'Upgrade detection', '升級偵測')}  ${c.dim('pga guard setup-ai')}`
          );
        }
        console.log('');
        console.log(
          `  ${c.dim(t(lang, 'Layer 1 (regex) blocks known attack patterns instantly at zero cost.', 'Layer 1 (正則) 零成本即時攔截已知攻擊模式。'))}`
        );
        console.log(
          `  ${c.dim(t(lang, 'Add Layer 2 (local AI) or 3 (cloud AI) for deeper detection.', '加入 Layer 2 (本地 AI) 或 Layer 3 (雲端 AI) 提升偵測深度。'))}`
        );
        if (tcUploadAllowed) {
          console.log(
            `  ${c.dim(t(lang, 'Collective defense ON: when an attack is blocked, only the matched rule ID,', '集體防禦已開啟：擋下攻擊時，只分享命中的規則 ID、'))}`
          );
          console.log(
            `  ${c.dim(t(lang, 'a one-way payload hash, and the source type are shared — never your prompts,', 'payload 的單向雜湊、來源類型 — 絕不含你的 prompt、'))}`
          );
          console.log(
            `  ${c.dim(t(lang, 'code, file contents, keys, hostname, or IP. Thank you for defending the commons.', '程式碼、檔案內容、金鑰、主機名或 IP。謝謝你一起守護社群。'))}`
          );
          console.log(
            `  ${c.dim(t(lang, 'Turn off anytime: pga config set telemetry false', '隨時可關閉：pga config set telemetry false'))}`
          );
        } else {
          // OPT-IN guidance (NOT a default, NOT a nag): explain the value + the
          // privacy guarantee + the one command, so the user can make an
          // informed choice. Collective defense stays OFF until they opt in.
          console.log(
            `  ${c.dim(t(lang, 'Collective defense is OFF — nothing leaves this machine.', '集體防禦目前關閉 — 沒有任何資料離開這台機器。'))}`
          );
          console.log(
            `  ${c.dim(t(lang, 'Want to help? The attacks you block feed the community threat pool that protects', '想幫忙嗎？你擋下的攻擊會匯入保護所有人的社群威脅池，'))}`
          );
          console.log(
            `  ${c.dim(t(lang, 'everyone — and you get community rules back faster. Shared: only the matched', '而你也能更快收到社群回流的規則。分享的只有命中的規則 ID、'))}`
          );
          console.log(
            `  ${c.dim(t(lang, 'rule ID, a one-way hash, and the source type. Never your prompts, code,', 'payload 的單向雜湊、來源類型。絕不含你的 prompt、程式碼、'))}`
          );
          console.log(
            `  ${c.dim(t(lang, 'file contents, keys, hostname, or IP. Opt in: pga config set telemetry true', '檔案內容、金鑰、主機名或 IP。開啟：pga config set telemetry true'))}`
          );
        }
        console.log('');

        // The full first run completed: record the durable marker so the next
        // `pga up` (and bare `pga`) skip the welcome + interactive setup and go
        // straight to scan -> protect -> summary. Independent of telemetry
        // consent, so opt-out users are no longer nagged every run.
        markInitialized();
      }
    );
}

/** Best-effort submit scan results to Threat Cloud for the flywheel */
async function submitToTC(
  skillName: string,
  skillDir: string,
  report: {
    riskScore: number;
    riskLevel: string;
    findings: ReadonlyArray<{
      id: string;
      category: string;
      severity: string;
      title: string;
      // Optional real-evidence fields — forwarded into the ATR proposal when the
      // scan captured them (source snippet is the genuine attack pattern).
      location?: string;
      explain?: { snippet?: string };
    }>;
  }
): Promise<void> {
  // Defense-in-depth: never let a raw filesystem path become the uploaded skill
  // name. discoverAllSkills() yields registry/manifest names, but strip path
  // separators + cap length so a path-like name can't leak a local directory tree.
  skillName = skillName.replace(/[\\/]/g, '_').slice(0, 80);
  const { ThreatCloudClient } = await import('@panguard-ai/panguard-guard');
  const { contentHash } = await import('@panguard-ai/scan-core');
  const { readFileSync: rf, existsSync: fe } = await import('node:fs');

  const dataDir = join(homedir(), '.panguard-guard');
  const tc = await ThreatCloudClient.create(TC_ENDPOINT, dataDir);

  // 1. Submit skill threat
  const skillMdPath = join(skillDir, 'SKILL.md');
  const skillHash = fe(skillMdPath) ? contentHash(rf(skillMdPath, 'utf-8')) : contentHash(skillDir);

  await tc.submitSkillThreat({
    skillHash,
    skillName,
    riskScore: report.riskScore,
    riskLevel: report.riskLevel as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    findingSummaries: report.findings.slice(0, 10).map((f) => ({
      id: f.id,
      category: f.category,
      severity: f.severity,
      title: f.title,
    })),
  });

  // 2. Submit ATR proposal for HIGH/CRITICAL
  if (
    (report.riskLevel === 'HIGH' || report.riskLevel === 'CRITICAL') &&
    report.findings.length > 0
  ) {
    // Emit a VALID draft-request proposal (real evidence + needsLLMDraft), never
    // a rule fabricated from the finding-title keywords. See atr-proposal.ts for
    // why the old title-keyword regex was scrapped (it detected our own report
    // text and had no precision test). The server/Guard drafter turns this into a
    // real, test-backed rule via the Rule Creation Standard.
    const proposal = buildSkillAuditProposal({
      skillName,
      riskLevel: report.riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
      source: 'pga-up',
      findings: report.findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        location: f.location,
        snippet: f.explain?.snippet,
      })),
    });
    if (proposal) await tc.submitATRProposal(proposal);
  }

  // 3. Report scan event for metrics
  void tc.reportScanEvent({
    source: 'cli-user',
    skillsScanned: 1,
    findingsCount: report.findings.length,
    confirmedMalicious: report.riskLevel === 'CRITICAL' ? 1 : 0,
    highlySuspicious: report.riskLevel === 'HIGH' ? 1 : 0,
    cleanCount: report.riskLevel === 'LOW' || report.riskScore === 0 ? 1 : 0,
  });
}

/** One-time activation report — only fires on first pga up */
async function reportActivation(): Promise<void> {
  const {
    existsSync: fe,
    writeFileSync: wf,
    mkdirSync: md,
    readFileSync: rf,
  } = await import('node:fs');
  const marker = join(homedir(), '.panguard', 'activated');
  if (fe(marker)) return;

  const { randomUUID } = await import('node:crypto');
  const idDir = join(homedir(), '.panguard');
  const idPath = join(idDir, 'client-id');
  let clientId: string;
  try {
    clientId = rf(idPath, 'utf-8').trim();
  } catch {
    clientId = randomUUID();
    try {
      // On a true first run ~/.panguard may not exist yet; create it (0o700)
      // before writing the client-id, otherwise the write ENOENTs and
      // readSensorId() keeps returning null forever.
      if (!fe(idDir)) md(idDir, { recursive: true, mode: 0o700 });
      wf(idPath, clientId, 'utf-8');
    } catch {
      /* best effort */
    }
  }

  const body = JSON.stringify({
    clientId,
    platform: process.env['TERM_PROGRAM'] ?? 'terminal',
    osType: `${process.platform}-${process.arch}`,
    panguardVersion: process.env['npm_package_version'] ?? 'unknown',
    nodeVersion: process.version,
  });

  const res = await fetch(`${TC_ENDPOINT}/api/activations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal: AbortSignal.timeout(5000),
  });

  if (res.ok) {
    md(join(homedir(), '.panguard'), { recursive: true });
    wf(marker, new Date().toISOString(), 'utf-8');
  }
}
