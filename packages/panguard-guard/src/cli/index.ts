#!/usr/bin/env node
/**
 * PanguardGuard CLI
 * PanguardGuard 命令列介面
 *
 * Uses brand-standard colors and layout from Panguard AI brand system.
 * Brand: Sage Green #8B9A8E, Cream #F5F1E8, Charcoal #1A1614
 *
 * @module @panguard-ai/panguard-guard/cli
 */

import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  c,
  banner,
  header,
  symbols,
  divider,
  statusPanel,
  spinner,
  setLogLevel,
  promptConfirm,
} from '@panguard-ai/core';
import type { StatusItem } from '@panguard-ai/core';
import { GuardEngine } from '../guard-engine.js';
import { loadConfig, saveConfig, DEFAULT_DATA_DIR } from '../config.js';
import type { GuardConfig } from '../types.js';
import { redactSecrets } from '../redact.js';
import { PidFile } from '../daemon/index.js';
import { installService, uninstallService } from '../daemon/index.js';
import { generateTestLicenseKey } from '../license/index.js';
import { generateInstallScript } from '../install/index.js';
import { DashboardRenderer } from './dashboard-renderer.js';
import type { DashboardState } from './dashboard-renderer.js';
import { removeDashboardToken } from '../dashboard/index.js';
import { SkillWatcher } from '../engines/skill-watcher.js';
import { commandScan } from './scan-command.js';
import {
  classifyThreatResponse,
  renderAutoResponse,
  renderLowConfidenceNote,
  InteractiveThreatQueue,
} from './interactive-handler.js';
import type { ThreatContext } from './interactive-handler.js';
import { DailySummaryCollector } from '../summary/daily-summary.js';
import { isSafeOutboundUrl } from '../net/validate-outbound-url.js';
import type { RuleValidation, CommonFailureCause } from './validate-rules.js';
import { queryLiveRuleCounts } from './live-status.js';

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _pkg = _require('../../package.json') as { version: string };
/** CLI version / CLI 版本 */
export const CLI_VERSION: string = _pkg.version;

/**
 * Compute the honest startup status from the actual mode AND loaded rule count.
 * A user in report-only mode, or in protection mode with zero loaded rules,
 * must NEVER see "PROTECTED" — that would misrepresent the security posture.
 */
export function computeStartupStatus(
  mode: string,
  ruleCount: number
): { label: string; status: 'safe' | 'caution' | 'critical' } {
  if (mode === 'learning') return { label: 'LEARNING', status: 'caution' };
  if (mode === 'report-only') return { label: 'REPORT-ONLY', status: 'caution' };
  // protection mode
  if (ruleCount <= 0) return { label: 'DEGRADED', status: 'critical' };
  return { label: 'PROTECTED', status: 'safe' };
}

/** Commands recognized by the switch below, used to detect an unknown command. */
const KNOWN_COMMANDS = [
  'start',
  'stop',
  'status',
  'install',
  'uninstall',
  'config',
  'generate-key',
  'install-script',
  'scan',
  'validate',
  'help',
] as const;

/**
 * Find the closest known command to an unrecognized one (simple Levenshtein),
 * so an "Unknown command" error can suggest a likely fix.
 */
function suggestCommand(input: string): string | undefined {
  const distance = (a: string, b: string): number => {
    const dp: number[][] = Array.from({ length: a.length + 1 }, () =>
      new Array<number>(b.length + 1).fill(0)
    );
    for (let i = 0; i <= a.length; i++) dp[i]![0] = i;
    for (let j = 0; j <= b.length; j++) dp[0]![j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i]![j] =
          a[i - 1] === b[j - 1]
            ? dp[i - 1]![j - 1]!
            : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
      }
    }
    return dp[a.length]![b.length]!;
  };
  let best: { cmd: string; dist: number } | undefined;
  for (const cmd of KNOWN_COMMANDS) {
    const dist = distance(input, cmd);
    if (best === undefined || dist < best.dist) best = { cmd, dist };
  }
  // Only suggest when reasonably close, otherwise a suggestion is noise.
  return best !== undefined && best.dist <= 3 ? best.cmd : undefined;
}

/**
 * Parse and execute CLI commands / 解析並執行 CLI 命令
 */
export async function runCLI(args: string[]): Promise<void> {
  const command = args[0] ?? 'help';
  const dataDir = extractOption(args, '--data-dir') ?? DEFAULT_DATA_DIR;
  const verbose = args.includes('--verbose');
  const dashboard = args.includes('--dashboard');
  const interactive = args.includes('--interactive');
  const managerUrl = extractOption(args, '--manager');
  const noTelemetry = args.includes('--no-telemetry');
  const showUploadData = args.includes('--show-upload-data');

  switch (command) {
    case 'start':
      await commandStart(
        dataDir,
        verbose,
        managerUrl,
        noTelemetry,
        showUploadData,
        dashboard,
        interactive
      );
      break;
    case 'stop':
      commandStop(dataDir);
      break;
    case 'status':
      await commandStatus(dataDir);
      break;
    case 'install':
      await commandInstall(dataDir);
      break;
    case 'uninstall':
      await commandUninstall(dataDir);
      break;
    case 'config': {
      // `config --set key=value` (or `config set key value`) mutates a
      // whitelisted setting, so the "enable it later" hint the CLI prints is a
      // real, runnable command — previously it errored (unknown option --set).
      const setKV =
        extractOption(args, '--set') ??
        (args[1] === 'set' && args[2] ? `${args[2]}=${args[3] ?? 'true'}` : undefined);
      if (setKV) {
        const eq = setKV.indexOf('=');
        const key = eq >= 0 ? setKV.slice(0, eq) : setKV;
        const rawVal = eq >= 0 ? setKV.slice(eq + 1) : 'true';
        const BOOL_KEYS = new Set([
          'threatCloudUploadEnabled',
          'threatCloudRuleSyncEnabled',
          'telemetryEnabled',
          'showUploadData',
        ]);
        if (!BOOL_KEYS.has(key)) {
          console.log(`  ${symbols.fail} Unknown or non-settable key: ${c.sage(key)}`);
          console.log(`  ${c.dim('Settable: ' + [...BOOL_KEYS].join(', '))}`);
          break;
        }
        const val = rawVal === 'true' || rawVal === '1';
        const cfgPath = join(dataDir, 'config.json');
        const cfg = loadConfig(cfgPath);
        (cfg as unknown as Record<string, unknown>)[key] = val;
        saveConfig(cfg, cfgPath);
        console.log(`  ${symbols.pass} ${key} = ${c.sage(String(val))}`);
        console.log(`  ${c.dim('Restart guard to apply: pga guard restart')}`);
        break;
      }
      commandConfig(dataDir);
      break;
    }
    case 'generate-key': {
      const tier = (args[1] ?? 'pro') as 'free' | 'pro' | 'enterprise';
      const key = generateTestLicenseKey(tier);
      console.log(`  ${symbols.pass} Generated ${c.bold(tier)} license key: ${c.sage(key)}`);
      break;
    }
    case 'install-script': {
      // The license key is a secret. Prefer PANGUARD_LICENSE_KEY (env) over the
      // legacy --license-key flag, which is visible in `ps`/`ps aux` argv and
      // captured in shell history. This restores the project's own secret-input
      // hierarchy (env > stdin > file > argv, never) for the installer itself.
      const envKey = process.env['PANGUARD_LICENSE_KEY'];
      const argvKey = extractOption(args, '--license-key');
      if (argvKey && !envKey) {
        process.stderr.write(
          `  ${symbols.warn} --license-key on the command line is visible via \`ps\` and lands in ` +
            `shell history. Prefer: PANGUARD_LICENSE_KEY=... pga install-script\n`
        );
      }
      const licenseKey = envKey ?? argvKey;
      // Constrain the key charset so it can never inject into the generated
      // bash/PowerShell config it is interpolated into.
      if (licenseKey && !/^[A-Za-z0-9._-]+$/.test(licenseKey)) {
        process.stderr.write(
          `  ${symbols.fail} License key contains unexpected characters; refusing to embed it.\n`
        );
        break;
      }
      const script = generateInstallScript({ dataDir, licenseKey });
      if (licenseKey) {
        // Never echo a script that embeds a secret to stdout (terminal scrollback,
        // pipes, CI logs). Write it to an exclusively-created, owner-only file and
        // print only the path.
        const { openSync, writeSync, closeSync, fstatSync, unlinkSync, mkdirSync, chmodSync } =
          await import('node:fs');
        const { join } = await import('node:path');
        const { homedir, platform } = await import('node:os');
        const { randomBytes } = await import('node:crypto');
        const isWin = platform() === 'win32';
        const dir = join(homedir(), '.panguard');
        // Create 0700; tighten even if it already existed (Node ignores `mode`
        // on a pre-existing dir, so don't trust a dir we didn't just create).
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        if (!isWin) {
          try {
            chmodSync(dir, 0o700);
          } catch {
            /* best effort */
          }
        }
        // Random, unpredictable name. 'wx' = O_CREAT|O_EXCL: fails with EEXIST on
        // a pre-existing file OR a pre-planted symlink, so an attacker cannot make
        // us write the secret through their file/link. mode 0o600 is honored here
        // because O_EXCL guarantees a brand-new file. Verify with fstat before the
        // secret touches disk; refuse (never truncate) on any anomaly.
        const outPath = join(
          dir,
          `install-panguard-${randomBytes(6).toString('hex')}.${isWin ? 'ps1' : 'sh'}`
        );
        let fd: number;
        try {
          fd = openSync(outPath, 'wx', 0o600);
        } catch (err) {
          process.stderr.write(
            `  ${symbols.fail} Could not create a private file for the install script ` +
              `(${err instanceof Error ? err.message : String(err)}). Aborting to avoid leaking the key.\n`
          );
          process.exitCode = 1;
          break;
        }
        let refused = false;
        try {
          if (!isWin) {
            const st = fstatSync(fd);
            if ((st.mode & 0o777) !== 0o600) {
              process.stderr.write(
                `  ${symbols.fail} Refusing to write the key: created file is not 0600 ` +
                  `(mode ${(st.mode & 0o777).toString(8)}).\n`
              );
              refused = true;
            }
          }
          if (!refused) writeSync(fd, script);
        } finally {
          closeSync(fd);
        }
        if (refused) {
          // fstat check failed after create — remove the empty file we made.
          try {
            unlinkSync(outPath);
          } catch {
            /* best effort */
          }
          process.exitCode = 1;
          break;
        }
        console.log(
          `  ${symbols.pass} Install script written to ${c.sage(outPath)} ${c.dim('(0600 — contains your license key)')}`
        );
        console.log(
          `  ${c.dim('Run it on the target machine, then delete it. Do not commit, pipe, or share it.')}`
        );
      } else {
        console.log(script);
      }
      break;
    }
    case 'scan':
      await commandScan(args.slice(1));
      break;
    case 'validate':
      await commandValidate(args.slice(1));
      break;
    case 'help':
      printHelp();
      break;
    default: {
      // Unrecognized command: fail loudly instead of silently succeeding with
      // help text. A typo'd command must never look like a successful run.
      // (`command` defaults to 'help' when args are empty, so reaching this
      // branch always means the user typed something we don't recognize.)
      process.stderr.write(`  ${symbols.fail} Unknown command: '${command}'\n`);
      const suggestion = suggestCommand(command);
      if (suggestion !== undefined) {
        process.stderr.write(`  ${c.dim(`Did you mean '${suggestion}'?`)}\n`);
      }
      process.stderr.write(`  ${c.dim("Run 'panguard-guard help' to see all commands.")}\n`);
      process.exitCode = 1;
      break;
    }
  }
}

/**
 * Dry-run validate a rules directory. Used by the
 * `pga migrate ... --deploy-to-guard` workflow to verify a candidate rules
 * dir before pushing it into a running Guard.
 *
 * Usage:
 *   panguard-guard validate <rules-dir>
 *   panguard-guard validate <rules-dir> --json     (machine-readable)
 *
 * Exit 0 = every rule passed. Exit 1 = any rule failed (or dir missing).
 */
/** Max rule-detail blocks printed before collapsing the rest into a note.
 *  Keeps a large systemic failure (e.g. hundreds of rules sharing one
 *  templating mistake) from dumping an unreadable wall of near-duplicate
 *  blocks — the aggregated "common failure causes" section above already
 *  carries the signal; --json still returns every result untruncated. */
const MAX_VALIDATE_RULE_BLOCKS = 20;

/** Max affected-rule ids listed inline per aggregated common cause. */
const MAX_COMMON_CAUSE_IDS_SHOWN = 5;

/** Print the "N rules share this failure" aggregation with a fix hint. */
function printCommonFailureCauses(common: ReadonlyArray<CommonFailureCause>): void {
  if (common.length === 0) return;
  console.log(divider());
  console.log(`  ${symbols.warn} ${c.bold('common failure causes:')}`);
  for (const cause of common) {
    console.log(`\n  ${c.critical(`${cause.count}x`)}  ${cause.message}`);
    console.log(`    ${c.dim('fix:')} ${cause.fixHint}`);
    const shown = cause.ruleIds.slice(0, MAX_COMMON_CAUSE_IDS_SHOWN);
    const rest = cause.ruleIds.length - shown.length;
    const suffix = rest > 0 ? c.dim(` ...and ${rest} more`) : '';
    console.log(`    ${c.dim('affects:')} ${shown.join(', ')}${suffix}`);
  }
}

/** Print each failing rule's own detail block, capped for readability. */
function printPerRuleFailures(failures: ReadonlyArray<RuleValidation>): void {
  console.log(divider());
  console.log(`  ${symbols.fail} ${c.bold('failures:')}`);
  const shown = failures.slice(0, MAX_VALIDATE_RULE_BLOCKS);
  for (const r of shown) {
    console.log(`\n  ${c.bold(r.ruleId ?? '<no id>')}  ${c.dim(r.file)}`);
    for (const reason of r.failures) {
      console.log(`    ${symbols.fail} ${reason}`);
    }
  }
  const rest = failures.length - shown.length;
  if (rest > 0) {
    console.log(
      `\n  ${c.dim(`...and ${rest} more rule(s) with failures (use --json for the full list).`)}`
    );
  }
}

async function commandValidate(args: string[]): Promise<void> {
  const positional = args.filter((a) => !a.startsWith('--'));
  const dir = positional[0];
  const jsonMode = args.includes('--json');

  if (!dir) {
    console.error(`  ${symbols.fail} usage: panguard-guard validate <rules-dir> [--json]`);
    process.exit(1);
    return;
  }

  const { validateRulesDir, summarizeCommonFailureCauses } = await import('./validate-rules.js');
  let report;
  try {
    report = validateRulesDir(dir);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  ${symbols.fail} ${msg}`);
    process.exit(1);
    return;
  }

  if (jsonMode) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    process.exit(report.failed === 0 ? 0 : 1);
    return;
  }

  console.log(banner(CLI_VERSION));
  console.log(header('Validating ATR rules directory'));
  console.log(`  ${symbols.info} ${report.directory}`);
  console.log(divider());
  console.log(
    `  ${symbols.pass} passed: ${c.sage(String(report.passed))}` +
      `    ${symbols.fail} failed: ${report.failed > 0 ? c.alert(String(report.failed)) : '0'}` +
      `    total: ${report.totalRules}`
  );

  if (report.failed > 0) {
    printCommonFailureCauses(summarizeCommonFailureCauses(report.failures));
    printPerRuleFailures(report.failures);
  }

  process.exit(report.failed === 0 ? 0 : 1);
}

/** Start the guard engine / 啟動守護引擎 */
async function commandStart(
  dataDir: string,
  verbose = false,
  managerUrl?: string,
  noTelemetry = false,
  showUploadData = false,
  dashboardMode = false,
  interactiveMode = false
): Promise<void> {
  // Default quiet mode: suppress structured JSON logs
  if (!verbose) {
    setLogLevel('silent');
  }

  // When called from pga up, suppress the banner (pga up has its own output)
  if (!process.env['PANGUARD_QUIET_GUARD']) {
    console.log(banner(CLI_VERSION));
  }

  const pidFile = new PidFile(dataDir);
  if (pidFile.isRunning()) {
    console.log(`  ${symbols.warn} PanguardGuard is already running`);
    return;
  }

  const sp = spinner('Starting PanguardGuard...');
  const config = loadConfig(join(dataDir, 'config.json'));

  // Pass --manager URL to config for distributed architecture
  if (managerUrl) {
    config.managerUrl = managerUrl;
  }
  if (noTelemetry) {
    config.threatCloudUploadEnabled = false;
    config.telemetryEnabled = false;
  }
  if (showUploadData) {
    config.showUploadData = true;
  }

  // Auto-provision a TC client key — ONLY when the user has opted into uploads,
  // and NEVER block daemon startup on it. threatCloudEndpoint defaults to
  // tc.panguard.ai, so without these guards a fresh daemon makes a blocking
  // network call to Threat Cloud before the dashboard binds — and a slow /
  // firewalled / unreachable (e.g. dead IPv6) route hangs it for ~75s (the
  // request's idle-timeout does not cover the TCP/TLS connect phase). Gate on
  // opt-in (default OFF = no call = instant start) and cap the wait so even an
  // opted-in user with a bad network still gets a working daemon + dashboard.
  if (
    !config.threatCloudApiKey &&
    config.threatCloudEndpoint &&
    config.threatCloudUploadEnabled === true
  ) {
    try {
      const { loadOrProvisionTCKey } = await import('../threat-cloud/tc-key-provisioner.js');
      const { getAnonymousClientId } = await import('../threat-cloud/client-id.js');
      const provisionedKey = await Promise.race([
        loadOrProvisionTCKey(config.threatCloudEndpoint, getAnonymousClientId()),
        new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), 4000)),
      ]);
      if (provisionedKey) {
        config.threatCloudApiKey = provisionedKey;
      }
    } catch {
      // Never let TC provisioning block or crash startup.
    }
  }

  // S5: verify config integrity + self-state before the engine starts. On a genuine
  // first run, establish the seal. On tamper / self-removal, start anyway but warn
  // LOUDLY — never silently honor a weakened config as if PROTECTED (the S2 invariant).
  try {
    const {
      verifyConfigIntegrity,
      checkSelfState,
      sealConfigManifest,
      wasInitialized,
      collectSelfState,
      mergeSelfState,
      readSelfStateRefs,
    } = await import('../integrity.js');
    const cfgRecord = config as unknown as Record<string, unknown>;
    let verdict = verifyConfigIntegrity(cfgRecord, dataDir);
    const selfState = checkSelfState(dataDir);
    if (verdict.status === 'unsealed' && !wasInitialized(dataDir)) {
      // True first run — establish trust AND record the guard's own artifacts so
      // their later removal is detectable. Sealing empty refs (the old behavior)
      // left checkSelfState iterating nothing → self-removal detection was dead.
      sealConfigManifest(cfgRecord, collectSelfState(), dataDir);
      verdict = { status: 'sealed', findings: [], checkedAt: verdict.checkedAt };
    } else if (verdict.status === 'sealed' && selfState.ok) {
      // Config trust intact and nothing currently missing: fold in any newly-present
      // artifacts (LaunchAgent installed after the first seal, or an in-place upgrade
      // from a build that sealed empty refs). Merge never drops a recorded ref, and
      // we only re-seal an already-verified config when the inventory actually grew —
      // so this never masks a tamper nor rewrites the manifest needlessly.
      const recorded = readSelfStateRefs(dataDir);
      const merged = mergeSelfState(recorded, collectSelfState());
      if (merged.length > recorded.length) {
        sealConfigManifest(cfgRecord, merged, dataDir);
      }
    }
    if (verdict.status !== 'sealed' || !selfState.ok) {
      process.stderr.write(
        `\n[panguard-guard] INTEGRITY: ${verdict.status.toUpperCase()} — protection state may have been changed outside the guard.\n`
      );
      // Field NAME only, never the value — config can hold secrets.
      for (const f of verdict.findings) {
        process.stderr.write(`  - config.${f.field} changed (${f.severity})\n`);
      }
      for (const f of selfState.findings) {
        process.stderr.write(`  - ${f.kind} ${f.reason}${f.label ? ` (${f.label})` : ''}\n`);
      }
      process.stderr.write(
        '  Review the changes above. If you made this change intentionally, re-run ' +
          '"panguard-guard start" to re-seal the integrity manifest.\n\n'
      );
    }
  } catch {
    /* integrity is best-effort — never block daemon startup (consistent with TC provisioning) */
  }

  const engine = await GuardEngine.create(config);

  const shutdown = async () => {
    console.log(`\n  ${symbols.info} Shutting down PanguardGuard...`);
    await engine.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());

  // SIGHUP triggers live rule reload without process restart. Lets
  // `pga migrate-pro --deploy-to-guard` deploy new rules with zero
  // detection downtime. Atomicity: see GuardATREngine.reloadRules() docs.
  process.on('SIGHUP', () => {
    void (async () => {
      try {
        const result = await engine.reloadRules();
        console.log(
          `  ${symbols.pass} Rules reloaded: ${result.total} (${result.bundled} bundled + ${result.custom} custom)`
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  ${symbols.fail} Reload failed: ${msg}`);
      }
    })();
  });

  // Optional fsnotify watcher on the ATR rules dir. Triggers reload on any
  // .yaml / .yml file change (debounced 500ms). Opt-in via env:
  //   PANGUARD_WATCH_RULES=1
  // Rules dir is derived from dataDir (consistent with rule-loader.ts).
  const watchRules = process.env['PANGUARD_WATCH_RULES'] === '1';
  if (watchRules) {
    try {
      const { watch } = await import('node:fs');
      const rulesDir = join(config.dataDir, 'atr-rules');
      let debounceTimer: ReturnType<typeof setTimeout> | null = null;
      const watcher = watch(
        rulesDir,
        { recursive: true },
        (eventType: string, filename: string | null) => {
          if (!filename) return;
          if (!filename.endsWith('.yaml') && !filename.endsWith('.yml')) return;
          if (debounceTimer) clearTimeout(debounceTimer);
          debounceTimer = setTimeout(() => {
            void engine
              .reloadRules()
              .then((result) => {
                console.log(
                  `  ${symbols.pass} Rules auto-reloaded (${eventType} ${filename}): ${result.total}`
                );
              })
              .catch((err: unknown) => {
                const msg = err instanceof Error ? err.message : String(err);
                console.error(`  ${symbols.fail} Auto-reload failed: ${msg}`);
              });
          }, 500);
        }
      );
      process.once('SIGINT', () => watcher.close());
      process.once('SIGTERM', () => watcher.close());
      console.log(`  ${symbols.info} Watching ${rulesDir} for rule changes`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ${symbols.warn} fs.watch failed: ${msg} (live reload disabled)`);
    }
  }

  await engine.start();
  sp.succeed('PanguardGuard started');

  // Rule counts
  const rules = engine.getRuleCounts();
  const rulesSummary = `ATR: ${rules.atr}`;

  // Zero loaded rules = detection is silently off. The engine's no-rules
  // warning goes through the structured logger, which `commandStart` mutes to
  // 'silent' in non-verbose mode — so a degraded Guard would otherwise start up
  // looking healthy. Surface it loudly on stderr regardless of log level and in
  // both the quiet (pga up) and normal output paths.
  if (rules.atr <= 0) {
    console.error(
      `  ${c.critical(symbols.fail)} ${c.critical('DEGRADED')}: 0 ATR rules loaded — ` +
        `pattern detection is OFF. Reinstall the @panguard-ai/atr package to restore detection.`
    );
  }

  // Status box (suppressed when called from pga up which has its own summary)
  if (process.env['PANGUARD_QUIET_GUARD']) {
    // Minimal output for pga up integration
    console.log(`  ${c.safe(symbols.pass)} Guard started (PID ${process.pid})`);
  } else {
    const startupStatus = computeStartupStatus(config.mode, rules.atr);
    const statusColor =
      startupStatus.status === 'safe'
        ? c.safe
        : startupStatus.status === 'caution'
          ? c.caution
          : c.critical;
    console.log(
      statusPanel('PANGUARD AI Guard Active', [
        {
          label: 'Status',
          value: statusColor(startupStatus.label),
          status: startupStatus.status,
        },
        { label: 'PID', value: c.sage(String(process.pid)) },
        { label: 'Mode', value: c.sage(config.mode) },
        { label: 'Rules', value: c.sage(rulesSummary) },
        { label: 'Data Dir', value: c.dim(dataDir) },
        ...(config.dashboardEnabled
          ? [{ label: 'Dashboard', value: c.underline(`http://localhost:${config.dashboardPort}`) }]
          : []),
        ...(config.threatCloudEndpoint
          ? [{ label: 'Threat Cloud', value: c.dim(config.threatCloudEndpoint) }]
          : []),
      ])
    );

    // Threat intelligence sharing transparency message — OPT-IN, default OFF.
    // Only "enabled" when the user explicitly turned it on (=== true).
    if (config.threatCloudUploadEnabled === true) {
      console.log(`  ${symbols.info} Threat intelligence sharing: ${c.safe('enabled')}`);
      console.log(
        `  ${c.dim('  Detected threats are anonymously uploaded to Panguard Threat Cloud')}`
      );
      console.log(`  ${c.dim('  Disable: panguard-guard start --no-telemetry')}`);
    } else {
      console.log(`  ${symbols.info} Threat intelligence sharing: ${c.dim('disabled')}`);
      console.log(`  ${c.dim('  No data will be uploaded to Panguard Threat Cloud')}`);
    }
    if (config.showUploadData) {
      console.log(`  ${symbols.info} Upload data preview: ${c.safe('enabled')}`);
    }
    console.log('');

    // Free tier: show what's enabled/disabled. With zero loaded ATR rules,
    // pattern matching cannot fire \u2014 never paint a green checkmark over a
    // non-functional detection layer. Show a red DEGRADED line instead so the
    // banner matches the DEGRADED Status above.
    if (rules.atr > 0) {
      console.log(
        `  ${c.safe('\u2713')} Pattern matching + heuristic correlation on every event (Layer A + B)`
      );
    } else {
      console.log(
        `  ${c.critical(symbols.fail)} ${c.critical('Layer A DEGRADED')}: 0 ATR rules loaded \u2014 pattern detection is OFF. ` +
          `Reinstall the @panguard-ai/atr package to restore detection.`
      );
    }

    console.log('');
    const semanticOn = Boolean(
      config.ai?.provider ||
      process.env['PANGUARD_AI_KEY'] ||
      process.env['ANTHROPIC_API_KEY'] ||
      process.env['OPENAI_API_KEY'] ||
      process.env['PANGUARD_LLM_ENDPOINT']
    );
    if (semanticOn) {
      const provider = config.ai?.provider ?? 'configured LLM';
      console.log(
        `  ${c.safe('\u2713')} Layer C Semantic (advisory): ${c.sage(provider)} \u2014 flags for review, never auto-blocks`
      );
    } else {
      console.log(
        `  ${symbols.info} Layer C Semantic is off. Optional: connect your own LLM (cloud API or local Ollama) for advisory analysis \u2014 it never auto-blocks.`
      );
    }
  } // end of PANGUARD_QUIET_GUARD else block

  // ── First-run welcome / 首次啟動歡迎 ──────────────────────────────
  if (!process.env['PANGUARD_QUIET_GUARD']) {
    await showFirstRunWelcome(config.dashboardPort, engine.getRuleCounts().atr);
    console.log(`  ${symbols.info} Monitoring...`);
  }
  console.log('');

  // ── TUI Dashboard mode ──────────────────────────────────────────────
  const dashboardRenderer = dashboardMode ? new DashboardRenderer(5000) : null;

  // ── Telemetry batch + notification debounce ────────────────────────
  const TC_ENDPOINT = config.threatCloudEndpoint ?? 'https://tc.panguard.ai';
  const telemetryBatch: Array<{
    event: string;
    platform: string;
    skillCount: number;
    findingCount: number;
    severity: string;
  }> = [];
  let telemetryFlushTimer: ReturnType<typeof setTimeout> | null = null;
  let notificationDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  const pendingNotifications: string[] = [];

  function flushTelemetryBatch(): void {
    if (telemetryBatch.length === 0) return;
    const batch = [...telemetryBatch];
    telemetryBatch.length = 0;
    const telemetryUrl = `${TC_ENDPOINT}/api/telemetry`;
    // SSRF guard: reject non-https / private / metadata endpoints, and refuse
    // to follow redirects (a redirect could point telemetry at an internal host).
    if (!isSafeOutboundUrl(telemetryUrl)) {
      return;
    }
    for (const evt of batch) {
      try {
        void fetch(telemetryUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...evt, ts: new Date().toISOString() }),
          signal: AbortSignal.timeout(3000),
          redirect: 'error',
        }).catch(() => {
          /* best effort */
        });
      } catch {
        // Never block guard for telemetry
      }
    }
  }

  function scheduleTelemetryFlush(): void {
    if (telemetryFlushTimer) return;
    telemetryFlushTimer = setTimeout(() => {
      telemetryFlushTimer = null;
      flushTelemetryBatch();
    }, 30_000); // flush every 30s
  }

  function pushTelemetryEvent(event: string, findingCount: number, severity: string): void {
    // Opt-in, default OFF: only queue telemetry when explicitly enabled.
    if (config.threatCloudUploadEnabled !== true) return;
    telemetryBatch.push({
      event,
      platform: `${process.platform}-${process.arch}`,
      skillCount: 0, // will be populated async later if needed
      findingCount,
      severity,
    });
    scheduleTelemetryFlush();
  }

  function pushNotification(title: string, message: string): void {
    if (process.platform !== 'darwin') return;
    pendingNotifications.push(`${title}: ${message}`);
    if (notificationDebounceTimer) clearTimeout(notificationDebounceTimer);
    notificationDebounceTimer = setTimeout(() => {
      notificationDebounceTimer = null;
      const msgs = pendingNotifications.splice(0, pendingNotifications.length);
      if (msgs.length === 0) return;
      const combined = msgs.length === 1 ? msgs[0] : `${msgs.length} skill audit results`;
      void import('node:child_process')
        .then(({ execFileSync }) => {
          try {
            // execFileSync (no shell) prevents shell injection; escaping the
            // AppleScript string literal prevents a skill name with quotes or
            // backslashes from breaking out of the notification text.
            const safe = (combined ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            execFileSync(
              'osascript',
              ['-e', `display notification "${safe}" with title "PanGuard"`],
              { timeout: 2000 }
            );
          } catch {
            // Notification failed — non-critical
          }
        })
        .catch(() => {});
    }, 5_000); // debounce 5s
  }

  // ── Skill Install Watcher ────────────────────────────────────────────
  // Local detection always runs (dashboard alerts, blacklist checks). The
  // OUTBOUND flywheel submitters (skill threat + ATR proposal) carry a skill
  // name and findings to Threat Cloud, so they are collective-defense sharing:
  // wire them ONLY when the user has explicitly opted in (=== true, never
  // !== false). Opted out => submitters stay undefined => SkillWatcher uploads
  // nothing.
  const sharingOptedIn = config.threatCloudUploadEnabled === true;
  const skillWatcher = new SkillWatcher({
    pollInterval: 10_000,
    submitThreat: sharingOptedIn ? engine.getSkillThreatSubmitter() : undefined,
    submitATRProposal: sharingOptedIn ? engine.getATRProposalSubmitter() : undefined,
  });

  skillWatcher.on('skill-added', (change: { name: string; platformId: string }) => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    if (dashboardRenderer) {
      dashboardRenderer.pushEvent({
        time,
        icon: symbols.info,
        message: `skill-install: ${change.name} on ${change.platformId}`,
      });
    } else if (!verbose) {
      console.log(
        `  ${symbols.info} ${c.sage(`[${time}]`)} New skill: ${c.bold(change.name)} on ${change.platformId}`
      );
    }
  });

  skillWatcher.on('skill-removed', (change: { name: string; platformId: string }) => {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    if (dashboardRenderer) {
      dashboardRenderer.pushEvent({
        time,
        icon: symbols.warn,
        message: `skill-removed: ${change.name} from ${change.platformId}`,
      });
    } else if (!verbose) {
      console.log(
        `  ${symbols.warn} ${c.dim(`[${time}]`)} Skill removed: ${change.name} from ${change.platformId}`
      );
    }
  });

  skillWatcher.on(
    'skill-audit-complete',
    (result: { name: string; riskLevel: string; riskScore: number; autoWhitelisted: boolean }) => {
      const time = new Date().toLocaleTimeString('en-US', { hour12: false });
      const icon =
        result.riskLevel === 'LOW'
          ? symbols.pass
          : result.riskLevel === 'MEDIUM'
            ? symbols.warn
            : symbols.fail;
      const riskColor =
        result.riskLevel === 'LOW'
          ? c.safe
          : result.riskLevel === 'MEDIUM'
            ? c.caution
            : c.critical;

      if (dashboardRenderer) {
        const statusMsg = result.autoWhitelisted
          ? 'SAFE (whitelisted)'
          : riskColor(result.riskLevel);
        dashboardRenderer.pushEvent({
          time,
          icon,
          message: `skill-audit: ${result.name} ${String.fromCharCode(8594)} ${statusMsg}`,
        });
      } else if (!verbose) {
        console.log(
          `  ${icon} ${c.sage(`[${time}]`)} Audit: ${result.name} = ${riskColor(result.riskLevel)} (${result.riskScore}/100)`
        );
        if (result.autoWhitelisted) {
          console.log(`    ${symbols.pass} Auto-whitelisted`);
        }
      }

      // Telemetry + macOS notification
      pushTelemetryEvent('skill_audit', result.riskScore, result.riskLevel);
      if (result.riskLevel === 'HIGH' || result.riskLevel === 'CRITICAL') {
        pushNotification(
          'Skill Audit',
          `${result.name}: ${result.riskLevel} (${result.riskScore}/100)`
        );
      }
    }
  );

  void skillWatcher.start();

  // ── Daily Summary Collector ────────────────────────────────────────
  const dailySummary = new DailySummaryCollector(dataDir);
  dailySummary.start();

  // ── Interactive Threat Queue ────────────────────────────────────────
  const threatQueue = interactiveMode ? new InteractiveThreatQueue() : null;

  // Update shutdown handler to also stop skill watcher, dashboard, summary
  const originalShutdown = shutdown;
  const enhancedShutdown = async () => {
    if (telemetryFlushTimer) clearTimeout(telemetryFlushTimer);
    flushTelemetryBatch();
    if (notificationDebounceTimer) clearTimeout(notificationDebounceTimer);
    skillWatcher.stop();
    dailySummary.stop();
    if (dashboardRenderer) dashboardRenderer.stop();
    await originalShutdown();
  };
  process.removeAllListeners('SIGINT');
  process.removeAllListeners('SIGTERM');
  process.on('SIGINT', () => void enhancedShutdown());
  process.on('SIGTERM', () => void enhancedShutdown());

  // ── Dashboard or Quiet mode event callback ──────────────────────────
  if (dashboardRenderer) {
    // Dashboard mode: feed events to TUI renderer
    const getState = (): DashboardState => {
      const status = engine.getStatus();
      const rules = engine.getRuleCounts();
      // Honest posture: only report 'protected' when actually enforcing
      // (protection mode WITH loaded rules). Learning, report-only, and the
      // degraded 0-rules case must never render as PROTECTED — they fall back
      // to the cautionary 'learning' label until a 'report-only'/'degraded'
      // variant is added to DashboardState (see dashboard-renderer.ts).
      const tuiStatus: DashboardState['status'] = !status.running
        ? 'stopped'
        : status.mode === 'protection' && rules.atr > 0
          ? 'protected'
          : 'learning';
      return {
        status: tuiStatus,
        uptime: status.uptime,
        eventsProcessed: status.eventsProcessed,
        threatsDetected: status.threatsDetected,
        actionsExecuted: status.actionsExecuted,
        mode: status.mode,
        ruleCounts: rules,
        whitelistedSkills: status.whitelistedSkills ?? 0,
        trackedSkills: status.trackedSkills ?? 0,
        aiProvider: config.ai?.provider,
        aiModel: config.ai?.model,
        learningProgress: status.learningProgress,
      };
    };

    engine.setEventCallback((type, data) => {
      const time = new Date().toLocaleTimeString('en-US', { hour12: false });
      if (type === 'threat') {
        dashboardRenderer.pushThreat({
          time,
          category: String(data['category'] ?? 'unknown'),
          source: String(data['sourceIP'] ?? 'unknown'),
          confidence: Number(data['confidence'] ?? 0),
          action: String(data['action'] ?? 'none'),
        });
      } else if (type === 'status') {
        dashboardRenderer.pushEvent({
          time,
          icon: symbols.pass,
          message: `heartbeat: ${Number(data['eventsProcessed'] ?? 0).toLocaleString()} events`,
        });
      }
    });

    dashboardRenderer.start(getState);
  } else if (!verbose) {
    // Quiet mode: status summary every 60s, threat alerts with interactive routing
    let lastStatusTime = 0;
    engine.setEventCallback((type, data) => {
      if (type === 'status') {
        const now = Date.now();
        if (now - lastStatusTime < 60_000) return;
        lastStatusTime = now;
        const time = new Date().toLocaleTimeString('en-US', { hour12: false });
        const events = Number(data['eventsProcessed'] ?? 0);
        const threats = Number(data['threatsDetected'] ?? 0);
        const uploaded = Number(data['uploaded'] ?? 0);

        // Feed daily summary
        dailySummary.recordEvent();

        if (!process.env['PANGUARD_QUIET_GUARD']) {
          console.log(
            c.dim(
              `  [${time}] Events: ${events.toLocaleString()} | Threats: ${threats} | Uploaded: ${uploaded}`
            )
          );
        }
      } else if (type === 'threat') {
        const time = new Date().toLocaleTimeString('en-US', { hour12: false });
        const confidence = Number(data['confidence'] ?? 0);
        const category = String(data['category'] ?? 'unknown');
        const sourceIP = String(data['sourceIP'] ?? 'unknown');
        const action = String(data['action'] ?? 'none');

        // Feed daily summary
        dailySummary.recordThreat(category, action === 'blocked', sourceIP);

        // Route based on confidence
        const responseType = classifyThreatResponse(confidence);
        const context: ThreatContext = {
          category,
          sourceIP,
          confidence,
          details: String(data['details'] ?? ''),
          timestamp: time,
        };

        if (responseType === 'auto') {
          renderAutoResponse(context, action);
        } else if (responseType === 'interactive' && threatQueue) {
          void threatQueue.enqueue(context);
        } else if (responseType === 'log') {
          renderLowConfidenceNote(context);
        } else {
          // Non-interactive mode with medium confidence: show as regular threat
          console.log('');
          console.log(`  ${symbols.warn} ${c.caution(`[${time}]`)} Threat detected`);
          console.log(`      Type: ${c.bold(category)}`);
          console.log(`      Source: ${c.sage(sourceIP)}`);
          console.log(`      Confidence: ${confidence}%`);
          console.log(`      Action: ${action}`);
          console.log('');
        }
      }
    });

    if (!process.env['PANGUARD_QUIET_GUARD']) {
      console.log(c.dim('  Press Ctrl+C to stop'));
      console.log('');
    }
  }
}

// ---------------------------------------------------------------------------
// AI setup guide — shown when no AI layers are configured
// AI 設定指南 — 當沒有配置 AI 層時顯示
// ---------------------------------------------------------------------------

/**
 * Show first-run welcome with onboarding guidance.
 * Only shown once — writes a marker file after display.
 */
async function showFirstRunWelcome(dashboardPort: number, atrRuleCount: number): Promise<void> {
  const { existsSync, writeFileSync, mkdirSync } = await import('node:fs');
  const markerPath = join(homedir(), '.panguard', '.guard-onboarded');

  if (existsSync(markerPath)) return;

  console.log('');
  console.log(divider());
  console.log('');
  console.log(`  ${c.sage(c.bold('Welcome to PanGuard AI Guard!'))}`);
  console.log('');
  console.log(`  Your agent security protection is now active.`);
  console.log('');
  console.log(`  ${c.bold('Dashboard:')}`);
  console.log(`    ${c.underline(`http://localhost:${dashboardPort}`)}`);
  console.log('');
  console.log(`  ${c.bold('Quick commands:')}`);
  console.log(`    ${c.sage('panguard-guard start')}    Start protection + dashboard`);
  console.log(`    ${c.sage('panguard-guard status')}   Check protection status`);
  console.log(`    ${c.sage('panguard-guard scan')}     Scan all installed skills`);
  console.log(`    ${c.sage('panguard-guard help')}     List all commands`);
  console.log('');
  console.log(
    `  ${c.dim('Tip: for the full experience (the')} ${c.sage('pga')} ${c.dim('command, interactive menu, audits),')}`
  );
  console.log(`  ${c.dim('install the CLI:')} ${c.sage('npm install -g panguard')}`);
  console.log('');
  console.log(`  ${c.bold('What Guard does:')}`);
  console.log(`    ${symbols.pass} Monitors new skill installations in real-time`);
  // Real loaded rule count, never a hardcoded "61+" — an at-launch snapshot
  // from the engine, so the banner tells the truth about what's enforcing.
  console.log(`    ${symbols.pass} Auto-audits skills with ${atrRuleCount} ATR threat rules`);
  console.log(`    ${symbols.pass} Blocks critical threats, alerts on suspicious ones`);
  console.log(`    ${symbols.pass} Syncs community threat intelligence via Threat Cloud`);
  console.log('');
  console.log(divider());
  console.log('');

  // Write marker so this only shows once
  try {
    const dir = join(homedir(), '.panguard');
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(markerPath, new Date().toISOString(), 'utf-8');
  } catch {
    // Non-critical — will just show again next time
  }
}

// ---------------------------------------------------------------------------

/** Stop the guard engine / 停止守護引擎 */
function commandStop(dataDir: string): void {
  const pidFile = new PidFile(dataDir);
  const pid = pidFile.read();

  if (!pid) {
    console.log(`  ${symbols.info} PanguardGuard is not running`);
    return;
  }

  if (!pidFile.isRunning()) {
    console.log(`  ${symbols.warn} Process not found, cleaning up PID file`);
    pidFile.remove();
    // The dead daemon never ran its graceful dashboard.stop(), so its launch
    // token may be orphaned on disk — remove it so it cannot outlive the daemon.
    removeDashboardToken();
    return;
  }

  try {
    process.kill(pid, 'SIGTERM');
    console.log(`  ${symbols.pass} PanguardGuard stopped ${c.dim(`(PID: ${pid})`)}`);
    // The daemon removes its own token in dashboard.stop() on SIGTERM, but that
    // is async; clean up here too so the secret is gone the moment stop returns.
    removeDashboardToken();
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  ${symbols.fail} Failed to stop: ${msg}`);
  }
}

/** Show engine status / 顯示引擎狀態 */
async function commandStatus(dataDir: string): Promise<void> {
  console.log(header());

  const { existsSync } = await import('node:fs');
  const pidFile = new PidFile(dataDir);
  const pid = pidFile.read();
  const running = pidFile.isRunning();

  // Finding #34: distinguish a persisted config from in-memory defaults. When no
  // config.json exists, loadConfig() returns hardcoded defaults (mode:protection,
  // etc.) — rendering those as if they were a saved, active config reads as
  // "protected" on a never-configured install. Trust config only when a real
  // config file exists — either the guard-specific one OR the master config
  // (~/.panguard/config.json) that loadConfig() also resolves from.
  const configExists =
    existsSync(join(dataDir, 'config.json')) ||
    existsSync(join(homedir(), '.panguard', 'config.json'));
  // A running daemon IS configured even if no config.json is on disk yet — the
  // standalone `panguard-guard start` flow runs on in-memory defaults without
  // writing the file. So "NOT CONFIGURED" applies ONLY to a never-started,
  // never-saved install; a live daemon must never be mislabeled that way.
  const notConfigured = !configExists && !running;
  let config: ReturnType<typeof loadConfig> | undefined;
  if (configExists || running) {
    try {
      config = loadConfig(join(dataDir, 'config.json'));
    } catch {
      config = undefined;
    }
  }

  // Finding #35: a running daemon in protection mode with zero loaded rules is
  // DEGRADED, not PROTECTED. `status` is the command a user re-runs later to
  // re-check posture, so it must reflect the same honest computeStartupStatus
  // rule the startup log uses — query the live daemon (fail-safe: undefined =
  // "unknown", never treated as healthy).
  let liveRules: Awaited<ReturnType<typeof queryLiveRuleCounts>>;
  if (running && config) {
    liveRules = await queryLiveRuleCounts(config.dashboardPort);
  }
  const degraded =
    running && config?.mode === 'protection' && liveRules !== undefined && liveRules.atr <= 0;

  const statusValue = notConfigured
    ? c.caution('NOT CONFIGURED')
    : !running
      ? c.critical('STOPPED')
      : degraded
        ? c.critical('DEGRADED (0 rules)')
        : c.safe('RUNNING');
  const statusState: 'safe' | 'caution' | 'critical' = notConfigured
    ? 'caution'
    : !running || degraded
      ? 'critical'
      : 'safe';

  const items: StatusItem[] = [
    { label: 'Status', value: statusValue, status: statusState },
    ...(pid ? [{ label: 'PID', value: c.sage(String(pid)) }] : []),
    { label: 'Data Dir', value: c.dim(dataDir) },
  ];

  if (running && liveRules !== undefined) {
    items.push({
      label: 'ATR Rules',
      value: liveRules.atr > 0 ? c.safe(String(liveRules.atr)) : c.critical('0 — detection OFF'),
      status: liveRules.atr > 0 ? ('safe' as const) : ('critical' as const),
    });
  }

  if (config) {
    items.push({ label: 'Mode', value: c.sage(config.mode) });
    items.push({
      label: 'Dashboard',
      value: config.dashboardEnabled
        ? c.underline(`http://localhost:${config.dashboardPort}`)
        : c.dim('disabled'),
    });
    items.push({
      label: 'License',
      value: config.licenseKey ? c.safe('configured') : c.caution('free tier'),
      status: config.licenseKey ? ('safe' as const) : ('caution' as const),
    });
  } else {
    items.push({
      label: 'Config',
      value: c.caution('not configured'),
      status: 'caution' as const,
    });
  }

  console.log(statusPanel('PANGUARD AI Security Status', items));

  if (notConfigured) {
    console.log(
      `  ${c.dim('Not configured yet.')} Run ${c.sage('panguard-guard start')} to set up and start protection.`
    );
  } else if (degraded) {
    console.log(
      `  ${c.critical(symbols.fail)} ${c.critical('DEGRADED')}: the daemon is running but 0 ATR rules are loaded — ` +
        `pattern detection is OFF. Restore the bundled rules with ${c.sage('pga upgrade')}.`
    );
  }
}

/**
 * Apply a single Threat Cloud consent answer to a config.
 *
 * The three participation flags move together on purpose. Upload without rule
 * sync gives a deployment the cost of contributing findings and none of the
 * benefit of receiving the rules those findings produce, and
 * `threatCloudRuleSyncEnabled` has no other code path that can turn it on —
 * `rule-loader.ts` bails out on `!== true`, so leaving it behind here strands
 * it at its default forever. This mirrors `askTelemetryConsent()` in the
 * panguard package, which derives the same three flags from one answer.
 *
 * Returns a new object; the input config is not mutated.
 */
export function applyThreatCloudConsent(config: GuardConfig, agreed: boolean): GuardConfig {
  return {
    ...config,
    telemetryEnabled: agreed,
    threatCloudUploadEnabled: agreed,
    threatCloudRuleSyncEnabled: agreed,
    threatCloudEndpoint: agreed
      ? (config.threatCloudEndpoint ?? 'https://tc.panguard.ai/api')
      : config.threatCloudEndpoint,
  };
}

/** Install as system service / 安裝為系統服務 */
async function commandInstall(dataDir: string): Promise<void> {
  const sp = spinner('Installing PanguardGuard as system service...');
  try {
    const execPath = process.argv[1] ?? join(homedir(), '.npm-global', 'bin', 'panguard-guard');
    // node + script as discrete argv parts: never whitespace-split, and robust
    // on Windows where the script has no shebang to self-execute.
    const result = await installService([process.execPath, execPath], dataDir);
    sp.succeed(`Service installed: ${c.sage(result)}`);
    // An explicit install/reinstall is a TRUST event: re-baseline the sealed
    // LaunchAgent ref to the plist installService just wrote. A legitimate reinstall
    // that changed the service path (e.g. npm install → curl prebuilt binary, or an
    // upgrade) otherwise leaves `checkSelfState` reporting "launchagent tampered"
    // forever — the daemon's re-seal deliberately refuses to launder a changed
    // LaunchAgent, and `pga up` can't clear it. Re-bless ONLY the LaunchAgent (which
    // we just legitimately wrote), never the hook/proxy refs, so a concurrent hijack
    // of those stays detected. Best-effort + only when a baseline already exists.
    try {
      const {
        wasInitialized,
        readSelfStateRefs,
        forgetSelfState,
        collectSelfState,
        sealConfigManifest,
      } = await import('../integrity.js');
      if (wasInitialized(dataDir)) {
        const keptNonLaunchAgent = forgetSelfState(readSelfStateRefs(dataDir), ['launchagent']);
        const currentLaunchAgent = collectSelfState().filter((r) => r.kind === 'launchagent');
        const rebased = [...keptNonLaunchAgent, ...currentLaunchAgent];
        const cfg = loadConfig(join(dataDir, 'config.json'));
        sealConfigManifest(cfg as unknown as Record<string, unknown>, rebased, dataDir);
      }
    } catch {
      /* re-baseline is best-effort — the service is already installed */
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    sp.fail(`Install failed: ${msg}`);
    console.error(c.dim('  You may need to run with elevated privileges (sudo/admin).'));
    return;
  }

  // ── Threat Cloud setup / 設定 Threat Cloud ──
  console.log('');
  const configPath = join(dataDir, 'config.json');
  const config = loadConfig(configPath);
  const uiLang = (config.lang === 'zh-TW' ? 'zh-TW' : 'en') as 'en' | 'zh-TW';

  const enableTC = await promptConfirm({
    message: {
      en: 'Enable Threat Cloud collective defense? (optional, off by default)',
      'zh-TW': '啟用 Threat Cloud 集體防禦？（選用，預設關閉）',
    },
    // Opt-in: default OFF so a bare Enter declines and nothing is shared.
    defaultValue: false,
    lang: uiLang,
  });

  const updated = applyThreatCloudConsent(config, enableTC);
  try {
    saveConfig(updated, configPath);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(c.dim(`  Warning: could not save config: ${msg}`));
    return;
  }

  if (enableTC) {
    console.log(
      `  ${symbols.pass} Threat Cloud enabled: ${c.sage(updated.threatCloudEndpoint ?? 'https://tc.panguard.ai/api')}`
    );
    console.log(c.dim('    Every scan strengthens the collective defense network.'));
    console.log(c.dim('    每次掃描都會強化集體防禦網路。'));
  } else {
    console.log(`  ${symbols.info} Threat Cloud disabled (offline mode).`);
    console.log(
      c.dim(
        '    You can enable it later: panguard-guard config --set threatCloudUploadEnabled=true'
      )
    );
    console.log(
      c.dim(
        '    Rule sync is a separate flag: panguard-guard config --set threatCloudRuleSyncEnabled=true'
      )
    );
  }
}

/** Uninstall system service / 解除安裝系統服務 */
async function commandUninstall(dataDir: string): Promise<void> {
  const sp = spinner('Uninstalling PanguardGuard service...');
  let removed = false;
  try {
    const result = await uninstallService();
    removed = true;
    sp.succeed(`Service uninstalled: ${c.sage(result)}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    sp.fail(`Uninstall failed: ${msg}`);
  }
  // Remove the persisted dashboard launch token so the secret never lingers
  // after the service is gone.
  removeDashboardToken();
  // A LEGITIMATE removal must rebuild trust: drop the LaunchAgent ref from the
  // sealed manifest and re-seal, or the next `guard start` warns forever and the
  // dashboard shows TAMPERED with no natural recovery (self-state never drops on
  // merge). Best-effort + only when the manifest was already sealed — never
  // create a seal here, and never let a re-seal failure mask the uninstall.
  if (removed) {
    try {
      const { wasInitialized, readSelfStateRefs, forgetSelfState, sealConfigManifest } =
        await import('../integrity.js');
      if (wasInitialized(dataDir)) {
        const kept = forgetSelfState(readSelfStateRefs(dataDir), ['launchagent']);
        const config = loadConfig(join(dataDir, 'config.json'));
        sealConfigManifest(config as unknown as Record<string, unknown>, kept, dataDir);
      }
    } catch {
      /* re-seal is best-effort — the service is already uninstalled */
    }
  }
}

/** Show current configuration / 顯示當前配置 */
function commandConfig(dataDir: string): void {
  console.log(header('Configuration'));
  try {
    const configPath = join(dataDir, 'config.json');
    const saved = existsSyncSafe(configPath);
    const config = loadConfig(configPath);
    if (!saved) {
      // No config.json at this --data-dir yet: loadConfig returned in-memory
      // defaults whose own dataDir field points at the DEFAULT dir, which would
      // contradict the --data-dir the user just passed. Reflect the requested
      // path and flag that these are unsaved defaults, not a persisted config.
      (config as { dataDir?: string }).dataDir = dataDir;
      console.log(`  ${c.caution('(unsaved defaults — no config.json at this data dir yet)')}\n`);
    }
    // Redact secret-bearing fields (ai.apiKey, threatCloudApiKey, license key,
    // notification botToken / webhook secret / smtp pass) before printing —
    // a plaintext config dump must never expose a stored secret to the terminal
    // or scrollback. Shared redactor — see ../redact.ts.
    console.log(JSON.stringify(redactSecrets(config), null, 2));
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  ${symbols.fail} Failed to load config: ${msg}`);
  }
}

/** Best-effort existsSync via the module's existing createRequire helper. */
function existsSyncSafe(p: string): boolean {
  try {
    return (_require('node:fs') as typeof import('node:fs')).existsSync(p);
  } catch {
    return false;
  }
}

/** Print help message / 列印幫助訊息 */
function printHelp(): void {
  console.log(banner(CLI_VERSION));

  console.log(`  ${c.bold('Usage:')} panguard-guard <command> [options]`);
  console.log('');
  console.log(divider('Commands'));
  console.log('');

  const commands = [
    { cmd: 'scan', desc: 'Scan all installed MCP skills for threats' },
    { cmd: 'start', desc: 'Start the guard engine' },
    { cmd: 'stop', desc: 'Stop the guard engine' },
    { cmd: 'status', desc: 'Show engine status' },
    { cmd: 'install', desc: 'Install as system service' },
    { cmd: 'uninstall', desc: 'Remove system service' },
    { cmd: 'config', desc: 'Show current configuration' },
    { cmd: 'help', desc: 'Show this help' },
  ];

  for (const { cmd, desc } of commands) {
    console.log(`  ${c.sage(cmd.padEnd(18))} ${desc}`);
  }

  console.log('');
  console.log(divider('Options'));
  console.log('');
  console.log(
    `  ${c.sage('--data-dir <path>'.padEnd(22))} Data directory ${c.dim('(default: ~/.panguard-guard)')}`
  );
  console.log(
    `  ${c.sage('--verbose'.padEnd(22))} Show all event logs ${c.dim('(default: quiet mode)')}`
  );
  console.log(`  ${c.sage('--manager <url>'.padEnd(22))} Manager URL for distributed mode`);
  console.log(`  ${c.sage('--no-telemetry'.padEnd(22))} Disable threat intelligence sharing`);
  console.log(`  ${c.sage('--show-upload-data'.padEnd(22))} Show anonymized data before upload`);
  console.log(
    `  ${c.sage('--dashboard'.padEnd(22))} Enable live TUI dashboard ${c.dim('(default: quiet mode)')}`
  );
  console.log(`  ${c.sage('--interactive'.padEnd(22))} Prompt for medium-confidence threats`);
  console.log(`  ${c.sage('--license-key <key>'.padEnd(22))} License key for install-script`);
  console.log('');
  console.log(c.dim(`  Version: ${CLI_VERSION}`));
  console.log('');
}

/** Extract and validate option value from args */
function extractOption(args: string[], option: string): string | undefined {
  const idx = args.indexOf(option);
  if (idx !== -1 && idx + 1 < args.length) {
    const value = args[idx + 1];
    if (value === undefined) return undefined;
    if (value.startsWith('-')) return undefined;
    if (option === '--data-dir') {
      // Reject path traversal, shell metacharacters, quotes, and any
      // control/newline character. Quotes and newlines are NOT sufficient to
      // trip the older `;&|\`$` check but can still close out the
      // double-quoted DATA_DIR="..." assignment in the generated install
      // script (see install/index.ts assertSafeDataDir) — reject them here
      // too so a bad value is caught at the CLI boundary, not just downstream.
      // eslint-disable-next-line no-control-regex -- rejecting control chars is the intent
      if (/\.\.[\\/]/.test(value) || /[;&|`$"']/.test(value) || /[\x00-\x1f\x7f]/.test(value)) {
        console.error(`  ${symbols.fail} Invalid ${option} value: unsafe characters`);
        return undefined;
      }
    }
    return value;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// CLI entry point (when run directly)
// CLI 進入點（直接執行時）
// ---------------------------------------------------------------------------

const isDirectRun =
  process.argv[1] &&
  (process.argv[1].endsWith('/panguard-guard') ||
    process.argv[1].includes('panguard-guard/dist/cli'));

if (isDirectRun) {
  runCLI(process.argv.slice(2)).catch((err) => {
    console.error('Error:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
