#!/usr/bin/env node
/**
 * Panguard AI - Unified CLI
 * Panguard AI - 統一命令列介面
 *
 * Single entry point for all Panguard security tools.
 * 所有 Panguard 資安工具的統一入口。
 *
 * @module @panguard-ai/panguard/cli
 */

import * as Sentry from '@sentry/node';
import { Command } from 'commander';
import { PANGUARD_VERSION } from '../index.js';

// Sentry init — no-op when PANGUARD_SENTRY_DSN is unset so end-customers can
// opt out by leaving the env var empty. Separate from server-side SENTRY_DSN
// so the panguard.ai org can inject its own DSN at build time without
// affecting third-party CLI users.
if (process.env['PANGUARD_SENTRY_DSN']) {
  Sentry.init({
    dsn: process.env['PANGUARD_SENTRY_DSN'],
    tracesSampleRate: 0.1,
    release: PANGUARD_VERSION,
    environment: process.env['NODE_ENV'] ?? 'production',
  });
  Sentry.setTag('cli_version', PANGUARD_VERSION);
  Sentry.setTag('platform', process.platform);
}
import { scanCommand } from './commands/scan.js';
import { guardCommand } from './commands/guard.js';
// reportCommand is intentionally NOT imported/registered in the free CLI —
// the compliance report generator is an enterprise feature, hidden until the
// paid tier launches. See the addCommand site below.
// import { reportCommand } from './commands/report.js';
import { chatCommand } from './commands/chat.js';
import { trapCommand } from './commands/trap.js';
import { threatCommand } from './commands/threat.js';
import { demoCommand } from './commands/demo.js';
import { initCommand } from './commands/init.js';
import { deployCommand } from './commands/deploy.js';
import { statusCommand } from './commands/status.js';
import { sensorCommand } from './commands/sensor.js';
import { loginCommand } from './commands/login.js';
import { logoutCommand } from './commands/logout.js';
import { whoamiCommand } from './commands/whoami.js';
// Lazy-loaded: these depend on optional packages that may not be installed.
function lazyCommand(
  name: string,
  desc: string,
  modulePath: string,
  exportName: string
): () => Command {
  return () => {
    const cmd = new Command(name).description(desc);
    cmd.allowUnknownOption(true);
    cmd.action(async () => {
      try {
        const mod = await import(modulePath);
        const realCmd = mod[exportName]() as Command;
        await realCmd.parseAsync(process.argv);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  Error: ${msg}`);
        process.exitCode = 1;
      }
    });
    return cmd;
  };
}
const hardeningCommand = lazyCommand(
  'hardening',
  'Security hardening',
  './commands/hardening.js',
  'hardeningCommand'
);
// Enterprise-only: resolves @panguard/migrator from a private workspace or
// `pnpm link`. Community installs skip this command silently — the lazyCommand
// wrapper only attempts the dynamic import when migrate-pro is invoked.
const migrateProCommand = lazyCommand(
  'migrate-pro',
  'Convert Sigma/YARA detection rules to ATR YAML (Enterprise)',
  '@panguard/migrator/cli/migrate-pro',
  'migrateProCommand'
);
import { upgradeCommand } from './commands/upgrade.js';
import { configCommand } from './commands/config.js';
import { doctorCommand } from './commands/doctor.js';
import { hookCommand } from './commands/hook.js';
import { auditCommand } from './commands/audit.js';
import { skillsCommand } from './commands/skills.js';
import { hacktivityCommand } from './commands/hacktivity.js';
import { setupCommand } from './commands/setup.js';
import { reportCommand as reportSignCommand } from './commands/report-sign.js';
import { startInteractive } from './interactive.js';
import { upCommand } from './commands/up.js';

const program = new Command();

program
  .name('panguard')
  .description('Panguard AI - Security for AI Agents')
  .version(PANGUARD_VERSION);

const hidden = { hidden: true };

// ── The commands a normal user actually needs (shown in help) ──
//    `pga up` is the whole product in one line: scan → start protection → open
//    the dashboard. Everything else is reachable from the dashboard, so we keep
//    the default help tiny. Every hidden command below still works if you type it.
program.addCommand(upCommand()); // scan → protect → dashboard (the one command)
program.addCommand(scanCommand()); // scan a skill / path before you install it
program.addCommand(statusCommand()); // am I protected right now?
program.addCommand(doctorCommand()); // diagnose + fix problems
program.addCommand(upgradeCommand()); // update to the latest rules + engine

// ── Power-user / advanced — fully functional, hidden from the default help so
//    the surface stays small. `pga up` already does setup + hook install + guard.
program.addCommand(setupCommand(), hidden);
program.addCommand(auditCommand(), hidden);
program.addCommand(skillsCommand(), hidden);
program.addCommand(guardCommand(), hidden);
program.addCommand(sensorCommand(), hidden);
program.addCommand(loginCommand(), hidden);
program.addCommand(logoutCommand(), hidden);
program.addCommand(whoamiCommand(), hidden);
program.addCommand(chatCommand(), hidden);
program.addCommand(configCommand(), hidden);
program.addCommand(hookCommand(), hidden);
program.addCommand(trapCommand(), hidden);
// The enterprise-tier AI Compliance Audit Evidence GENERATOR is NOT in the
// free community CLI. (Re-enable behind a license gate when it returns.)
// Report SIGNING/VERIFICATION however is a public trust primitive — the
// /trust/signing-key page tells every auditor to run
// `pga report sign verify <report.json> --expect-key <key_id>`, so that
// command must exist in the free CLI (verification needs no license).
program.addCommand(reportSignCommand(), hidden);
program.addCommand(threatCommand(), hidden);
program.addCommand(demoCommand(), hidden);
program.addCommand(initCommand(), hidden);
program.addCommand(deployCommand(), hidden);
program.addCommand(hardeningCommand(), hidden);
program.addCommand(hacktivityCommand(), hidden);
program.addCommand(migrateProCommand(), hidden);

const userArgs = process.argv.slice(2);
// "-v" is treated as a version alias too: a single-letter flag must never fall
// through to the side-effectful first-run setup wizard (which writes config
// files). Commander only registers -V/--version, so we map -v to version output
// ourselves below.
const helpFlags = new Set(['-h', '--help', '-V', '--version', '-v']);
const hasSubcommand = userArgs.some((a) => !a.startsWith('-'));
const hasHelpOrVersion = userArgs.some((a) => helpFlags.has(a));
// The `hook` command is invoked by Claude Code per tool call and its stdout is
// parsed as JSON — it must emit NOTHING else (no update banner, no update check,
// no first-run wizard). Detect it early and stay silent + fast.
const isHookCommand = userArgs[0] === 'hook';

/**
 * Show "What's new" message once after upgrade.
 * Compares current version against ~/.panguard/.last-seen-version.
 * Only shown on interactive commands (no args, no --json).
 */
async function showWhatsNewIfUpgraded(): Promise<void> {
  const { existsSync, readFileSync, writeFileSync, mkdirSync } = await import('node:fs');
  const { join } = await import('node:path');

  const home = process.env['HOME'] ?? process.env['USERPROFILE'] ?? '.';
  const dir = join(home, '.panguard');
  const versionFile = join(dir, '.last-seen-version');

  // Read last seen version
  let lastSeen = '';
  try {
    if (existsSync(versionFile)) {
      lastSeen = readFileSync(versionFile, 'utf-8').trim();
    }
  } catch {
    // Non-critical
  }

  // Compare with current
  if (lastSeen === PANGUARD_VERSION) return;

  // Show what's new (only if upgrading, not first install)
  if (lastSeen !== '') {
    console.log(`\n  Panguard AI updated: ${lastSeen} \u2192 ${PANGUARD_VERSION}\n`);

    // Try to read CHANGELOG.md for current version's highlights
    try {
      const { fileURLToPath } = await import('node:url');
      const { dirname } = await import('node:path');
      const cliDir = dirname(fileURLToPath(import.meta.url));
      // CHANGELOG.md is at repo root, CLI is at packages/panguard/dist/cli/
      const changelogPaths = [
        join(cliDir, '..', '..', '..', '..', 'CHANGELOG.md'), // from dist
        join(cliDir, '..', '..', 'CHANGELOG.md'), // fallback
      ];
      let changelog = '';
      for (const p of changelogPaths) {
        if (existsSync(p)) {
          changelog = readFileSync(p, 'utf-8');
          break;
        }
      }
      if (changelog) {
        // Extract current version section
        const versionHeader = `## [${PANGUARD_VERSION}]`;
        const startIdx = changelog.indexOf(versionHeader);
        if (startIdx >= 0) {
          const afterHeader = changelog.indexOf('\n', startIdx) + 1;
          const nextVersion = changelog.indexOf('\n## [', afterHeader);
          const section = changelog.substring(
            afterHeader,
            nextVersion > 0 ? nextVersion : undefined
          );
          // Extract "### Added" and "### Fixed" bullet points (first 6 lines max)
          const bullets = section
            .split('\n')
            .filter((l: string) => l.startsWith('- **'))
            .slice(0, 6)
            .map((l: string) => {
              const match = l.match(/^- \*\*(.+?)\*\*\.?\s*(.*)$/);
              if (!match) return l;
              const title = (match[1] ?? '').replace(/\.$/, '');
              const desc = match[2] ?? '';
              return desc ? `  - ${title} -- ${desc}` : `  - ${title}`;
            });
          if (bullets.length > 0) {
            console.log("  What's new:");
            for (const b of bullets) {
              console.log(`  ${b}`);
            }
            console.log('');
          }
        }
      }
    } catch {
      // CHANGELOG read failed — show simple message
      console.log(`  Run "pg --help" to see new commands.\n`);
    }
  }

  // Write current version
  try {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(versionFile, PANGUARD_VERSION, 'utf-8');
  } catch {
    // Non-critical
  }
}

/**
 * Check npm for a newer version of Panguard CLI.
 * Non-blocking, max once per 24 hours, best-effort.
 */
async function checkForUpdates(): Promise<void> {
  const { existsSync, readFileSync, writeFileSync, mkdirSync } = await import('node:fs');
  const { join } = await import('node:path');

  const home = process.env['HOME'] ?? process.env['USERPROFILE'] ?? '.';
  const dir = join(home, '.panguard');
  const checkFile = join(dir, '.last-update-check');

  // Only check once per 24 hours
  try {
    if (existsSync(checkFile)) {
      const lastCheck = parseInt(readFileSync(checkFile, 'utf-8').trim(), 10);
      if (Date.now() - lastCheck < 24 * 60 * 60 * 1000) return;
    }
  } catch {
    // Non-critical
  }

  // Write timestamp immediately to avoid duplicate checks
  try {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(checkFile, String(Date.now()), 'utf-8');
  } catch {
    // Non-critical
  }

  try {
    const res = await fetch('https://registry.npmjs.org/@panguard-ai/panguard/latest', {
      signal: AbortSignal.timeout(3_000),
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return;
    const data = (await res.json()) as { version?: string };
    const latest = data.version;
    if (!latest || latest === PANGUARD_VERSION) return;

    // Simple semver comparison: split on dots, compare numerically
    const cur = PANGUARD_VERSION.split('.').map(Number);
    const lat = latest.split('.').map(Number);
    const isNewer =
      (lat[0] ?? 0) > (cur[0] ?? 0) ||
      ((lat[0] ?? 0) === (cur[0] ?? 0) && (lat[1] ?? 0) > (cur[1] ?? 0)) ||
      ((lat[0] ?? 0) === (cur[0] ?? 0) &&
        (lat[1] ?? 0) === (cur[1] ?? 0) &&
        (lat[2] ?? 0) > (cur[2] ?? 0));

    if (isNewer) {
      console.log(
        `\n  Update available: ${PANGUARD_VERSION} \u2192 ${latest}` + `\n  Run: pga upgrade\n`
      );
    }
  } catch {
    // Network failure — silently skip
  }
}

async function main(): Promise<void> {
  // "-v" version alias. Commander only registers -V/--version, so a bare `pga -v`
  // would otherwise reach program.parseAsync() as an unknown option (or, worse,
  // fall through to the first-run setup wizard which writes config). Handle it
  // here, printing the same bare version string as --version, then exit.
  if (userArgs.length === 1 && userArgs[0] === '-v') {
    console.log(PANGUARD_VERSION);
    return;
  }

  // Show "what's new" on interactive use (not --json, not --help, not the hook)
  const isJsonMode = userArgs.includes('--json');
  if (!hasHelpOrVersion && !isJsonMode && !isHookCommand) {
    await showWhatsNewIfUpgraded();
    // Non-blocking update check (fire and forget on non-JSON interactive use)
    void checkForUpdates();
  }

  if (!hasSubcommand && !hasHelpOrVersion && !isHookCommand) {
    // First-run detection uses the shared durable marker
    // (~/.panguard/.initialized), the SAME marker `pga up` and `pga setup`
    // write on first success. The old check looked at ~/.panguard/config.json,
    // a file that is never written (setup saves to ~/.panguard-guard/config.json),
    // so the setup wizard re-triggered on every bare `pga` even after setup.
    const { isFirstRun, markInitialized } = await import('./first-run.js');

    if (isFirstRun()) {
      // First time user — run setup wizard directly, then mark initialized so
      // subsequent bare `pga` goes straight to the interactive menu.
      console.log('\n  Welcome to PanGuard AI! / 歡迎使用 PanGuard AI!\n');
      // Be transparent about what first-run setup changes (it configures your
      // AI platforms + installs a background service) and how to undo it, so the
      // zero-config flow is informed rather than surprising.
      console.log('  First run: PanGuard will detect your AI agent platforms, add its MCP');
      console.log(
        '  config to each, and install a background Guard service (auto-starts on boot).'
      );
      console.log('  Undo anytime:  pga guard uninstall  ·  pga setup --remove\n');
      await program.parseAsync(['node', 'panguard', 'setup']);
      markInitialized();
      return;
    }

    // Extract --lang value if present
    const langIdx = userArgs.indexOf('--lang');
    const lang = langIdx >= 0 ? userArgs[langIdx + 1] : undefined;
    await startInteractive(lang);
  } else {
    await program.parseAsync();
  }
}

main().catch(async (err: unknown) => {
  console.error('Fatal error:', err instanceof Error ? err.message : err);
  if (process.env['PANGUARD_SENTRY_DSN']) {
    try {
      Sentry.captureException(err, {
        tags: { cli_version: PANGUARD_VERSION, platform: process.platform },
      });
      // Flush queued events before exit; 2s budget then drop.
      await Sentry.close(2000);
    } catch {
      // Sentry must never block exit on a CLI error path.
    }
  }
  process.exit(1);
});
