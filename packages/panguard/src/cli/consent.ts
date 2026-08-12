/**
 * Telemetry consent — first-run collective-defense disclosure.
 *
 * Collective-defense sharing is OPT-IN and defaults to OFF. On first interactive
 * run we explain BOTH the value (your blocked attacks become ATR rules that
 * protect everyone, and you get community rules back faster) and the privacy
 * guarantee (matched rule ID, a one-way payload hash, source type — never
 * prompts/code/file contents/keys, no IP, no hostname, a random install ID),
 * then ask the user to turn it ON; pressing Enter declines. This is an informed
 * invitation, not a nag or a pre-checked default. Raw samples are never sent.
 * Non-interactive (CI) stays OFF until explicitly enabled. Nothing leaves the
 * machine unless the user explicitly opts in (gates are `=== true`).
 */

import { existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';
import { c, symbols } from '@panguard-ai/core';
import { loadGuardConfig, updateGuardConfig } from './guard-config.js';

const GUARD_CONFIG_DIR = join(homedir(), '.panguard-guard');
const CONSENT_MARKER = join(GUARD_CONFIG_DIR, '.telemetry-prompted');

/** Check if consent has already been asked */
export function hasConsentBeenAsked(): boolean {
  return existsSync(CONSENT_MARKER);
}

/**
 * Mark consent as asked (regardless of answer). Exported so a command that owns
 * its own consent prompt (e.g. `pga setup`'s Threat Cloud question) can record
 * that the user has already been asked — preventing the trailing
 * `ensureTelemetryConsent()` from re-prompting and overwriting the first answer.
 */
export function markConsentAsked(): void {
  try {
    if (!existsSync(GUARD_CONFIG_DIR)) {
      mkdirSync(GUARD_CONFIG_DIR, { recursive: true });
    }
    writeFileSync(CONSENT_MARKER, new Date().toISOString(), 'utf-8');
  } catch {
    // If we can't write the marker, we'll ask again next time — not a blocker
  }
}

/**
 * Print the full what's-shared / never-shared Collective Defense disclosure.
 * Shared by the first-run consent prompt AND `pga config show --verbose` /
 * `pga tc --explain`, so a user who wants to re-read what they agreed to
 * (or are about to agree to) months later sees the exact same copy — not a
 * status-line summary that drops the privacy detail.
 *
 * The "END-TO-END ENCRYPT" line below is stated as unconditional fact
 * because it IS one: postThreats() (packages/panguard-guard/src/threat-cloud
 * /index.ts) throws and refuses to upload rather than falling back to
 * plaintext-over-TLS when sealing is unavailable, so whenever an upload
 * actually leaves the machine, it is always sealed. Never soften this back
 * to "when possible" without re-verifying that fail-closed invariant still
 * holds.
 */
export function printCollectiveDefenseDisclosure(): void {
  console.log('');
  console.log(
    `  ${symbols.info} ${c.bold('Join Collective Defense (your choice, reversible anytime)')}`
  );
  console.log('');
  console.log(
    `  ${c.dim('Why join: every rule-matched attack you see can become a community rule,')}`
  );
  console.log(
    `  ${c.dim('and you get every community rule back automatically. With the local AI')}`
  );
  console.log(`  ${c.dim('layer on (free — pga guard setup-ai), PanGuard ALSO reports UNKNOWN')}`);
  console.log(
    `  ${c.dim('suspicious behavior it can’t yet match to a rule — so novel attacks the')}`
  );
  console.log(`  ${c.dim('AI flags become new rules too. Reporting an unknown never blocks it.')}`);
  console.log('');
  console.log(`  ${c.bold('If you agree, PanGuard will:')}`);
  console.log(`  ${c.dim('  1. Connect to Threat Cloud and share minimal, ANONYMIZED threat')}`);
  console.log(
    `  ${c.dim('     signatures — the matched rule ID(s) (or “none” for unknown threats),')}`
  );
  console.log(
    `  ${c.dim('     attack category + MITRE technique, a coarse country region, and a')}`
  );
  console.log(`  ${c.dim('     truncated IP (last two octets zeroed).')}`);
  console.log(
    `  ${c.dim('  2. Anonymize it on your machine, then END-TO-END ENCRYPT it — sealed so')}`
  );
  console.log(
    `  ${c.dim('     only the Threat Cloud backend can read it, not the network or a relay.')}`
  );
  console.log(`  ${c.dim('  3. Auto-update your detection rules from the community.')}`);
  console.log('');
  console.log(
    `  ${c.dim('NEVER shared: your prompts, code, file contents, secrets, file paths,')}`
  );
  console.log(
    `  ${c.dim('hostname, or username. Raw samples are never sent. A stable random install')}`
  );
  console.log(`  ${c.dim('ID links your own submissions (pseudonymous, not fully anonymous).')}`);
  console.log('');
  console.log(`  ${c.dim('Turn off anytime: pga config set telemetry false (upload) /')}`);
  console.log(`  ${c.dim('pga config set threat-cloud false (rule sync).')}`);
  console.log('');
}

/**
 * Ask the user for telemetry consent (opt-in).
 * Returns true if the user opted in, false otherwise.
 *
 * In non-interactive mode (no TTY), defaults to OFF and marks as asked.
 */
export async function askTelemetryConsent(): Promise<boolean> {
  // Non-interactive (CI / headless): we cannot show the disclosure, so stay
  // fully OFF — set both flags explicitly false (not just unset) so the guard's
  // upload gate blocks. Opt in by setting the flags in config for headless use.
  if (!process.stdin.isTTY) {
    const config = loadGuardConfig();
    await updateGuardConfig({
      ...config,
      telemetryEnabled: false,
      threatCloudUploadEnabled: false,
      threatCloudRuleSyncEnabled: false,
    });
    markConsentAsked();
    return false;
  }

  printCollectiveDefenseDisclosure();

  // Opt-in: default is NO. Pressing Enter declines (default OFF).
  const answer = await promptYesNo('  Agree and join Collective Defense? [y/N] ', false);

  const config = loadGuardConfig();
  // A single "I agree" wires the whole loop: contribute (upload) AND receive
  // (rule sync). Declining leaves every flag off — nothing connects, nothing syncs.
  await updateGuardConfig({
    ...config,
    telemetryEnabled: answer,
    threatCloudUploadEnabled: answer,
    threatCloudRuleSyncEnabled: answer,
  });
  markConsentAsked();

  if (answer) {
    console.log(
      `  ${c.safe('Connected to Threat Cloud. Rules will auto-update; you are defending the commons.')}`
    );
  } else {
    console.log(`  ${c.dim('No problem. Nothing connects and nothing leaves your machine.')}`);
  }
  console.log('');

  return answer;
}

/**
 * Simple yes/no prompt. Empty input (Enter) returns `defaultYes`; otherwise true
 * only for y/yes. For opt-in consent pass `defaultYes = false` so a bare Enter
 * declines and nothing is shared.
 */
function promptYesNo(question: string, defaultYes = false): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      if (normalized === '') {
        resolve(defaultYes);
        return;
      }
      resolve(normalized === 'y' || normalized === 'yes');
    });
  });
}

/**
 * Non-interactive read: has the user explicitly opted in to Threat Cloud upload?
 *
 * Use this on one-off code paths (e.g. `pga scan <path>`) that must NEVER trigger
 * an outbound upload — or an interactive prompt — but still need to honour a prior
 * opt-in. Defaults to FALSE (no upload) when config is absent or unreadable, so the
 * privacy guarantee holds by default. Gate is `=== true`, matching the guard's
 * upload gate.
 */
export function isThreatCloudUploadEnabled(): boolean {
  try {
    return loadGuardConfig().threatCloudUploadEnabled === true;
  } catch {
    return false;
  }
}

/**
 * Check and ask for telemetry consent if not yet asked.
 * Call this at the start of scan/setup commands.
 * Returns the current telemetryEnabled value.
 */
export async function ensureTelemetryConsent(): Promise<boolean> {
  if (!hasConsentBeenAsked()) {
    return askTelemetryConsent();
  }
  // Already asked — return current setting
  const config = loadGuardConfig();
  return config.telemetryEnabled === true;
}
