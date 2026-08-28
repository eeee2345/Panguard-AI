/**
 * rule-sync.ts - Threat Cloud synchronization extracted from GuardEngine
 *
 * Contains:
 * - syncThreatCloud() - periodic ATR/IP/domain/whitelist/blacklist sync
 * - getSkillThreatSubmitter() - bound callback for SkillWatcher
 * - getSkillBlacklistChecker() - bound callback for SkillWatcher
 * - setupCloudSyncTimer() - timer creation helper
 *
 * @module @panguard-ai/panguard-guard/rule-sync
 */

import { createHash } from 'node:crypto';
import { createLogger } from '@panguard-ai/core';
import type { ThreatIntelFeedManager } from '@panguard-ai/core';
import { isNewerVersion } from './auto-rules.js';
// Re-export so existing `@panguard-ai/panguard-guard` importers keep working;
// the lean copy lives in ./auto-rules for the hook's subpath import.
export { resolveStagedAutoRules } from './auto-rules.js';
export type { StagedAutoRules } from './auto-rules.js';
import type { GuardConfig } from './types.js';
import type { ThreatCloudClient } from './threat-cloud/index.js';
import type { GuardATREngine } from './engines/atr-engine.js';

const logger = createLogger('panguard-guard:rule-sync');

/** Track last sync time for incremental blacklist/whitelist fetching */
let lastBlacklistSync: string | undefined;
let lastWhitelistSync: string | undefined;
/** First sync always does full fetch, then switches to incremental */
let isFirstSync = true;

/**
 * Minimum community confidence before a blacklist entry may revoke a locally
 * whitelisted skill. Without a threshold, a single report (or a MITM /
 * compromised Threat Cloud relay injecting one fabricated entry) could revoke
 * protection for an arbitrary skill — turning the community feed into a
 * poisoning vector. Require corroboration: enough distinct reports AND a
 * meaningful average risk score.
 */
const BLACKLIST_MIN_REPORT_COUNT = 5;
const BLACKLIST_MIN_AVG_RISK_SCORE = 50;

/** Dependencies needed for cloud sync operations */
export interface CloudSyncDeps {
  readonly atrEngine: GuardATREngine;
  readonly threatCloud: ThreatCloudClient;
  readonly feedManager: ThreatIntelFeedManager;
  readonly config: GuardConfig;
}

/**
 * Periodic Threat Cloud sync: re-fetch rules and blocklist.
 * Syncs ATR rules; IP and domain blocklists;
 * skill whitelist and blacklist.
 */
export async function syncThreatCloud(deps: CloudSyncDeps): Promise<void> {
  const { atrEngine, threatCloud, feedManager, config } = deps;

  // Outbound collective-defense sharing is opt-in: it is allowed ONLY when the
  // user has explicitly enabled it. Absent/unset config is treated as OFF (the
  // gate is `=== true`, never `!== false`). This governs every OUTBOUND post in
  // this function; the INBOUND indicator pulls below run regardless because they
  // download community blocklists/lists and never reveal anything about this host.
  const sharingOptedIn = config.threatCloudUploadEnabled === true;

  try {
    // NOTE: Detection RULES are intentionally NOT pulled from Threat Cloud here.
    // Live-applying arbitrary rule content from a network relay into the engine
    // is a supply-chain attack surface — a compromised or MITM'd relay could push
    // ReDoS patterns or auto-blocking rules to every client every few minutes with
    // no review. Rules ship bundled with the npm package (integrity-verified,
    // immutable, publicly auditable) and change only via `pga upgrade`; a daily
    // npm version check (checkForRuleUpdates) NOTIFIES when a newer published
    // ruleset is available. The feeds below are threat INDICATORS (IP/domain
    // blocklists, community skill lists), not executable detection logic.

    // Refresh IP blocklist
    const ips = await threatCloud.fetchBlocklist();
    const addedIPs =
      ips.length > 0 ? feedManager.addExternalIPs(ips, 'threat_cloud_blocklist', 85) : 0;

    // Refresh domain blocklist
    let addedDomains = 0;
    try {
      const domains = await threatCloud.fetchDomainBlocklist();
      addedDomains =
        domains.length > 0
          ? feedManager.addExternalDomains(domains, 'threat_cloud_blocklist', 85)
          : 0;
    } catch (err: unknown) {
      logger.warn(
        `Domain blocklist sync failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // Report locally whitelisted skills to Threat Cloud (batch) — OUTBOUND
    // collective-defense sharing, so only when the user has opted in.
    if (sharingOptedIn) {
      try {
        const localSkills = atrEngine
          .getWhitelistManager()
          .getAll()
          .filter((s) => s.source === 'fingerprint' || s.source === 'manual');
        if (localSkills.length > 0) {
          await threatCloud.reportSafeSkillsBatch(
            localSkills.map((s) => ({ skillName: s.name, fingerprintHash: s.fingerprintHash }))
          );
        }
      } catch (err: unknown) {
        logger.warn(
          `Skill whitelist upload failed: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Sync community skill whitelist (incremental after first sync)
    let importedSkills = 0;
    try {
      const since = isFirstSync ? undefined : lastWhitelistSync;
      const communitySkills = await threatCloud.fetchSkillWhitelist(since);
      if (communitySkills.length > 0) {
        importedSkills = atrEngine
          .getWhitelistManager()
          .importCommunityWhitelist(communitySkills.map((s) => ({ name: s.name, hash: s.hash })));
      }
      lastWhitelistSync = new Date().toISOString();
    } catch (err: unknown) {
      logger.warn(
        `Skill whitelist sync failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // Sync community skill blacklist (incremental after first sync)
    let revokedSkills = 0;
    try {
      const since = isFirstSync ? undefined : lastBlacklistSync;
      const blacklist = await threatCloud.fetchSkillBlacklist(since);
      const whitelistMgr = atrEngine.getWhitelistManager();
      let skippedLowConfidence = 0;
      for (const entry of blacklist) {
        // Poisoning guard: only revoke when the community signal is corroborated.
        if (
          entry.reportCount < BLACKLIST_MIN_REPORT_COUNT ||
          entry.avgRiskScore < BLACKLIST_MIN_AVG_RISK_SCORE
        ) {
          skippedLowConfidence++;
          continue;
        }
        const wasRevoked = whitelistMgr.revoke(
          entry.skillName,
          `community-blacklist: ${entry.reportCount} reports, avg risk ${entry.avgRiskScore}`
        );
        if (wasRevoked) revokedSkills++;
      }
      if (skippedLowConfidence > 0) {
        logger.info(
          `Community blacklist: ${skippedLowConfidence} entr(ies) skipped below revoke threshold ` +
            `(>=${BLACKLIST_MIN_REPORT_COUNT} reports & >=${BLACKLIST_MIN_AVG_RISK_SCORE} avg risk required)`
        );
      }
      if (revokedSkills > 0) {
        logger.warn(`Community blacklist: ${revokedSkills} skill(s) revoked`);
      }
      lastBlacklistSync = new Date().toISOString();
    } catch (err: unknown) {
      logger.warn(
        `Skill blacklist sync failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // After first full sync, switch to incremental
    isFirstSync = false;

    // NOTE: There is intentionally NO periodic device heartbeat / phone-home.
    // A privacy-respecting tool must not beacon hostname (or any device identity)
    // to the cloud on a timer. The ONLY outbound Threat Cloud traffic is the
    // event-driven, anonymized threat upload that fires when a real threat is
    // caught (see event-processor.reportAndNotify), plus the opt-in skill
    // whitelist batch above — both gated on explicit consent. Everything in this
    // sync is otherwise an INBOUND pull of community indicators.

    logger.info(
      `Threat Cloud indicator sync: ${addedIPs} IPs, ${addedDomains} domains, ` +
        `${importedSkills} whitelist, ${revokedSkills} blacklist`
    );
  } catch (err: unknown) {
    logger.warn(`Threat Cloud sync failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Create a cloud sync interval timer that calls syncThreatCloud every 5 minutes.
 * Returns the timer handle (caller is responsible for clearing it).
 */
export function setupCloudSyncTimer(deps: CloudSyncDeps): ReturnType<typeof setInterval> {
  return setInterval(
    () => {
      void syncThreatCloud(deps);
    },
    5 * 60 * 1000
  ); // 5 minutes — fast enough for near-realtime protection
}

/**
 * Get a skill threat submitter function for SkillWatcher integration.
 * Returns a bound callback that submits to Threat Cloud.
 */
export function getSkillThreatSubmitter(
  threatCloud: ThreatCloudClient
): (submission: {
  skillHash: string;
  skillName: string;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  findingSummaries?: Array<{ id: string; category: string; severity: string; title: string }>;
}) => Promise<boolean> {
  return (submission) => threatCloud.submitSkillThreat(submission);
}

/**
 * Get an ATR proposal submitter function for SkillWatcher flywheel integration.
 * Bridges skill audit findings into the ATR rule generation pipeline.
 */
export function getATRProposalSubmitter(
  threatCloud: ThreatCloudClient
): (proposal: {
  patternHash: string;
  ruleContent: string;
  llmProvider: string;
  llmModel: string;
  selfReviewVerdict: string;
}) => Promise<boolean> {
  return (proposal) => threatCloud.submitATRProposal(proposal);
}

/**
 * Get a skill blacklist checker function for SkillWatcher integration.
 * Checks if a skill name appears in the community blacklist from Threat Cloud.
 * Uses a 5-minute in-memory cache to avoid hitting TC on every check.
 */
export function getSkillBlacklistChecker(
  threatCloud: ThreatCloudClient
): (skillName: string) => Promise<boolean> {
  const BLACKLIST_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  let cachedBlacklist: Array<{ skillName: string }> = [];
  let cacheTimestamp = 0;

  return async (skillName: string): Promise<boolean> => {
    if (Date.now() - cacheTimestamp > BLACKLIST_CACHE_TTL) {
      cachedBlacklist = await threatCloud.fetchSkillBlacklist();
      cacheTimestamp = Date.now();
    }
    const normalized = skillName.toLowerCase().trim().replace(/\s+/g, '-');
    return cachedBlacklist.some(
      (entry) => entry.skillName.toLowerCase().trim().replace(/\s+/g, '-') === normalized
    );
  };
}

/** Read the bundled agent-threat-rules version (filesystem walk-up, immune to
 * the package's ESM `exports` map which blocks require.resolve of package.json). */
async function readBundledAtrVersion(): Promise<string | null> {
  try {
    const { fileURLToPath } = await import('node:url');
    const { dirname, join } = await import('node:path');
    const { existsSync, readFileSync } = await import('node:fs');
    let dir = dirname(fileURLToPath(import.meta.url));
    for (let i = 0; i < 12; i++) {
      const pkgPath = join(dir, 'node_modules', 'agent-threat-rules', 'package.json');
      if (existsSync(pkgPath)) {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version?: string };
        return pkg.version ?? null;
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return null;
  } catch {
    return null;
  }
}

export interface RuleUpdateStatus {
  readonly updateAvailable: boolean;
  readonly currentVersion: string | null;
  readonly latestVersion: string | null;
  readonly checkedAt: string;
}

/**
 * Daily rule-update CHECK — notify-only. Queries the public npm registry for the
 * latest published agent-threat-rules version and compares it to the version
 * bundled with this install. It does NOT download or apply anything: detection
 * rules are the engine's trust root and change only via an explicit,
 * npm-integrity-verified `pga upgrade`. The result is logged and written to
 * <dataDir>/rule-update.json so the dashboard and CLI can surface it.
 */
export async function checkForRuleUpdates(deps: CloudSyncDeps): Promise<RuleUpdateStatus> {
  const checkedAt = new Date().toISOString();
  const currentVersion = await readBundledAtrVersion();
  let latestVersion: string | null = null;
  try {
    const res = await fetch('https://registry.npmjs.org/agent-threat-rules/latest', {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const body = (await res.json()) as { version?: string };
      latestVersion = body.version ?? null;
    }
  } catch (err: unknown) {
    logger.warn(`Rule update check failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  const updateAvailable =
    !!currentVersion && !!latestVersion && isNewerVersion(latestVersion, currentVersion);

  if (updateAvailable) {
    logger.info(
      `New detection rules available: agent-threat-rules ${currentVersion} -> ${latestVersion}. ` +
        `Run "pga upgrade" to update — rules are verified by npm and never auto-applied.`
    );
  }

  // Persist for the dashboard / CLI to surface (best-effort, owner-only perms).
  try {
    const { writeFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const status: RuleUpdateStatus = { updateAvailable, currentVersion, latestVersion, checkedAt };
    writeFileSync(join(deps.config.dataDir, 'rule-update.json'), JSON.stringify(status, null, 2), {
      mode: 0o600,
    });
  } catch {
    /* best-effort surface; the log line above is the primary signal */
  }

  return { updateAvailable, currentVersion, latestVersion, checkedAt };
}

/**
 * Verify a downloaded tarball against an npm SRI integrity string
 * ("sha512-<base64>", possibly space-separated alternatives). Returns true only
 * when a supported-algorithm digest of `buf` matches. This is the TRUST ANCHOR
 * for auto-update: a byte that does not hash to the registry-published value
 * means tamper/MITM, and the bundle MUST be discarded. Hash comparison is over
 * public values, so a plain === is correct.
 */
export function verifyTarballIntegrity(buf: Buffer, integrity: string): boolean {
  for (const entry of integrity.trim().split(/\s+/)) {
    const dash = entry.indexOf('-');
    if (dash < 0) continue;
    const algo = entry.slice(0, dash);
    const expected = entry.slice(dash + 1);
    if (algo !== 'sha512' && algo !== 'sha384' && algo !== 'sha256') continue;
    if (createHash(algo).update(buf).digest('base64') === expected) return true;
  }
  return false;
}

/**
 * Gap A (slice 1): download the latest agent-threat-rules bundle from npm,
 * VERIFY its integrity, and stage the rules on disk. Runs only when
 * config.autoUpdateRules === true. Returns the staged rules dir, or null (never
 * throws into the daemon).
 *
 * SECURITY: the npm SRI check is the trust anchor — a tarball whose hash does
 * not match the registry-published dist.integrity is DISCARDED (never extracted,
 * never loaded). The tarball must come from registry.npmjs.org.
 *
 * SCOPE: this fetches + verifies + stages ONLY. Staged rules are DETECT-only and
 * are NOT wired into the enforce path here — arming is gated behind an explicit
 * user trust step. See docs/design/gap-a-auto-rule-update.md.
 */
export async function pullRuleUpdate(deps: CloudSyncDeps): Promise<string | null> {
  if (deps.config.autoUpdateRules !== true) return null;
  const status = await checkForRuleUpdates(deps);
  if (!status.updateAvailable || !status.latestVersion) return null;
  const version = status.latestVersion;
  try {
    const metaRes = await fetch(
      `https://registry.npmjs.org/agent-threat-rules/${encodeURIComponent(version)}`,
      { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15_000) }
    );
    if (!metaRes.ok) return null;
    const meta = (await metaRes.json()) as {
      dist?: { tarball?: string; integrity?: string };
    };
    const tarball = meta.dist?.tarball;
    const integrity = meta.dist?.integrity;
    if (!tarball || !integrity) {
      logger.warn('Rule auto-update: registry metadata missing tarball/integrity — refusing.');
      return null;
    }
    // Never follow the tarball URL off the official registry host.
    if (new URL(tarball).host !== 'registry.npmjs.org') {
      logger.warn(`Rule auto-update: tarball host is not registry.npmjs.org — refusing.`);
      return null;
    }
    const tarRes = await fetch(tarball, { signal: AbortSignal.timeout(30_000) });
    if (!tarRes.ok) return null;
    const buf = Buffer.from(await tarRes.arrayBuffer());
    if (!verifyTarballIntegrity(buf, integrity)) {
      logger.error(
        'Rule auto-update: INTEGRITY MISMATCH — tarball discarded, nothing loaded (possible tamper/MITM).'
      );
      return null;
    }
    const { mkdirSync, writeFileSync, rmSync, existsSync, cpSync } = await import('node:fs');
    const { join } = await import('node:path');
    const { execFileSync } = await import('node:child_process');
    const { tmpdir } = await import('node:os');
    const dest = join(deps.config.dataDir, 'auto-rules', version);
    if (existsSync(dest)) return dest; // already staged this version
    const work = join(tmpdir(), `pg-atr-${version}-${process.pid}`);
    mkdirSync(work, { recursive: true, mode: 0o700 });
    try {
      const tgz = join(work, 'bundle.tgz');
      writeFileSync(tgz, buf, { mode: 0o600 });
      // Extract ONLY package/rules from the verified archive.
      execFileSync('tar', ['-xzf', tgz, '-C', work, 'package/rules'], {
        timeout: 30_000,
        windowsHide: true,
      });
      const extracted = join(work, 'package', 'rules');
      if (!existsSync(extracted)) return null;
      mkdirSync(join(deps.config.dataDir, 'auto-rules'), { recursive: true, mode: 0o700 });
      cpSync(extracted, dest, { recursive: true });
      logger.info(
        `Rule auto-update: staged agent-threat-rules@${version} (integrity-verified) — detect-only until trusted.`
      );
      return dest;
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  } catch (err: unknown) {
    logger.warn(
      `Rule auto-update pull failed: ${err instanceof Error ? err.message : String(err)}`
    );
    return null;
  }
}

/**
 * Create a DAILY rule-update-check timer (notify-only). Rules are not a
 * real-time feed; the integrity-checked npm registry is the source of truth, so
 * checking once a day is both sufficient and far smaller an attack surface than
 * a high-frequency live pull. Returns the timer handle (caller clears it).
 */
export function setupRuleUpdateCheckTimer(deps: CloudSyncDeps): ReturnType<typeof setInterval> {
  const tick = async (): Promise<void> => {
    await checkForRuleUpdates(deps);
    // Gap A (opt-in): when auto-update is on, also pull + integrity-verify + stage
    // the latest bundle so a fresh, verified copy is always on disk. Staging is
    // DETECT-only foundation — nothing is armed to BLOCK here.
    if (deps.config.autoUpdateRules === true) await pullRuleUpdate(deps);
  };
  return setInterval(
    () => {
      void tick();
    },
    24 * 60 * 60 * 1000
  );
}
