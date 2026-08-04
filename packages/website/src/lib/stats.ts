/**
 * Single source of truth for all marketing statistics.
 *
 * Usage: Import STATS directly in components. RuleStatsContext wraps STATS
 * with live API data from /api/threat-intel/stats (rule counts only).
 * Ecosystem stats are static until P2 TC API integration.
 *
 * When adding new stats: update here first, then all components auto-update.
 *
 * Derived from (verified 2026-03-12):
 *   packages/panguard-guard/src/types.ts       -> ResponseAction union (11 types)
 *   packages/core/src/ai/funnel-router.ts      -> 3 layers
 *   vitest run (159 test files)                -> 3,528 test cases
 *   packages/panguard/src/cli/index.ts         -> 23 top-level commands
 *   packages/panguard-mcp/src/server.ts        -> 10 MCP tools shown on /product/mcp
 *   packages/panguard-skill-auditor/src/checks/ -> 8 audit checks
 *   agent-threat-rules/rules/                  -> 747 ATR rules (npm v3.5.8). The web-scanner bundle atr-rules-compiled.json ships the 650 production rules (draft/deprecated excluded, mirroring the runtime engine). Re-sync with the three-command flow above when bumping ATR.
 *   packages/panguard-guard/src/playbook/      -> 3 playbook templates
 *   packages/panguard-guard/src/collectors/     -> 4 log parsers
 *
 * When rules are added/removed, update the numbers here and the entire
 * site picks them up automatically.
 */
export const STATS = {
  /** Must match packages/panguard/package.json "version" */
  cliVersion: '1.8.26',
  /**
   * Synced from agent-threat-rules by: pnpm update agent-threat-rules ->
   * node scripts/compile-atr-rules.mjs -> node scripts/apply-atr-stats.mjs.
   * atrRules/totalRules below is the full ATR corpus (747). The web-scanner
   * bundle (src/lib/atr-rules-compiled.json) ships the 650 production rules
   * only — draft/deprecated are excluded to mirror the runtime engine.
   */
  atrVersion: '3.5.11',
  /**
   * Full ATR corpus (agent-threat-rules v3.5.8 on npm = 747 YAML rules) —
   * auditable by `npm i agent-threat-rules@3.5.8 && find rules -name '*.yaml' | wc -l`.
   * The online scanner runs the 650 production subset (see atr-rules-compiled.json).
   */
  atrRules: 768,
  /** Total detection patterns across the full ATR corpus (747 rules, v3.5.8). */
  atrPatterns: 3_200,
  totalRules: 768,
  /** Use this for all user-facing display — avoids stale hardcoded counts. */
  totalRulesDisplay: '768' as const,
  /** Separate display for honest breakdown */
  atrRulesDisplay: '768' as const,
  /** Promotion interval in Threat Cloud */
  promotionIntervalMinutes: 2,
  testsPassing: 3_528,
  testFiles: 159,
  detectionLayers: 3,
  responseActions: 11,
  cliCommands: 23,
  products: 6,
  aiAgents: 4,
  mcpTools: 10,
  playbookTemplates: 3,
  logParsers: 4,
  license: 'MIT' as const,
  skillAuditChecks: 8,
  atrDraftRules: 17,
  /**
   * OWASP Agentic Top 10 coverage (from agent-threat-rules/docs/OWASP-MAPPING.md)
   * Sync when rules are added/removed.
   */
  owaspAgentic: {
    totalCategories: 10,
    coveredCategories: 10,
    totalMappings: 866,
    categories: [
      { id: 'ASI01', rules: 445, strength: 'STRONG' as const },
      { id: 'ASI02', rules: 32, strength: 'STRONG' as const },
      { id: 'ASI03', rules: 107, strength: 'STRONG' as const },
      { id: 'ASI04', rules: 71, strength: 'STRONG' as const },
      { id: 'ASI05', rules: 65, strength: 'STRONG' as const },
      { id: 'ASI06', rules: 54, strength: 'STRONG' as const },
      { id: 'ASI07', rules: 21, strength: 'STRONG' as const },
      { id: 'ASI08', rules: 48, strength: 'STRONG' as const },
      { id: 'ASI09', rules: 16, strength: 'STRONG' as const },
      { id: 'ASI10', rules: 7, strength: 'MODERATE' as const },
    ],
  },
  /** Per-category breakdown — counted from the full agent-threat-rules v3.5.8 corpus (747 rules). */
  rulesByCategory: {
    'prompt-injection': 246,
    'context-exfiltration': 119,
    'agent-manipulation': 108,
    'tool-poisoning': 97,
    'privilege-escalation': 51,
    'skill-compromise': 45,
    'model-abuse': 38,
    'excessive-autonomy': 33,
    'data-poisoning': 7,
    'model-security': 3,
  },
  /** Compliance frameworks ATR maps to (per-rule metadata) — matches complianceFrameworkList length. */
  complianceFrameworks: 7,
  complianceFrameworkList: [
    'OWASP Agentic Top 10:2026',
    'OWASP LLM Top 10:2025',
    'MITRE ATLAS',
    'NIST AI RMF',
    'EU AI Act',
    'ISO/IEC 42001',
    'SAFE-MCP',
  ],
  /** Rule source corpora integrated in v2.2.0 sprint */
  ruleSourceCorpora: [
    'NVIDIA garak (3,475 prompts)',
    'HackAPrompt EMNLP 2023 (4,780 samples)',
    'NeMo-Guardrails vendor suite',
    'llm-guard vendor suite',
    'Promptfoo vendor suite',
    'PromptInject NeurIPS 2022',
    'OWASP LLM Top 10 + MITRE ATLAS PoCs',
    'CISA KEV catalog',
    'Spring AI CVE disclosures',
  ],
  /** Threat Intel Pipeline stats (auto-updated by CI every hour) */
  threatIntel: {
    sources: 11,
    activeSources: 10,
    validatedRecords: 5_146,
    autoGeneratedATR: 0,
    promotedRules: 808,
    draftRules: 536,
    lastSync: '2026-03-27',
    syncInterval: '1h',
  },
  /**
   * Ecosystem scanning stats (from crawl-mcp-registry + audit-npm-skills-v2 pipeline)
   *
   * Pipeline: crawl-mcp-registry.ts → audit-npm-skills-v2.ts → push-to-threat-cloud.ts
   * Source: npm registry, GitHub API, awesome-lists (8 queries, pagination)
   * Updated: 2026-03-16
   */
  ecosystem: {
    /** Total MCP/AI skill entries crawled from registries (ClawHub 37,394 + OpenClaw 50,283 + Skills.sh 3,115) */
    entriesCrawled: 90_792,
    /** npm packages found in crawl */
    npmPackages: 2_769,
    /** Skills actually scanned — TC live data is authoritative; fallback synced 2026-04-16 */
    skillsScanned: 67_799,
    /** Total MCP tool definitions extracted from scanned packages */
    toolsExtracted: 35_858,
    /** Packages with security findings (any severity) */
    packagesWithFindings: 2_322,
    /** Threats detected (confirmed + suspicious) — synced from TC 2026-04-16 */
    maliciousFound: 11_324,
    /** ATR rule candidates from scan findings */
    atrRulesGenerated: 225,
    /** Total ATR rule matches across all packages */
    atrRuleMatches: 3_361,
    /** Top ATR rule: ATR-2026-099 hit count */
    topAtrRuleHits: 1_515,
    /** Triple threat packages (shell + network + filesystem access) */
    tripleThreat: 249,
    /** Packages with postinstall scripts */
    postinstallScripts: 122,
    /** Breakdown by severity */
    findingsCritical: 182,
    findingsHigh: 1_124,
    findingsMedium: 1_016,
    findingsLow: 7_354,
    findingsClean: 26_718,
    /** Skills verified safe by community + TC (live from /api/metrics) */
    whitelistedSkills: 8_066,
    /** Skills confirmed malicious and blocked (live from /api/metrics) */
    blacklistedSkills: 1_096,
    /** Total skill threat reports submitted to TC */
    skillThreatsTotal: 21_669,
    registrySources: 3,
    lastCrawl: '2026-04-16',
  },
  /**
   * Benchmark results — verified against 資安/state/facts.json 2026-07-04.
   * All numbers are corpus-level Layer 1 (deterministic rules) measurements;
   * ALWAYS display with corpus + version context, never as engine-wide claims.
   *
   * PINT: self-built 850-sample PINT-format corpus (deepset prompt-injections +
   *   Lakera Gandalf); NOT Lakera's official private PINT benchmark.
   * SKILL.md: real-world skill corpus (498 samples from ClawHub + OpenClaw + Skills.sh)
   * Garak: NVIDIA in-the-wild jailbreak corpus (650 samples)
   * HackAPrompt: EMNLP 2023 competition corpus (4,780 deterministic samples)
   */
  // All recall/precision/fp values are PERCENTAGES (0-100) for a single
  // consistent unit across the site — call sites render `${value}%` directly.
  benchmark: {
    pint: { recall: 60.31, precision: 100, fp: 0, samples: 850 },
    skill: { recall: 100, precision: 97, fp: 0.2, samples: 498 },
    garak: {
      recall: 97.2,
      samples: 650,
      perFamily: { latentinjection: 34.4, sysprompt_extraction: 67.9, dan: 90.2 },
    },
    hackaprompt: { recall: 69.6, precision: 100, samples: 4_780, baselineRecall: 28.6 },
    /**
     * Lane-based false-positive rates on the 65K-sample benign gate (v3.5.0
     * detection lanes). There is NO single engine-wide FP number — enforce lane
     * (stable + confirm-gated rules) and hunt lane (all rules, the default)
     * behave differently by design. Cite the lane, never a blended figure.
     */
    benignLanes: {
      enforceFp: 0.24,
      huntFp: 9,
      samples: 65_000,
      defaultLane: 'hunt' as const,
    },
    asOf: '2026-07-04',
  },
  /**
   * 2026-04 wild scan of published agent skills.
   *
   * CALIBER DISCIPLINE — these numbers have DIFFERENT denominators and must never
   * be mixed. The scan report's own per-registry table is the arithmetic proof:
   *
   *   OpenClaw          56,480 scanned →   751 flagged  (1.33%)
   *   Other sources (4) 39,616 scanned →   551 flagged  (1.39%)
   *   Total             96,096 scanned → 1,302 flagged  (1.35%)
   *
   * So 751 is the OpenClaw-ONLY flag count, and it is a FLAG count, not a
   * confirmed-malware count. Pairing "751" with "96,096" — as the site and the
   * launch copy did until 2026-07-19 — overstates by using one registry's
   * numerator against every registry's denominator, and calls a flag a
   * confirmation. `confirmedMalware` (552) is the post-manual-review figure and
   * is the only one that belongs next to `skillsScanned`.
   *
   * KNOWN GAP: the curation from raw flags to these published counts
   * (1,434 → 1,302; OpenClaw 1,376 → 751) has no recorded methodology. If asked
   * how the filter worked, say it was not written down at the time — do not
   * reconstruct a rationale.
   */
  wildScan: {
    skillsScanned: 96_096,
    registries: 4,
    flagged: 1_302,
    confirmedMalware: 552,
    threatActors: 3,
    /** Worst single registry, on its OWN denominator. Never pair with skillsScanned. */
    openClaw: { scanned: 56_480, flagged: 751 },
    asOf: '2026-04-16',
  },
  /** Standards coverage */
  coverage: {
    owaspAgentic: '10/10',
    safeMcp: 91.8,
    safeMcpDetail: '78/85',
  },
  /** Ecosystem adoption — evidence-tiered per deck v11 (2026-07-02); every merge links to its PR */
  adoption: {
    /** Cisco AI Defense skill-scanner: 314-rule ATR pack merged (deck v11 canonical figure) */
    ciscoRulesMerged: 314,
    /** Microsoft AGT: PR #908 (15 rules) → PR #1277 expanded to 287 rules + weekly auto-sync workflow auto-pulls v2.2.0 */
    microsoftRulesMerged: 287,
    /** Microsoft Copilot SWE Agent → AGT#1981 (5/11 06:07 UTC) regression-test fixtures presuming ATR detection */
    microsoftCopilotLoopIssue: 1981,
    /** 13 external PR merges across 6 external orgs */
    externalPRMerges: 13,
    externalOrgs: 6,
    /**
     * Monthly downloads summed across @panguard-ai/* npm scope + agent-threat-rules
     * + pyatr (PyPI). Manually re-fetched 2026-05-26 from npmjs.org + pypistats.org;
     * not auto-synced from stats.json (that file does not track this number today).
     * TODO: wire scripts/sync-npm-downloads.ts to refresh this monthly.
     */
    npmDownloads30d: 10_046,
    /** Tier-1 institutions with active engagement: Microsoft, Cisco, Gen Digital (Sage), MISP, OWASP, NVIDIA, IBM */
    /** Tier-1 in conversation: Microsoft, Cisco, Gen Digital, MISP, OWASP, NVIDIA (IBM dropped — PR #4109 closed without merge). */
    tier1Institutions: 6,
    /** Vendor + standards-body merges: MISP×2 + OWASP A-S-R-H + Gen Digital Sage */
    standardsBodyMerges: 4,
    /** Production CVE coverage (Spring AI + LiteLLM + Semantic Kernel via ATR v2.1.2/v2.1.4) */
    cveCoverage: [
      'CVE-2026-26030',
      'CVE-2026-25592',
      'CVE-2026-41705',
      'CVE-2026-41712',
      'CVE-2026-41713',
      'CVE-2026-42208',
      'CVE-2025-59536',
      'CVE-2026-21852',
    ],
    cisaKevCovered: 1,
    agentsProtected: 50,
    githubStars: 86,
    /** Agent runtimes PanGuard auto-detects and registers its MCP protection into. */
    platformsSupported: 17,
  },
  /** Platform coverage */
  platform: {
    layerCoverage: '5 of 7' as const,
    /** L2 Audit, L3 Protect, L4 Detect, L5 Deceive, L6 Respond shipped today */
    layersShipped: [2, 3, 4, 5, 6] as const,
    /** L1 Discover (central inventory) + L7 Govern (compliance reporting + AIAM) — coming Q2/Q3 2026 */
    layersComingSoon: [1, 7] as const,
    upstreamMerged: ['Microsoft AGT', 'Cisco AI Defense'] as const,
  },
  /**
   * NOTE: These fallback numbers are only used when TC live API is unreachable.
   * Website components should always prefer fetchLiveMetrics() for real-time data.
   * Update these periodically to keep fallbacks reasonable.
   */
  lastUpdated: '2026-06-16T11:05:13.632Z',
} as const;

export type Stats = typeof STATS;

/**
 * Live metrics from Threat Cloud API.
 * Used on the website to show real-time numbers from all scan sources.
 * Falls back to static STATS.ecosystem values if TC is unavailable.
 *
 * Usage:
 *   const metrics = await fetchLiveMetrics();
 *   // metrics.totalSkillsScanned -- from all sources (bulk + CLI + web)
 *   // metrics.totalAgentsProtected -- unique devices with panguard installed
 */
export interface LiveMetrics {
  totalSkillsScanned: number;
  totalAgentsProtected: number;
  totalThreatsDetected: number;
  totalAtrRules: number;
  sources: {
    bulk: { skills: number; findings: number };
    cli: { skills: number; findings: number; devices: number };
    web: { skills: number; findings: number };
  };
  lastUpdated: string;
}

const TC_METRICS_URL = process.env['THREAT_CLOUD_URL']
  ? `${process.env['THREAT_CLOUD_URL']}/api/metrics`
  : 'https://tc.panguard.ai/api/metrics';

/** Fetch live metrics from Threat Cloud, with static fallback */
export async function fetchLiveMetrics(): Promise<LiveMetrics> {
  try {
    const resp = await fetch(TC_METRICS_URL, {
      next: { revalidate: 60 },
    } as RequestInit);
    if (!resp.ok) throw new Error(`TC returned ${resp.status}`);
    const json = (await resp.json()) as { ok: boolean; data: LiveMetrics };
    if (json.ok && json.data) return json.data;
  } catch {
    // Fallback to static stats
  }

  return {
    totalSkillsScanned: STATS.ecosystem.skillsScanned,
    totalAgentsProtected: 0,
    totalThreatsDetected: STATS.ecosystem.maliciousFound,
    totalAtrRules: STATS.atrRules,
    sources: {
      bulk: { skills: STATS.ecosystem.skillsScanned, findings: STATS.ecosystem.maliciousFound },
      cli: { skills: 0, findings: 0, devices: 0 },
      web: { skills: 0, findings: 0 },
    },
    lastUpdated: STATS.lastUpdated,
  };
}

/** Product maturity label */
export type MaturityLevel = 'GA' | 'Beta' | 'ComingSoon';

/** Maturity status for each feature / product */
export const MATURITY: Record<string, MaturityLevel> = {
  scan: 'GA',
  guard: 'GA',
  chat: 'GA',
  threatCloud: 'GA',
  skillAuditor: 'GA',
  mcp: 'GA',
  trap: 'GA',
  report: 'GA',
};
