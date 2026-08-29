/**
 * @panguard-ai/scan-core - Unified type definitions
 *
 * Shared between CLI Skill Auditor and Website scanner.
 * These are the canonical types for all scan operations.
 */

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

// ---------------------------------------------------------------------------
// Findings & Checks
// ---------------------------------------------------------------------------

export type FindingCategory =
  | 'manifest'
  | 'prompt-injection'
  | 'tool-poisoning'
  | 'context-exfiltration'
  | 'agent-manipulation'
  | 'privilege-escalation'
  | 'excessive-autonomy'
  | 'data-poisoning'
  | 'model-abuse'
  | 'skill-compromise'
  | 'code'
  | 'secrets'
  | 'dependency'
  | 'permission'
  | 'ai-analysis'
  | 'atr';

/** Single scan finding */
export interface Finding {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: FindingCategory | string;
  readonly location?: string;
}

/** Result of a single check category */
export interface CheckResult {
  readonly status: 'pass' | 'warn' | 'fail' | 'info';
  readonly label: string;
  readonly findings?: readonly Finding[];
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// ---------------------------------------------------------------------------
// Context Signals
// ---------------------------------------------------------------------------

export interface ContextSignal {
  readonly id: string;
  readonly type: 'booster' | 'reducer';
  readonly label: string;
  readonly weight: number;
}

export interface ContextSignals {
  readonly signals: readonly ContextSignal[];
  readonly multiplier: number;
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

export interface SkillMetadata {
  readonly author?: string;
  readonly version?: string;
  readonly tags?: readonly string[];
  readonly triggers?: readonly string[];
  readonly openclaw?: {
    readonly requires?: {
      readonly bins?: readonly string[];
      readonly env?: readonly string[];
      readonly config?: readonly string[];
    };
    readonly primaryEnv?: string;
    readonly os?: readonly string[];
    readonly always?: boolean;
    readonly homepage?: string;
  };
  readonly [key: string]: unknown;
}

export interface SkillManifest {
  readonly name: string;
  readonly description: string;
  readonly license?: string;
  readonly homepage?: string;
  readonly userInvocable?: boolean;
  readonly disableModelInvocation?: boolean;
  readonly commandDispatch?: string;
  readonly commandTool?: string;
  readonly metadata?: SkillMetadata;
  readonly 'allowed-tools'?: readonly string[];
  /** Raw instruction body (after frontmatter) */
  readonly instructions: string;
  /**
   * Frontmatter keys whose YAML value did not match the declared type and had to
   * be coerced. Absent when the manifest parsed cleanly.
   *
   * Present so a degraded parse is visible in the report rather than silently
   * normalised: a manifest that only scans because we repaired it is a weaker
   * piece of evidence than one that was well-formed, and the consumer should be
   * able to tell the difference.
   */
  readonly parseDegraded?: readonly string[];
}

// ---------------------------------------------------------------------------
// ATR Rule (compiled form for pattern matching)
// ---------------------------------------------------------------------------

export interface ATRRuleCompiled {
  readonly id: string;
  readonly title: string;
  readonly severity: string;
  readonly category: string;
  readonly scan_target?: 'mcp' | 'skill' | 'runtime' | null;
  readonly rule_version?: number;
  readonly patterns: ReadonlyArray<{
    readonly field: string;
    readonly pattern: string;
    readonly desc: string;
  }>;
}

export interface CompiledRule extends ATRRuleCompiled {
  readonly compiled: ReadonlyArray<{ readonly regex: RegExp; readonly desc: string }>;
}

// ---------------------------------------------------------------------------
// Scan Result
// ---------------------------------------------------------------------------

export interface ScanOptions {
  /** Source type hint: 'skill' (SKILL.md) or 'documentation' (README, docs) */
  readonly sourceType?: 'skill' | 'documentation';
  /** Pre-compiled ATR rules (if omitted, no ATR scanning) */
  readonly atrRules?: readonly CompiledRule[];
  /** Skill name override (auto-detected from frontmatter if omitted) */
  readonly skillName?: string;
}

export interface ScanResult {
  readonly skillName: string | null;
  readonly manifest: SkillManifest | null;
  readonly findings: readonly Finding[];
  readonly checks: readonly CheckResult[];
  readonly riskScore: number;
  readonly riskLevel: RiskLevel;
  readonly contextSignals: ContextSignals;
  readonly atrRulesEvaluated: number;
  readonly atrPatternsMatched: number;
  readonly contentHash: string;
  readonly patternHash: string;
  readonly durationMs: number;
}
