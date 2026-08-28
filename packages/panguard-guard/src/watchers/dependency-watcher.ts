/**
 * DependencyWatcher - Monitors package manager lockfiles for supply-chain threats
 * DependencyWatcher - 監控套件管理器鎖定檔以偵測供應鏈威脅
 *
 * Detects:
 * 1. New package installations (diff old vs new)
 * 2. Known CVEs via `npm audit --json`
 * 3. Typosquatting (Levenshtein distance <= 2 from popular packages)
 * 4. Suspicious preinstall/postinstall scripts
 *
 * @module @panguard-ai/panguard-guard/watchers/dependency-watcher
 */

import { EventEmitter } from 'node:events';
import { existsSync, readFileSync, watch } from 'node:fs';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const logger = createLogger('panguard-guard:dependency-watcher');

// -- Constants --

/** Files to watch for dependency changes */
const WATCHED_FILES = [
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'requirements.txt',
  'Pipfile',
  'Pipfile.lock',
  'pyproject.toml',
  'go.mod',
  'go.sum',
] as const;

/** Popular packages used for typosquat detection */
const POPULAR_PACKAGES: readonly string[] = [
  'express',
  'react',
  'lodash',
  'axios',
  'webpack',
  'babel',
  'typescript',
  'next',
  'vue',
  'angular',
  'svelte',
  'fastify',
  'nest',
  'prisma',
  'mongoose',
  'sequelize',
  'knex',
  'dotenv',
  'cors',
  'helmet',
  'jsonwebtoken',
  'bcrypt',
  'passport',
  'socket.io',
  'redis',
  'pg',
  'mysql2',
  'chalk',
  'commander',
  'inquirer',
  'ora',
  'zod',
  'yup',
  'anthropic',
  'openai',
  'langchain',
] as const;

/** Maximum Levenshtein distance to flag as typosquat */
const TYPOSQUAT_THRESHOLD = 2;

let eventCounter = 0;

// -- Levenshtein Distance --

/**
 * Compute Levenshtein distance between two strings.
 * Standard dynamic programming implementation with no external deps.
 */
export function levenshtein(a: string, b: string): number {
  const aLen = a.length;
  const bLen = b.length;

  if (aLen === 0) return bLen;
  if (bLen === 0) return aLen;

  // Use single-row optimization
  let prev = Array.from({ length: bLen + 1 }, (_, i) => i);

  for (let i = 1; i <= aLen; i++) {
    const curr = [i];
    for (let j = 1; j <= bLen; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        (prev[j] ?? 0) + 1, // deletion
        (curr[j - 1] ?? 0) + 1, // insertion
        (prev[j - 1] ?? 0) + cost // substitution
      );
    }
    prev = curr;
  }

  return prev[bLen] ?? 0;
}

// -- Typosquat Detection --

/**
 * Check if a package name is a potential typosquat of a popular package.
 * Returns the popular package it resembles, or null if no match.
 */
export function detectTyposquat(
  name: string,
  popularPackages: readonly string[] = POPULAR_PACKAGES
): string | null {
  const lower = name.toLowerCase();

  for (const popular of popularPackages) {
    // Skip exact match (not a typosquat)
    if (lower === popular) continue;

    const distance = levenshtein(lower, popular);
    if (distance > 0 && distance <= TYPOSQUAT_THRESHOLD) {
      return popular;
    }
  }

  return null;
}

// -- Package Diff --

interface PackageJson {
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
  readonly scripts?: Readonly<Record<string, string>>;
}

/**
 * Extract all dependency names from a package.json structure.
 */
function extractDependencyNames(pkg: PackageJson): ReadonlySet<string> {
  const names = new Set<string>();
  if (pkg.dependencies) {
    for (const name of Object.keys(pkg.dependencies)) {
      names.add(name);
    }
  }
  if (pkg.devDependencies) {
    for (const name of Object.keys(pkg.devDependencies)) {
      names.add(name);
    }
  }
  return names;
}

/**
 * Diff two sets to find newly added items.
 */
function findNewPackages(
  oldNames: ReadonlySet<string>,
  newNames: ReadonlySet<string>
): readonly string[] {
  const added: string[] = [];
  for (const name of newNames) {
    if (!oldNames.has(name)) {
      added.push(name);
    }
  }
  return added;
}

// -- npm audit --

interface NpmAuditVulnerability {
  readonly severity: string;
  readonly title?: string;
  readonly url?: string;
  readonly range?: string;
  readonly via?: unknown;
}

interface NpmAuditResult {
  readonly vulnerabilities?: Readonly<Record<string, NpmAuditVulnerability>>;
}

/**
 * Run npm audit and return parsed results.
 * Returns null if npm is not available or audit fails.
 */
export function runNpmAudit(cwd: string): Promise<NpmAuditResult | null> {
  return new Promise((resolve) => {
    execFile(
      'npm',
      ['audit', '--json'],
      { cwd, timeout: 30_000, maxBuffer: 5 * 1024 * 1024, windowsHide: true },
      (error, stdout) => {
        // npm audit exits non-zero when vulnerabilities found; that is expected
        if (!stdout) {
          resolve(null);
          return;
        }
        try {
          const parsed = JSON.parse(stdout) as NpmAuditResult;
          resolve(parsed);
        } catch (err) {
          process.stderr.write(
            `[dependency-watcher] npm audit JSON parse failed: ${err instanceof Error ? err.message : String(err)}\n`
          );
          resolve(null);
        }
      }
    );
  });
}

// -- Suspicious Scripts Detection --

/**
 * Check a package.json for suspicious install scripts.
 * Returns list of suspicious script names found.
 */
export function detectSuspiciousScripts(pkg: PackageJson): readonly string[] {
  const suspiciousKeys = ['preinstall', 'postinstall', 'preuninstall', 'install'];
  const found: string[] = [];

  if (!pkg.scripts) return found;

  for (const key of suspiciousKeys) {
    const script = pkg.scripts[key];
    if (script && script.trim().length > 0) {
      found.push(key);
    }
  }

  return found;
}

// -- SecurityEvent Builders --

function buildEventId(): string {
  eventCounter++;
  return `dep-${Date.now()}-${eventCounter}`;
}

function buildSecurityEvent(
  severity: Severity,
  category: string,
  description: string,
  metadata: Record<string, unknown>
): SecurityEvent {
  return {
    id: buildEventId(),
    timestamp: new Date(),
    source: 'file',
    severity,
    category,
    description,
    raw: metadata,
    host: 'localhost',
    metadata,
  };
}

// -- DependencyWatcher --

export class DependencyWatcher extends EventEmitter {
  private running = false;
  private readonly watchDir: string;
  private readonly fsWatchers: Map<string, ReturnType<typeof watch>> = new Map();
  private readonly packageSnapshots: Map<string, ReadonlySet<string>> = new Map();

  constructor(watchDir: string) {
    super();
    this.watchDir = watchDir;
  }

  /**
   * Check if the watch directory contains any dependency files.
   */
  checkAvailability(): boolean {
    return WATCHED_FILES.some((f) => existsSync(join(this.watchDir, f)));
  }

  /**
   * Take an initial snapshot of package.json dependencies for diffing.
   */
  private snapshotPackageJson(filePath: string): void {
    try {
      const content = readFileSync(filePath, 'utf-8');
      const pkg = JSON.parse(content) as PackageJson;
      const names = extractDependencyNames(pkg);
      this.packageSnapshots.set(filePath, names);
    } catch {
      // File may not exist or be invalid JSON
    }
  }

  /**
   * Start watching dependency files for changes.
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Snapshot initial state
    const pkgJsonPath = join(this.watchDir, 'package.json');
    if (existsSync(pkgJsonPath)) {
      this.snapshotPackageJson(pkgJsonPath);
    }

    // Set up file watchers for each dependency file that exists
    for (const fileName of WATCHED_FILES) {
      const filePath = join(this.watchDir, fileName);
      if (!existsSync(filePath)) continue;

      try {
        const watcher = watch(filePath, { persistent: false }, (eventType) => {
          if (eventType === 'change') {
            void this.handleFileChange(fileName, filePath);
          }
        });

        this.fsWatchers.set(fileName, watcher);
        logger.info(`Watching dependency file: ${fileName}`);
      } catch (err: unknown) {
        logger.warn(
          `Could not watch ${fileName}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    logger.info(`DependencyWatcher started for ${this.watchDir}`);
  }

  /**
   * Handle a change to a watched dependency file.
   */
  private async handleFileChange(fileName: string, filePath: string): Promise<void> {
    logger.info(`Dependency file changed: ${fileName}`);

    if (fileName === 'package.json') {
      await this.handlePackageJsonChange(filePath);
    } else if (this.isJsLockfile(fileName)) {
      await this.handleJsLockfileChange();
    } else {
      // Non-JS dependency file changed
      this.emit(
        'event',
        buildSecurityEvent('low', 'supply-chain', `Dependency file changed: ${fileName}`, {
          fileName,
          watchDir: this.watchDir,
        })
      );
    }
  }

  /**
   * Handle package.json changes: diff packages, check typosquat, check scripts.
   */
  private async handlePackageJsonChange(filePath: string): Promise<void> {
    const oldNames = this.packageSnapshots.get(filePath) ?? new Set<string>();

    let newPkg: PackageJson;
    try {
      const content = readFileSync(filePath, 'utf-8');
      newPkg = JSON.parse(content) as PackageJson;
    } catch {
      return; // File may be in mid-write
    }

    const newNames = extractDependencyNames(newPkg);
    const added = findNewPackages(oldNames, newNames);

    // Update snapshot (immutable: replace, don't mutate)
    this.packageSnapshots.set(filePath, newNames);

    if (added.length === 0) return;

    logger.info(`New packages detected: ${added.join(', ')}`);

    // Check each new package for typosquatting
    for (const pkgName of added) {
      const resembles = detectTyposquat(pkgName);
      if (resembles) {
        this.emit(
          'event',
          buildSecurityEvent(
            'high',
            'supply-chain',
            `Potential typosquat detected: "${pkgName}" resembles popular package "${resembles}"`,
            { packageName: pkgName, resembles, type: 'typosquat' }
          )
        );
      }
    }

    // Check for suspicious install scripts in the new package.json
    const suspicious = detectSuspiciousScripts(newPkg);
    if (suspicious.length > 0) {
      this.emit(
        'event',
        buildSecurityEvent(
          'medium',
          'supply-chain',
          `Suspicious install scripts found: ${suspicious.join(', ')}`,
          { scripts: suspicious, type: 'suspicious_scripts' }
        )
      );
    }
  }

  /**
   * Handle JS lockfile changes: run npm audit.
   */
  private async handleJsLockfileChange(): Promise<void> {
    const audit = await runNpmAudit(this.watchDir);
    if (!audit?.vulnerabilities) return;

    const entries = Object.entries(audit.vulnerabilities);
    if (entries.length === 0) return;

    for (const [name, vuln] of entries) {
      const severity = this.mapAuditSeverity(vuln.severity);
      this.emit(
        'event',
        buildSecurityEvent(
          severity,
          'vulnerability',
          `CVE found in "${name}": ${vuln.title ?? vuln.severity} severity`,
          {
            packageName: name,
            vulnSeverity: vuln.severity,
            title: vuln.title,
            url: vuln.url,
            type: 'cve',
          }
        )
      );
    }
  }

  /**
   * Map npm audit severity string to Panguard Severity.
   */
  private mapAuditSeverity(auditSeverity: string): Severity {
    const s = auditSeverity.toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'moderate' || s === 'medium') return 'medium';
    if (s === 'low') return 'low';
    return 'info';
  }

  /**
   * Check if a filename is a JS/Node lockfile.
   */
  private isJsLockfile(fileName: string): boolean {
    return (
      fileName === 'package-lock.json' || fileName === 'pnpm-lock.yaml' || fileName === 'yarn.lock'
    );
  }

  /**
   * Stop all file watchers and clean up.
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    for (const [fileName, watcher] of this.fsWatchers) {
      watcher.close();
      logger.debug(`Stopped watching: ${fileName}`);
    }
    this.fsWatchers.clear();
    this.packageSnapshots.clear();

    logger.info('DependencyWatcher stopped');
  }
}
