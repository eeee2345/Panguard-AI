/**
 * ProcessWatcher - Monitors child process execution for suspicious patterns
 * ProcessWatcher - 監控子程序執行的可疑模式
 *
 * Detects:
 * 1. Suspicious shell command execution (bash -c, sh -c, eval)
 * 2. Data exfiltration attempts (curl/wget piping, nc reverse shells)
 * 3. Credential access patterns (reading .ssh, .aws, /etc/shadow)
 * 4. Script interpreter abuse (python -c, perl -e, node -e)
 * 5. Privilege escalation indicators (sudo, chmod +s, chown root)
 *
 * Complements ProcessMonitor (birth/death tracking) and SyscallMonitor (kernel-level).
 * This watcher operates at the application layer, analyzing command-line arguments.
 *
 * @module @panguard-ai/panguard-guard/watchers/process-watcher
 */

import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { platform, hostname } from 'node:os';
import { createLogger } from '@panguard-ai/core';
import type { SecurityEvent, Severity } from '@panguard-ai/core';

const execFileAsync = promisify(execFile);
const logger = createLogger('panguard-guard:process-watcher');

// -- Detection pattern definitions --

/** Command-line threat pattern */
export interface CommandPattern {
  readonly id: string;
  readonly name: string;
  readonly pattern: RegExp;
  readonly severity: Severity;
  readonly category: string;
}

/** Suspicious shell execution patterns */
const SHELL_PATTERNS: readonly CommandPattern[] = [
  {
    id: 'inline-shell',
    name: 'Inline shell command',
    pattern: /\b(?:bash|sh|zsh|dash)\s+-c\s+/,
    severity: 'medium',
    category: 'execution',
  },
  {
    id: 'eval-exec',
    name: 'Eval/exec invocation',
    pattern: /\beval\s+['"]|exec\s+['"]|\bsource\s+/,
    severity: 'high',
    category: 'execution',
  },
  {
    id: 'hidden-shell',
    name: 'Hidden shell process',
    pattern: /\/dev\/tcp\/|\/dev\/udp\//,
    severity: 'critical',
    category: 'execution',
  },
  {
    id: 'pipe-shell',
    name: 'Piped shell execution',
    pattern: /\|\s*(?:bash|sh|zsh)\b/,
    severity: 'critical',
    category: 'execution',
  },
] as const;

/** Data exfiltration patterns */
const EXFIL_PATTERNS: readonly CommandPattern[] = [
  {
    id: 'curl-exfil',
    name: 'Curl data upload',
    pattern: /\bcurl\b.*(?:-d\s|--data\s|-F\s|--form\s|-T\s|--upload-file\s)/,
    severity: 'high',
    category: 'exfiltration',
  },
  {
    id: 'wget-download',
    name: 'Wget to file',
    pattern: /\bwget\b.*(?:-O\s|-P\s|--output-document)/,
    severity: 'medium',
    category: 'exfiltration',
  },
  {
    id: 'nc-reverse',
    name: 'Netcat reverse shell',
    pattern: /\b(?:nc|ncat|netcat)\b.*-e\s/,
    severity: 'critical',
    category: 'exfiltration',
  },
  {
    id: 'dns-exfil',
    name: 'DNS exfiltration',
    pattern: /\b(?:dig|nslookup|host)\b.*\$\(/,
    severity: 'high',
    category: 'exfiltration',
  },
] as const;

/** Credential access patterns */
const CRED_PATTERNS: readonly CommandPattern[] = [
  {
    id: 'ssh-key-access',
    name: 'SSH key file access',
    pattern: /(?:cat|less|more|head|tail|cp|scp)\s+.*\.ssh\/(?:id_|authorized_keys|known_hosts)/,
    severity: 'high',
    category: 'credential-access',
  },
  {
    id: 'aws-cred-access',
    name: 'AWS credential access',
    pattern: /(?:cat|less|more|head|tail|cp)\s+.*\.aws\/(?:credentials|config)/,
    severity: 'high',
    category: 'credential-access',
  },
  {
    id: 'shadow-access',
    name: 'Shadow file access',
    pattern: /(?:cat|less|more|head|tail)\s+.*\/etc\/(?:shadow|passwd|sudoers)/,
    severity: 'critical',
    category: 'credential-access',
  },
  {
    id: 'env-dump',
    name: 'Environment variable dump',
    pattern: /\b(?:printenv|env|set)\b.*(?:\||>)/,
    severity: 'medium',
    category: 'credential-access',
  },
  {
    id: 'keychain-access',
    name: 'Keychain/credential store access',
    pattern: /\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)/,
    severity: 'critical',
    category: 'credential-access',
  },
] as const;

/** Script interpreter abuse patterns */
const SCRIPT_PATTERNS: readonly CommandPattern[] = [
  {
    id: 'python-inline',
    name: 'Python inline execution',
    pattern: /\bpython[23]?\s+-c\s+/,
    severity: 'medium',
    category: 'execution',
  },
  {
    id: 'perl-inline',
    name: 'Perl inline execution',
    pattern: /\bperl\s+-e\s+/,
    severity: 'medium',
    category: 'execution',
  },
  {
    id: 'node-inline',
    name: 'Node.js inline execution',
    pattern: /\bnode\s+-e\s+/,
    severity: 'medium',
    category: 'execution',
  },
  {
    id: 'ruby-inline',
    name: 'Ruby inline execution',
    pattern: /\bruby\s+-e\s+/,
    severity: 'medium',
    category: 'execution',
  },
] as const;

/** Privilege escalation patterns */
const PRIVESC_PATTERNS: readonly CommandPattern[] = [
  {
    id: 'chmod-setuid',
    name: 'Setuid bit modification',
    pattern: /\bchmod\b.*[+]s\b/,
    severity: 'critical',
    category: 'privilege-escalation',
  },
  {
    id: 'chown-root',
    name: 'Ownership change to root',
    pattern: /\bchown\b.*\broot\b/,
    severity: 'high',
    category: 'privilege-escalation',
  },
  {
    id: 'sudo-nopasswd',
    name: 'Sudo NOPASSWD modification',
    pattern: /\bsudo\b.*NOPASSWD|\/etc\/sudoers/,
    severity: 'critical',
    category: 'privilege-escalation',
  },
] as const;

/** All patterns combined */
const ALL_PATTERNS: readonly CommandPattern[] = [
  ...SHELL_PATTERNS,
  ...EXFIL_PATTERNS,
  ...CRED_PATTERNS,
  ...SCRIPT_PATTERNS,
  ...PRIVESC_PATTERNS,
] as const;

/** Suspicious process names (standalone, no command args needed) */
const SUSPICIOUS_BINARIES = new Set([
  'meterpreter',
  'mimikatz',
  'lazagne',
  'Empire',
  'cobaltstrike',
  'socat',
]);

let eventCounter = 0;

// -- Pure detection functions (exported for testing) --

/** Process info from system polling */
export interface ProcessSnapshot {
  readonly pid: number;
  readonly name: string;
  readonly command: string;
  readonly user?: string;
  readonly ppid?: number;
}

/**
 * Scan a command line against all threat patterns.
 * Returns all matching patterns.
 */
export function scanCommandLine(command: string): readonly CommandPattern[] {
  const matches: CommandPattern[] = [];
  for (const pat of ALL_PATTERNS) {
    if (pat.pattern.test(command)) {
      matches.push(pat);
    }
  }
  return matches;
}

/**
 * Check if a process name is a known suspicious binary.
 */
export function isSuspiciousBinary(name: string): boolean {
  return SUSPICIOUS_BINARIES.has(name);
}

/**
 * Create a SecurityEvent for process watcher detections.
 */
export function createProcessEvent(opts: {
  readonly severity: Severity;
  readonly category: string;
  readonly description: string;
  readonly metadata: Record<string, unknown>;
}): SecurityEvent {
  eventCounter++;
  return {
    id: `proc-${Date.now()}-${eventCounter}`,
    timestamp: new Date(),
    source: 'process',
    severity: opts.severity,
    category: opts.category,
    description: opts.description,
    raw: opts.metadata,
    host: hostname(),
    metadata: {
      ...opts.metadata,
      watcher: 'process-watcher',
    },
  };
}

// -- ProcessWatcher class --

/**
 * ProcessWatcher monitors running processes for suspicious command-line patterns.
 *
 * Usage:
 *   const watcher = new ProcessWatcher(5000);
 *   if (await watcher.checkAvailability()) {
 *     watcher.on('event', (event) => handleEvent(event));
 *     await watcher.start();
 *   }
 */
export class ProcessWatcher extends EventEmitter {
  private running = false;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private readonly pollIntervalMs: number;
  /** Track alerted PIDs to avoid duplicate alerts for the same process */
  private readonly alertedPids: Set<number> = new Set();
  /** Track previous PIDs to detect new processes only */
  private previousPids: ReadonlySet<number> = new Set();

  constructor(pollIntervalMs = 5000) {
    super();
    this.pollIntervalMs = pollIntervalMs;
  }

  /**
   * Check if process listing is available on this platform.
   */
  async checkAvailability(): Promise<boolean> {
    try {
      const os = platform();
      if (os === 'darwin' || os === 'linux') {
        await execFileAsync('ps', ['-eo', 'pid,ppid,user,comm,args'], { timeout: 3000 });
        return true;
      }
      if (os === 'win32') {
        await execFileAsync('tasklist', ['/FO', 'CSV', '/V'], { timeout: 5000, windowsHide: true });
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Start monitoring processes at the configured poll interval.
   */
  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;

    // Initial snapshot (no alerts on first poll — establishes baseline)
    const initial = await this.getProcessList();
    this.previousPids = new Set(initial.map((p) => p.pid));

    this.pollTimer = setInterval(() => {
      void this.pollAndAnalyze();
    }, this.pollIntervalMs);

    logger.info(`ProcessWatcher started (poll interval: ${this.pollIntervalMs}ms)`);
  }

  /**
   * Stop monitoring and clean up.
   */
  stop(): void {
    if (!this.running) return;
    this.running = false;

    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.alertedPids.clear();
    this.previousPids = new Set();

    logger.info('ProcessWatcher stopped');
  }

  /**
   * Whether the watcher is currently active.
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Manually trigger a single poll cycle.
   * Useful for testing without waiting for the interval.
   */
  async pollOnce(): Promise<void> {
    await this.pollAndAnalyze();
  }

  /**
   * Poll the process list and analyze new processes.
   */
  private async pollAndAnalyze(): Promise<void> {
    try {
      const processes = await this.getProcessList();
      const currentPids = new Set(processes.map((p) => p.pid));

      // Only analyze newly appeared processes
      for (const proc of processes) {
        if (this.previousPids.has(proc.pid)) continue;
        if (this.alertedPids.has(proc.pid)) continue;

        this.analyzeProcess(proc);
      }

      // Clean up alertedPids for processes that no longer exist
      for (const pid of this.alertedPids) {
        if (!currentPids.has(pid)) {
          this.alertedPids.delete(pid);
        }
      }

      // Update snapshot (immutable replace)
      this.previousPids = currentPids;
    } catch (err) {
      logger.warn(`Process poll failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Analyze a single process for suspicious patterns.
   */
  private analyzeProcess(proc: ProcessSnapshot): void {
    const command = proc.command;

    // Check known suspicious binaries
    if (isSuspiciousBinary(proc.name)) {
      this.alertedPids.add(proc.pid);
      this.emit(
        'event',
        createProcessEvent({
          severity: 'critical',
          category: 'execution',
          description: `Known malicious binary detected: ${proc.name} (PID ${proc.pid})`,
          metadata: {
            trigger: 'suspicious_binary',
            processName: proc.name,
            pid: proc.pid,
            ppid: proc.ppid,
            user: proc.user,
            command,
          },
        })
      );
      return;
    }

    // Scan command line for threat patterns
    const matches = scanCommandLine(command);
    if (matches.length === 0) return;

    // Use the highest severity match
    const severityOrder: Record<Severity, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };
    const sorted = [...matches].sort(
      (a, b) => severityOrder[b.severity] - severityOrder[a.severity]
    );
    const primary = sorted[0]!;

    this.alertedPids.add(proc.pid);
    this.emit(
      'event',
      createProcessEvent({
        severity: primary.severity,
        category: primary.category,
        description: `${primary.name}: ${proc.name} (PID ${proc.pid})`,
        metadata: {
          trigger: 'command_pattern',
          patternId: primary.id,
          patternName: primary.name,
          processName: proc.name,
          pid: proc.pid,
          ppid: proc.ppid,
          user: proc.user,
          command: this.redactCommand(command),
          matchCount: matches.length,
          allPatternIds: matches.map((m) => m.id),
        },
      })
    );
  }

  /**
   * Redact potentially sensitive values from command strings for logging.
   * Truncate long commands and mask obvious secrets.
   */
  private redactCommand(command: string): string {
    const maxLen = 500;
    let redacted =
      command.length > maxLen ? command.substring(0, maxLen) + '...[truncated]' : command;
    // Mask values after common secret env patterns
    redacted = redacted.replace(
      /((?:KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|API_KEY)\s*=\s*)\S+/gi,
      '$1[REDACTED]'
    );
    return redacted;
  }

  /**
   * Get the current process list from the OS.
   */
  private async getProcessList(): Promise<readonly ProcessSnapshot[]> {
    const os = platform();
    if (os === 'darwin' || os === 'linux') {
      return this.getUnixProcessList();
    }
    if (os === 'win32') {
      return this.getWindowsProcessList();
    }
    return [];
  }

  /**
   * Parse Unix ps output into ProcessSnapshot array.
   */
  private async getUnixProcessList(): Promise<readonly ProcessSnapshot[]> {
    try {
      const { stdout } = await execFileAsync('ps', ['-eo', 'pid,ppid,user,comm,args'], {
        timeout: 5000,
        maxBuffer: 10 * 1024 * 1024,
      });

      const lines = stdout.trim().split('\n');
      // Skip header line
      const processes: ProcessSnapshot[] = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]!.trim();
        if (!line) continue;

        // Format: PID PPID USER COMM ARGS...
        const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)/);
        if (!match) continue;

        processes.push({
          pid: parseInt(match[1]!, 10),
          ppid: parseInt(match[2]!, 10),
          user: match[3]!,
          name: match[4]!,
          command: match[5] ?? match[4]!,
        });
      }

      return processes;
    } catch {
      return [];
    }
  }

  /**
   * Parse Windows tasklist output into ProcessSnapshot array.
   */
  private async getWindowsProcessList(): Promise<readonly ProcessSnapshot[]> {
    try {
      const { stdout } = await execFileAsync('tasklist', ['/FO', 'CSV', '/V'], {
        timeout: 5000,
        maxBuffer: 10 * 1024 * 1024,
        windowsHide: true,
      });

      const lines = stdout.trim().split('\n');
      const processes: ProcessSnapshot[] = [];
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]!;
        // CSV format: "Image Name","PID",...
        const parts = line.split('","');
        if (parts.length < 2) continue;
        const name = (parts[0] ?? '').replace(/^"/, '');
        const pid = parseInt(parts[1] ?? '0', 10);
        if (isNaN(pid)) continue;
        processes.push({ pid, name, command: name });
      }
      return processes;
    } catch {
      return [];
    }
  }
}
