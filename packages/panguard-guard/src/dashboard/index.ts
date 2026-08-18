/**
 * Web Dashboard - Real-time monitoring interface
 * Web Dashboard - 即時監控介面
 *
 * Provides an HTTP server with WebSocket push for:
 * - System status overview / 系統狀態概覽
 * - Event timeline / 事件時間軸
 * - Threat map visualization / 威脅地圖視覺化
 * - Configuration management / 配置管理
 *
 * Uses only Node.js built-in http module with native WebSocket handshake.
 *
 * @module @panguard-ai/panguard-guard/dashboard
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import {
  existsSync,
  readFileSync,
  readdirSync,
  writeFileSync,
  mkdirSync,
  renameSync,
  rmSync,
  chmodSync,
} from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { lookup } from 'node:dns/promises';
import { WebSocketServer, type WebSocket as WS } from 'ws';
import { createLogger } from '@panguard-ai/core';
import { FileQuarantine } from '../response/file-quarantine.js';
import { normalizeSkillName } from '../engines/skill-whitelist.js';
import type { SkillWhitelistManager } from '../engines/skill-whitelist.js';
import type {
  DashboardStatus,
  DashboardEvent,
  ThreatMapEntry,
  GuardConfig,
  ThreatVerdict,
} from '../types.js';
import { saveConfig, loadConfig } from '../config.js';
import { verifyConfigIntegrity, checkSelfState } from '../integrity.js';
import { redactSecrets, SECRET_KEY_RE, SECRET_VALUE_RE, REDACTED } from '../redact.js';
import { scrubSecretValues } from '../agent/scrub-secrets.js';
import { DashboardRelayClient, type RelayClientConfig } from './relay-client.js';
import {
  AuditChain,
  getAuditKey,
  anonymizeActorForExport,
  canonicalize,
  type ChainedRecord,
  type VerifyResult,
} from '../audit/index.js';
import type { ReportRecord } from '../agent/report-agent.js';

// ESM-compatible __dirname resolution. import.meta.dirname is Node 20.11+
// but the project's engines field already requires >=20, so fall back to
// fileURLToPath only as a safety net for older Node 20 patch versions.
const HERE: string =
  (import.meta as unknown as { dirname?: string }).dirname ??
  dirname(fileURLToPath(import.meta.url));

// Package version, read live from package.json (same pattern as src/index.ts
// and src/cli/index.ts) so SARIF/evidence-pack exports never carry a stale
// hardcoded version literal.
const _require = createRequire(import.meta.url);
const _pkg = _require('../../package.json') as { version: string };
const PANGUARD_VERSION: string = _pkg.version;

/**
 * Dashboard HTML lives in a sibling file (`dashboard.html`) and is read at
 * module init so the template can be authored as standalone HTML and edited
 * without touching TypeScript. The file ships in the package because
 * `package.json#files` includes `dist/` (the build copies it via postbuild).
 */
const DASHBOARD_HTML: string = readFileSync(join(HERE, 'dashboard.html'), 'utf-8');

const logger = createLogger('panguard-guard:dashboard');

/** WebSocket client tracking */
interface WSClient {
  ws: WS;
  alive: boolean;
  connectedAt: number;
  ip: string;
}

/** Rate limiter state per IP */
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const RATE_LIMIT_MAX = 120;
const RATE_LIMIT_WINDOW_MS = 60_000;
// Small pre-auth cap: bounds 401/403 spam from an unauthenticated local caller
// WITHOUT letting it consume the authenticated user's RATE_LIMIT_MAX budget. The
// authenticated budget is checked only AFTER token validation, keyed on the
// token, so an unauthenticated flood can never exhaust the real dashboard's
// quota. Loopback-only binding means per-IP keying adds nothing, so the pre-auth
// bucket is a single global counter that just caps the reject path.
const PREAUTH_RATE_LIMIT_MAX = 240;
const MAX_WS_CLIENTS = 20;
const MAX_WS_PER_IP = 5;

/**
 * Layer C is downgraded to 'degraded' when its last advisory call errored and no
 * successful call has landed since (or none ever has). This window bounds how
 * long a stale success keeps the layer green after errors start: if the most
 * recent success is older than this AND there is a more recent error, the layer
 * reports degraded. 15 minutes is long enough to ride out a transient blip but
 * short enough to surface a dead key / dead local model promptly.
 */
const LAYER_C_STALE_SUCCESS_MS = 15 * 60_000;

/**
 * The dashboard's per-launch auth token is persisted here (0o600) while the
 * daemon runs, so a *separate* process — `pga up` on a rerun, an
 * already-running daemon, a headless host — can build the authenticated launch
 * URL (http://127.0.0.1:PORT/?token=<token>) instead of opening a bare URL that
 * 401s. The token is the launch secret that mints the dashboard auth cookie, so
 * it is treated exactly like the cookie: owner-only file mode, never logged, and
 * removed when the dashboard stops so a stale token cannot linger after exit.
 */
const DASHBOARD_TOKEN_DIR = join(homedir(), '.panguard-guard');
const DASHBOARD_TOKEN_PATH = join(DASHBOARD_TOKEN_DIR, 'dashboard-token');

/**
 * Remove the persisted dashboard launch token. Exported so `pga guard stop` /
 * `pga guard uninstall` can guarantee the secret never outlives the daemon even
 * when the process is killed without a graceful `stop()` (e.g. SIGTERM mid-run).
 * Best-effort: a missing file or permission error is not fatal.
 */
export function removeDashboardToken(expectedToken?: string): void {
  try {
    if (!existsSync(DASHBOARD_TOKEN_PATH)) return;
    // Owner-aware delete: on a restart/overlap a departing OLD daemon must not
    // erase a NEWLY-started daemon's live token. When the caller knows its own
    // token, only remove the file if the on-disk contents still match it.
    if (expectedToken !== undefined) {
      let onDisk = '';
      try {
        onDisk = readFileSync(DASHBOARD_TOKEN_PATH, 'utf-8');
      } catch {
        /* unreadable — fall through to a best-effort remove */
      }
      if (onDisk && onDisk !== expectedToken) return; // belongs to another daemon
    }
    rmSync(DASHBOARD_TOKEN_PATH, { force: true });
  } catch {
    /* best effort — never block shutdown on token cleanup */
  }
}

/**
 * Path of the collective-defense consent marker. Mirrors the CLI consent module
 * (packages/panguard/src/cli/consent.ts:CONSENT_MARKER) so that turning
 * collective defense ON or OFF from the dashboard counts as "the user has been
 * asked and answered" — otherwise the next `pga up` / `pga scan` first-run
 * prompt would overwrite the dashboard choice. The marker is purely a "consent
 * has been recorded" signal; it never enables anything on its own. The upload
 * gate is still `threatCloudUploadEnabled === true`, default OFF. Resolved at
 * call time (not module load) so it always follows the live home directory.
 */
function consentMarkerPath(): string {
  return join(homedir(), '.panguard-guard', '.telemetry-prompted');
}

/**
 * Record that the user has answered the collective-defense question (from the
 * dashboard toggle). Best-effort: a missing dir is created; any failure is
 * swallowed so a read-only home directory never blocks saving the config.
 */
function markConsentAnswered(): void {
  try {
    const dir = join(homedir(), '.panguard-guard');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    writeFileSync(consentMarkerPath(), new Date().toISOString(), {
      encoding: 'utf-8',
      mode: 0o600,
    });
  } catch {
    /* best effort — if we can't write the marker, the CLI re-asks next run */
  }
}

/** Relay configuration for connecting to a remote Manager */
export interface DashboardRelayOptions {
  readonly managerUrl: string;
  readonly agentId: string;
  readonly token: string;
}

/** Per-layer runtime health, computed from live engine state (never hard-coded). */
interface LayerState {
  readonly state: 'active' | 'idle' | 'degraded' | 'off';
  readonly detail: string;
  readonly optional?: boolean;
}
interface LayerHealth {
  readonly a: LayerState;
  readonly b: LayerState;
  readonly c: LayerState;
}

/**
 * Honest enforcement posture — what the daemon will ACTUALLY do on a detection,
 * not just the mode label. 'protection' mode with no armed response policy is
 * detect-and-notify, NOT prevention, and must not read as a green PROTECTED.
 */
interface EnforcementStatus {
  readonly mode: string;
  readonly posture:
    | 'protected'
    | 'monitoring'
    | 'report-only'
    | 'learning'
    | 'off'
    | 'tampered'
    | 'degraded';
  readonly osActionsArmed: boolean;
  readonly armedActions: string[];
  /** Actions the user ENABLED in config that cannot actually fire on this host
   *  (root-only action on a non-root daemon, or an empty allow-list). Surfaced so
   *  the cockpit can say "armed but inert" instead of a fake-green PROTECTED. */
  readonly inertActions?: string[];
  /** S5: config-integrity + self-removal verdict surfaced to the cockpit. */
  readonly integrity?: {
    readonly status: string;
    readonly changedFields: number;
    readonly selfRemoval: number;
  };
}

/**
 * Dashboard Server manages the HTTP + WebSocket real-time dashboard
 */
export class DashboardServer {
  private server: ReturnType<typeof createServer> | null = null;
  // Did the HTTP server actually bind this port? False after an EADDRINUSE /
  // listen error, so the launcher never opens a /?token= URL for a dead server.
  private listening = false;
  // Did the launch token land on disk? Surfaced so a running-but-tokenless
  // daemon (dashboard 401s) is self-diagnosable via status/doctor.
  private tokenPersisted = false;
  private wsClients: Set<WSClient> = new Set();
  private status: DashboardStatus;
  private recentEvents: DashboardEvent[] = [];
  private threatMap: ThreatMapEntry[] = [];
  private readonly maxRecentEvents = 200;
  private readonly port: number;
  private getConfig: (() => GuardConfig) | null = null;
  private configApplier: ((cfg: GuardConfig) => void) | null = null;
  // The LIVE skill-whitelist manager the detection engine actually consults.
  // When present, "Mark safe"/"Un-trust" route through it so the change takes
  // effect on the running daemon AND is persisted in the format the gate reads.
  private whitelistManager: SkillWhitelistManager | null = null;
  private getRulesProvider:
    | (() => Array<{
        id: string;
        title: string;
        severity: string;
        category: string;
        description: string;
      }>)
    | null = null;
  private readonly authToken: string;
  private rateLimits: Map<string, RateLimitEntry> = new Map();
  private relayClient: DashboardRelayClient | null = null;
  private readonly relayConfig: DashboardRelayOptions | undefined;
  /**
   * Cached @panguard-ai/panguard-mcp/config module. Resolved ONCE (first use)
   * and reused, so the long-running daemon does not re-resolve/re-read a module
   * path on every API request — closing a per-request module-planting window.
   * `null` = not yet attempted; a settled promise resolving to `null` = the
   * optional module is unavailable in this install.
   */
  private mcpConfigModulePromise: Promise<Record<string, unknown> | null> | null = null;

  /**
   * Cache for the EXPENSIVE platform / skill detection (`/api/agents`,
   * `/api/installed-skills`). Detection runs a `claude mcp list` subprocess
   * (~4.5s, and it BLOCKS the event loop) plus other on-disk probes, and the
   * Overview tab POLLS `/api/agents` — so before caching, the dashboard froze
   * for seconds on every poll and the Coverage / Skills tabs sat blank. We now
   * serve the last snapshot instantly and refresh in the background at most once
   * per TTL (warmed at start()). Platform/skill installs change on the order of
   * minutes, so a 5-minute TTL is safe.
   */
  private readonly detectCache = new Map<string, { data: unknown; ts: number }>();
  private readonly detectInflight = new Map<string, Promise<unknown>>();
  private static readonly DETECT_TTL_MS = 300_000;

  /**
   * Live health of the optional Layer C (semantic LLM) client, reported by the
   * engine via reportLayerCOutcome(). Config-presence alone is NOT health: an
   * expired cloud key or a dead local Ollama still has a config object, so
   * without this the layer-health row would keep showing green 'active' while
   * every advisory call silently fails. `null` = the engine has not reported an
   * outcome yet (no call has been attempted since launch).
   */
  private layerCHealth: {
    readonly lastSuccessAt: number | null;
    readonly lastErrorAt: number | null;
    readonly lastError: string | null;
  } | null = null;

  constructor(port: number, relayConfig?: DashboardRelayOptions) {
    this.port = port;
    this.authToken = randomBytes(32).toString('hex');
    this.relayConfig = relayConfig;
    this.status = {
      mode: 'learning',
      uptime: 0,
      eventsProcessed: 0,
      threatsDetected: 0,
      actionsExecuted: 0,
      learningProgress: 0,
      baselineConfidence: 0,
      memoryUsageMB: 0,
      cpuPercent: 0,
      recentVerdicts: [],
    };
  }

  setConfigGetter(getter: () => GuardConfig): void {
    this.getConfig = getter;
  }

  /**
   * Wire the engine's live-config applier. When a config-writing handler (e.g.
   * the Threat Cloud / mode POST) persists a new config to disk, it ALSO calls
   * this so the engine mutates its in-memory `this.config` + `this.mode` and
   * re-arms enforcement for the new mode. Without it, the daemon kept serving
   * the stale config it was constructed with: GET /api/config and /api/status
   * returned the old value, enforcement kept the old mode, and the UI control
   * snapped back — the change looked rejected even though disk was updated.
   */
  setConfigApplier(applier: (cfg: GuardConfig) => void): void {
    this.configApplier = applier;
  }

  /**
   * Wire a callback that returns the live set of ATR rules currently loaded by
   * the engine. Used by SARIF / Evidence Pack export so the auditor sees the
   * actual rules in effect (not a stale snapshot from disk).
   */
  setRulesProvider(
    getter: () => Array<{
      id: string;
      title: string;
      severity: string;
      category: string;
      description: string;
    }>
  ): void {
    this.getRulesProvider = getter;
  }

  /**
   * Inject the live skill-whitelist manager so dashboard "Mark safe"/"Un-trust"
   * mutate the SAME in-memory whitelist the detection engine consults (and
   * persist it correctly), instead of hand-writing a JSON record the gate never
   * matches. Wired by GuardEngine at startup.
   */
  setWhitelistManager(manager: SkillWhitelistManager): void {
    this.whitelistManager = manager;
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));

      // Handle port conflicts BEFORE attaching WSS to prevent unhandled error crashes
      this.server.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
          logger.warn(
            `Dashboard port ${this.port} already in use. ` +
              `Another Guard instance may be running. Dashboard disabled for this session.`
          );
          this.server = null;
          resolve(); // Don't crash — Guard can run without Dashboard
        } else {
          logger.error(`Dashboard server error: ${err.message}`);
          resolve();
        }
      });

      const wss = new WebSocketServer({ noServer: true });

      wss.on('connection', (ws: WS, req: IncomingMessage) => {
        if (this.wsClients.size >= MAX_WS_CLIENTS) {
          logger.warn('Max WebSocket connections reached');
          ws.close();
          return;
        }

        const origin = req.headers.origin ?? '';
        // Strict origin check: must be exactly loopback or absent (native clients)
        if (origin) {
          try {
            const parsed = new URL(origin);
            const isLoopback =
              parsed.hostname === '127.0.0.1' ||
              parsed.hostname === 'localhost' ||
              parsed.hostname === '::1';
            if (!isLoopback) {
              logger.warn(`Rejected WebSocket from non-loopback origin: ${origin}`);
              ws.close();
              return;
            }
          } catch {
            logger.warn(`Rejected WebSocket with malformed origin: ${origin}`);
            ws.close();
            return;
          }
        }

        // Require the dashboard auth token (the browser sends it as the
        // HttpOnly cookie on upgrade). Without this, any local process could
        // subscribe to the live verdict/event stream — same gate as the HTTP API.
        const wsCookieToken =
          (req.headers.cookie ?? '')
            .split(';')
            .map((c) => c.trim())
            .find((c) => c.startsWith('panguard_auth='))
            ?.split('=')[1] ?? '';
        if (
          !wsCookieToken ||
          wsCookieToken.length !== this.authToken.length ||
          !timingSafeEqual(Buffer.from(wsCookieToken), Buffer.from(this.authToken))
        ) {
          logger.warn('Rejected WebSocket without a valid auth token');
          ws.close();
          return;
        }

        // Per-IP connection limit
        const clientIP = req.socket.remoteAddress ?? 'unknown';
        const ipCount = [...this.wsClients].filter((c) => c.ip === clientIP).length;
        if (ipCount >= MAX_WS_PER_IP) {
          logger.warn(`Max WS connections per IP reached for ${clientIP}`);
          ws.close();
          return;
        }

        const client: WSClient = { ws, alive: true, connectedAt: Date.now(), ip: clientIP };
        this.wsClients.add(client);

        this.sendToClient(client, {
          type: 'status_update',
          data: {
            ...this.status,
            layers: this.computeLayers(),
            enforcement: this.computeEnforcement(),
          },
          timestamp: new Date().toISOString(),
        });

        ws.on('pong', () => {
          client.alive = true;
        });

        ws.on('close', () => {
          this.wsClients.delete(client);
        });

        ws.on('error', () => {
          this.wsClients.delete(client);
        });
      });

      // Handle WebSocket upgrade manually (noServer mode)
      this.server.on('upgrade', (req, socket, head) => {
        // DNS-rebinding defense: reject an upgrade whose Host is not the loopback
        // dashboard, before parsing the URL against it. Mirrors the HTTP gate so
        // a rebound hostname cannot open the live event stream either.
        if (!this.isAllowedHost(req.headers.host)) {
          socket.destroy();
          return;
        }
        const { pathname } = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
        if (pathname === '/ws') {
          wss.handleUpgrade(req, socket, head, (ws) => {
            wss.emit('connection', ws, req);
          });
        } else {
          socket.destroy();
        }
      });

      this.server.listen(this.port, '127.0.0.1', () => {
        this.listening = true;
        logger.info(`Dashboard started on http://127.0.0.1:${this.port}`);
        // Token never logged. The launcher (guard-engine) opens the browser at
        // /?token=<authToken>; that one-time token mints the HttpOnly auth
        // cookie used for all subsequent /api/* and /ws traffic.

        // Persist the launch token (0o600) so a separate `pga up` invocation can
        // build the authenticated URL for an already-running daemon instead of
        // opening a bare URL that 401s. Written only once the dashboard is truly
        // listening, so a present token file implies a reachable dashboard.
        this.persistAuthToken();

        if (this.relayConfig) {
          this.startRelayClient(this.relayConfig);
        }

        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    // Remove the persisted launch token so the secret never outlives the
    // dashboard — a stale token would point `pga up` at a dead port. Pass our
    // own token so a shutting-down OLD daemon never deletes a NEWER daemon's
    // live token during a restart/overlap.
    removeDashboardToken(this.authToken);
    this.listening = false;
    this.tokenPersisted = false;

    if (this.relayClient) {
      this.relayClient.disconnect();
      this.relayClient = null;
    }

    return new Promise((resolve) => {
      for (const client of this.wsClients) {
        try {
          client.ws.close();
        } catch {
          /* ignore */
        }
      }
      this.wsClients.clear();

      if (this.server) {
        this.server.close(() => {
          logger.info('Dashboard stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  updateStatus(update: Partial<DashboardStatus>): void {
    this.status = { ...this.status, ...update };
    this.broadcast({
      type: 'status_update',
      data: {
        ...this.status,
        layers: this.computeLayers(),
        enforcement: this.computeEnforcement(),
      },
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Record the outcome of a Layer C (semantic LLM) advisory call so the layer
   * health reflects LIVE reachability, not just config presence. The engine
   * calls this after each attempt: `ok:true` on a successful verdict, `ok:false`
   * with an error message when the provider rejected / timed out / billing-
   * blocked / local model down. Immutable update (new object each time) per the
   * project's no-mutation rule; broadcasts the refreshed layer health.
   */
  reportLayerCOutcome(ok: boolean, error?: string): void {
    const now = Date.now();
    const prev = this.layerCHealth;
    this.layerCHealth = ok
      ? {
          lastSuccessAt: now,
          lastErrorAt: prev?.lastErrorAt ?? null,
          lastError: null,
        }
      : {
          lastSuccessAt: prev?.lastSuccessAt ?? null,
          lastErrorAt: now,
          lastError: error ?? 'semantic layer call failed',
        };
    this.broadcast({
      type: 'status_update',
      data: {
        ...this.status,
        layers: this.computeLayers(),
        enforcement: this.computeEnforcement(),
      },
      timestamp: new Date().toISOString(),
    });
  }

  pushEvent(event: DashboardEvent): void {
    this.recentEvents.push(event);
    if (this.recentEvents.length > this.maxRecentEvents) {
      this.recentEvents.shift();
    }
    this.broadcast(event);
  }

  addVerdict(verdict: ThreatVerdict): void {
    this.status.recentVerdicts.push(verdict);
    if (this.status.recentVerdicts.length > 50) {
      this.status.recentVerdicts.shift();
    }
    this.broadcast({
      type: 'new_verdict',
      data: verdict,
      timestamp: new Date().toISOString(),
    });
  }

  addThreatMapEntry(entry: ThreatMapEntry): void {
    const existing = this.threatMap.find(
      (t) => t.sourceIP === entry.sourceIP && t.attackType === entry.attackType
    );
    if (existing) {
      existing.count += entry.count;
      existing.lastSeen = entry.lastSeen;
    } else {
      this.threatMap.push(entry);
    }
  }

  // ---------------------------------------------------------------------------
  // HTTP request handling
  // ---------------------------------------------------------------------------

  getAuthToken(): string {
    return this.authToken;
  }

  /** True only after the HTTP server actually bound its port (not EADDRINUSE). */
  isListening(): boolean {
    return this.listening;
  }

  /** True only after the launch token was written AND read back successfully. */
  isTokenPersisted(): boolean {
    return this.tokenPersisted;
  }

  /**
   * Re-persist the launch token if it vanished (or no longer matches ours) while
   * the dashboard is still listening. A stray cleanup, a `pga guard stop` that
   * raced a KeepAlive respawn, or a leftover pre-upgrade daemon can leave a LIVE
   * dashboard with no token file on disk — every visit then 401s ("Invalid
   * token") with no way to recover short of a restart. The engine calls this on
   * its periodic status tick so a running dashboard self-heals back to an
   * authenticated, reachable state. No-op when the token file is present and
   * already matches this daemon's token.
   */
  ensureTokenPersisted(): void {
    if (!this.listening) return;
    try {
      if (
        existsSync(DASHBOARD_TOKEN_PATH) &&
        readFileSync(DASHBOARD_TOKEN_PATH, 'utf-8') === this.authToken
      ) {
        return; // present and ours — nothing to heal
      }
    } catch {
      /* unreadable — fall through and rewrite */
    }
    this.persistAuthToken();
  }

  /**
   * Persist the launch token to ~/.panguard-guard/dashboard-token with 0o600 so
   * a separate `pga up` invocation (rerun, already-running daemon, headless,
   * copied URL) can construct the authenticated launch URL. The token is the
   * launch secret that mints the auth cookie, so it is written owner-only and
   * never logged — same handling as the cookie. Best-effort: a write failure
   * just means the CLI falls back to printing guidance instead of a live URL.
   */
  private persistAuthToken(): void {
    // Reliability matters: a dashboard that is LISTENING but has no token on disk
    // 401s every visit ("Invalid token") with no clue. Write, then READ BACK and
    // verify; retry a few times; log an affirmative line on success and an
    // actionable error (never the token value) on final failure so the state is
    // self-debuggable from the daemon log + `pga doctor`.
    let lastErr: unknown = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        if (!existsSync(DASHBOARD_TOKEN_DIR)) {
          mkdirSync(DASHBOARD_TOKEN_DIR, { recursive: true, mode: 0o700 });
        }
        // Atomic write via a temp file + rename so a concurrent reader never sees
        // a half-written token. The temp file is created owner-only from the start.
        const tmpPath = `${DASHBOARD_TOKEN_PATH}.tmp.${process.pid}`;
        writeFileSync(tmpPath, this.authToken, { encoding: 'utf-8', mode: 0o600 });
        renameSync(tmpPath, DASHBOARD_TOKEN_PATH);
        // chmod even if the file pre-existed, to tighten a loosely-created file.
        try {
          chmodSync(DASHBOARD_TOKEN_PATH, 0o600);
        } catch {
          /* platforms without POSIX permissions */
        }
        // Read back and confirm — a silent partial/failed write is exactly the
        // bug this hardens against.
        if (readFileSync(DASHBOARD_TOKEN_PATH, 'utf-8') === this.authToken) {
          this.tokenPersisted = true;
          logger.info(
            `Dashboard launch token persisted (0600) to ${DASHBOARD_TOKEN_PATH}. ` +
              `The authenticated URL is available via "pga status"/"pga up".`
          );
          return;
        }
        lastErr = new Error('readback mismatch');
      } catch (err) {
        lastErr = err;
      }
    }
    // Final failure: escalate to error with the recovery path. Never fatal —
    // the dashboard keeps serving; the CLI degrades to guidance text.
    this.tokenPersisted = false;
    logger.error(
      `Dashboard is serving but its launch token could not be written to ${DASHBOARD_TOKEN_PATH} ` +
        `(${lastErr instanceof Error ? lastErr.message : String(lastErr)}); the dashboard will return ` +
        `401 "Invalid token". Fix: ensure ~/.panguard-guard is writable (chmod 700), then run "pga up" to restart.`
    );
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    // Generate per-request nonce for CSP — eliminates unsafe-inline for scripts
    const nonce = randomBytes(16).toString('base64');

    res.setHeader('Access-Control-Allow-Origin', 'http://127.0.0.1:' + this.port);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' ws://127.0.0.1:${this.port} ws://localhost:${this.port}`
    );

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // DNS-rebinding defense-in-depth: this service binds to loopback only, so the
    // ONLY legitimate Host is 127.0.0.1:PORT / localhost:PORT. Reject any other
    // Host (e.g. a rebound attacker hostname resolving to 127.0.0.1) before any
    // other processing. Belt-and-suspenders on top of the cookie/CORS gate — it
    // does not depend on those staying correct.
    if (!this.isAllowedHost(req.headers.host)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Forbidden: invalid Host header' }));
      return;
    }

    // Parse the auth token ONCE (Authorization header first, then the HttpOnly
    // cookie) so the rate-limit tiering below and the /api gate share a single
    // verdict. Query-param tokens (?token=) are never accepted here — they leak
    // into server logs, browser history, and Referer headers. (The launch token
    // in GET /?token= only mints the cookie in serveIndex; it never authenticates
    // an API call.) timingSafeEqual is guarded by an equal-length short-circuit
    // so it is never handed mismatched-length buffers.
    const authHeader = req.headers.authorization ?? '';
    const headerToken = authHeader.replace('Bearer ', '');
    const cookieToken =
      (req.headers.cookie ?? '')
        .split(';')
        .map((c) => c.trim())
        .find((c) => c.startsWith('panguard_auth='))
        ?.split('=')[1] ?? '';
    const usedHeaderToken = headerToken.length > 0;
    const providedToken = headerToken || cookieToken;
    const authed =
      providedToken.length > 0 &&
      providedToken.length === this.authToken.length &&
      timingSafeEqual(Buffer.from(providedToken), Buffer.from(this.authToken));

    // Tiered rate limiting so an unauthenticated flood can NEVER throttle the
    // real dashboard. Authenticated requests are metered ONLY by the per-token
    // 'auth' budget (checked in the /api/* block); every UNAUTHENTICATED request
    // is metered by the separate 'preauth' bucket here. The two buckets never
    // share a counter, so exhausting the pre-auth cap (401 / 404 / index spam)
    // leaves the authenticated user's API traffic completely untouched — closing
    // the shared-bucket DoS where any local process could 429 the real user.
    // Loopback-only binding makes per-IP keying meaningless, so each tier is a
    // single global bucket, not a per-IP one.
    if (!authed) {
      if (!this.checkRateLimit('preauth', PREAUTH_RATE_LIMIT_MAX)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
        return;
      }
    }

    const url = req.url ?? '/';

    if (url === '/' || url.split('?')[0] === '/') {
      this.serveIndex(req, res, nonce);
      return;
    }

    if (url.startsWith('/api/')) {
      if (!authed) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      // Authenticated budget: enforced ONLY after the token is validated so an
      // unauthenticated caller can never consume it. Keyed on the token tier
      // rather than the always-identical loopback IP.
      if (!this.checkRateLimit('auth', RATE_LIMIT_MAX)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
        return;
      }

      // CSRF defense for state-changing requests. The CSRF-exploitable path is a
      // browser that auto-attaches the SameSite cookie; for it the Origin header
      // MUST be present and match a loopback origin. An ABSENT Origin is NOT
      // treated as same-origin — it is rejected — because a same-origin browser
      // fetch always sends Origin on POST/PUT/DELETE. The only legitimate caller
      // with no Origin is a non-browser client (CLI / script / test), which
      // cannot ride a victim's cookie and instead supplies the token explicitly
      // in the Authorization header — that path is exempt (an attacker's
      // cross-site page cannot set a custom Authorization header).
      if (req.method && req.method !== 'GET' && req.method !== 'HEAD') {
        if (!usedHeaderToken) {
          const origin = req.headers.origin;
          const allowedOrigins = [`http://127.0.0.1:${this.port}`, `http://localhost:${this.port}`];
          if (!origin || !allowedOrigins.includes(origin)) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                error: 'Forbidden: missing or cross-origin Origin on cookie-authenticated request',
              })
            );
            return;
          }
        }
      }
    }

    const pathname = url.split('?')[0];

    switch (pathname) {
      case '/api/status':
        this.jsonResponse(res, this.buildStatusResponse());
        break;
      case '/api/export/sarif':
        if (req.method === 'POST') {
          this.handleSarifExport(res).catch((err: unknown) => {
            logger.error(
              `handleSarifExport error: ${err instanceof Error ? err.message : String(err)}`
            );
            if (!res.headersSent) this.jsonResponse(res, { error: 'Export failed' }, 500);
          });
        } else {
          this.jsonResponse(res, { error: 'Method not allowed' }, 405);
        }
        break;
      case '/api/export/evidence':
        if (req.method === 'POST') {
          // Evidence Pack = signed compliance-audit-evidence generation = an
          // Enterprise feature. Gate server-side (not just hiding the button) so
          // a local process cannot POST this endpoint on a free Community install.
          if (!this.isPaidTier()) {
            this.jsonResponse(
              res,
              {
                error:
                  'Evidence Pack export is an Enterprise feature. See https://panguard.ai/pricing',
              },
              403
            );
            break;
          }
          this.handleEvidenceExport(res).catch((err: unknown) => {
            logger.error(
              `handleEvidenceExport error: ${err instanceof Error ? err.message : String(err)}`
            );
            if (!res.headersSent) this.jsonResponse(res, { error: 'Export failed' }, 500);
          });
        } else {
          this.jsonResponse(res, { error: 'Method not allowed' }, 405);
        }
        break;
      case '/api/events':
        this.jsonResponse(res, this.recentEvents);
        break;
      case '/api/threat-map':
        this.jsonResponse(res, this.threatMap);
        break;
      case '/api/verdicts':
        this.jsonResponse(res, this.status.recentVerdicts);
        break;
      case '/api/config': {
        if (this.getConfig) {
          // Redact secret-bearing fields by KEY name before exposing config to
          // the browser. The dashboard only needs to know a channel is
          // configured — never the secret value. Key-name matching survives
          // config-shape drift (new secret fields are caught automatically).
          // Shared with the CLI `config` dump — see ../redact.ts.
          this.jsonResponse(res, redactSecrets(this.getConfig()));
        } else {
          this.jsonResponse(res, { error: 'Config not available' }, 503);
        }
        break;
      }
      case '/api/skills':
        this.handleSkillsApi(res);
        break;
      case '/api/ai-config':
        // Read-only. The semantic-layer LLM is configured ONLY via the terminal
        // command `pga guard ai`, which reads the key echo-off and writes it
        // AES-256-GCM-encrypted to ~/.panguard/llm.enc (read by the persistent
        // daemon; shell env vars do not reach a launchd/systemd daemon). Never
        // written through HTTP — a dashboard POST that persisted an API key and an
        // arbitrary endpoint was a credential-write + data-exfil surface.
        if (req.method === 'POST') {
          this.jsonResponse(
            res,
            {
              error: 'Read-only: configure the semantic layer with `pga guard ai` in your terminal',
            },
            405
          );
        } else {
          this.handleAiConfigGet(res);
        }
        break;
      case '/api/rules':
        this.handleRulesApi(res);
        break;
      case '/api/threat-cloud':
        if (req.method === 'POST') {
          this.handleThreatCloudPost(req, res);
        } else {
          this.handleThreatCloudGet(res);
        }
        break;
      case '/api/enforce':
        if (req.method === 'POST') {
          this.handleEnforcePost(req, res);
        } else {
          this.jsonResponse(res, { error: 'Method not allowed' }, 405);
        }
        break;
      case '/api/loaded-rules':
        this.handleLoadedRulesApi(res);
        break;
      case '/api/proxy-verdicts':
        this.handleProxyVerdictsApi(res).catch((err: unknown) => {
          logger.error(
            `handleProxyVerdictsApi error: ${err instanceof Error ? err.message : String(err)}`
          );
          if (!res.headersSent) this.jsonResponse(res, { error: 'Read failed' }, 500);
        });
        break;
      case '/api/installed-skills':
        this.handleInstalledSkillsApi(res).catch((err: unknown) => {
          logger.error(
            `handleInstalledSkillsApi error: ${err instanceof Error ? err.message : String(err)}`
          );
          if (!res.headersSent) this.jsonResponse(res, { error: 'Internal error' }, 500);
        });
        break;
      case '/api/skills/quarantine':
        if (req.method === 'POST') {
          this.handleQuarantinePost(req, res).catch((err: unknown) => {
            logger.error(
              `handleQuarantinePost error: ${err instanceof Error ? err.message : String(err)}`
            );
            if (!res.headersSent) this.jsonResponse(res, { error: 'Internal error' }, 500);
          });
        } else {
          this.jsonResponse(res, { error: 'Method not allowed' }, 405);
        }
        break;
      case '/api/skills/whitelist':
        if (req.method === 'POST') {
          this.handleWhitelistPost(req, res).catch((err: unknown) => {
            logger.error(
              `handleWhitelistPost error: ${err instanceof Error ? err.message : String(err)}`
            );
            if (!res.headersSent) this.jsonResponse(res, { error: 'Internal error' }, 500);
          });
        } else {
          this.jsonResponse(res, { error: 'Method not allowed' }, 405);
        }
        break;
      case '/api/skills/unwhitelist':
        if (req.method === 'POST') {
          this.handleUnwhitelistPost(req, res).catch((err: unknown) => {
            logger.error(
              `handleUnwhitelistPost error: ${err instanceof Error ? err.message : String(err)}`
            );
            if (!res.headersSent) this.jsonResponse(res, { error: 'Internal error' }, 500);
          });
        } else {
          this.jsonResponse(res, { error: 'Method not allowed' }, 405);
        }
        break;
      case '/api/skills/quarantined':
        this.handleQuarantinedListApi(res).catch((err: unknown) => {
          logger.error(
            `handleQuarantinedListApi error: ${err instanceof Error ? err.message : String(err)}`
          );
          if (!res.headersSent) this.jsonResponse(res, { error: 'Internal error' }, 500);
        });
        break;
      case '/api/skills/restore':
        if (req.method === 'POST') {
          this.handleRestorePost(req, res).catch((err: unknown) => {
            logger.error(
              `handleRestorePost error: ${err instanceof Error ? err.message : String(err)}`
            );
            if (!res.headersSent) this.jsonResponse(res, { error: 'Internal error' }, 500);
          });
        } else {
          this.jsonResponse(res, { error: 'Method not allowed' }, 405);
        }
        break;
      case '/api/rule-update':
        this.handleRuleUpdateApi(res);
        break;
      case '/api/agents':
        this.handleAgentsApi(res).catch((err: unknown) => {
          logger.error(
            `handleAgentsApi error: ${err instanceof Error ? err.message : String(err)}`
          );
          if (!res.headersSent) this.jsonResponse(res, { error: 'Internal error' }, 500);
        });
        break;
      default:
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
    }
  }

  /**
   * Fixed-window rate limiter. `key` selects the bucket ('preauth' for the
   * unauthenticated reject-path cap, 'auth' for the token-authenticated budget)
   * and `max` its ceiling. Splitting the buckets is what stops an unauthenticated
   * flood from exhausting the authenticated user's quota — the two never share a
   * counter. Loopback-only binding makes per-IP keying meaningless (every caller
   * is 127.0.0.1), so the key is the bucket name, not the source IP.
   */
  private checkRateLimit(key: string, max: number): boolean {
    const now = Date.now();

    // Periodic cleanup of expired entries to prevent unbounded growth
    if (this.rateLimits.size > 100) {
      for (const [k, val] of this.rateLimits) {
        if (now > val.resetAt) this.rateLimits.delete(k);
      }
    }

    const entry = this.rateLimits.get(key);
    if (!entry || now > entry.resetAt) {
      this.rateLimits.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
      return true;
    }
    entry.count++;
    return entry.count <= max;
  }

  /**
   * True when the request's Host header targets this loopback dashboard. The
   * server binds to 127.0.0.1 only, so the sole legitimate Host is
   * 127.0.0.1:PORT or localhost:PORT (the port may be omitted for default
   * ports, which never applies here, but we accept a bare hostname match too).
   * Any other Host — including a rebound attacker hostname resolving to
   * loopback — is rejected. IPv6 loopback ([::1]) is accepted for completeness.
   */
  private isAllowedHost(hostHeader: string | undefined): boolean {
    if (!hostHeader) return false;
    // Host is "hostname[:port]"; an IPv6 literal is bracketed: "[::1]:PORT".
    let hostname: string;
    let port: string;
    if (hostHeader.startsWith('[')) {
      const end = hostHeader.indexOf(']');
      if (end === -1) return false;
      hostname = hostHeader.slice(1, end);
      port = hostHeader.slice(end + 1).replace(/^:/, '');
    } else {
      const colon = hostHeader.lastIndexOf(':');
      if (colon === -1) {
        hostname = hostHeader;
        port = '';
      } else {
        hostname = hostHeader.slice(0, colon);
        port = hostHeader.slice(colon + 1);
      }
    }
    const loopback = hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
    if (!loopback) return false;
    // Port, when present, must match the dashboard port. A bare hostname (no
    // port) is allowed so tooling that drops the port on a default-looking URL
    // still works; loopback + no port cannot reach a foreign origin.
    return port === '' || port === String(this.port);
  }

  private serveIndex(req: IncomingMessage, res: ServerResponse, nonce: string): void {
    // The auth cookie is a LAUNCH SECRET — it is minted only for a request that
    // carries the correct one-time token in the query string (the URL the `pga`
    // CLI prints and opens: http://127.0.0.1:PORT/?token=<authToken>). An
    // UNAUTHENTICATED GET / (no token, or a wrong token — e.g. a malicious local
    // page probing the port) still receives the HTML shell, but NO Set-Cookie,
    // so it cannot reach any /api/* endpoint or the /ws stream. This closes the
    // "GET / hands a valid auth token to any caller" hole: the token comes from
    // the CLI that started the dashboard, never from serving the index.
    const queryToken = this.extractLaunchToken(req.url ?? '/');
    const launched =
      !!queryToken &&
      queryToken.length === this.authToken.length &&
      timingSafeEqual(Buffer.from(queryToken), Buffer.from(this.authToken));

    // Inject nonce into <script> tag for CSP compliance.
    const html = DASHBOARD_HTML.replace('<script>', `<script nonce="${nonce}">`);
    const headers: Record<string, string> = {
      'Content-Type': 'text/html; charset=utf-8',
    };
    if (launched) {
      // HttpOnly + SameSite=Strict: not readable by JS and not attached to
      // cross-site requests. Issued only once the launch token is verified.
      headers['Set-Cookie'] = `panguard_auth=${this.authToken}; HttpOnly; SameSite=Strict; Path=/`;
    }
    res.writeHead(200, headers);
    res.end(html);
  }

  /** Parse the one-time launch token from a `GET /?token=...` request URL. */
  private extractLaunchToken(url: string): string {
    const qIndex = url.indexOf('?');
    if (qIndex === -1) return '';
    try {
      return new URLSearchParams(url.slice(qIndex + 1)).get('token') ?? '';
    } catch {
      return '';
    }
  }

  /**
   * Compose the status envelope returned by /api/status.
   * Adds a `license` field so the SPA can gate Pilot-only UI without making
   * a second round-trip; the underlying tier comes from GuardConfig
   * (cliTier overrides licenseKey) or defaults to community.
   */
  private buildStatusResponse(): DashboardStatus & {
    license: { tier: 'community' | 'pilot' | 'enterprise' | 'free' | 'pro' };
    layers: LayerHealth;
    enforcement: EnforcementStatus;
    hostPlatform: NodeJS.Platform;
  } {
    const cfg = this.getConfig?.();
    const rawTier = cfg?.cliTier ?? this.status.licenseTier ?? 'community';
    const tier = this.normalizeLicenseTier(rawTier);
    return {
      ...this.status,
      licenseTier: tier,
      license: { tier },
      layers: this.computeLayers(),
      enforcement: this.computeEnforcement(),
      // The GUARD HOST's platform (not the browser's). Key-storage copy that
      // claims POSIX 0600 must reflect the machine the file actually lives on —
      // a Windows host viewed from a Mac browser (or vice-versa) would otherwise
      // show the wrong permissions claim.
      hostPlatform: process.platform,
    };
  }

  /**
   * Real per-layer health, derived from live engine state — NOT hard-coded.
   * The dashboard's "Layer A/B Active" used to be static green in the HTML, so it
   * stayed green even with zero rules loaded or the engine stopped. This computes
   * the truth: Layer A (deterministic pattern) is active only when rules are
   * actually loaded AND the engine is running; Layer B (deterministic heuristic +
   * baseline) tracks the running state; Layer C (optional semantic) reflects
   * whether the user has configured a BYO LLM (config.ai) — it is advisory and
   * off-by-default, so "off" is a healthy state, not a fault.
   */
  private computeLayers(): LayerHealth {
    const cfg = this.getConfig?.();
    const ruleCount = this.status.atrRuleCount ?? 0;
    // Detection (Layer A/B) runs in every active mode — including report-only,
    // which still evaluates events and records verdicts, it just takes no OS
    // action. Treating report-only as "idle" was the dashboard saying detection
    // was off while it was in fact firing. (HTML updatePBar already includes it.)
    const running =
      this.status.mode === 'learning' ||
      this.status.mode === 'protection' ||
      this.status.mode === 'report-only';
    const aiConfigured = !!cfg?.ai;
    return {
      a: {
        state: ruleCount > 0 && running ? 'active' : ruleCount > 0 ? 'idle' : 'degraded',
        detail:
          ruleCount > 0
            ? `${ruleCount} pattern rules loaded`
            : 'no rules loaded — pattern detection off; reinstall ATR rules',
      },
      b: {
        // Heuristic correlation runs whenever detection is active. Don't claim a
        // "behavioral baseline" that doesn't exist yet — say plainly whether the
        // baseline has formed (baselineConfidence) instead of a flat green claim.
        state: running ? 'active' : 'idle',
        detail: !running
          ? 'idle — detection not active'
          : (this.status.baselineConfidence ?? 0) > 0
            ? 'heuristic correlation + behavioral baseline'
            : 'heuristic correlation; behavioral baseline still forming',
      },
      c: this.computeLayerC(aiConfigured),
    };
  }

  /**
   * Layer C (optional semantic LLM) health. Its state is NOT config-presence:
   * a configured client whose key expired / hit a billing block / whose local
   * model died is reported 'degraded' (with the live error), matching the
   * honesty bar Layer A already meets (0 rules -> degraded). A configured client
   * with recent success — or one that has simply not been exercised yet — reads
   * 'active'. The cost line is grounded in the user's OWN flagged-event count so
   * a quiet dev box and a noisy CI runner no longer get the identical claim.
   */
  private computeLayerC(aiConfigured: boolean): LayerState {
    if (!aiConfigured) {
      return {
        state: 'off',
        optional: true,
        detail:
          'off · optional advisory LLM. Connect your own model with `pga guard ai` (free local Ollama, or a cloud key that bills only on flagged events). Advisory only — flags for review, never auto-blocks; runs only on already-flagged events.',
      };
    }
    const h = this.layerCHealth;
    // Degraded when the most recent attempt errored and no success has landed
    // since (or the last success is older than the stale window). This is the
    // "expired key / dead Ollama still shows green" fix.
    const errored =
      !!h?.lastErrorAt &&
      (h.lastSuccessAt === null ||
        h.lastErrorAt > h.lastSuccessAt ||
        Date.now() - h.lastSuccessAt > LAYER_C_STALE_SUCCESS_MS);
    // Grounded cost line: reference the user's actual flagged-event volume
    // rather than an unqualified flat "a few cents" claim (findings 26 + 30).
    const flagged = this.status.threatsDetected ?? 0;
    const costLine =
      flagged > 0
        ? `${flagged} flagged event${flagged === 1 ? '' : 's'} so far — a cloud model bills only on these (roughly cents at typical per-event token cost), free with local Ollama`
        : 'no flagged events yet — a cloud model bills only when events are flagged (roughly cents each at typical token cost), free with local Ollama';
    if (errored) {
      return {
        state: 'degraded',
        optional: true,
        detail: `semantic layer configured but the last call failed: ${
          h?.lastError ?? 'unknown error'
        } — advisory verdicts are not landing until it recovers. Re-check the key/model with \`pga guard ai\`.`,
      };
    }
    return {
      state: 'active',
      optional: true,
      detail: `semantic verdict configured (advisory) · runs only on flagged events, not every action · ${costLine}`,
    };
  }

  /**
   * Honest enforcement posture. The dashboard used to print PROTECTED whenever
   * mode === 'protection', even with an all-off enforcement policy that takes no
   * action — the exact "says PROTECTED, prevents nothing" overclaim the audit
   * flagged. Reports what the daemon ACTUALLY does: 'protected' when protection mode
   * is on (the guard + inline blockers — built-in-tool hook + MCP proxy — deny
   * hard-deny threats in real time, the default after `pga up`, no root needed);
   * 'report-only' / 'learning' / 'off' per mode. Honesty overrides: 0 rules ->
   * 'degraded', and a stripped hook / config tamper -> 'tampered' (S5), so PROTECTED
   * can never outlive the actual blocker.
   */
  private computeEnforcement(): EnforcementStatus {
    const cfg = this.getConfig?.();
    const mode = this.status.mode ?? 'learning';
    const ep = cfg?.enforcementPolicy;
    // FAKE-GREEN GUARD (S2): an OS action counts as EFFECTIVELY armed — and can
    // lift the posture to PROTECTED — only if it can ACTUALLY execute on this host.
    // Reporting a config flag as armed when the action can never fire is the exact
    // "says PROTECTED, prevents nothing" overclaim the honesty doctrine forbids.
    //  - block-IP / disable-account shell to pfctl|iptables / dscl|usermod, which
    //    need ROOT. The daemon installs per-user (non-root by design), so on a
    //    non-root install they physically cannot run.
    //  - kill-process / isolate-file run unprivileged, but safety-rules rejects
    //    EVERY target when the allow-list is empty, so an empty allow-list is inert.
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const armed: string[] = [];
    const inertActions: string[] = [];
    if (ep?.blockIPs?.enabled) {
      if (isRoot) armed.push('block IPs');
      else inertActions.push('block IPs (needs root — daemon runs unprivileged)');
    }
    if (ep?.killProcesses?.enabled) {
      if ((ep.killProcesses.allowedProcessNames?.length ?? 0) > 0) armed.push('kill processes');
      else inertActions.push('kill processes (no processes allow-listed)');
    }
    if (ep?.isolateFiles?.enabled) {
      if ((ep.isolateFiles.allowedPaths?.length ?? 0) > 0) armed.push('isolate files');
      else inertActions.push('isolate files (no paths allow-listed)');
    }
    if (ep?.disableAccounts?.enabled) {
      if (isRoot) armed.push('disable accounts');
      else inertActions.push('disable accounts (needs root — daemon runs unprivileged)');
    }
    const osActionsArmed = mode === 'protection' && armed.length > 0;
    // Protection mode = the guard is running with the INLINE blockers (built-in-tool
    // hook guarding the agent's own Bash/Edit/Write/WebFetch + the MCP proxy) DENYING
    // hard-deny threats the moment they happen — no root required, ON by default after
    // `pga up` (the hook installs at 'guarded', which blocks critical/high). That is
    // genuine, working protection, so protection mode reads PROTECTED. The OS-auto-
    // response actions (armed/inert above) are an optional ADVANCED layer surfaced
    // separately, never required for PROTECTED. Honesty is preserved elsewhere: 0 rules
    // -> 'degraded' below, and if the built-in hook is later stripped the S5 self-state
    // check overrides this to 'tampered', so PROTECTED can never outlive the blocker.
    let posture: EnforcementStatus['posture'];
    if (mode === 'protection') posture = 'protected';
    else if (mode === 'report-only') posture = 'report-only';
    else if (mode === 'learning') posture = 'learning';
    else posture = 'off';

    // Detection engine is a no-op with zero rules loaded — the guard cannot
    // detect anything, so an active/report posture would be a fake-green claim.
    // Downgrade to 'degraded' (matches the CLI TUI, which gates on rule count).
    const ruleCount = this.status.atrRuleCount ?? 0;
    if (ruleCount <= 0 && (posture === 'protected' || posture === 'report-only')) {
      posture = 'degraded';
    }

    // S5: config integrity + self-removal override the posture. Never claim
    // PROTECTED/MONITORING when the config was changed outside the guard or a
    // hook/LaunchAgent/proxy was removed — the cockpit must stay honest (S2).
    let integrity: EnforcementStatus['integrity'];
    if (cfg) {
      try {
        const dataDir = cfg.dataDir ?? join(homedir(), '.panguard-guard');
        const v = verifyConfigIntegrity(cfg as unknown as Record<string, unknown>, dataDir);
        const self = checkSelfState(dataDir);
        integrity = {
          status: v.status,
          changedFields: v.findings.length,
          selfRemoval: self.findings.length,
        };
        if (v.status === 'tampered' || v.status === 'manifest-tampered' || !self.ok) {
          posture = 'tampered';
        }
      } catch {
        /* integrity is best-effort — never break the status response */
      }
    }
    return { mode, posture, osActionsArmed, armedActions: armed, inertActions, integrity };
  }

  private normalizeLicenseTier(t: string): 'community' | 'pilot' | 'enterprise' | 'free' | 'pro' {
    const lower = (t ?? '').toLowerCase();
    if (
      lower === 'pilot' ||
      lower === 'enterprise' ||
      lower === 'pro' ||
      lower === 'free' ||
      lower === 'community'
    ) {
      return lower;
    }
    return 'community';
  }

  /** True only for paid tiers (pilot/enterprise/pro) — gates Enterprise-only
   *  features like compliance Evidence Pack export. */
  private isPaidTier(): boolean {
    const cfg = this.getConfig?.();
    const tier = this.normalizeLicenseTier(cfg?.cliTier ?? this.status.licenseTier ?? 'community');
    return tier === 'pilot' || tier === 'enterprise' || tier === 'pro';
  }

  /**
   * Load all loaded ATR rules from disk. Shared between SARIF + Evidence export.
   * Returns the same shape as /api/loaded-rules.
   */
  private loadAtrRulesForExport(): Array<{
    id: string;
    title: string;
    severity: string;
    category: string;
    description: string;
  }> {
    // Prefer the live engine-provided list (always accurate, in-memory).
    // Fall back to scanning YAML on disk for legacy installs.
    if (this.getRulesProvider) {
      try {
        const live = this.getRulesProvider();
        if (live.length > 0) return live;
      } catch {
        /* fall through to disk scan */
      }
    }
    const rulesDir = join(
      this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard'),
      '..',
      'agent-threat-rules',
      'rules'
    );
    const candidates = [
      rulesDir,
      join(homedir(), '.panguard-guard', 'rules'),
      join(homedir(), '.panguard-guard', 'atr', 'rules'),
    ];
    const rules: Array<{
      id: string;
      title: string;
      severity: string;
      category: string;
      description: string;
    }> = [];
    for (const dir of candidates) {
      if (!existsSync(dir)) continue;
      try {
        const files = readdirSync(dir).filter(
          (f: string) => f.endsWith('.yaml') || f.endsWith('.yml')
        );
        for (const file of files) {
          try {
            const content = readFileSync(join(dir, file), 'utf-8');
            const id = content.match(/^id:\s*["']?([^"'\n]+)/m)?.[1]?.trim() ?? file;
            const title = content.match(/^title:\s*["']?([^"'\n]+)/m)?.[1]?.trim() ?? '';
            const severity =
              content.match(/^severity:\s*["']?([^"'\n]+)/m)?.[1]?.trim() ?? 'medium';
            const category =
              content.match(/category:\s*["']?([^"'\n]+)/m)?.[1]?.trim() ?? 'unknown';
            const description =
              content.match(/^description:\s*["']?([^"'\n]+)/m)?.[1]?.trim() ?? '';
            if (id && title) {
              rules.push({
                id,
                title,
                severity,
                category,
                description: description.slice(0, 200),
              });
            }
          } catch {
            // skip unreadable rule file
          }
        }
        if (rules.length > 0) break; // first dir with rules wins
      } catch {
        // skip unreadable dir
      }
    }
    return rules;
  }

  /**
   * Resolve the durable events.jsonl path from config (falls back to the default
   * data dir). This is the REAL on-disk log — exports read it, not the bounded
   * in-memory recentVerdicts snapshot — which is what proves the export reflects
   * what was actually persisted.
   */
  private eventsLogPath(): string {
    const dataDir = this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard');
    return join(dataDir, 'events.jsonl');
  }

  /**
   * Read the durable events chain end-to-end and verify it.
   *
   * Honesty contract: this reads the on-disk events.jsonl (across rotation) via
   * AuditChain.readAll() and verifies the hash chain. A tampered or corrupt log
   * NEVER throws here — the caller catches and marks integrity:'TAMPERED' and
   * still emits the document (an auditor must always get a verdict, even a bad one).
   */
  private async readDurableEventsVerified(): Promise<{
    records: ReportRecord[];
    verify: VerifyResult;
    headSeq: number;
    headHash: string;
  }> {
    const key = await getAuditKey().catch(() => undefined);
    const chain = new AuditChain(this.eventsLogPath(), { key });
    const chained = await chain.readAll();
    const verify = await chain.verify();
    const head = chain.getHead();
    // Unwrap each chained record to its ReportRecord payload (downstream shape).
    const records = chained
      .map((rec) => (rec as ChainedRecord<ReportRecord>).payload)
      .filter((p): p is ReportRecord => !!p && typeof p === 'object');
    return { records, verify, headSeq: head.seq, headHash: head.hash };
  }

  /**
   * Map a hash-chain verify result to an honest integrity label for exports.
   * Collapsing every `ok:false` into 'TAMPERED' was dishonest: a pristine fresh
   * install (reason 'empty', zero events) and a legitimate pre-chain upgrade
   * (reason 'unchained-legacy') are benign, expected states — NOT forgery.
   * 'TAMPERED' is reserved for actual chain-break evidence (hash-break / seq-gap
   * / bad-hmac / truncated). This keeps the honest-status invariant: a clean box
   * must never accuse itself of tampering.
   */
  private static integrityLabelFor(
    verify: VerifyResult
  ): 'VERIFIED' | 'NO_RECORDS' | 'LEGACY_PREFIX' | 'TAMPERED' {
    if (verify.ok) return 'VERIFIED';
    switch (verify.reason) {
      case 'empty':
        return 'NO_RECORDS';
      case 'unchained-legacy':
        return 'LEGACY_PREFIX';
      case 'hash-break':
      case 'seq-gap':
      case 'bad-hmac':
      case 'truncated':
        return 'TAMPERED';
      default:
        // Unknown/future non-ok reason: fail toward the honest-but-cautious
        // label rather than silently claiming VERIFIED.
        return 'TAMPERED';
    }
  }

  /**
   * Real SARIF 2.1.0 export.
   * - tool.driver.rules: every ATR rule actually loaded by this Guard instance.
   * - results: one entry per durable event in the on-disk events.jsonl chain.
   * - level mapping: malicious=error, suspicious=warning, benign=note.
   * - run.properties.attestation.chain: the hash-chain verdict over the durable
   *   log; integrity:'TAMPERED' when verification fails (still emitted).
   *
   * Compatible with GitHub Code Scanning, Microsoft Defender XDR, Sentinel,
   * and any SARIF 2.1.0 consumer.
   */
  private async handleSarifExport(res: ServerResponse): Promise<void> {
    const cfg = this.getConfig?.();
    const workspaceId = (cfg as { workspaceId?: string } | undefined)?.workspaceId ?? 'local';
    const generatedAt = new Date().toISOString();
    const rules = this.loadAtrRulesForExport();

    // Read the DURABLE on-disk events chain (not the in-memory snapshot) and
    // verify it. Never 500 on a tampered/corrupt log — catch and mark.
    let durable: {
      records: ReportRecord[];
      verify: VerifyResult;
      headSeq: number;
      headHash: string;
    };
    try {
      durable = await this.readDurableEventsVerified();
    } catch (err) {
      logger.error(
        `SARIF export durable read failed (emitting TAMPERED): ${
          err instanceof Error ? err.message : String(err)
        }`
      );
      // A read EXCEPTION is a genuine failure (unreadable/corrupt log), not an
      // empty chain — use 'truncated' so integrityLabelFor keeps emitting
      // 'TAMPERED', never the benign 'NO_RECORDS'.
      durable = {
        records: [],
        verify: { ok: false, verifiedCount: 0, firstBadIndex: -1, reason: 'truncated' },
        headSeq: -1,
        headHash: '',
      };
    }

    const severityToLevel = (s: string): 'error' | 'warning' | 'note' | 'none' => {
      const v = s.toLowerCase();
      if (v === 'critical' || v === 'high' || v === 'malicious') return 'error';
      if (v === 'medium' || v === 'suspicious') return 'warning';
      if (v === 'low' || v === 'informational' || v === 'benign') return 'note';
      return 'none';
    };

    const results = durable.records.map((rec, idx) => {
      const v = rec.verdict;
      const ruleId =
        rec.rule?.id ??
        (() => {
          const ruleMatch = (v.evidence ?? []).find((e) => e.source === 'rule_match');
          const ruleData = ruleMatch?.data as { rule_id?: string; ruleId?: string } | undefined;
          return ruleData?.rule_id ?? ruleData?.ruleId ?? 'ATR-UNCLASSIFIED';
        })();
      return {
        ruleId,
        ruleIndex: rules.findIndex((r) => r.id === ruleId),
        level: severityToLevel(v.conclusion),
        message: {
          text: v.reasoning || `Verdict: ${v.conclusion} (confidence ${v.confidence}%)`,
        },
        properties: {
          confidence: v.confidence,
          conclusion: v.conclusion,
          recommendedAction: v.recommendedAction,
          mitreTechnique: v.mitreTechnique,
          verdictIndex: idx,
          // Forensic attribution, username-anonymized for the exported document.
          actor: anonymizeActorForExport(rec.actor),
          decisionId: rec.decisionId,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: `panguard://workspace/${workspaceId}/verdict/${idx}`,
              },
            },
          },
        ],
      };
    });

    // Honest integrity label: 'empty' (fresh install) and 'unchained-legacy'
    // (pre-chain upgrade) are benign and must NOT read as 'TAMPERED'.
    const integrity = DashboardServer.integrityLabelFor(durable.verify);
    const attestationChain = {
      algorithm: 'sha256-hmac',
      verified: durable.verify.ok,
      verifiedCount: durable.verify.verifiedCount,
      firstBadIndex: durable.verify.firstBadIndex,
      reason: durable.verify.reason,
      headSeq: durable.headSeq,
      headHash: durable.headHash,
    };

    const sarif = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'PanGuard Guard',
              version: PANGUARD_VERSION,
              informationUri: 'https://panguard.ai',
              rules: rules.map((r) => ({
                id: r.id,
                name: r.title,
                shortDescription: { text: r.title },
                fullDescription: { text: r.description },
                defaultConfiguration: { level: severityToLevel(r.severity) },
                properties: {
                  category: r.category,
                  severity: r.severity,
                  tags: ['ai-agent', 'atr', r.category, r.severity].filter(Boolean),
                },
                helpUri: `https://atr.panguard.ai/rules/${r.id}`,
              })),
            },
          },
          invocations: [
            {
              // Real outcome: false when the durable audit chain failed to verify
              // (integrity TAMPERED), not an unconditional 'true'. workingDirectory
              // omitted rather than a fabricated fixed path. Times reflect when the
              // report was generated (the export snapshot), not a fake scan window.
              executionSuccessful: durable.verify.ok,
              startTimeUtc: generatedAt,
              endTimeUtc: generatedAt,
            },
          ],
          properties: {
            workspace_id: workspaceId,
            generated_at: generatedAt,
            panguard_version: PANGUARD_VERSION,
            mode: this.status.mode,
            rules_loaded: rules.length,
            threats_detected: this.status.threatsDetected,
            events_processed: this.status.eventsProcessed,
            integrity,
            attestation: { chain: attestationChain },
          },
          // Defence-in-depth: scrub any secret that slipped into event-derived
          // text before it reaches the auditor's file. The attestation chain is
          // hashed over the durable records independently, so scrubbing this
          // human-readable projection does not affect integrity verification.
          results: scrubSecretValues(results),
        },
      ],
    };

    const body = JSON.stringify(sarif, null, 2);
    res.writeHead(200, {
      'Content-Type': 'application/sarif+json',
      'Content-Disposition': `attachment; filename="panguard-${workspaceId}-${generatedAt.slice(0, 10)}.sarif.json"`,
      'Content-Length': Buffer.byteLength(body).toString(),
    });
    res.end(body);
  }

  /**
   * Real Evidence Pack export.
   * - Includes every loaded ATR rule with its severity/category for the auditor.
   * - Includes every verdict from the DURABLE on-disk events.jsonl chain (NOT the
   *   bounded in-memory recentVerdicts snapshot) — verdicts are anonymized.
   * - Embeds attestation.chain {algorithm, verified, verifiedCount, firstBadIndex,
   *   reason, headSeq, headHash} — the hash-chain verdict over the durable log.
   * - Sets top-level integrity:'TAMPERED' when verification fails, and STILL
   *   emits (an auditor must always receive a verdict, even a failing one).
   * - Also keeps a document self-SHA-256 over the DEEP canonical content
   *   (v1.2; keys sorted at every depth so nested content is covered).
   *
   * Suitable for SOC 2 / EU AI Act Article 15 audit submission alongside the
   * deeper enterprise PDF (panguard-enterprise/migrator/src/evidence/pdf.ts).
   */
  private async handleEvidenceExport(res: ServerResponse): Promise<void> {
    const cfg = this.getConfig?.();
    const workspaceId = (cfg as { workspaceId?: string } | undefined)?.workspaceId ?? 'local';
    const generatedAt = new Date().toISOString();
    const rules = this.loadAtrRulesForExport();

    // Read the DURABLE on-disk events chain and verify it. Never 500 on a
    // tampered/corrupt log — catch and mark integrity:'TAMPERED'.
    let durable: {
      records: ReportRecord[];
      verify: VerifyResult;
      headSeq: number;
      headHash: string;
    };
    try {
      durable = await this.readDurableEventsVerified();
    } catch (err) {
      logger.error(
        `Evidence export durable read failed (emitting TAMPERED): ${
          err instanceof Error ? err.message : String(err)
        }`
      );
      // A read EXCEPTION is a genuine failure (unreadable/corrupt log), not an
      // empty chain — use 'truncated' so integrityLabelFor keeps emitting
      // 'TAMPERED', never the benign 'NO_RECORDS'.
      durable = {
        records: [],
        verify: { ok: false, verifiedCount: 0, firstBadIndex: -1, reason: 'truncated' },
        headSeq: -1,
        headHash: '',
      };
    }

    // Honest integrity label: reserve 'TAMPERED' for real chain-break evidence.
    // 'empty' (fresh install) => 'NO_RECORDS'; 'unchained-legacy' (pre-chain
    // upgrade) => 'LEGACY_PREFIX'. See integrityLabelFor.
    const integrity: 'VERIFIED' | 'NO_RECORDS' | 'LEGACY_PREFIX' | 'TAMPERED' =
      DashboardServer.integrityLabelFor(durable.verify);

    const content = {
      kind: 'panguard.evidence-pack',
      // 1.2: attestation.sha256 became a DEEP canonical hash. The 1.1 hash used
      // a JSON.stringify replacer ARRAY, which filters keys at every depth, so
      // it covered only the top-level skeleton — nested verdict/summary content
      // could be edited without breaking the recompute.
      version: '1.2',
      workspace_id: workspaceId,
      generated_at: generatedAt,
      panguard_version: PANGUARD_VERSION,
      mode: this.status.mode,
      // Top-level integrity verdict over the durable audit log.
      integrity,
      summary: {
        threats_total: this.status.threatsDetected,
        events_processed: this.status.eventsProcessed,
        actions_executed: this.status.actionsExecuted,
        rules_active: rules.length,
        rules_loaded: rules.length,
        uptime_ms: this.status.uptime,
        baseline_confidence: this.status.baselineConfidence,
        durable_events: durable.records.length,
      },
      rules_loaded: rules.map((r) => ({
        id: r.id,
        title: r.title,
        severity: r.severity,
        category: r.category,
      })),
      // Scrub secret values out of the free-text verdict fields before they are
      // written into the auditor doc (and before the self-SHA is computed over
      // it, so the hash stays consistent). Covers records that predate the
      // write-path scrubber or carry a secret shape it did not catch.
      verdicts: scrubSecretValues(
        durable.records.map((rec, idx) => ({
          index: idx,
          conclusion: rec.verdict.conclusion,
          confidence: rec.verdict.confidence,
          reasoning: rec.verdict.reasoning,
          recommendedAction: rec.verdict.recommendedAction,
          mitreTechnique: rec.verdict.mitreTechnique,
          evidence_sources: (rec.verdict.evidence ?? []).map((e) => e.source),
          rule: rec.rule,
          decisionId: rec.decisionId,
          // Username-anonymized actor — never leak OS usernames into the auditor doc.
          actor: anonymizeActorForExport(rec.actor),
        }))
      ),
      attestation: {
        method: 'sha256',
        note: 'SHA-256 below is over the canonical JSON of this document (JSON-normalized, object keys deep-sorted at every depth) with attestation.sha256 set to the empty string. Recompute with any canonicalizer that sorts object keys recursively and compare.',
        sha256: '',
        // Hash-chain attestation over the durable on-disk events log.
        chain: {
          algorithm: 'sha256-hmac',
          verified: durable.verify.ok,
          verifiedCount: durable.verify.verifiedCount,
          firstBadIndex: durable.verify.firstBadIndex,
          reason: durable.verify.reason,
          headSeq: durable.headSeq,
          headHash: durable.headHash,
        },
      },
    };

    // Canonical hash: deep-canonical JSON (keys sorted at EVERY depth) over the
    // document with attestation.sha256 emptied. Never use a JSON.stringify
    // replacer ARRAY here — an array acts as a key filter at all depths, so the
    // hash would cover only the top-level skeleton and nested tampering would
    // survive a recompute.
    const canonical = canonicalize(content);
    const hash = createHash('sha256').update(canonical).digest('hex');
    content.attestation.sha256 = hash;

    const body = JSON.stringify(content, null, 2);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="panguard-evidence-${workspaceId}-${generatedAt.slice(0, 10)}.json"`,
      'Content-Length': Buffer.byteLength(body).toString(),
    });
    res.end(body);
  }

  private jsonResponse(res: ServerResponse, data: unknown, statusCode = 200): void {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  // ---------------------------------------------------------------------------
  // Skills + AI Config API
  // ---------------------------------------------------------------------------

  private handleSkillsApi(res: ServerResponse): void {
    const dataDir = this.getConfig?.()?.dataDir;
    const whitelistPath = join(
      dataDir ?? join(homedir(), '.panguard-guard'),
      'skill-whitelist.json'
    );

    if (!existsSync(whitelistPath)) {
      this.jsonResponse(res, { skills: [], total: 0, autoCount: 0, manualCount: 0 });
      return;
    }

    try {
      const raw = readFileSync(whitelistPath, 'utf-8');
      const data = JSON.parse(raw) as {
        whitelist?: Array<{ name: string; source?: string; reason?: string; addedAt?: string }>;
        skills?: Array<{ name: string; source?: string; reason?: string; addedAt?: string }>;
      };
      // Support both formats: engine writes 'whitelist', legacy might use 'skills'
      const skills = data.whitelist ?? data.skills ?? [];
      const autoCount = skills.filter(
        (s) => s.source === 'fingerprint' || s.source === 'static'
      ).length;
      const manualCount = skills.filter(
        (s) => s.source === 'manual' || s.source === 'community'
      ).length;
      this.jsonResponse(res, { skills, total: skills.length, autoCount, manualCount });
    } catch {
      this.jsonResponse(res, { skills: [], total: 0, autoCount: 0, manualCount: 0 });
    }
  }

  private handleAiConfigGet(res: ServerResponse): void {
    if (!this.getConfig) {
      this.jsonResponse(res, { error: 'Config not available' }, 503);
      return;
    }
    const config = this.getConfig();
    // Never return raw config.ai — it carries plaintext apiKey / byokApiKey.
    // Expose only the non-secret shape the SPA needs; presence of a key is a
    // boolean, never the value.
    this.jsonResponse(res, {
      ai: config.ai
        ? {
            provider: config.ai.provider,
            model: config.ai.model,
            // A BYO-LLM endpoint set via `pga guard ai` can legitimately embed a
            // credential in the URL (https://user:token@host/v1 or
            // https://host/v1?key=SECRET). /api/config runs redactSecrets on the
            // whole config, but this hand-picked path must redact too or it leaks
            // the credential into the JSON body + the settings UI input.
            endpoint: DashboardServer.redactEndpointUrl(config.ai.endpoint),
            hasApiKey: !!config.ai.apiKey,
          }
        : null,
      mode: config.mode,
      dashboardEnabled: config.dashboardEnabled,
    });
  }

  // handleAiConfigPost was removed: the dashboard no longer writes LLM
  // credentials or endpoints over HTTP (that was a credential-write + exfil
  // surface). The LLM is configured via env vars only (ANTHROPIC_API_KEY /
  // OPENAI_API_KEY for cloud, or PANGUARD_SEMANTIC=1 with local Ollama).
  // /api/ai-config is now read-only (handleAiConfigGet).

  // ---------------------------------------------------------------------------
  // Validation helpers
  // ---------------------------------------------------------------------------

  /**
   * True when `host` is a private/internal/loopback/link-local address (or
   * `localhost`). Covers IPv4 private ranges, the cloud metadata IP, and IPv6
   * loopback / unique-local (fc00::/7) / link-local (fe80::/10). Self-contained
   * so the SSRF check stays in this file. Accepts bracket-wrapped IPv6 literals.
   */
  private static isPrivateHost(host: string): boolean {
    if (host === 'localhost' || host === '0.0.0.0') return true;
    if (
      host.startsWith('127.') ||
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      host.startsWith('169.254.') // includes the 169.254.169.254 metadata IP
    )
      return true;
    // Block 172.16.0.0/12
    if (host.startsWith('172.')) {
      const second = parseInt(host.split('.')[1] ?? '0', 10);
      if (second >= 16 && second <= 31) return true;
    }
    // IPv6 loopback / unspecified / private (ULA fc00::/7) / link-local (fe80::/10).
    const v6 = (
      host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
    ).toLowerCase();
    if (v6 === '::1' || v6 === '::') return true;
    if (
      v6.startsWith('fc') ||
      v6.startsWith('fd') || // fc00::/7 unique-local
      v6.startsWith('fe8') ||
      v6.startsWith('fe9') ||
      v6.startsWith('fea') ||
      v6.startsWith('feb') // fe80::/10 link-local
    ) {
      return true;
    }
    return false;
  }

  /**
   * Resolve the endpoint hostname to its A/AAAA records and return false if ANY
   * resolves to a private/internal/loopback address — the outbound DNS-rebinding
   * defense. A resolution failure returns false (fail-closed: we do not persist
   * an endpoint we cannot prove is public). An IP-literal host is validated
   * directly without a DNS round-trip.
   */
  private static async endpointResolvesPublic(url: string): Promise<boolean> {
    let hostname: string;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      return false;
    }
    // IP literal (v4 or bracketed v6): check directly, no DNS needed.
    const isV4Literal = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    const isV6Literal =
      hostname.includes(':') || (hostname.startsWith('[') && hostname.endsWith(']'));
    if (isV4Literal || isV6Literal) {
      const mapped = DashboardServer.extractMappedIpv4(hostname);
      return !DashboardServer.isPrivateHost(mapped ?? hostname);
    }
    try {
      const records = await lookup(hostname, { all: true });
      if (records.length === 0) return false;
      for (const r of records) {
        const addr = r.address.toLowerCase();
        const mapped = DashboardServer.extractMappedIpv4(addr);
        if (DashboardServer.isPrivateHost(mapped ?? addr)) return false;
      }
      return true;
    } catch {
      // DNS failure — fail closed rather than persist an unverifiable endpoint.
      return false;
    }
  }

  /**
   * Redact any credential embedded in an endpoint URL before it is returned to
   * the browser. A BYO-LLM endpoint can carry a secret in userinfo
   * (https://user:token@host) or in a query param (?key=..., ?api_key=...,
   * ?token=..., ?access_token=...). We strip userinfo and replace secret-ish
   * query-param VALUES with [redacted], preserving scheme+host+path+port so the
   * settings UI can still show WHERE the model lives. A clean URL is returned
   * unchanged. `undefined` stays `undefined` (channel not configured).
   */
  private static redactEndpointUrl(url: string | undefined): string | undefined {
    if (!url) return url;
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      // Not a parseable URL — if it merely looks secret-ish by the shared value
      // regex, redact wholesale; otherwise pass through unchanged.
      return SECRET_VALUE_RE.test(url) ? REDACTED : url;
    }
    // Strip userinfo (https://user:token@host -> https://host).
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }
    // Redact secret-ish query-param values by key name. SECRET_KEY_RE catches
    // *_key/*_token/etc., but common LLM providers pass credentials as bare
    // `?key=` (Google Gemini) or `?access_key=` which it does not match — cover
    // those explicit credential-bearing param names too.
    const CRED_QUERY_KEY =
      /^(key|apikey|api[-_]?key|access[-_]?key|access[-_]?token|auth[-_]?token|token|secret|password|pwd)$/i;
    for (const k of [...parsed.searchParams.keys()]) {
      if (SECRET_KEY_RE.test(k) || CRED_QUERY_KEY.test(k)) parsed.searchParams.set(k, REDACTED);
    }
    return parsed.toString();
  }

  private static isValidEndpointUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
      if (parsed.hostname.length === 0) return false;

      // Block private/internal IPs to prevent SSRF.
      const h = parsed.hostname.toLowerCase();
      if (h === '[::1]') return false;

      // Normalize an IPv6-mapped IPv4 (e.g. [::ffff:169.254.169.254] or
      // [::ffff:7f00:1]) down to its embedded IPv4 so the private-IP checks
      // below catch it — otherwise an operator can smuggle a private target
      // past the literal-prefix checks.
      const mapped = DashboardServer.extractMappedIpv4(h);
      const candidate = mapped ?? h;

      if (DashboardServer.isPrivateHost(candidate)) return false;

      return true;
    } catch {
      return false;
    }
  }

  /**
   * If `host` is an IPv6-mapped IPv4 address, return the embedded dotted-quad
   * IPv4; otherwise null. Accepts the URL bracket form ([...]), the
   * dotted-quad tail (::ffff:1.2.3.4) and the hex tail (::ffff:0102:0304).
   */
  private static extractMappedIpv4(host: string): string | null {
    // Strip URL IPv6 brackets if present.
    const inner = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    const m = /^::ffff:(.+)$/i.exec(inner);
    const tail = m?.[1];
    if (!tail) return null;
    // Dotted-quad form: ::ffff:1.2.3.4
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(tail)) return tail;
    // Hex form: ::ffff:0102:0304  ->  1.2.3.4
    const hex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(tail);
    if (hex?.[1] && hex[2]) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      if (Number.isNaN(hi) || Number.isNaN(lo)) return null;
      return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Rules + Threat Cloud + Installed Skills API
  // ---------------------------------------------------------------------------

  private handleRulesApi(res: ServerResponse): void {
    const dataDir = this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard');
    const config = this.getConfig?.();

    let lastSync: string | null = null;
    const cachePath = join(dataDir, 'threat-cloud-cache.json');
    if (existsSync(cachePath)) {
      try {
        const cache = JSON.parse(readFileSync(cachePath, 'utf-8')) as { lastSync?: string };
        lastSync = cache.lastSync ?? null;
      } catch {
        /* ignore */
      }
    }

    this.jsonResponse(res, {
      atr: this.status.atrRuleCount ?? 0,
      atrMatchCount: this.status.atrMatchCount ?? 0,
      atrDrafterPatterns: this.status.atrDrafterPatterns ?? 0,
      atrDrafterSubmitted: this.status.atrDrafterSubmitted ?? 0,
      lastSync,
      // Consent-gated, default OFF — not endpoint presence (the endpoint has a
      // hardcoded default, which made this read "enabled" for every user).
      threatCloudEnabled: config?.threatCloudUploadEnabled === true,
      threatCloudConfigured: config?.threatCloudEndpoint !== undefined,
    });
  }

  private handleThreatCloudGet(res: ServerResponse): void {
    const dataDir = this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard');
    const config = this.getConfig?.();

    let stats = { totalUploaded: 0, totalRulesReceived: 0, queueSize: 0 };
    let lastSync: string | null = null;
    const cachePath = join(dataDir, 'threat-cloud-cache.json');
    if (existsSync(cachePath)) {
      try {
        const cache = JSON.parse(readFileSync(cachePath, 'utf-8')) as {
          totalUploaded?: number;
          totalRulesReceived?: number;
          queueSize?: number;
          lastSync?: string;
        };
        stats = {
          totalUploaded: cache.totalUploaded ?? 0,
          totalRulesReceived: cache.totalRulesReceived ?? 0,
          queueSize: cache.queueSize ?? 0,
        };
        lastSync = cache.lastSync ?? null;
      } catch {
        /* ignore */
      }
    }

    let clientId = '';
    // Client ID lives in ~/.panguard/client-id (not dataDir which is ~/.panguard-guard)
    const clientIdPath = join(homedir(), '.panguard', 'client-id');
    if (existsSync(clientIdPath)) {
      try {
        const fullId = readFileSync(clientIdPath, 'utf-8').trim();
        clientId = fullId.slice(0, 8) + '****-****-' + fullId.slice(-4);
      } catch {
        /* ignore */
      }
    }

    // Opt-in, default OFF: only "enabled" when explicitly turned on (=== true).
    const uploadEnabled = config?.threatCloudUploadEnabled === true;
    const endpoint = config?.threatCloudEndpoint ?? 'https://tc.panguard.ai/api';
    // Whether the collective-defense question has been answered at least once
    // (first-run prompt OR a dashboard toggle). Lets the UI distinguish
    // "never asked" from "deliberately off". Never affects the upload gate.
    const consentAsked = existsSync(consentMarkerPath());

    this.jsonResponse(res, {
      // `enabled` reflects actual consent (default OFF) — not endpoint presence.
      // The endpoint ships with a hardcoded default, so keying `enabled` off it
      // reported Threat Cloud as on for everyone, even users who never opted in.
      enabled: config?.threatCloudUploadEnabled === true,
      // `configured` is the old endpoint-presence signal, renamed so the UI can
      // tell "an endpoint is set / reachable" apart from "the user consented".
      configured: config?.threatCloudEndpoint !== undefined,
      connected: lastSync !== null,
      endpoint,
      uploadEnabled,
      consentAsked,
      ...stats,
      clientId,
      lastSync,
    });
  }

  private handleThreatCloudPost(req: IncomingMessage, res: ServerResponse): void {
    if (!this.getConfig) {
      this.jsonResponse(res, { error: 'Config not available' }, 503);
      return;
    }

    let body = '';
    let aborted = false;
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
      if (body.length > 10_000) {
        aborted = true;
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        req.destroy();
      }
    });
    req.on('end', () => {
      void this.finishThreatCloudPost(body, aborted, res);
    });
  }

  /**
   * POST /api/enforce { armed: boolean } — the dashboard "Arm protection" toggle.
   *
   * Arm  => mode 'protection': the PreToolUse hook + MCP proxy BLOCK critical /
   *         high-confidence threats (the offending tool call is denied and simply
   *         does not run — fully reversible, nothing is deleted or killed).
   * Disarm => mode 'report-only': detection + logging stay on, nothing is blocked.
   *
   * Deliberately does NOT touch enforcementPolicy, so the destructive OS actions
   * (kill process / block IP / isolate file / disable account) remain off unless
   * the user configures them separately. Arming can never do something
   * irreversible. Persists to disk AND applies to the live engine (same
   * merge-from-disk pattern as the threat-cloud consent save, so two saves
   * compose instead of clobbering each other).
   */
  private handleEnforcePost(req: IncomingMessage, res: ServerResponse): void {
    if (!this.getConfig) {
      this.jsonResponse(res, { error: 'Config not available' }, 503);
      return;
    }
    let body = '';
    let aborted = false;
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
      if (body.length > 2_000) {
        aborted = true;
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (aborted) return;
      try {
        const update = JSON.parse(body || '{}') as { armed?: unknown };
        if (typeof update.armed !== 'boolean') {
          this.jsonResponse(res, { error: 'Missing boolean "armed"' }, 400);
          return;
        }
        const nextMode: GuardConfig['mode'] = update.armed ? 'protection' : 'report-only';
        const live = this.getConfig!();
        const configPath = join(live.dataDir ?? join(homedir(), '.panguard-guard'), 'config.json');
        const config: GuardConfig = existsSync(configPath) ? loadConfig(configPath) : live;
        const updatedConfig: GuardConfig = { ...config, mode: nextMode };
        saveConfig(updatedConfig);
        if (this.configApplier) this.configApplier(updatedConfig);
        this.jsonResponse(res, { success: true, armed: update.armed, mode: nextMode });
      } catch {
        this.jsonResponse(res, { error: 'Invalid JSON' }, 400);
      }
    });
  }

  /**
   * Body-complete half of handleThreatCloudPost. Split out so it can be `async`
   * — the endpoint SSRF check now resolves DNS (see validateEndpointForWrite),
   * which cannot run inside a synchronous 'end' listener.
   */
  private async finishThreatCloudPost(
    body: string,
    aborted: boolean,
    res: ServerResponse
  ): Promise<void> {
    if (aborted) return;
    try {
      const update = JSON.parse(body) as {
        uploadEnabled?: boolean;
        // Collective-defense single answer. When present it is the source of
        // truth for BOTH telemetryEnabled and threatCloudUploadEnabled (they
        // move together, exactly like the CLI first-run consent prompt) and it
        // records the consent marker. Opt-in: only `true` turns sharing on.
        consentGiven?: boolean;
        endpoint?: string;
        mode?: string;
      };

      if (update.consentGiven !== undefined && typeof update.consentGiven !== 'boolean') {
        this.jsonResponse(res, { error: 'consentGiven must be a boolean' }, 400);
        return;
      }
      if (update.uploadEnabled !== undefined && typeof update.uploadEnabled !== 'boolean') {
        this.jsonResponse(res, { error: 'uploadEnabled must be a boolean' }, 400);
        return;
      }

      if (update.endpoint !== undefined) {
        // Shape check + literal-IP SSRF gate (fast, synchronous).
        if (!DashboardServer.isValidEndpointUrl(update.endpoint)) {
          this.jsonResponse(res, { error: 'Invalid endpoint URL' }, 400);
          return;
        }
        // DNS-resolution SSRF gate: a hostname like tc.attacker.com can resolve
        // to 127.0.0.1 / 169.254.169.254 / a 10.x host and slip past the literal
        // checks. Resolve every A/AAAA record and reject if ANY is private. The
        // outbound TC client re-validates at fetch time (rule-loader path) to
        // close the resolve-then-rebind window; this is the write-time gate.
        const dnsSafe = await DashboardServer.endpointResolvesPublic(update.endpoint);
        if (!dnsSafe) {
          this.jsonResponse(
            res,
            { error: 'Endpoint host resolves to a private or internal address' },
            400
          );
          return;
        }
      }
      // Accept all THREE real modes. Omitting 'report-only' here used to both
      // reject a legitimate report-only save (400) and let the binary UI toggle
      // silently overwrite a user's report-only config with 'learning' on the
      // next save — quietly downgrading their enforcement posture.
      if (
        update.mode !== undefined &&
        update.mode !== 'learning' &&
        update.mode !== 'report-only' &&
        update.mode !== 'protection'
      ) {
        this.jsonResponse(res, { error: 'Invalid mode' }, 400);
        return;
      }

      // Merge base = the CURRENT ON-DISK config, not the stale live config
      // the daemon was constructed with. Two consecutive saves (e.g. a mode
      // change then a consent toggle) used to each spread the stale live
      // config and rewrite the OTHER field back to its launch-time value —
      // the consent POST would clobber a freshly-saved report-only mode back
      // to protection. Re-reading disk makes saves compose instead of fight.
      // Falls back to the live config when no file exists yet (fresh install).
      const live = this.getConfig!();
      const configPath = join(live.dataDir ?? join(homedir(), '.panguard-guard'), 'config.json');
      const config: GuardConfig = existsSync(configPath) ? loadConfig(configPath) : live;
      // consentGiven is the single collective-defense answer: it drives BOTH
      // flags so they can never drift apart (the CLI gate reads both). A plain
      // `uploadEnabled` is still honoured for the legacy upload toggle, but
      // consentGiven wins when both are sent.
      const sharingEnabled =
        update.consentGiven ?? update.uploadEnabled ?? config.threatCloudUploadEnabled;
      const updatedConfig: GuardConfig = {
        ...config,
        threatCloudUploadEnabled: sharingEnabled,
        // Keep the deprecated telemetryEnabled flag in lockstep — the CLI
        // upload gate and consent module both read it.
        telemetryEnabled: update.consentGiven ?? update.uploadEnabled ?? config.telemetryEnabled,
        threatCloudEndpoint: update.endpoint ?? config.threatCloudEndpoint,
        mode: (update.mode as GuardConfig['mode']) ?? config.mode,
      };

      saveConfig(updatedConfig);
      // Push the persisted change into the live daemon so getConfig() /
      // /api/status / enforcement immediately reflect it (no stale read, no
      // UI snap-back). The engine mutates its in-memory config + mode and
      // re-arms enforcement for the new mode. A restart is still required for
      // OS-level response actions, which the UI surfaces as "pending restart".
      if (this.configApplier) {
        this.configApplier(updatedConfig);
      }
      // The user has now answered the collective-defense question from the
      // dashboard, so the CLI first-run prompt must not re-ask and clobber it.
      if (update.consentGiven !== undefined) {
        markConsentAnswered();
      }
      this.jsonResponse(res, { success: true });
    } catch {
      this.jsonResponse(res, { error: 'Invalid JSON' }, 400);
    }
  }

  private handleLoadedRulesApi(res: ServerResponse): void {
    // Reuse the same rules source SARIF / Evidence export uses. Prefers the
    // engine's in-memory rules; falls back to YAML scan on disk. Without this
    // alignment the Rules tab said "No rules match the filters" even when the
    // engine had 394 rules loaded (verified live 2026-05-12).
    try {
      const rules = this.loadAtrRulesForExport();
      this.jsonResponse(res, { rules, total: rules.length });
    } catch {
      this.jsonResponse(res, { rules: [], total: 0 });
    }
  }

  private async handleProxyVerdictsApi(res: ServerResponse): Promise<void> {
    const verdictLog = join(homedir(), '.panguard-guard', 'proxy-verdicts.jsonl');
    if (!existsSync(verdictLog)) {
      this.jsonResponse(res, { verdicts: [], total: 0, verified: true, firstBadIndex: -1 });
      return;
    }

    try {
      const key = await getAuditKey().catch(() => undefined);
      const chain = new AuditChain(verdictLog, { key });
      const records = await chain.readAll();
      const verify = await chain.verify();
      // Unwrap the chain envelope to the original verdict payload, newest first.
      const verdicts = records
        .slice(-50)
        .reverse()
        .map((rec) => {
          const payload = (rec as ChainedRecord<Record<string, unknown>>).payload;
          return payload ?? rec; // legacy lines have no .payload
        });
      this.jsonResponse(res, {
        verdicts,
        total: records.length,
        verified: verify.ok,
        firstBadIndex: verify.firstBadIndex,
        reason: verify.reason,
      });
    } catch (err) {
      // Never 500 on a tampered/corrupt log — report the failure honestly.
      logger.error(
        `Proxy verdicts read failed: ${err instanceof Error ? err.message : String(err)}`
      );
      this.jsonResponse(res, {
        verdicts: [],
        total: 0,
        verified: false,
        firstBadIndex: -1,
        reason: 'empty',
      });
    }
  }

  private async handleInstalledSkillsApi(res: ServerResponse): Promise<void> {
    const dataDir = this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard');
    const whitelistPath = join(dataDir, 'skill-whitelist.json');

    let whitelist: Array<{ name: string; source?: string }> = [];
    if (existsSync(whitelistPath)) {
      try {
        const raw = readFileSync(whitelistPath, 'utf-8');
        const data = JSON.parse(raw) as {
          whitelist?: Array<{ name: string; source?: string }>;
          skills?: Array<{ name: string; source?: string }>;
        };
        whitelist = data.whitelist ?? data.skills ?? [];
      } catch {
        /* ignore */
      }
    }

    const whitelistedNames = new Set(whitelist.map((s) => s.name));

    let allSkills: Array<{
      name: string;
      platform: string;
      command?: string;
      whitelisted: boolean;
      source?: string;
    }> = [];

    try {
      // Cached: skill discovery shares the same expensive platform detection
      // (blocking `claude mcp list`). Serve the last snapshot instantly.
      const discovered = await this.cachedDetect('skills', () => this.computeDiscoveredSkills());
      if (discovered.length > 0 || this.detectCache.has('skills')) {
        const discoveredNames = new Set(discovered.map((s) => s.name));
        allSkills = discovered.map((s) => ({
          name: s.name,
          platform: s.platformId ?? s.platform ?? 'unknown',
          command: s.command,
          whitelisted: whitelistedNames.has(s.name),
          source: whitelist.find((w) => w.name === s.name)?.source,
        }));
        // Merge whitelist entries that were not found by discovery
        for (const w of whitelist) {
          if (!discoveredNames.has(w.name)) {
            allSkills.push({
              name: w.name,
              platform: 'whitelist-only',
              whitelisted: true,
              source: w.source,
            });
          }
        }
      }
    } catch {
      allSkills = whitelist.map((s) => ({
        name: s.name,
        platform: 'unknown',
        whitelisted: true,
        source: s.source,
      }));
    }

    // If discovery returned nothing but whitelist has entries, merge them in
    if (allSkills.length === 0 && whitelist.length > 0) {
      allSkills = whitelist.map((s) => ({
        name: s.name,
        platform: 'whitelist-only',
        whitelisted: true,
        source: s.source,
      }));
    }

    this.jsonResponse(res, {
      skills: allSkills,
      total: allSkills.length,
      whitelisted: allSkills.filter((s) => s.whitelisted).length,
      tracked: allSkills.filter((s) => !s.whitelisted).length,
    });
  }

  /**
   * Read a JSON request body (≤10KB) for the action POST endpoints. Resolves to
   * the parsed object, or null after having already written the error response
   * (payload too large / invalid JSON / stream error) — callers just return on null.
   */
  private readJsonBody(
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<Record<string, unknown> | null> {
    return new Promise((resolveBody) => {
      let body = '';
      let aborted = false;
      req.on('data', (chunk: Buffer) => {
        body += chunk.toString();
        if (body.length > 10_000) {
          aborted = true;
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Payload too large' }));
          req.destroy();
          resolveBody(null);
        }
      });
      req.on('end', () => {
        if (aborted) return;
        try {
          resolveBody(JSON.parse(body || '{}') as Record<string, unknown>);
        } catch {
          this.jsonResponse(res, { error: 'Invalid JSON' }, 400);
          resolveBody(null);
        }
      });
      req.on('error', () => resolveBody(null));
    });
  }

  /**
   * POST /api/skills/quarantine — move a flagged file-based skill into quarantine.
   * Resolves the skill name under ~/.claude/skills/, contains it against path
   * traversal, confirms it exists, then uses the existing FileQuarantine (atomic
   * move + 0o700 perms + restorable manifest). MCP-server config entries are not
   * file-based and cannot be quarantined this way.
   */
  private async handleQuarantinePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readJsonBody(req, res);
    if (body === null) return;
    const name = typeof body['name'] === 'string' ? (body['name'] as string).trim() : '';
    if (!name) {
      this.jsonResponse(res, { error: 'Missing skill name' }, 400);
      return;
    }
    const skillsRoot = join(homedir(), '.claude', 'skills');
    const target = resolve(skillsRoot, name);
    // Containment: the resolved path must stay strictly inside the skills dir.
    if (target === skillsRoot || !target.startsWith(skillsRoot + sep)) {
      this.jsonResponse(res, { error: 'Invalid skill name' }, 400);
      return;
    }
    if (!existsSync(target)) {
      this.jsonResponse(
        res,
        {
          error:
            'Not a file-based skill (no folder under ~/.claude/skills) — remove its config entry instead',
        },
        404
      );
      return;
    }
    try {
      const fq = new FileQuarantine();
      await fq.initialize();
      const record = await fq.quarantine(target, `Quarantined from dashboard: ${name}`);
      logger.warn(`Skill quarantined via dashboard: ${name}`);
      this.jsonResponse(res, { success: true, quarantinePath: record.quarantinePath });
    } catch (err: unknown) {
      this.jsonResponse(
        res,
        { error: `Quarantine failed: ${err instanceof Error ? err.message : String(err)}` },
        500
      );
    }
  }

  /**
   * POST /api/skills/whitelist — mark a skill safe (false positive) by adding it
   * to the local skill-whitelist.json the installed-skills view reads. Atomic
   * write (tmp + rename), owner-only perms.
   */
  private async handleWhitelistPost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readJsonBody(req, res);
    if (body === null) return;
    const name = typeof body['name'] === 'string' ? (body['name'] as string).trim() : '';
    if (!name) {
      this.jsonResponse(res, { error: 'Missing skill name' }, 400);
      return;
    }
    try {
      // Preferred: mutate the LIVE gate. add() computes normalizedName, uses a
      // valid WhitelistSource, updates the in-memory Map the detection engine
      // reads, and persists — so "Mark safe" takes effect immediately and the
      // engine actually stops flagging the skill (was a fake-green before).
      if (this.whitelistManager) {
        // add() returns false when the whitelist is at capacity (the skill was
        // NOT added) — surface that honestly instead of a green success that the
        // gate never matches.
        const added = this.whitelistManager.add(name, 'manual', 'Marked safe from dashboard');
        if (!added) {
          this.jsonResponse(res, { error: 'Whitelist is at capacity — could not mark safe' }, 409);
          return;
        }
        this.jsonResponse(res, { success: true });
        return;
      }
      // Fallback (no engine wired, e.g. relay-only): still write a VALID record —
      // normalizedName + a real source — so a later engine start honors it.
      // Never the old partial record (missing normalizedName) that never matched.
      const dataDir = this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard');
      const whitelistPath = join(dataDir, 'skill-whitelist.json');
      let entries: Array<{
        name: string;
        normalizedName?: string;
        source?: string;
        addedAt?: string;
      }> = [];
      if (existsSync(whitelistPath)) {
        try {
          const raw = JSON.parse(readFileSync(whitelistPath, 'utf-8')) as {
            whitelist?: typeof entries;
            skills?: typeof entries;
          };
          entries = raw.whitelist ?? raw.skills ?? [];
        } catch {
          /* corrupt file — start fresh */
        }
      }
      const normalizedName = normalizeSkillName(name);
      if (
        !entries.some((s) => (s.normalizedName ?? normalizeSkillName(s.name)) === normalizedName)
      ) {
        entries.push({ name, normalizedName, source: 'manual', addedAt: new Date().toISOString() });
      }
      mkdirSync(dataDir, { recursive: true });
      const tmp = `${whitelistPath}.tmp.${process.pid}`;
      writeFileSync(tmp, JSON.stringify({ whitelist: entries }, null, 2), { mode: 0o600 });
      renameSync(tmp, whitelistPath);
      this.jsonResponse(res, { success: true });
    } catch (err: unknown) {
      this.jsonResponse(
        res,
        { error: `Whitelist failed: ${err instanceof Error ? err.message : String(err)}` },
        500
      );
    }
  }

  /**
   * POST /api/skills/unwhitelist — remove a skill from the local whitelist, so a
   * mistaken "Mark safe" is reversible from the dashboard (the whitelist used to
   * be append-only with no in-product undo). Atomic write, owner-only perms.
   */
  private async handleUnwhitelistPost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readJsonBody(req, res);
    if (body === null) return;
    const name = typeof body['name'] === 'string' ? (body['name'] as string).trim() : '';
    if (!name) {
      this.jsonResponse(res, { error: 'Missing skill name' }, 400);
      return;
    }
    try {
      // Preferred: REVOKE on the LIVE gate. revoke() marks the skill revoked so
      // isWhitelisted() returns false immediately AND auto-promotion is blocked,
      // then persists. We must NOT use remove(): remove() deletes the revoked
      // flag, so on the next tool event atr-engine.autoPromote() would silently
      // re-whitelist a stable-fingerprint skill the user just un-trusted (a fake
      // un-trust). revoke() is what the engine's own action handler uses.
      if (this.whitelistManager) {
        const removed = this.whitelistManager.revoke(name, 'Un-trusted from dashboard');
        this.jsonResponse(res, { success: true, removed });
        return;
      }
      const dataDir = this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard');
      const whitelistPath = join(dataDir, 'skill-whitelist.json');
      if (!existsSync(whitelistPath)) {
        this.jsonResponse(res, { success: true, removed: false });
        return;
      }
      let entries: Array<{ name: string; normalizedName?: string; source?: string }> = [];
      try {
        const raw = JSON.parse(readFileSync(whitelistPath, 'utf-8')) as {
          whitelist?: typeof entries;
          skills?: typeof entries;
        };
        entries = raw.whitelist ?? raw.skills ?? [];
      } catch {
        this.jsonResponse(res, { success: true, removed: false });
        return;
      }
      // Match by normalized name so a differently-cased/spaced name still removes.
      const target = normalizeSkillName(name);
      const next = entries.filter(
        (s) => (s.normalizedName ?? normalizeSkillName(s.name)) !== target
      );
      const removed = next.length !== entries.length;
      mkdirSync(dataDir, { recursive: true });
      const tmp = `${whitelistPath}.tmp.${process.pid}`;
      writeFileSync(tmp, JSON.stringify({ whitelist: next }, null, 2), { mode: 0o600 });
      renameSync(tmp, whitelistPath);
      this.jsonResponse(res, { success: true, removed });
    } catch (err: unknown) {
      this.jsonResponse(
        res,
        { error: `Un-whitelist failed: ${err instanceof Error ? err.message : String(err)}` },
        500
      );
    }
  }

  /**
   * GET /api/skills/quarantined — the list of currently quarantined files, so the
   * user can SEE what's quarantined and restore it. The quarantine confirm dialog
   * promises restorability; this + /api/skills/restore make that promise real.
   */
  private async handleQuarantinedListApi(res: ServerResponse): Promise<void> {
    try {
      const fq = new FileQuarantine();
      await fq.initialize();
      const records = fq.getActiveRecords().map((r) => ({
        id: r.id,
        originalPath: r.originalPath,
        reason: r.reason,
        quarantinedAt: r.quarantinedAt,
      }));
      this.jsonResponse(res, { records, total: records.length });
    } catch (err: unknown) {
      logger.error(`quarantined list failed: ${err instanceof Error ? err.message : String(err)}`);
      this.jsonResponse(res, { records: [], total: 0 });
    }
  }

  /**
   * POST /api/skills/restore — restore a quarantined file to its original path,
   * honoring the reversibility the UI promises. Body: { id }.
   */
  private async handleRestorePost(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readJsonBody(req, res);
    if (body === null) return;
    const id = typeof body['id'] === 'string' ? (body['id'] as string).trim() : '';
    if (!id) {
      this.jsonResponse(res, { error: 'Missing quarantine id' }, 400);
      return;
    }
    try {
      const fq = new FileQuarantine();
      await fq.initialize();
      const result = await fq.restore(id);
      if (result.success) {
        logger.warn(`Quarantined file restored via dashboard: ${id}`);
        this.jsonResponse(res, { success: true, message: result.message });
      } else {
        this.jsonResponse(res, { success: false, error: result.message }, 400);
      }
    } catch (err: unknown) {
      this.jsonResponse(
        res,
        { error: `Restore failed: ${err instanceof Error ? err.message : String(err)}` },
        500
      );
    }
  }

  /**
   * GET /api/rule-update — surface the daily notify-only rule-update check that
   * rule-sync writes to <dataDir>/rule-update.json. The backend computed this
   * signal ("newer detection rules published") but nothing read it, so the most
   * actionable security update was invisible. Notify-only: never auto-applies.
   */
  private handleRuleUpdateApi(res: ServerResponse): void {
    const dataDir = this.getConfig?.()?.dataDir ?? join(homedir(), '.panguard-guard');
    const updatePath = join(dataDir, 'rule-update.json');
    if (!existsSync(updatePath)) {
      this.jsonResponse(res, {
        updateAvailable: false,
        currentVersion: null,
        latestVersion: null,
        checkedAt: null,
        neverChecked: true,
      });
      return;
    }
    try {
      const status = JSON.parse(readFileSync(updatePath, 'utf-8'));
      this.jsonResponse(res, status);
    } catch {
      this.jsonResponse(res, {
        updateAvailable: false,
        currentVersion: null,
        latestVersion: null,
        checkedAt: null,
        neverChecked: true,
      });
    }
  }

  /**
   * Load the optional @panguard-ai/panguard-mcp/config module once and cache it.
   * The bare specifier resolves relative to this compiled module (not an
   * attacker-controlled cwd), and we resolve it a single time so no per-request
   * disk re-resolution happens in the daemon. Returns `null` when the optional
   * module is not installed in this configuration.
   */
  private loadMcpConfigModule(): Promise<Record<string, unknown> | null> {
    if (this.mcpConfigModulePromise === null) {
      this.mcpConfigModulePromise = import('@panguard-ai/panguard-mcp/config' as string)
        .then((m) => m as Record<string, unknown>)
        .catch(() => null);
    }
    return this.mcpConfigModulePromise;
  }

  /**
   * Serve a cached detection snapshot instantly; refresh in the background when
   * stale. A request NEVER waits on a fresh compute unless there is nothing
   * cached yet (first call), and even then it dedupes on any in-flight compute
   * (e.g. the start() warm), so the expensive `claude mcp list` runs at most
   * once per TTL rather than once per poll. Warmed at start().
   */
  private cachedDetect<T>(key: string, compute: () => Promise<T>): Promise<T> {
    const c = this.detectCache.get(key);
    const fresh = c !== undefined && Date.now() - c.ts < DashboardServer.DETECT_TTL_MS;
    if (c !== undefined && !fresh && !this.detectInflight.has(key)) {
      // Stale-while-revalidate: kick a background refresh, serve the stale value.
      void this.runDetect(key, compute).catch(() => undefined);
    }
    if (c !== undefined) return Promise.resolve(c.data as T);
    // Nothing cached yet — dedupe on any in-flight compute.
    return this.runDetect(key, compute);
  }

  private runDetect<T>(key: string, compute: () => Promise<T>): Promise<T> {
    const existing = this.detectInflight.get(key);
    if (existing) return existing as Promise<T>;
    const p = (async () => {
      try {
        const data = await compute();
        this.detectCache.set(key, { data, ts: Date.now() });
        return data;
      } finally {
        this.detectInflight.delete(key);
      }
    })();
    this.detectInflight.set(key, p);
    return p;
  }

  private async computeDetectedPlatforms(): Promise<
    Array<{ id: string; name: string; detected: boolean; alreadyConfigured: boolean }>
  > {
    const mcpConfig = await this.loadMcpConfigModule();
    const detect = mcpConfig?.['detectPlatforms'] as
      | (() => Promise<
          Array<{ id: string; name: string; detected: boolean; alreadyConfigured: boolean }>
        >)
      | undefined;
    if (!detect) return [];
    const platforms = await detect();
    return platforms.map((p) => ({
      id: p.id,
      name: p.name,
      detected: p.detected,
      alreadyConfigured: p.alreadyConfigured,
    }));
  }

  private async computeDiscoveredSkills(): Promise<
    Array<{ name: string; platformId?: string; platform?: string; command?: string }>
  > {
    const mcpConfig = await this.loadMcpConfigModule();
    const discover = mcpConfig?.['discoverAllSkills'] as
      | (() => Promise<
          Array<{ name: string; platformId?: string; platform?: string; command?: string }>
        >)
      | undefined;
    if (!discover) return [];
    return discover();
  }

  private async handleAgentsApi(res: ServerResponse): Promise<void> {
    type AgentInfo = {
      id: string;
      name: string;
      detected: boolean;
      alreadyConfigured: boolean;
    };
    let agents: AgentInfo[] = [];
    try {
      // Cached: detection runs a blocking `claude mcp list` (~4.5s). Serve the
      // last snapshot instantly so this polled endpoint never freezes the loop.
      agents = await this.cachedDetect('platforms', () => this.computeDetectedPlatforms());
    } catch {
      /* module not installed — return empty list */
    }
    this.jsonResponse(res, {
      agents,
      total: agents.length,
      detected: agents.filter((a) => a.detected).length,
      configured: agents.filter((a) => a.alreadyConfigured).length,
    });
  }

  // ---------------------------------------------------------------------------
  // WebSocket helpers
  // ---------------------------------------------------------------------------

  private sendToClient(client: WSClient, event: DashboardEvent): void {
    try {
      if (client.ws.readyState === 1) {
        client.ws.send(JSON.stringify(event));
      }
    } catch {
      this.wsClients.delete(client);
    }
  }

  private broadcast(event: DashboardEvent): void {
    for (const client of this.wsClients) {
      this.sendToClient(client, event);
    }

    if (this.relayClient?.isConnected) {
      this.relayClient.sendEvent(event as unknown as Record<string, unknown>);
    }
  }

  // ---------------------------------------------------------------------------
  // Relay client management
  // ---------------------------------------------------------------------------

  private startRelayClient(config: DashboardRelayOptions): void {
    const relayConfig: RelayClientConfig = {
      managerUrl: config.managerUrl,
      agentId: config.agentId,
      token: config.token,
    };

    this.relayClient = new DashboardRelayClient(relayConfig);

    this.relayClient.on('connected', () => {
      logger.info('Dashboard relay connected to Manager');
    });

    this.relayClient.on('disconnected', () => {
      logger.info('Dashboard relay disconnected from Manager');
    });

    this.relayClient.on('error', (err: Error) => {
      logger.warn(`Dashboard relay error: ${err.message}`);
    });

    this.relayClient.on('message', (msg: Record<string, unknown>) => {
      logger.debug(`Relay received command: ${JSON.stringify(msg)}`);
    });

    this.relayClient.connect();
  }

  getRelayClient(): DashboardRelayClient | null {
    return this.relayClient;
  }
}
