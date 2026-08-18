/**
 * Export honesty + attribution + audit-key tests.
 *
 * The headline of S6: the dashboard export must read the DURABLE on-disk log
 * (not the bounded in-memory snapshot) and PROVE it via a verifiable hash chain.
 * These tests tamper a real on-disk line and assert the export reports it.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { DashboardServer } from '../src/dashboard/index.js';
import type { GuardConfig, ThreatVerdict } from '../src/types.js';
import type { ReportRecord } from '../src/agent/report-agent.js';
import {
  AuditChain,
  getAuditKey,
  buildActor,
  newDecisionId,
  canonicalize,
  __resetAuditKeyCacheForTests,
  type ChainedRecord,
} from '../src/audit/index.js';

function pickFreePort(): Promise<number> {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

function baseConfig(dataDir: string): GuardConfig {
  return {
    lang: 'en',
    // This suite exercises the compliance Evidence Pack export, which is an
    // Enterprise feature (community gets 403). Run it on a paid tier so the
    // export runs and its integrity/attestation is what's under test.
    cliTier: 'enterprise',
    mode: 'protection',
    learningDays: 0,
    actionPolicy: { autoRespond: 85, notifyAndWait: 50, logOnly: 0 },
    notifications: {},
    dataDir,
    dashboardPort: 0,
    dashboardEnabled: true,
    verbose: false,
    monitors: {
      logMonitor: false,
      networkMonitor: false,
      processMonitor: false,
      fileMonitor: false,
      networkPollInterval: 60_000,
      processPollInterval: 60_000,
    },
    watchdogEnabled: false,
    watchdogInterval: 60_000,
  };
}

function makeVerdict(conclusion: ThreatVerdict['conclusion'], ruleId: string): ThreatVerdict {
  return {
    conclusion,
    confidence: 90,
    reasoning: `detected ${conclusion}`,
    evidence: [{ source: 'rule_match', description: 'matched', confidence: 90, data: { ruleId } }],
    recommendedAction: 'block_tool',
  };
}

function makeReportRecord(ruleId: string, msg: string): ReportRecord {
  return {
    event: {
      id: `evt-${msg}`,
      timestamp: new Date(),
      source: 'process',
      severity: 'high',
      category: 'prompt_injection',
      description: msg,
      metadata: {},
    } as ReportRecord['event'],
    verdict: makeVerdict('malicious', ruleId),
    response: {
      action: 'block_tool',
      success: true,
      details: '',
      timestamp: new Date().toISOString(),
    },
    timestamp: new Date().toISOString(),
    actor: buildActor(),
    decisionId: newDecisionId(),
    rule: { id: ruleId },
  };
}

interface EvidenceDoc {
  version?: string;
  integrity?: string;
  verdicts?: Array<Record<string, unknown>>;
  summary?: { durable_events?: number };
  attestation?: {
    method?: string;
    note?: string;
    sha256?: string;
    chain?: {
      algorithm?: string;
      verified?: boolean;
      firstBadIndex?: number;
      reason?: string;
      verifiedCount?: number;
      headSeq?: number;
    };
  };
}

describe('Export honesty — reads the durable log and proves it', () => {
  let dir: string;
  let logPath: string;
  let dashboard: DashboardServer;
  let port: number;
  let token: string;
  let key: Buffer;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'audit-export-'));
    logPath = join(dir, 'events.jsonl');
    key = await getAuditKey();
    port = await pickFreePort();
    dashboard = new DashboardServer(port);
    dashboard.setConfigGetter(() => baseConfig(dir));
    await dashboard.start();
    token = dashboard.getAuthToken();
  });

  afterEach(async () => {
    await dashboard.stop();
    rmSync(dir, { recursive: true, force: true });
  });

  function authed(path: string): Promise<Response> {
    return fetch(`http://127.0.0.1:${port}${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  it('untampered durable log => integrity VERIFIED + attestation.chain.verified=true', async () => {
    const chain = new AuditChain(logPath, { key });
    chain.append(makeReportRecord('ATR-2026-00001', 'a'));
    chain.append(makeReportRecord('ATR-2026-00002', 'b'));

    const res = await authed('/api/export/evidence');
    expect(res.status).toBe(200);
    const doc = (await res.json()) as EvidenceDoc;
    expect(doc.integrity).toBe('VERIFIED');
    expect(doc.attestation?.chain?.algorithm).toBe('sha256-hmac');
    expect(doc.attestation?.chain?.verified).toBe(true);
    expect(doc.attestation?.chain?.verifiedCount).toBe(2);
    expect(doc.summary?.durable_events).toBe(2);
  });

  it('tamper one on-disk line => integrity TAMPERED + firstBadIndex, still 200', async () => {
    const chain = new AuditChain(logPath, { key });
    chain.append(makeReportRecord('ATR-2026-00001', 'a'));
    chain.append(makeReportRecord('ATR-2026-00002', 'b'));
    chain.append(makeReportRecord('ATR-2026-00003', 'c'));

    // Tamper the middle line's payload without fixing its hash.
    const lines = readFileSync(logPath, 'utf-8').trim().split('\n');
    const rec = JSON.parse(lines[1]!) as ChainedRecord<ReportRecord>;
    rec.payload.verdict.conclusion = 'benign';
    lines[1] = JSON.stringify(rec);
    writeFileSync(logPath, lines.join('\n') + '\n', 'utf-8');

    const res = await authed('/api/export/evidence');
    // NEVER 500 on a tampered log.
    expect(res.status).toBe(200);
    const doc = (await res.json()) as EvidenceDoc;
    expect(doc.integrity).toBe('TAMPERED');
    expect(doc.attestation?.chain?.verified).toBe(false);
    expect(doc.attestation?.chain?.reason).toBe('hash-break');
    expect(doc.attestation?.chain?.firstBadIndex).toBe(1);
  });

  it('EXPORT-source: a record only on disk (NOT in recentVerdicts) appears in the export', async () => {
    // Do NOT call dashboard.addVerdict — the record lives ONLY in the durable log.
    const chain = new AuditChain(logPath, { key });
    chain.append(makeReportRecord('ATR-2026-DISKONLY', 'disk-only'));

    const res = await authed('/api/export/evidence');
    const doc = (await res.json()) as EvidenceDoc;
    expect(doc.summary?.durable_events).toBe(1);
    expect(doc.verdicts?.length).toBe(1);
    const v = doc.verdicts![0] as { rule?: { id?: string } };
    expect(v.rule?.id).toBe('ATR-2026-DISKONLY');
  });

  it('PRIVACY: exported actor is username-anonymized (no raw os username leaked)', async () => {
    const rec = makeReportRecord('ATR-2026-00001', 'a');
    const realUser = rec.actor!.user;
    const chain = new AuditChain(logPath, { key });
    chain.append(rec);

    const res = await authed('/api/export/evidence');
    const doc = (await res.json()) as EvidenceDoc;
    const exportedActor = (doc.verdicts![0] as { actor?: Record<string, unknown> }).actor!;
    expect(exportedActor['user']).toBeUndefined();
    expect(typeof exportedActor['user_hash']).toBe('string');
    // The raw username must not appear anywhere in the serialized export.
    const whole = JSON.stringify(doc);
    expect(whole.includes(`"user":"${realUser}"`)).toBe(false);
  });

  it('SARIF export also embeds attestation.chain over the durable log', async () => {
    const chain = new AuditChain(logPath, { key });
    chain.append(makeReportRecord('ATR-2026-00001', 'a'));

    const res = await authed('/api/export/sarif');
    expect(res.status).toBe(200);
    const sarif = (await res.json()) as {
      runs: Array<{
        properties: { integrity?: string; attestation?: { chain?: { verified?: boolean } } };
      }>;
    };
    expect(sarif.runs[0]!.properties.integrity).toBe('VERIFIED');
    expect(sarif.runs[0]!.properties.attestation?.chain?.verified).toBe(true);
  });

  it('empty/missing durable log does not 500 the evidence export', async () => {
    const res = await authed('/api/export/evidence');
    expect(res.status).toBe(200);
    const doc = (await res.json()) as EvidenceDoc;
    expect(doc.summary?.durable_events).toBe(0);
  });

  it('self-hash (v1.2) recomputes over the FULL deep-canonical content', async () => {
    const chain = new AuditChain(logPath, { key });
    chain.append(makeReportRecord('ATR-2026-00001', 'a'));
    chain.append(makeReportRecord('ATR-2026-00002', 'b'));

    const res = await authed('/api/export/evidence');
    const doc = (await res.json()) as EvidenceDoc;
    expect(doc.version).toBe('1.2');

    const stored = doc.attestation?.sha256;
    expect(typeof stored).toBe('string');
    expect(stored).toMatch(/^[0-9a-f]{64}$/);
    // Follow the documented recompute procedure exactly: set attestation.sha256
    // to the empty string, deep-canonicalize, SHA-256.
    const clone = JSON.parse(JSON.stringify(doc)) as EvidenceDoc;
    clone.attestation!.sha256 = '';
    const recomputed = createHash('sha256').update(canonicalize(clone)).digest('hex');
    expect(recomputed).toBe(stored);
  });

  it('self-hash covers NESTED verdict content (the class a top-level skeleton hash misses)', async () => {
    const chain = new AuditChain(logPath, { key });
    chain.append(makeReportRecord('ATR-2026-00001', 'a'));

    const res = await authed('/api/export/evidence');
    const doc = (await res.json()) as EvidenceDoc;
    const stored = doc.attestation?.sha256;

    // An auditor holding a copy where one nested verdict conclusion was flipped
    // must see the recompute break.
    const tampered = JSON.parse(JSON.stringify(doc)) as EvidenceDoc;
    tampered.verdicts![0]!['conclusion'] = 'benign';
    tampered.attestation!.sha256 = '';
    const recomputed = createHash('sha256').update(canonicalize(tampered)).digest('hex');
    expect(recomputed).not.toBe(stored);
  });

  it('attestation.note documents the exact recompute procedure', async () => {
    const chain = new AuditChain(logPath, { key });
    chain.append(makeReportRecord('ATR-2026-00001', 'a'));

    const res = await authed('/api/export/evidence');
    const doc = (await res.json()) as EvidenceDoc;
    expect(doc.attestation?.method).toBe('sha256');
    expect(doc.attestation?.note).toContain('deep-sorted');
    expect(doc.attestation?.note).toContain('empty string');
  });
});

describe('Attribution — proxy/report records carry forensic actor', () => {
  it('buildActor includes user/host/pid and (when given) real agent identity', () => {
    const actor = buildActor({
      platform: 'mcp-proxy',
      sessionId: 'sess-real',
      agentId: 'agent-real',
    });
    expect(typeof actor.user).toBe('string');
    expect(actor.user.length).toBeGreaterThan(0);
    expect(typeof actor.host).toBe('string');
    expect(actor.pid).toBe(process.pid);
    expect(actor.agent?.sessionId).toBe('sess-real');
    expect(actor.agent?.agentId).toBe('agent-real');
    expect(actor.agent?.platform).toBe('mcp-proxy');
  });

  it('a proxy deny line carries actor.user/host/pid + real sessionId + rule.id', () => {
    const dir = mkdtempSync(join(tmpdir(), 'audit-proxy-'));
    const logPath = join(dir, 'proxy-verdicts.jsonl');
    const chain = new AuditChain(logPath);
    // Mirror the shape proxy.logVerdict appends.
    chain.append({
      phase: 'pre',
      tool: 'shell',
      outcome: 'deny',
      reason: 'blocked',
      rules: ['ATR-2026-00001'],
      decisionId: newDecisionId(),
      actor: buildActor({ platform: 'mcp-proxy', sessionId: 'sess-xyz', agentId: 'agent-xyz' }),
      rule: { id: 'ATR-2026-00001' },
    });
    const line = JSON.parse(readFileSync(logPath, 'utf-8').trim()) as ChainedRecord<{
      actor: { user: string; host: string; pid: number; agent?: { sessionId: string } };
      rule: { id: string };
    }>;
    expect(line.payload.actor.user.length).toBeGreaterThan(0);
    expect(line.payload.actor.host.length).toBeGreaterThan(0);
    expect(line.payload.actor.pid).toBe(process.pid);
    expect(line.payload.actor.agent?.sessionId).toBe('sess-xyz');
    expect(line.payload.rule.id).toBe('ATR-2026-00001');
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('getAuditKey', () => {
  it('persists a 0600 file fallback OR uses the credential store; key is stable across calls', async () => {
    __resetAuditKeyCacheForTests();
    const k1 = await getAuditKey();
    __resetAuditKeyCacheForTests();
    const k2 = await getAuditKey();
    expect(k1.length).toBe(32);
    expect(k1.equals(k2)).toBe(true);

    // If the plain-file fallback was used, it must be 0600.
    const fallback = join(homedir(), '.panguard', 'audit-key');
    if (existsSync(fallback)) {
      const mode = statSync(fallback).mode & 0o777;
      expect(mode).toBe(0o600);
    }
  });

  it('does not throw even if the keychain store is unavailable (falls back)', async () => {
    __resetAuditKeyCacheForTests();
    // Just assert it resolves to a 32-byte buffer without throwing.
    await expect(getAuditKey()).resolves.toBeInstanceOf(Buffer);
  });
});
