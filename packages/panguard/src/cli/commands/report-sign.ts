/**
 * `pga report sign verify` - offline verification of issuer-signed audit reports.
 * `pga report sign verify` - 發行方簽章稽核報告的離線驗證。
 *
 * The free half of the trust promise on /trust/signing-key: audit reports
 * issued by PanGuard AI carry a PGA-SIG-V1 issuer signature, and anyone -
 * auditor, partner, regulator - can verify one offline:
 *
 *   pga report sign verify <report.json> --expect-key <key_id>
 *
 * Verification recomputes the canonical hash FROM THE REPORT BODY (never
 * trusting the stated integrity.sha256), then checks the embedded Ed25519
 * block: embedded key must hash to the embedded key_id, signature must match
 * the context-bound payload. WHICH key to trust comes from outside the
 * document: the bundled published key_id list below (delivered through the
 * signed npm package), or an explicit --expect-key pin.
 *
 * SIGNING is not here: issuer key lifecycle (keygen/show), hash
 * counter-signing (Mode B) and one-step issuing (Mode A) live in the private
 * enterprise tooling. Verification needs no license; signing needs the issuer.
 *
 * @module @panguard-ai/panguard/cli/commands/report-sign
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';

import { verifyAuditReport, type AuditReportVerifyResult } from '@panguard-ai/core';

/**
 * Published issuer key_ids - the active keys listed at
 * website /.well-known/panguard-signing-key.json. Keep the two in sync: the
 * .well-known file is the authoritative publication, this copy makes offline
 * verification work out of the box. Per the published policy, a report signed
 * by a key_id not listed (and not explicitly pinned) must not be trusted.
 */
export const TRUSTED_ISSUER_KEY_IDS: readonly string[] = ['pgk1-621b5f58dbfa5e2c'];

/** Injectable output sink so tests can capture CLI output without spawning. */
export interface ReportSignIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

const defaultIo: ReportSignIo = {
  out: (line: string) => console.log(line),
  err: (line: string) => console.error(line),
};

export interface RunReportSignVerifyOptions {
  /** Require the report to be issuer-signed by exactly this key_id. */
  expectKey?: string;
  /** Emit machine-readable JSON instead of human output. */
  json?: boolean;
  /** Trusted key_id list override (tests / air-gapped pinning). */
  trustedKeyIds?: readonly string[];
}

/** Exit codes: 0 = verified, 1 = not verified, 2 = usage/environment error. */
export async function runReportSignVerify(
  file: string,
  opts: RunReportSignVerifyOptions,
  io: ReportSignIo = defaultIo
): Promise<number> {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (err) {
    io.err(`Cannot read ${file}: ${messageOf(err)}`);
    return 2;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    io.err(`${file} is not valid JSON: ${messageOf(err)}`);
    return 2;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    io.err(`${file} must contain a JSON object at the top level.`);
    return 2;
  }

  const result = verifyAuditReport(parsed as Record<string, unknown>, {
    trustedKeyIds: opts.trustedKeyIds ?? TRUSTED_ISSUER_KEY_IDS,
    ...(opts.expectKey !== undefined ? { expectKeyId: opts.expectKey } : {}),
  });

  if (opts.json === true) {
    io.out(JSON.stringify({ file, ...result }));
    return result.ok ? 0 : 1;
  }
  return emitHuman(io, file, result);
}

function emitHuman(io: ReportSignIo, file: string, result: AuditReportVerifyResult): number {
  if (!result.ok) {
    io.err(`NOT VERIFIED (${result.reason ?? 'unknown'}): ${file}`);
    if (result.detail !== undefined) io.err(`  ${result.detail}`);
    return 1;
  }
  if (result.status === 'verified-issuer') {
    io.out(`VERIFIED: ${file}`);
    io.out(`  integrity   body matches SHA-256 ${result.sha256 ?? ''}`);
    io.out(
      `  signature   Ed25519 valid (issuer=${result.issuer ?? ''}, key_id=${result.keyId ?? ''}, jurisdiction=${result.jurisdiction ?? ''})`
    );
    io.out(
      result.trustedKey === true
        ? '  trust       key_id is on the published trust list (/trust/signing-key)'
        : '  trust       key_id pinned via --expect-key (not on the published list)'
    );
    return 0;
  }
  // Hash-only outcomes: the document matches its stated hash, but there is no
  // offline-verifiable issuer signature - say so plainly.
  io.out(`HASH VERIFIED (no issuer signature): ${file}`);
  io.out(`  integrity   body matches SHA-256 ${result.sha256 ?? ''}`);
  io.out(
    result.status === 'hash-only-server'
      ? '  signature   server-signed: offline verification of the server key is not yet available'
      : `  signature   unsigned (${result.detail ?? 'unknown reason'})`
  );
  return 0;
}

/** Commander tree: report > sign > verify (verification only - signing is enterprise-side). */
export function reportCommand(): Command {
  const verify = new Command('verify')
    .description('Offline-verify an issuer-signed audit report against the published key')
    .argument('<file>', 'audit report JSON')
    .option('--expect-key <keyId>', 'require this exact issuer key_id (pgk1-...)')
    .option('--json', 'machine-readable output')
    .action(async (file: string, opts: RunReportSignVerifyOptions) => {
      process.exitCode = await runReportSignVerify(file, opts);
    });

  const sign = new Command('sign').description(
    'Audit report signature tools (PGA-SIG-V1) - verification is free; issuing lives in the enterprise tooling'
  );
  sign.addCommand(verify);

  const report = new Command('report').description(
    'Audit report verification (PGA-SIG-V1 issuer signatures)'
  );
  report.addCommand(sign);
  return report;
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
