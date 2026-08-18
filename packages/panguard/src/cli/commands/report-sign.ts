/**
 * `pga report sign` / `pga report sign verify` - PGA-SIG-V1 report signing.
 * `pga report sign` / `pga report sign verify` - PGA-SIG-V1 報告簽章與驗證。
 *
 * Implements the public trust promise on /trust/signing-key: audit reports
 * issued by PanGuard AI are signed with the issuer Ed25519 key, and anyone can
 * verify a report OFFLINE with the published public key:
 *
 *   pga report sign verify <report.json> --expect-key <key_id>
 *
 * Signing is issuer-side only: the private key comes from the
 * PANGUARD_SIGNING_KEY environment variable or --key-file, and is never
 * shipped, logged, or echoed. Verification needs no secrets - the published
 * public key is bundled below as the default trust store (delivered through
 * the signed npm package), and --key can override it for key rotation.
 *
 * NOTE: this module is deliberately independent of the enterprise report
 * GENERATOR (which stays out of the free CLI). Verification is a trust
 * primitive and must be free for every auditor, regulator, and customer.
 *
 * @module @panguard-ai/panguard/cli/commands/report-sign
 */

import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'node:fs';

import { signReport, verifyReport } from '@panguard-ai/core';

/** Environment variable holding the issuer private key PEM (issuer-side only). */
export const SIGNING_KEY_ENV = 'PANGUARD_SIGNING_KEY';

/**
 * Bundled trust store: the issuer public keys published at
 * website /.well-known/panguard-signing-key.json. Keep the two in sync - the
 * .well-known file is the authoritative publication, this copy makes offline
 * verification work out of the box.
 */
export const TRUSTED_ISSUER_KEYS: ReadonlyArray<{ keyId: string; publicKeyPem: string }> = [
  {
    keyId: 'pgk1-621b5f58dbfa5e2c',
    publicKeyPem:
      '-----BEGIN PUBLIC KEY-----\n' +
      'MCowBQYDK2VwAyEAE8yWwjJ9K3FUibtTZq640dHJVEGw26AM8NiM749fzqU=\n' +
      '-----END PUBLIC KEY-----\n',
  },
];

/** Injectable output sink so tests can capture CLI output without spawning. */
export interface ReportSignIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

const defaultIo: ReportSignIo = {
  out: (line: string) => console.log(line),
  err: (line: string) => console.error(line),
};

export interface RunReportSignOptions {
  /** Path to the issuer private key PEM. Default: env PANGUARD_SIGNING_KEY. */
  keyFile?: string;
  /** Output path. Default: <file>.signed.json next to the input. */
  out?: string;
}

export interface RunReportSignVerifyOptions {
  /** Require the report to be signed by exactly this key_id. */
  expectKey?: string;
  /** Trusted public key PEM file - overrides the bundled trust store. */
  key?: string;
  /** Emit machine-readable JSON instead of human output. */
  json?: boolean;
}

/** Exit codes: 0 = ok, 1 = verification failed, 2 = usage/environment error. */
export async function runReportSign(
  file: string,
  opts: RunReportSignOptions,
  io: ReportSignIo = defaultIo
): Promise<number> {
  const doc = readJsonObject(file, io);
  if (doc === null) return 2;

  let privateKeyPem: string;
  if (opts.keyFile !== undefined) {
    try {
      privateKeyPem = readFileSync(opts.keyFile, 'utf8');
    } catch (err) {
      io.err(`Cannot read key file ${opts.keyFile}: ${messageOf(err)}`);
      return 2;
    }
  } else {
    const fromEnv = process.env[SIGNING_KEY_ENV];
    if (fromEnv === undefined || fromEnv.trim() === '') {
      io.err(
        `No signing key: set ${SIGNING_KEY_ENV} to the issuer private key PEM or pass --key-file <path>.`
      );
      return 2;
    }
    privateKeyPem = fromEnv;
  }

  let signed: Record<string, unknown>;
  try {
    signed = signReport(doc, privateKeyPem);
  } catch {
    // Never include crypto library detail here - it can quote the bad key input.
    io.err('Signing failed: the provided key is not a valid Ed25519 private key PEM.');
    return 2;
  }

  const outPath = opts.out ?? defaultSignedPath(file);
  try {
    writeFileSync(outPath, JSON.stringify(signed, null, 2) + '\n', 'utf8');
  } catch (err) {
    io.err(`Cannot write ${outPath}: ${messageOf(err)}`);
    return 2;
  }

  const envelope = signed['signature'] as { key_id: string };
  io.out(`Signed with ${envelope.key_id} -> ${outPath}`);
  return 0;
}

/** Exit codes: 0 = verified, 1 = not verified, 2 = usage/environment error. */
export async function runReportSignVerify(
  file: string,
  opts: RunReportSignVerifyOptions,
  io: ReportSignIo = defaultIo
): Promise<number> {
  const doc = readJsonObject(file, io);
  if (doc === null) return 2;

  const claimedKeyId = readClaimedKeyId(doc);

  let publicKeyPem: string;
  if (opts.key !== undefined) {
    try {
      publicKeyPem = readFileSync(opts.key, 'utf8');
    } catch (err) {
      io.err(`Cannot read key file ${opts.key}: ${messageOf(err)}`);
      return 2;
    }
  } else {
    const trusted =
      claimedKeyId === undefined
        ? TRUSTED_ISSUER_KEYS[0]
        : TRUSTED_ISSUER_KEYS.find((k) => k.keyId === claimedKeyId);
    if (trusted === undefined) {
      const known = TRUSTED_ISSUER_KEYS.map((k) => k.keyId).join(', ');
      return emitFailure(
        io,
        opts,
        file,
        claimedKeyId,
        'unknown-key',
        `Report claims key_id ${claimedKeyId ?? '(none)'} which is not in the bundled trust store (${known}). ` +
          'Cross-check /.well-known/panguard-signing-key.json or pass --key <public-key.pem>.'
      );
    }
    publicKeyPem = trusted.publicKeyPem;
  }

  const result = verifyReport(doc, {
    publicKeyPem,
    ...(opts.expectKey !== undefined ? { expectKeyId: opts.expectKey } : {}),
  });

  if (!result.ok) {
    return emitFailure(
      io,
      opts,
      file,
      result.keyId ?? claimedKeyId,
      result.reason ?? 'bad-signature',
      `NOT VERIFIED (${result.reason ?? 'bad-signature'}): ${file}`
    );
  }

  if (opts.json === true) {
    io.out(
      JSON.stringify({
        ok: true,
        file,
        keyId: result.keyId,
        payloadSha256: result.payloadSha256,
        signedAt: result.signedAt,
      })
    );
  } else {
    io.out(`VERIFIED: ${file}`);
    io.out(`  key_id      ${result.keyId ?? ''}`);
    io.out(`  signed_at   ${result.signedAt ?? ''}`);
    io.out(`  payload_sha ${result.payloadSha256 ?? ''}`);
  }
  return 0;
}

/** Commander tree: report > sign (default action) > verify. */
export function reportCommand(): Command {
  const verify = new Command('verify')
    .description('Verify a signed report offline against the published issuer key')
    .argument('<file>', 'signed report JSON')
    .option('--expect-key <keyId>', 'require this exact issuer key_id')
    .option('--key <path>', 'trusted public key PEM (overrides the bundled trust store)')
    .option('--json', 'machine-readable output')
    .action(async (file: string, opts: RunReportSignVerifyOptions) => {
      process.exitCode = await runReportSignVerify(file, opts);
    });

  const sign = new Command('sign')
    .description(`Sign a report JSON with the issuer private key (${SIGNING_KEY_ENV})`)
    .argument('<file>', 'report JSON to sign')
    .option('--key-file <path>', `issuer private key PEM (default: env ${SIGNING_KEY_ENV})`)
    .option('--out <path>', 'output path (default: <file>.signed.json)')
    .action(async (file: string, opts: RunReportSignOptions) => {
      process.exitCode = await runReportSign(file, opts);
    });
  sign.addCommand(verify);

  const report = new Command('report').description(
    'Audit report signing and verification (PGA-SIG-V1)'
  );
  report.addCommand(sign);
  return report;
}

// ---------------------------------------------------------------------------

function readJsonObject(file: string, io: ReportSignIo): Record<string, unknown> | null {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (err) {
    io.err(`Cannot read ${file}: ${messageOf(err)}`);
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    io.err(`${file} is not valid JSON: ${messageOf(err)}`);
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    io.err(`${file} must contain a JSON object at the top level.`);
    return null;
  }
  return parsed as Record<string, unknown>;
}

function readClaimedKeyId(doc: Record<string, unknown>): string | undefined {
  const sig = doc['signature'];
  if (sig === null || typeof sig !== 'object' || Array.isArray(sig)) return undefined;
  const keyId = (sig as Record<string, unknown>)['key_id'];
  return typeof keyId === 'string' ? keyId : undefined;
}

function emitFailure(
  io: ReportSignIo,
  opts: RunReportSignVerifyOptions,
  file: string,
  keyId: string | undefined,
  reason: string,
  humanMessage: string
): number {
  if (opts.json === true) {
    io.out(JSON.stringify({ ok: false, file, keyId, reason }));
  } else {
    io.err(humanMessage);
  }
  return 1;
}

function defaultSignedPath(file: string): string {
  return file.endsWith('.json') ? `${file.slice(0, -5)}.signed.json` : `${file}.signed.json`;
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
