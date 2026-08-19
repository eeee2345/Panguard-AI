/**
 * PGA-SIG-V1 — offline verification of issuer-signed audit reports.
 * PGA-SIG-V1 — 發行方簽章稽核報告的離線驗證。
 *
 * WIRE-FORMAT AUTHORITY: the private issuer tooling (@panguard/migrator
 * signing/) defines this format and is the only thing that SIGNS. This public
 * module implements the free VERIFICATION half the trust page promises
 * (/trust/signing-key): any auditor, partner, or regulator can check a report
 * offline without a license. Key lifecycle (keygen/show), hash counter-signing
 * and one-step issuing live in the enterprise tooling only.
 *
 * The signed payload is a deterministic, context-bound string — never the bare
 * hash — so a signature for one (kind, framework, jurisdiction) cannot be
 * replayed onto another artifact type or legal framing:
 *
 *   PGA-SIG-V1\n<kind>\n<framework>\n<jurisdiction>\n<sha256>\n<key_id>\n<signed_at>
 *
 * Trust model: the signature block embeds the public key; verification checks
 * the embedded key hashes to the embedded key_id (the pinnable anchor), then
 * verifies Ed25519 over the reconstructed payload. WHICH key_ids to trust is
 * the caller's decision — the published list on /trust/signing-key, or an
 * explicit --expect-key pin.
 *
 * Boundary honesty: verification proves the report was not modified after
 * signing and was signed by the holder of the key_id's private key. It does
 * not attest the inputs were correct when recorded, and it is not
 * tamper-proof. Wording: tamper-evident, never tamper-proof.
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

import { canonicalizeAudit } from './canonical.js';

export const SIG_PAYLOAD_FORMAT = 'PGA-SIG-V1';
/** key_id = 'pgk1-' + first 16 hex of SHA-256 over the SPKI DER of the public key. */
export const KEY_ID_PREFIX = 'pgk1-';

/** Embedded, self-contained signature block (JSON-safe) — issuer wire format. */
export interface IssuerSignature {
  scheme: 'issuer';
  payload_format: typeof SIG_PAYLOAD_FORMAT;
  alg: 'Ed25519';
  key_id: string;
  issuer: string;
  /** SPKI PEM — enables offline verification; pin via key_id. */
  public_key_pem: string;
  signature_b64: string;
  signed_at: string;
  kind: string;
  framework: string;
  jurisdiction: string;
}

/** The integrity block of an audit-pack report. */
export interface AuditIntegrity {
  sha256: string;
  signature_scheme: 'server' | 'issuer' | 'none';
  key_id?: string;
  issuer_signature?: IssuerSignature;
  unsigned_reason?: string;
}

/** Derive the public key identifier as published on the trust page. Throws on invalid input. */
export function deriveKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return KEY_ID_PREFIX + createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/** Rebuild the exact context-bound string the issuer signed. */
export function buildSigningPayload(
  sha256: string,
  binding: { kind: string; framework: string; jurisdiction: string },
  keyId: string,
  signedAt: string
): string {
  return [
    SIG_PAYLOAD_FORMAT,
    binding.kind,
    binding.framework,
    binding.jurisdiction,
    sha256,
    keyId,
    signedAt,
  ].join('\n');
}

export type AuditVerifyReason =
  | 'not-an-audit-report'
  | 'legacy-hash-schema'
  | 'hash-mismatch'
  | 'missing-issuer-signature'
  | 'unsupported-payload-format'
  | 'embedded-key-unreadable'
  | 'embedded-key-id-mismatch'
  | 'bad-signature'
  | 'expect-key-mismatch'
  | 'expected-key-but-not-issuer-signed'
  | 'untrusted-key-id';

export interface IssuerSigVerifyResult {
  valid: boolean;
  reason?: AuditVerifyReason;
  detail?: string;
}

/**
 * Offline verification of an issuer signature against an independently
 * recomputed sha256. Checks, in order: payload format, key_id <-> public-key
 * binding, then Ed25519 over the reconstructed payload. Total function.
 */
export function verifyIssuerSignature(sha256: string, sig: IssuerSignature): IssuerSigVerifyResult {
  if (sig.payload_format !== SIG_PAYLOAD_FORMAT) {
    return {
      valid: false,
      reason: 'unsupported-payload-format',
      detail: String(sig.payload_format),
    };
  }
  let derivedKeyId: string;
  try {
    derivedKeyId = deriveKeyId(sig.public_key_pem);
  } catch (err) {
    return {
      valid: false,
      reason: 'embedded-key-unreadable',
      detail: err instanceof Error ? err.message : String(err),
    };
  }
  if (derivedKeyId !== sig.key_id) {
    return {
      valid: false,
      reason: 'embedded-key-id-mismatch',
      detail: `embedded public key hashes to ${derivedKeyId}, block claims ${sig.key_id}`,
    };
  }
  const payload = buildSigningPayload(
    sha256,
    { kind: sig.kind, framework: sig.framework, jurisdiction: sig.jurisdiction },
    sig.key_id,
    sig.signed_at
  );
  let ok: boolean;
  try {
    ok = edVerify(
      null,
      Buffer.from(payload, 'utf-8'),
      createPublicKey(sig.public_key_pem),
      Buffer.from(sig.signature_b64, 'base64')
    );
  } catch {
    ok = false;
  }
  return ok ? { valid: true } : { valid: false, reason: 'bad-signature' };
}

/**
 * Recompute the canonical body hash of a v2 audit report (everything except
 * `integrity`). Returns null for pre-v2 reports: the legacy subset hash covered
 * only part of the body, and a fail-closed public tool refuses to bless it —
 * the hashSchema marker lives INSIDE the hashed body, so stripping it from a
 * v2 report breaks the hash rather than downgrading the check.
 */
export function computeAuditHashV2(report: Record<string, unknown>): string | null {
  const metadata = report['metadata'];
  const hashSchema =
    metadata !== null && typeof metadata === 'object'
      ? (metadata as Record<string, unknown>)['hashSchema']
      : undefined;
  if (hashSchema !== 'v2') return null;
  const { integrity: _integrity, ...body } = report;
  return createHash('sha256').update(canonicalizeAudit(body)).digest('hex');
}

export type AuditVerifyStatus = 'verified-issuer' | 'hash-only-server' | 'hash-only-unsigned';

export interface AuditReportVerifyResult {
  ok: boolean;
  status?: AuditVerifyStatus;
  reason?: AuditVerifyReason;
  detail?: string;
  /** Recomputed canonical body hash. */
  sha256?: string;
  keyId?: string;
  issuer?: string;
  jurisdiction?: string;
  /** True when the signing key_id is in the caller's trusted list. */
  trustedKey?: boolean;
}

export interface VerifyAuditReportOptions {
  /** Require the report to be issuer-signed by exactly this key_id. */
  expectKeyId?: string;
  /**
   * key_ids trusted without an explicit pin — normally the published list from
   * /.well-known/panguard-signing-key.json. An issuer-signed report whose
   * key_id is neither pinned nor in this list fails with 'untrusted-key-id'
   * (the trust page policy: an unlisted key_id must not be trusted).
   */
  trustedKeyIds: readonly string[];
}

/**
 * Full offline verification of an audit-pack report JSON: structure, canonical
 * body hash, then the signature per scheme. Total function — never throws.
 */
export function verifyAuditReport(
  report: Record<string, unknown>,
  opts: VerifyAuditReportOptions
): AuditReportVerifyResult {
  const integrity = readIntegrity(report);
  if (integrity === null) {
    const kind = report['kind'];
    return {
      ok: false,
      reason: 'not-an-audit-report',
      detail:
        kind === 'panguard.evidence-pack'
          ? 'this is a guard evidence pack (self-attested); it is not an issuer-signed audit report'
          : 'missing metadata/attestation/integrity blocks',
    };
  }

  const recomputed = computeAuditHashV2(report);
  if (recomputed === null) {
    return {
      ok: false,
      reason: 'legacy-hash-schema',
      detail:
        'report predates hashSchema v2 (subset hash) — request a re-issued v2 report for full offline verification',
    };
  }
  if (recomputed !== integrity.sha256) {
    return {
      ok: false,
      reason: 'hash-mismatch',
      sha256: recomputed,
      detail: `body hashes to ${recomputed}, report states ${integrity.sha256}`,
    };
  }

  if (integrity.signature_scheme === 'issuer') {
    const sig = integrity.issuer_signature;
    if (sig === undefined) {
      return { ok: false, reason: 'missing-issuer-signature', sha256: recomputed };
    }
    const outcome = verifyIssuerSignature(recomputed, sig);
    if (!outcome.valid) {
      return {
        ok: false,
        reason: outcome.reason ?? 'bad-signature',
        sha256: recomputed,
        keyId: sig.key_id,
        ...(outcome.detail !== undefined ? { detail: outcome.detail } : {}),
      };
    }
    if (opts.expectKeyId !== undefined && opts.expectKeyId !== sig.key_id) {
      return {
        ok: false,
        reason: 'expect-key-mismatch',
        sha256: recomputed,
        keyId: sig.key_id,
        detail: `report signed by ${sig.key_id}, expected ${opts.expectKeyId}`,
      };
    }
    const trustedKey = opts.trustedKeyIds.includes(sig.key_id);
    if (opts.expectKeyId === undefined && !trustedKey) {
      return {
        ok: false,
        reason: 'untrusted-key-id',
        sha256: recomputed,
        keyId: sig.key_id,
        issuer: sig.issuer,
        detail: `key_id ${sig.key_id} is not in the published trust list — pin it explicitly with --expect-key only if you verified it out of band`,
      };
    }
    return {
      ok: true,
      status: 'verified-issuer',
      sha256: recomputed,
      keyId: sig.key_id,
      issuer: sig.issuer,
      jurisdiction: sig.jurisdiction,
      trustedKey,
    };
  }

  if (opts.expectKeyId !== undefined) {
    return {
      ok: false,
      reason: 'expected-key-but-not-issuer-signed',
      sha256: recomputed,
      detail: `--expect-key requires an issuer signature, but signature_scheme is '${integrity.signature_scheme}'`,
    };
  }
  if (integrity.signature_scheme === 'server') {
    return { ok: true, status: 'hash-only-server', sha256: recomputed };
  }
  return {
    ok: true,
    status: 'hash-only-unsigned',
    sha256: recomputed,
    ...(integrity.unsigned_reason !== undefined ? { detail: integrity.unsigned_reason } : {}),
  };
}

/** Structural read of the integrity block; null when this is not an audit report. */
function readIntegrity(report: Record<string, unknown>): AuditIntegrity | null {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) return null;
  const metadata = report['metadata'];
  const attestation = report['attestation'];
  const integrity = report['integrity'];
  if (
    metadata === null ||
    typeof metadata !== 'object' ||
    attestation === null ||
    typeof attestation !== 'object' ||
    integrity === null ||
    typeof integrity !== 'object' ||
    Array.isArray(integrity)
  ) {
    return null;
  }
  const block = integrity as Record<string, unknown>;
  if (typeof block['sha256'] !== 'string' || typeof block['signature_scheme'] !== 'string') {
    return null;
  }
  return integrity as unknown as AuditIntegrity;
}
