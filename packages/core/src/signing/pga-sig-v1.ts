/**
 * PGA-SIG-V1 — detached Ed25519 issuer signature over an audit report.
 * PGA-SIG-V1 — 稽核報告的 Ed25519 發行方簽章格式。
 *
 * This implements the payload format advertised on the public trust page
 * (website /trust/signing-key and /.well-known/panguard-signing-key.json):
 * a `signature` envelope embedded in the report JSON, signing the canonical
 * form of the report WITHOUT that envelope. Anyone holding the published
 * public key can verify offline; the envelope never carries key material —
 * trust comes from the verifier's key store, not from the document.
 *
 * Boundary honesty: this makes an issued report tamper-EVIDENT after signing.
 * It does not attest that the inputs were correct when recorded (garbage in,
 * signed garbage out) and it is not tamper-PROOF.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
} from 'node:crypto';

import { canonicalJson } from './canonical.js';

export const PGA_SIG_FORMAT = 'PGA-SIG-V1';
export const PGA_SIG_ALG = 'Ed25519';
/** key_id = 'pgk1-' + first 16 hex of SHA-256 over the SPKI DER of the public key. */
export const KEY_ID_PREFIX = 'pgk1-';

/** The signature envelope embedded in a signed report under `signature`. */
export interface PgaSignatureEnvelope {
  format: typeof PGA_SIG_FORMAT;
  alg: typeof PGA_SIG_ALG;
  key_id: string;
  signed_at: string;
  /** SHA-256 hex over the canonical payload (report without `signature`). */
  payload_sha256: string;
  /** Ed25519 signature (base64) over the same canonical payload bytes. */
  signature: string;
}

export interface SignReportOptions {
  /** Override the signed_at timestamp (ISO 8601) — for deterministic tests. */
  signedAt?: string;
}

export type VerifyFailureReason =
  | 'missing-signature'
  | 'unsupported-format'
  | 'key-id-mismatch'
  | 'payload-hash-mismatch'
  | 'bad-signature'
  | 'invalid-public-key';

export interface VerifyReportResult {
  ok: boolean;
  keyId?: string;
  payloadSha256?: string;
  signedAt?: string;
  reason?: VerifyFailureReason;
}

export interface VerifyReportOptions {
  /** Trusted public key (SPKI PEM). Trust anchors live OUTSIDE the document. */
  publicKeyPem: string;
  /** When set, the envelope's key_id must equal this exactly. */
  expectKeyId?: string;
}

/**
 * Derive the public key identifier as published on the trust page.
 * Throws on invalid input — issuer-side tooling must fail loud, not sign blind.
 */
export function deriveKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return KEY_ID_PREFIX + createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/**
 * Sign a report object, returning a NEW object with the `signature` envelope
 * attached. The input is never mutated. An existing `signature` field is
 * replaced (re-signing is idempotent over the payload).
 */
export function signReport(
  report: Record<string, unknown>,
  privateKeyPem: string,
  opts?: SignReportOptions
): Record<string, unknown> {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    throw new TypeError('signReport: report must be a plain JSON object');
  }
  const privateKey = createPrivateKey(privateKeyPem);
  const publicPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  const keyId = deriveKeyId(publicPem);

  const payload = stripSignature(report);
  const canonical = canonicalJson(payload);
  const envelope: PgaSignatureEnvelope = {
    format: PGA_SIG_FORMAT,
    alg: PGA_SIG_ALG,
    key_id: keyId,
    signed_at: opts?.signedAt ?? new Date().toISOString(),
    payload_sha256: sha256Hex(canonical),
    signature: edSign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('base64'),
  };
  return { ...payload, signature: envelope };
}

/**
 * Verify a signed report against a trusted public key. Total function: never
 * throws — every failure mode maps to a typed reason so callers (CLI, CI) can
 * report precisely what broke.
 */
export function verifyReport(
  report: Record<string, unknown>,
  opts: VerifyReportOptions
): VerifyReportResult {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) {
    return { ok: false, reason: 'missing-signature' };
  }
  const envelope = readEnvelope(report);
  if (envelope === null) {
    const raw = report['signature'];
    return {
      ok: false,
      reason: raw === undefined || raw === null ? 'missing-signature' : 'unsupported-format',
    };
  }

  let derivedId: string;
  try {
    derivedId = deriveKeyId(opts.publicKeyPem);
  } catch {
    return { ok: false, keyId: envelope.key_id, reason: 'invalid-public-key' };
  }
  if (opts.expectKeyId !== undefined && opts.expectKeyId !== envelope.key_id) {
    return { ok: false, keyId: envelope.key_id, reason: 'key-id-mismatch' };
  }
  if (envelope.key_id !== derivedId) {
    return { ok: false, keyId: envelope.key_id, reason: 'key-id-mismatch' };
  }

  const canonical = canonicalJson(stripSignature(report));
  const payloadSha256 = sha256Hex(canonical);
  if (payloadSha256 !== envelope.payload_sha256) {
    return { ok: false, keyId: envelope.key_id, payloadSha256, reason: 'payload-hash-mismatch' };
  }

  let valid = false;
  try {
    valid = edVerify(
      null,
      Buffer.from(canonical, 'utf8'),
      createPublicKey(opts.publicKeyPem),
      Buffer.from(envelope.signature, 'base64')
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    return { ok: false, keyId: envelope.key_id, payloadSha256, reason: 'bad-signature' };
  }
  return { ok: true, keyId: envelope.key_id, payloadSha256, signedAt: envelope.signed_at };
}

/** Report content without the signature envelope — the signed payload. */
function stripSignature(report: Record<string, unknown>): Record<string, unknown> {
  const { signature: _omitted, ...payload } = report;
  return payload;
}

/** Parse the `signature` field into a well-formed envelope, or null. */
function readEnvelope(report: Record<string, unknown>): PgaSignatureEnvelope | null {
  const raw = report['signature'];
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const env = raw as Record<string, unknown>;
  if (env['format'] !== PGA_SIG_FORMAT || env['alg'] !== PGA_SIG_ALG) return null;
  if (
    typeof env['key_id'] !== 'string' ||
    typeof env['signed_at'] !== 'string' ||
    typeof env['payload_sha256'] !== 'string' ||
    typeof env['signature'] !== 'string'
  ) {
    return null;
  }
  return {
    format: PGA_SIG_FORMAT,
    alg: PGA_SIG_ALG,
    key_id: env['key_id'],
    signed_at: env['signed_at'],
    payload_sha256: env['payload_sha256'],
    signature: env['signature'],
  };
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}
