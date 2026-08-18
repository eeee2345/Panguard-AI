import { describe, it, expect } from 'vitest';
import { createHash, generateKeyPairSync } from 'node:crypto';

import {
  PGA_SIG_FORMAT,
  canonicalJson,
  deriveKeyId,
  signReport,
  verifyReport,
  type PgaSignatureEnvelope,
} from '@panguard-ai/core/signing/index.js';

/**
 * The PUBLISHED issuer public key from
 * packages/website/public/.well-known/panguard-signing-key.json (key_id
 * pgk1-621b5f58dbfa5e2c). deriveKeyId MUST reproduce that exact id from this
 * PEM — it is a public trust promise, not an implementation detail.
 */
const PUBLISHED_PEM =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MCowBQYDK2VwAyEAE8yWwjJ9K3FUibtTZq640dHJVEGw26AM8NiM749fzqU=\n' +
  '-----END PUBLIC KEY-----\n';
const PUBLISHED_KEY_ID = 'pgk1-621b5f58dbfa5e2c';

function makeKeys(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

function sampleReport(): Record<string, unknown> {
  return {
    kind: 'panguard.evidence-pack',
    version: '1.1',
    workspace_id: 'ws-test',
    generated_at: '2026-08-18T00:00:00.000Z',
    summary: { threats_total: 3, events_processed: 120 },
    verdicts: [
      { index: 0, conclusion: 'threat', confidence: 0.97 },
      { index: 1, conclusion: 'clean', confidence: 0.99 },
    ],
  };
}

describe('deriveKeyId', () => {
  it('reproduces the published key_id from the published PEM', () => {
    expect(deriveKeyId(PUBLISHED_PEM)).toBe(PUBLISHED_KEY_ID);
  });

  it('derives a pgk1- prefixed 16-hex id for any valid key', () => {
    const { publicPem } = makeKeys();
    expect(deriveKeyId(publicPem)).toMatch(/^pgk1-[0-9a-f]{16}$/);
  });

  it('throws on garbage input (issuer-side must fail loud)', () => {
    expect(() => deriveKeyId('not a pem')).toThrow();
  });
});

describe('canonicalJson', () => {
  it('is independent of object key insertion order at every depth', () => {
    const a = { outer: { b: 2, a: 1 }, list: [{ y: 1, x: 2 }] };
    const b = { list: [{ x: 2, y: 1 }], outer: { a: 1, b: 2 } };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
  });

  it('preserves array order', () => {
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });

  it('covers NESTED values, not just the top-level skeleton', () => {
    const base = sampleReport();
    const tampered = sampleReport();
    (tampered['verdicts'] as Array<Record<string, unknown>>)[0]!['conclusion'] = 'clean';
    expect(canonicalJson(base)).not.toBe(canonicalJson(tampered));
  });

  it('normalizes toJSON values (Date) to their plain JSON form', () => {
    const when = new Date('2026-08-18T00:00:00.000Z');
    expect(canonicalJson({ at: when })).toBe(canonicalJson({ at: '2026-08-18T00:00:00.000Z' }));
  });
});

describe('signReport', () => {
  it('sign then verify round-trips', () => {
    const { privatePem, publicPem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const result = verifyReport(signed, { publicKeyPem: publicPem });
    expect(result.ok).toBe(true);
    expect(result.keyId).toBe(deriveKeyId(publicPem));
  });

  it('does not mutate the input report', () => {
    const { privatePem } = makeKeys();
    const report = sampleReport();
    const before = JSON.stringify(report);
    signReport(report, privatePem);
    expect(JSON.stringify(report)).toBe(before);
  });

  it('attaches a complete envelope and nothing else', () => {
    const { privatePem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const envelope = signed['signature'] as PgaSignatureEnvelope;
    expect(Object.keys(envelope).sort()).toEqual([
      'alg',
      'format',
      'key_id',
      'payload_sha256',
      'signature',
      'signed_at',
    ]);
    expect(envelope.format).toBe(PGA_SIG_FORMAT);
    expect(envelope.alg).toBe('Ed25519');
    // In-band public keys are forbidden: trust comes from the verifier's key
    // store, never from the document itself.
    expect(JSON.stringify(envelope)).not.toContain('PUBLIC KEY');
  });

  it('honors a deterministic signedAt override', () => {
    const { privatePem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem, {
      signedAt: '2026-08-18T12:00:00.000Z',
    });
    const envelope = signed['signature'] as PgaSignatureEnvelope;
    expect(envelope.signed_at).toBe('2026-08-18T12:00:00.000Z');
  });

  it('re-signing a signed report replaces the envelope and still verifies', () => {
    const first = makeKeys();
    const second = makeKeys();
    const once = signReport(sampleReport(), first.privatePem);
    const twice = signReport(once, second.privatePem);
    expect(verifyReport(twice, { publicKeyPem: second.publicPem }).ok).toBe(true);
    // Payload must be the original report, not report+old-envelope.
    const onceEnv = once['signature'] as PgaSignatureEnvelope;
    const twiceEnv = twice['signature'] as PgaSignatureEnvelope;
    expect(twiceEnv.payload_sha256).toBe(onceEnv.payload_sha256);
  });

  it('rejects non-object payloads (fail fast at the boundary)', () => {
    const { privatePem } = makeKeys();
    expect(() => signReport([] as unknown as Record<string, unknown>, privatePem)).toThrow();
    expect(() => signReport(null as unknown as Record<string, unknown>, privatePem)).toThrow();
  });

  it('throws on an invalid private key (issuer-side must fail loud)', () => {
    expect(() => signReport(sampleReport(), 'not a pem')).toThrow();
  });
});

describe('verifyReport', () => {
  it('flags a missing signature', () => {
    const { publicPem } = makeKeys();
    const result = verifyReport(sampleReport(), { publicKeyPem: publicPem });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('missing-signature');
  });

  it('flags an unsupported format version', () => {
    const { privatePem, publicPem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const mangled = {
      ...signed,
      signature: { ...(signed['signature'] as PgaSignatureEnvelope), format: 'PGA-SIG-V9' },
    };
    const result = verifyReport(mangled, { publicKeyPem: publicPem });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('unsupported-format');
  });

  it('detects tampering of a top-level field', () => {
    const { privatePem, publicPem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const tampered = { ...signed, workspace_id: 'ws-evil' };
    const result = verifyReport(tampered, { publicKeyPem: publicPem });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('payload-hash-mismatch');
  });

  it('detects tampering of a DEEP nested field (the skeleton-hash failure class)', () => {
    const { privatePem, publicPem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const tampered = JSON.parse(JSON.stringify(signed)) as Record<string, unknown>;
    (tampered['verdicts'] as Array<Record<string, unknown>>)[0]!['conclusion'] = 'clean';
    const result = verifyReport(tampered, { publicKeyPem: publicPem });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('payload-hash-mismatch');
  });

  it('detects a recomputed payload hash with a forged signature', () => {
    const { privatePem, publicPem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const tampered = JSON.parse(JSON.stringify(signed)) as Record<string, unknown>;
    (tampered['verdicts'] as Array<Record<string, unknown>>)[0]!['conclusion'] = 'clean';
    // Attacker recomputes payload_sha256 over the tampered payload so the hash
    // check passes — the Ed25519 signature must still catch it.
    const stripped: Record<string, unknown> = { ...tampered };
    delete stripped['signature'];
    const envelope = tampered['signature'] as PgaSignatureEnvelope;
    const rehashed = {
      ...tampered,
      signature: { ...envelope, payload_sha256: sha256Hex(canonicalJson(stripped)) },
    };
    const result = verifyReport(rehashed, { publicKeyPem: publicPem });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('bad-signature');
  });

  it('enforces expectKeyId', () => {
    const { privatePem, publicPem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const result = verifyReport(signed, {
      publicKeyPem: publicPem,
      expectKeyId: 'pgk1-0000000000000000',
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('key-id-mismatch');
  });

  it('rejects verification with a different key (claimed key_id not provable)', () => {
    const signer = makeKeys();
    const other = makeKeys();
    const signed = signReport(sampleReport(), signer.privatePem);
    const result = verifyReport(signed, { publicKeyPem: other.publicPem });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('key-id-mismatch');
  });

  it('returns invalid-public-key instead of throwing on a garbage key (verifier-side is total)', () => {
    const { privatePem } = makeKeys();
    const signed = signReport(sampleReport(), privatePem);
    const result = verifyReport(signed, { publicKeyPem: 'not a pem' });
    expect(result.ok).toBe(false);
    expect(result.reason).toBe('invalid-public-key');
  });
});

/** Local sha256 helper mirroring the production hash for the forged-hash test. */
function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}
