import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { verifyReport } from '@panguard-ai/core';

import {
  SIGNING_KEY_ENV,
  TRUSTED_ISSUER_KEYS,
  reportCommand,
  runReportSign,
  runReportSignVerify,
} from '../src/cli/commands/report-sign.js';

const PUBLISHED_KEY_ID = 'pgk1-621b5f58dbfa5e2c';

interface CapturedIo {
  out: string[];
  err: string[];
  io: { out: (line: string) => void; err: (line: string) => void };
}

function captureIo(): CapturedIo {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: { out: (line: string) => out.push(line), err: (line: string) => err.push(line) },
  };
}

function makeKeys(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

describe('report sign CLI', () => {
  let dir: string;
  let savedEnv: string | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'pga-report-sign-'));
    savedEnv = process.env[SIGNING_KEY_ENV];
    delete process.env[SIGNING_KEY_ENV];
  });

  afterEach(() => {
    if (savedEnv === undefined) delete process.env[SIGNING_KEY_ENV];
    else process.env[SIGNING_KEY_ENV] = savedEnv;
    rmSync(dir, { recursive: true, force: true });
  });

  function writeReport(name = 'report.json'): string {
    const file = join(dir, name);
    writeFileSync(
      file,
      JSON.stringify({ kind: 'panguard.evidence-pack', version: '1.1', summary: { total: 1 } })
    );
    return file;
  }

  describe('trust store', () => {
    it('bundles the published issuer key with the published key_id', () => {
      const entry = TRUSTED_ISSUER_KEYS.find((k) => k.keyId === PUBLISHED_KEY_ID);
      expect(entry).toBeDefined();
      expect(entry?.publicKeyPem).toContain('BEGIN PUBLIC KEY');
    });
  });

  describe('runReportSign', () => {
    it('signs with a --key-file and writes <file>.signed.json by default', async () => {
      const { privatePem, publicPem } = makeKeys();
      const keyFile = join(dir, 'issuer.pem');
      writeFileSync(keyFile, privatePem);
      const report = writeReport();
      const { io, out } = captureIo();

      const code = await runReportSign(report, { keyFile }, io);

      expect(code).toBe(0);
      const outFile = join(dir, 'report.signed.json');
      expect(existsSync(outFile)).toBe(true);
      const signed = JSON.parse(readFileSync(outFile, 'utf8')) as Record<string, unknown>;
      expect(verifyReport(signed, { publicKeyPem: publicPem }).ok).toBe(true);
      // The input file must be left untouched.
      const original = JSON.parse(readFileSync(report, 'utf8')) as Record<string, unknown>;
      expect(original['signature']).toBeUndefined();
      expect(out.join('\n')).toContain('report.signed.json');
    });

    it('signs with the key from the environment variable', async () => {
      const { privatePem, publicPem } = makeKeys();
      process.env[SIGNING_KEY_ENV] = privatePem;
      const report = writeReport();
      const { io } = captureIo();

      const code = await runReportSign(report, {}, io);

      expect(code).toBe(0);
      const signed = JSON.parse(readFileSync(join(dir, 'report.signed.json'), 'utf8')) as Record<
        string,
        unknown
      >;
      expect(verifyReport(signed, { publicKeyPem: publicPem }).ok).toBe(true);
    });

    it('respects --out', async () => {
      const { privatePem } = makeKeys();
      process.env[SIGNING_KEY_ENV] = privatePem;
      const report = writeReport();
      const outPath = join(dir, 'custom-name.json');
      const { io } = captureIo();

      const code = await runReportSign(report, { out: outPath }, io);

      expect(code).toBe(0);
      expect(existsSync(outPath)).toBe(true);
    });

    it('fails with exit 2 and no output file when no key is available', async () => {
      const report = writeReport();
      const { io, err } = captureIo();

      const code = await runReportSign(report, {}, io);

      expect(code).toBe(2);
      expect(existsSync(join(dir, 'report.signed.json'))).toBe(false);
      expect(err.join('\n')).toContain(SIGNING_KEY_ENV);
    });

    it('never echoes private key material to stdout or stderr', async () => {
      const { privatePem } = makeKeys();
      process.env[SIGNING_KEY_ENV] = privatePem;
      const report = writeReport();
      const { io, out, err } = captureIo();

      await runReportSign(report, {}, io);

      const keyBody = privatePem.replace(/-----[^-]+-----|\s/g, '').slice(0, 24);
      const everything = out.join('\n') + err.join('\n');
      expect(everything).not.toContain(keyBody);
      expect(everything).not.toContain('PRIVATE KEY');
    });

    it('fails with exit 2 on a malformed JSON input', async () => {
      const { privatePem } = makeKeys();
      process.env[SIGNING_KEY_ENV] = privatePem;
      const bad = join(dir, 'bad.json');
      writeFileSync(bad, '{ not json');
      const { io, err } = captureIo();

      const code = await runReportSign(bad, {}, io);

      expect(code).toBe(2);
      expect(err.length).toBeGreaterThan(0);
    });

    it('fails with exit 2 on a missing input file', async () => {
      const { privatePem } = makeKeys();
      process.env[SIGNING_KEY_ENV] = privatePem;
      const { io } = captureIo();

      const code = await runReportSign(join(dir, 'nope.json'), {}, io);

      expect(code).toBe(2);
    });
  });

  describe('runReportSignVerify', () => {
    async function signedFixture(): Promise<{ file: string; publicPem: string; keyId: string }> {
      const { privatePem, publicPem } = makeKeys();
      process.env[SIGNING_KEY_ENV] = privatePem;
      const report = writeReport();
      const { io } = captureIo();
      const code = await runReportSign(report, {}, io);
      expect(code).toBe(0);
      delete process.env[SIGNING_KEY_ENV];
      const file = join(dir, 'report.signed.json');
      const signed = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
      const keyId = (signed['signature'] as { key_id: string }).key_id;
      return { file, publicPem, keyId };
    }

    it('verifies a valid report with --key and exits 0', async () => {
      const { file, publicPem } = await signedFixture();
      const pubFile = join(dir, 'issuer.pub.pem');
      writeFileSync(pubFile, publicPem);
      const { io, out } = captureIo();

      const code = await runReportSignVerify(file, { key: pubFile }, io);

      expect(code).toBe(0);
      expect(out.join('\n')).toContain('VERIFIED');
    });

    it('fails a tampered report with exit 1 and prints the reason', async () => {
      const { file, publicPem } = await signedFixture();
      const doc = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
      (doc['summary'] as Record<string, unknown>)['total'] = 999;
      writeFileSync(file, JSON.stringify(doc));
      const pubFile = join(dir, 'issuer.pub.pem');
      writeFileSync(pubFile, publicPem);
      const { io, err } = captureIo();

      const code = await runReportSignVerify(file, { key: pubFile }, io);

      expect(code).toBe(1);
      expect(err.join('\n')).toContain('payload-hash-mismatch');
    });

    it('enforces --expect-key with exit 1 on mismatch', async () => {
      const { file, publicPem } = await signedFixture();
      const pubFile = join(dir, 'issuer.pub.pem');
      writeFileSync(pubFile, publicPem);
      const { io, err } = captureIo();

      const code = await runReportSignVerify(
        file,
        { key: pubFile, expectKey: 'pgk1-0000000000000000' },
        io
      );

      expect(code).toBe(1);
      expect(err.join('\n')).toContain('key-id-mismatch');
    });

    it('rejects a key_id absent from the trust store when no --key is given', async () => {
      const { file, keyId } = await signedFixture();
      const { io, err } = captureIo();

      const code = await runReportSignVerify(file, {}, io);

      expect(code).toBe(1);
      const text = err.join('\n');
      expect(text).toContain(keyId);
      expect(text).toContain('trust store');
    });

    it('emits machine-readable output with --json', async () => {
      const { file, publicPem } = await signedFixture();
      const pubFile = join(dir, 'issuer.pub.pem');
      writeFileSync(pubFile, publicPem);
      const { io, out } = captureIo();

      const code = await runReportSignVerify(file, { key: pubFile, json: true }, io);

      expect(code).toBe(0);
      const parsed = JSON.parse(out.join('\n')) as Record<string, unknown>;
      expect(parsed['ok']).toBe(true);
      expect(parsed['keyId']).toMatch(/^pgk1-/);
    });

    it('fails with exit 2 on a missing file', async () => {
      const { io } = captureIo();
      const code = await runReportSignVerify(join(dir, 'nope.json'), {}, io);
      expect(code).toBe(2);
    });

    it('fails with exit 1 on an unsigned report', async () => {
      const report = writeReport();
      const { io, err } = captureIo();

      const code = await runReportSignVerify(report, {}, io);

      expect(code).toBe(1);
      expect(err.join('\n')).toContain('missing-signature');
    });
  });

  describe('commander wiring', () => {
    it('exposes the exact syntax promised on the trust page: report sign verify <file> --expect-key <id>', async () => {
      const { file, publicPem } = await (async () => {
        const { privatePem, publicPem } = makeKeys();
        process.env[SIGNING_KEY_ENV] = privatePem;
        const report = writeReport();
        const { io } = captureIo();
        await runReportSign(report, {}, io);
        delete process.env[SIGNING_KEY_ENV];
        return { file: join(dir, 'report.signed.json'), publicPem };
      })();
      const pubFile = join(dir, 'issuer.pub.pem');
      writeFileSync(pubFile, publicPem);
      const signed = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
      const keyId = (signed['signature'] as { key_id: string }).key_id;

      const prevExit = process.exitCode;
      const cmd = reportCommand();
      await cmd.parseAsync(['sign', 'verify', file, '--expect-key', keyId, '--key', pubFile], {
        from: 'user',
      });
      expect(process.exitCode ?? 0).toBe(0);
      process.exitCode = prevExit;
    });

    it('registers report > sign > verify command tree', () => {
      const cmd = reportCommand();
      expect(cmd.name()).toBe('report');
      const sign = cmd.commands.find((c) => c.name() === 'sign');
      expect(sign).toBeDefined();
      expect(sign?.commands.find((c) => c.name() === 'verify')).toBeDefined();
    });
  });
});
