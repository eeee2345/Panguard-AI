/**
 * Threat Cloud consent tests.
 *
 * Pins the invariant that one answer drives all three participation flags.
 * The regression these guard against is silent: `threatCloudRuleSyncEnabled`
 * has no other code path that sets it to true, and `rule-loader.ts` bails out
 * on `!== true`, so a consent path that forgets it strands rule sync at its
 * default with no error and no warning.
 */

import { describe, it, expect, vi } from 'vitest';

vi.mock('@panguard-ai/core', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@panguard-ai/core');
  return {
    ...actual,
    createLogger: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }),
  };
});

import { applyThreatCloudConsent } from '../src/cli/index.js';
import { DEFAULT_GUARD_CONFIG } from '../src/config.js';

describe('applyThreatCloudConsent', () => {
  it('agreeing turns on all three participation flags', () => {
    const result = applyThreatCloudConsent(DEFAULT_GUARD_CONFIG, true);

    expect(result.telemetryEnabled).toBe(true);
    expect(result.threatCloudUploadEnabled).toBe(true);
    expect(result.threatCloudRuleSyncEnabled).toBe(true);
  });

  it('declining leaves all three off', () => {
    const result = applyThreatCloudConsent(DEFAULT_GUARD_CONFIG, false);

    expect(result.telemetryEnabled).toBe(false);
    expect(result.threatCloudUploadEnabled).toBe(false);
    expect(result.threatCloudRuleSyncEnabled).toBe(false);
  });

  it('declining turns off flags that were previously on', () => {
    const optedIn = applyThreatCloudConsent(DEFAULT_GUARD_CONFIG, true);
    const optedOut = applyThreatCloudConsent(optedIn, false);

    expect(optedOut.telemetryEnabled).toBe(false);
    expect(optedOut.threatCloudUploadEnabled).toBe(false);
    expect(optedOut.threatCloudRuleSyncEnabled).toBe(false);
  });

  it('agreeing sets a default endpoint when none is configured', () => {
    const withoutEndpoint = { ...DEFAULT_GUARD_CONFIG, threatCloudEndpoint: undefined };
    const result = applyThreatCloudConsent(withoutEndpoint, true);

    expect(result.threatCloudEndpoint).toBe('https://tc.panguard.ai/api');
  });

  it('agreeing preserves an endpoint the operator already configured', () => {
    const selfHosted = {
      ...DEFAULT_GUARD_CONFIG,
      threatCloudEndpoint: 'https://tc.internal.example/api',
    };
    const result = applyThreatCloudConsent(selfHosted, true);

    expect(result.threatCloudEndpoint).toBe('https://tc.internal.example/api');
  });

  it('declining does not rewrite a configured endpoint', () => {
    const selfHosted = {
      ...DEFAULT_GUARD_CONFIG,
      threatCloudEndpoint: 'https://tc.internal.example/api',
    };
    const result = applyThreatCloudConsent(selfHosted, false);

    expect(result.threatCloudEndpoint).toBe('https://tc.internal.example/api');
  });

  it('does not mutate the config it was given', () => {
    const before = { ...DEFAULT_GUARD_CONFIG };
    applyThreatCloudConsent(DEFAULT_GUARD_CONFIG, true);

    expect(DEFAULT_GUARD_CONFIG).toEqual(before);
  });

  it('leaves unrelated config untouched', () => {
    const configured = { ...DEFAULT_GUARD_CONFIG, mode: 'report-only' as const, lang: 'zh-TW' };
    const result = applyThreatCloudConsent(configured, true);

    expect(result.mode).toBe('report-only');
    expect(result.lang).toBe('zh-TW');
    expect(result.dataDir).toBe(configured.dataDir);
  });
});
