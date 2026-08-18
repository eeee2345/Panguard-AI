/**
 * Issuer signing stack — PGA-SIG-V1 report signatures.
 * 發行方簽章棧 — PGA-SIG-V1 報告簽章。
 */
export { canonicalJson } from './canonical.js';
export {
  PGA_SIG_FORMAT,
  PGA_SIG_ALG,
  KEY_ID_PREFIX,
  deriveKeyId,
  signReport,
  verifyReport,
} from './pga-sig-v1.js';
export type {
  PgaSignatureEnvelope,
  SignReportOptions,
  VerifyFailureReason,
  VerifyReportResult,
  VerifyReportOptions,
} from './pga-sig-v1.js';
