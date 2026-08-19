/**
 * Signing — offline verification of issuer-signed audit reports (PGA-SIG-V1).
 * 簽章 — 發行方簽章稽核報告的離線驗證(PGA-SIG-V1)。
 *
 * Verification only: the issuer key lifecycle and signing live in the private
 * enterprise tooling. This module is what lets ANYONE check a report against
 * the published key, offline, for free.
 */
export { canonicalizeAudit } from './canonical.js';
export {
  SIG_PAYLOAD_FORMAT,
  KEY_ID_PREFIX,
  deriveKeyId,
  buildSigningPayload,
  verifyIssuerSignature,
  computeAuditHashV2,
  verifyAuditReport,
} from './pga-sig-v1.js';
export type {
  IssuerSignature,
  AuditIntegrity,
  AuditVerifyReason,
  AuditVerifyStatus,
  IssuerSigVerifyResult,
  AuditReportVerifyResult,
  VerifyAuditReportOptions,
} from './pga-sig-v1.js';
