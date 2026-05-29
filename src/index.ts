/**
 * @agledger/verify-core — shared offline verification core for AGLedger audit
 * chains. One dependency (cborg), no network. The SDK /verify subpath, the CLI,
 * the MCP server, and @agledger/verify all build on this single body of logic.
 */
export { suggestion } from './failures.js';
export type { FailureCode } from './failures.js';

export {
  buildKeyRegistry,
  verifyChain,
} from './chain.js';
export type {
  KeySource,
  VerificationKey,
  KeyRegistry,
  NormalizedEntry,
  OptionalCheck,
  CheckApplicability,
  SignatureOutcome,
  ChainEntryResult,
  ChainResult,
  VerifyChainOptions,
} from './chain.js';

export { verifyAuditExport } from './audit-export.js';
export type {
  AuditExportEntryInput,
  RecordAuditExportInput,
  SigningKeyWindow,
  VerifyExportOptions,
  OutOfBandKeyEntry,
  EntryVerificationResult,
  VerifyExportResult,
} from './audit-export.js';

export {
  sha256Hex,
  sha256HexString,
  verifyEd25519Bytes,
  decodeCoseSign1,
  verifyCoseSign1,
  extractChainClaim,
  extractOnBehalfOfClaim,
  extractTraceparentClaim,
  decodePredicate,
  buildPredicateForRow,
  stripEnvelopeExtensions,
  deepEqual,
  merkleRoot,
  verifyInclusion,
  rfc9162LeafHash,
  rfc9162NodeHash,
  verifyRfc9162Inclusion,
  extractReceiptInclusionProof,
  verifyReceipt,
} from './primitives.js';
export type {
  CoseSign1Parts,
  CoseVerifyOutcome,
  ChainClaim,
  ReceiptInclusionProof,
  ReceiptVerifyOutcome,
} from './primitives.js';
