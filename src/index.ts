/**
 * @agledger/verify-core: shared offline verification core for AGLedger audit
 * chains. One dependency (cborg), no network. The SDK /verify subpath, the CLI,
 * the MCP server, and @agledger/verify all build on this single body of logic.
 */
export { suggestion } from './failures.js';
export type { FailureCode } from './failures.js';

export {
  buildAgentKeyRegistry,
  buildKeyRegistry,
  verifyChain,
} from './chain.js';
export type {
  AgentKeyRegistry,
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
  verifySignatureBytes,
  resolveKeyAlgorithm,
  algorithmByName,
  runtimeCanCompute,
  looksLikeEd25519Key,
  describeUnsupportedAlgorithm,
  decodeCoseSign1,
  verifyCoseSign1,
  extractActorClaim,
  extractChainClaim,
  extractKid,
  extractOnBehalfOfClaim,
  extractTraceparentClaim,
  extractAgentSignatureClaim,
  ed25519JwkThumbprint,
  ed25519JwkToSpki,
  verifyAgentSignature,
  AGENT_SIGNATURE_CONTEXT,
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
  KeyAlgorithm,
  ActorClaim,
  ChainClaim,
  AgentPublicKeyJwk,
  AgentSignatureClaim,
  AgentSignatureOutcome,
  ReceiptInclusionProof,
  ReceiptVerifyOutcome,
} from './primitives.js';
