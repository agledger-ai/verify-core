/**
 * Canonical failure taxonomy for AGLedger offline verification.
 *
 * One enum, shared by every surface (SDK /verify, CLI, MCP, @agledger/verify,
 * and — by mirroring these exact strings — the independent Python verifier).
 * SCREAMING_SNAKE to match the API's RFC 9290 problem-detail codes
 * (VALIDATION_ERROR, RATE_LIMIT_EXCEEDED, …), namespaced by sub-system:
 *
 *   CHAIN_*      per-record (and per-org schema-event) hash-chain entry checks
 *   CHECKPOINT_* vault checkpoint cross-check against the live chain
 *   TENANT_*     org_admin_reads Merkle log + signed tree heads
 *   <bare>       input/format-level failures that precede any chain walk
 *
 * Every code carries an actionable next step (`suggestion`) so a result is a
 * directive, not just a verdict.
 *
 * This is the strict union of the two taxonomies it replaces — the dump
 * verifier's `CHAIN_*`/`CHECKPOINT_*`/`TENANT_*` codes and the export
 * verifier's lower_snake reasons — with no tamper class dropped. Two renames
 * and three additions vs. the old dump set:
 *   - CHAIN_PAYLOAD_DRIFT      -> CHAIN_PAYLOAD_BINDING_MISMATCH (drift read as a
 *                                content/value judgement; this is a binding-
 *                                integrity check — the signed payload's STRUCTURE
 *                                no longer matches the canonical projection of the
 *                                row columns it is bound to. AGLedger never
 *                                inspects deliverable content.)
 *   - CHAIN_SIGNATURE_MISSING_KEY stays for "no key available for this id"; the
 *                                caller-policy case (requireKeyId / out-of-band-
 *                                only) splits out to CHAIN_KEY_POLICY_VIOLATION so
 *                                a retired/wrong-key policy hit is alertable apart
 *                                from a benign missing key.
 *   - CHAIN_KEY_EXPIRED (new)  temporal key-validity: entry signed outside the
 *                                signing key's activated_at..retired_at window.
 *   - CHAIN_EMPTY (new)        a chain/vault with nothing to verify is a non-clean
 *                                verdict, never a silent pass.
 */

export type FailureCode =
  // --- input / format (precede the chain walk) ---
  | 'UNSUPPORTED_FORMAT'
  | 'CHAIN_EMPTY'
  // --- per-record / per-org-schema hash chain ---
  | 'CHAIN_POSITION_GAP'
  | 'CHAIN_GENESIS_INVALID'
  | 'CHAIN_LINK_BROKEN'
  | 'CHAIN_HASH_MISMATCH'
  | 'CHAIN_MALFORMED_ENTRY'
  | 'CHAIN_COSE_DECODE_FAILED'
  | 'CHAIN_COSE_HEADER_MISMATCH'
  | 'CHAIN_PAYLOAD_BINDING_MISMATCH'
  | 'CHAIN_OIDC_ACTOR_MISMATCH'
  | 'CHAIN_SIGNATURE_INVALID'
  | 'CHAIN_SIGNATURE_MISSING_KEY'
  | 'CHAIN_KEY_POLICY_VIOLATION'
  | 'CHAIN_KEY_EXPIRED'
  // --- vault checkpoints ---
  | 'CHECKPOINT_ROW_MISSING'
  | 'CHECKPOINT_HASH_MISMATCH'
  | 'CHECKPOINT_SIGNATURE_INVALID'
  // --- org_admin_reads Merkle log + STH ---
  | 'TENANT_READ_LEAF_HASH_MISMATCH'
  | 'TENANT_READ_LEAF_INDEX_GAP'
  | 'TENANT_READ_SIGNATURE_INVALID'
  | 'TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH'
  | 'TENANT_CHECKPOINT_ROOT_MISMATCH'
  | 'TENANT_CHECKPOINT_SIGNATURE_INVALID'
  | 'TENANT_CHECKPOINT_FORK';

/**
 * Actionable next step per failure code. Kept terse and operational — what the
 * verifier's caller (auditor, compliance team, or agent) should do next.
 */
const SUGGESTIONS: Record<FailureCode, string> = {
  UNSUPPORTED_FORMAT:
    'This verifier reads exportFormatVersion 2.0 / RFC8949-CDE canonicalization. Re-export the chain from a current AGLedger instance, or upgrade the verifier to match the producing engine.',
  CHAIN_EMPTY:
    'No entries were present to verify. Confirm the record id / dump directory is correct and that the chain has not been truncated to zero rows.',
  CHAIN_POSITION_GAP:
    'A chain position is missing or out of order. The chain was truncated or reordered — obtain a complete, unmodified export/dump from the operator and re-run.',
  CHAIN_GENESIS_INVALID:
    'The first entry must carry previousHash = null. A non-null genesis link means the head of the chain was removed — request the full chain from position 1.',
  CHAIN_LINK_BROKEN:
    'An entry\'s previousHash does not match the prior entry\'s payloadHash. The chain was edited between these two entries — treat every entry from this position on as untrusted.',
  CHAIN_HASH_MISMATCH:
    'sha256(cose_sign1) does not equal the stored payloadHash. The envelope bytes or the stored hash were altered — the signed bytes are authoritative; the row was tampered with.',
  CHAIN_MALFORMED_ENTRY:
    'An entry is missing a required field (coseSign1 or payloadHash). The export/dump is incomplete or corrupt — regenerate it.',
  CHAIN_COSE_DECODE_FAILED:
    'The COSE_Sign1 envelope did not decode as a tagged 4-element structure. The signed bytes are corrupt — regenerate the export/dump.',
  CHAIN_COSE_HEADER_MISMATCH:
    'The position/previousHash signed in the COSE protected header disagree with the row columns. The visible columns were renumbered after signing — trust the signed header, not the columns.',
  CHAIN_PAYLOAD_BINDING_MISMATCH:
    'The signed payload\'s structure no longer matches the canonical projection of the row columns it is bound to — the visible (denormalised) payload was altered after signing. This is a binding-integrity failure, not a judgement on content.',
  CHAIN_OIDC_ACTOR_MISMATCH:
    'The denormalised actor OIDC issuer/subject columns disagree with the identity signed in predicate.on_behalf_of. The actor columns were tampered with after signing.',
  CHAIN_SIGNATURE_INVALID:
    'The Ed25519 COSE_Sign1 signature did not verify against the entry\'s signing key. The entry was forged or altered — obtain the verification keys out of band and re-run.',
  CHAIN_SIGNATURE_MISSING_KEY:
    'No public key was available for the entry\'s signingKeyId. Supply the key out of band (GET /v1/verification-keys or /.well-known/scitt-keys) and re-run.',
  CHAIN_KEY_POLICY_VIOLATION:
    'The entry\'s signing key violates the caller\'s trust policy (requireKeyId, or out-of-band keys required). Re-run with the expected key id, or with keys obtained out of band rather than the engine-embedded set.',
  CHAIN_KEY_EXPIRED:
    'The entry was signed outside its signing key\'s activated..retired window. A retired or not-yet-active key produced this entry — possible use of a compromised retired key.',
  CHECKPOINT_ROW_MISSING:
    'A signed checkpoint anchors a position that has no matching chain row. The chain was truncated below a checkpoint (out-of-band DELETE/TRUNCATE) — the checkpoint is proof of the missing rows.',
  CHECKPOINT_HASH_MISMATCH:
    'A checkpoint\'s payloadHash does not match the chain row at its position. The chain diverged from what was checkpointed — treat the chain as tampered.',
  CHECKPOINT_SIGNATURE_INVALID:
    'A checkpoint\'s COSE_Sign1 signature did not verify. The checkpoint was forged or altered — re-run with out-of-band verification keys.',
  TENANT_READ_LEAF_HASH_MISMATCH:
    'An org_admin_reads leaf hash does not match sha256(cose_sign1). The read-log leaf was altered after recording.',
  TENANT_READ_LEAF_INDEX_GAP:
    'org_admin_reads leaf indices are not gap-free for this org. A read-log entry was removed — obtain the complete log.',
  TENANT_READ_SIGNATURE_INVALID:
    'An org_admin_reads leaf\'s COSE_Sign1 signature did not verify. The read-log leaf was forged or altered.',
  TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH:
    'A signed tree head commits to more leaves than the dump contains. The read log was truncated below a checkpoint.',
  TENANT_CHECKPOINT_ROOT_MISMATCH:
    'The recomputed Merkle root does not match the signed root_hash. The read log diverged from what was checkpointed.',
  TENANT_CHECKPOINT_SIGNATURE_INVALID:
    'A signed-tree-head COSE_Sign1 signature did not verify. The STH was forged or altered.',
  TENANT_CHECKPOINT_FORK:
    'Two signed tree heads at the same tree_size carry different roots. This is an engine fork or signing-key compromise — escalate immediately.',
};

/** The actionable next step for a failure code. */
export function suggestion(code: FailureCode): string {
  return SUGGESTIONS[code];
}
