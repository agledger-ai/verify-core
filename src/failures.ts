/**
 * Canonical failure taxonomy for AGLedger offline verification.
 *
 * One enum, shared by every surface (SDK /verify, CLI, MCP, @agledger/verify,
 * and, by mirroring these exact strings, the independent Python verifier).
 * SCREAMING_SNAKE to match the API's RFC 9290 problem-detail codes
 * (VALIDATION_ERROR, RATE_LIMIT_EXCEEDED, …), namespaced by sub-system:
 *
 *   CHAIN_*      per-record (and per-org schema-event) hash-chain entry checks
 *   CHECKPOINT_* vault checkpoint cross-check against the live chain
 *   TENANT_*     org_admin_reads Merkle log + signed tree heads
 *   KEY_*        the vault key statements themselves (the key registry)
 *   <bare>       input/format-level failures that precede any chain walk
 *
 * Every code carries an actionable next step (`suggestion`) so a result is a
 * directive, not just a verdict.
 *
 * This is the strict union of the two taxonomies it replaces: the dump
 * verifier's `CHAIN_*`/`CHECKPOINT_*`/`TENANT_*` codes and the export
 * verifier's lower_snake reasons, with no tamper class dropped. Two renames
 * and three additions vs. the old dump set:
 *   - CHAIN_PAYLOAD_DRIFT      -> CHAIN_PAYLOAD_BINDING_MISMATCH (drift read as a
 *                                content/value judgement; this is a binding-
 *                                integrity check: the signed payload's STRUCTURE
 *                                no longer matches the canonical projection of the
 *                                row columns it is bound to. AGLedger never
 *                                inspects deliverable content.)
 *   - CHAIN_SIGNATURE_MISSING_KEY stays for "no key available for this id"; the
 *                                caller-policy case (requireKeyId / out-of-band-
 *                                only) splits out to CHAIN_KEY_POLICY_VIOLATION so
 *                                a retired/wrong-key policy hit is alertable apart
 *                                from a benign missing key.
 *   - CHAIN_KEY_EXPIRED (new)  temporal key-validity: entry written after the
 *                                signing key's retired_at, or after its
 *                                distrustedKeys cutoff.
 *   - CHAIN_KEY_NOT_YET_ACTIVE  entry written before the key's activated_at.
 *                                Split from CHAIN_KEY_EXPIRED so a consumer is
 *                                not told "expired" about a key that had not
 *                                started yet.
 *   - CHAIN_EMPTY (new)        a chain/vault with nothing to verify is a non-clean
 *                                verdict, never a silent pass.
 *
 * Later additions:
 *   - CHAIN_ENTRY_UNSIGNED     engine mirror of `signature_missing`: an entry with
 *                                no signing key id after a signed entry in its
 *                                chain, or written at or after the earliest
 *                                activatedAt in the key set. Earlier unsigned
 *                                entries stay reduced coverage.
 *   - CHECKPOINT_UNSIGNED      engine mirror of `checkpoint_unsigned`: the same
 *                                instant, applied to an unsigned checkpoint.
 *   - TENANT_READ_LEAF_UNSIGNED and TENANT_CHECKPOINT_UNSIGNED  the same two
 *                                rules on the org_admin_reads log (engine
 *                                `leaf_signature_missing`, `checkpoint_unsigned`).
 *   - CHAIN_SIGNING_KEY_UNANCHORED  engine mirror of `signing_key_unanchored`:
 *                                the entry's key is not linked by signed key
 *                                statements to a pinned trust anchor. With
 *                                CHECKPOINT_KEY_UNANCHORED,
 *                                TENANT_READ_KEY_UNANCHORED and
 *                                TENANT_CHECKPOINT_KEY_UNANCHORED for the
 *                                engine's `checkpoint_key_unanchored` and
 *                                `leaf_key_unanchored`.
 *   - KEY_STATEMENT_INVALID, KEY_CLOSURE_INVALID, CHAIN_KEY_WINDOW_DRIFT
 *                                engine mirrors of the key registry findings
 *                                `key_statement_invalid`, `key_closure_invalid`
 *                                and `key_window_drift`. They are about the
 *                                registry, not about any one entry.
 *   - CHECKPOINT_CLAIM_MISMATCH, TENANT_READ_CLAIM_MISMATCH,
 *     TENANT_CHECKPOINT_CLAIM_MISMATCH  engine mirrors of the vault's
 *                                `checkpoint_claim_mismatch` and the read log's
 *                                `leaf_claim_mismatch` and
 *                                `checkpoint_claim_mismatch`: the claim signed
 *                                inside the envelope does not decode, or says
 *                                something the row's columns do not.
 *
 * Server-side cert re-checks are not mirrored here. The engine's chain
 * verification also reports `cert_missing`, `cert_actor_drift`,
 * `cert_window_drift`, `cert_expired` and `agent_signature_invalid`, by
 * comparing what an entry sealed in `predicate.on_behalf_of.cert` against the
 * live `ephemeral_certs` row. Neither the export nor the dump carries that
 * table, so an offline verifier cannot reproduce those comparisons, and it
 * does not need to: it trusts only the signed bytes, which already fix the
 * sealed cert id, thumbprint and expiry. The one cert-related check that can
 * run offline is the agent signature, and only when the caller supplies the
 * cert's public key (CHAIN_AGENT_SIGNATURE_INVALID below).
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
  | 'CHAIN_KEY_NOT_YET_ACTIVE'
  | 'CHAIN_ALG_MISMATCH'
  | 'CHAIN_UNSUPPORTED_ALGORITHM'
  | 'CHAIN_SIGNING_KEY_DRIFT'
  | 'CHAIN_ACTOR_ATTRIBUTION_MISMATCH'
  | 'CHAIN_AGENT_SIGNATURE_INVALID'
  | 'CHAIN_ENTRY_UNSIGNED'
  | 'CHAIN_SIGNING_KEY_UNANCHORED'
  | 'CHAIN_KEY_WINDOW_DRIFT'
  // --- vault checkpoints ---
  | 'CHECKPOINT_ROW_MISSING'
  | 'CHECKPOINT_HASH_MISMATCH'
  | 'CHECKPOINT_SIGNATURE_INVALID'
  | 'CHECKPOINT_UNSIGNED'
  | 'CHECKPOINT_KEY_UNANCHORED'
  | 'CHECKPOINT_CLAIM_MISMATCH'
  // --- org_admin_reads Merkle log + STH ---
  | 'TENANT_READ_LEAF_HASH_MISMATCH'
  | 'TENANT_READ_LEAF_INDEX_GAP'
  | 'TENANT_READ_SIGNATURE_INVALID'
  | 'TENANT_READ_LEAF_UNSIGNED'
  | 'TENANT_READ_KEY_UNANCHORED'
  | 'TENANT_READ_CLAIM_MISMATCH'
  | 'TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH'
  | 'TENANT_CHECKPOINT_ROOT_MISMATCH'
  | 'TENANT_CHECKPOINT_SIGNATURE_INVALID'
  | 'TENANT_CHECKPOINT_UNSIGNED'
  | 'TENANT_CHECKPOINT_KEY_UNANCHORED'
  | 'TENANT_CHECKPOINT_CLAIM_MISMATCH'
  | 'TENANT_CHECKPOINT_FORK'
  // --- vault key statements ---
  | 'KEY_STATEMENT_INVALID'
  | 'KEY_CLOSURE_INVALID';

/**
 * Actionable next step per failure code. Kept terse and operational: what the
 * verifier's caller (auditor, compliance team, or agent) should do next.
 */
const SUGGESTIONS: Record<FailureCode, string> = {
  UNSUPPORTED_FORMAT:
    'This verifier reads exportFormatVersion 2.0 / RFC8949-CDE canonicalization. Re-export the chain from a current AGLedger instance, or upgrade the verifier to match the producing engine.',
  CHAIN_EMPTY:
    'No entries were present to verify. Confirm the record id / dump directory is correct and that the chain has not been truncated to zero rows.',
  CHAIN_POSITION_GAP:
    'A chain position is missing or out of order. The chain was truncated or reordered. Obtain a complete, unmodified export/dump from the operator and re-run.',
  CHAIN_GENESIS_INVALID:
    'The first entry must carry previousHash = null. A non-null genesis link means the head of the chain was removed. Request the full chain from position 1.',
  CHAIN_LINK_BROKEN:
    'An entry\'s previousHash does not match the prior entry\'s payloadHash. The chain was edited between these two entries. Treat every entry from this position on as untrusted.',
  CHAIN_HASH_MISMATCH:
    'sha256(cose_sign1) does not equal the stored payloadHash. The envelope bytes or the stored hash were altered. The signed bytes are authoritative; the row was tampered with.',
  CHAIN_MALFORMED_ENTRY:
    'An entry is missing a field the engine writes on every entry (coseSign1, payloadHash, or a parseable createdAt where a key window or the start of signing needs one), or carries it as another type. The export/dump is incomplete or was edited, and an entry the verifier cannot place is never read as early unsigned history. Regenerate the export/dump from the operator and re-run.',
  CHAIN_COSE_DECODE_FAILED:
    'The COSE_Sign1 envelope did not decode as a tagged 4-element structure. The signed bytes are corrupt. Regenerate the export/dump.',
  CHAIN_COSE_HEADER_MISMATCH:
    'The position/previousHash signed in the COSE protected header disagree with the row columns. The visible columns were renumbered after signing. Trust the signed header, not the columns.',
  CHAIN_PAYLOAD_BINDING_MISMATCH:
    'The signed payload\'s structure no longer matches the canonical projection of the row columns it is bound to: the visible (denormalised) payload was altered after signing. This is a binding-integrity failure, not a judgement on content.',
  CHAIN_OIDC_ACTOR_MISMATCH:
    'The denormalised actor OIDC issuer/subject columns disagree with the identity signed in predicate.on_behalf_of. The actor columns were tampered with after signing.',
  CHAIN_SIGNATURE_INVALID:
    'The COSE_Sign1 signature did not verify against the entry\'s signing key, under the algorithm that key commits to. The entry was forged or altered: obtain the verification keys out of band and re-run.',
  CHAIN_SIGNATURE_MISSING_KEY:
    'No public key was available for the entry\'s signingKeyId. Supply the key out of band (GET /v1/verification-keys or /.well-known/scitt-keys) and re-run.',
  CHAIN_KEY_POLICY_VIOLATION:
    'The entry\'s signing key violates the caller\'s key policy (requireKeyId, or requireSuppliedKeys refusing a key the artifact embeds). Re-run with the expected key id, or supply the keys yourself. Where a key came from does not make it trusted: pin a trust anchor (trustAnchors) for that.',
  CHAIN_KEY_EXPIRED:
    'The entry was written AFTER its signing key was retired, or after the instant distrustedKeys (VAULT_DISTRUSTED_KEYS on the Server) gives for that key; the detail says which. Possible use of a compromised key: check the key rotation and retention record for that key id.',
  CHAIN_KEY_NOT_YET_ACTIVE:
    'The entry was written BEFORE its signing key was activated. Not a rotation problem: the usual causes are a backdated entry or clock skew between the signer and the key registry. Compare the entry write time against the key activation time before treating this as tamper.',
  CHAIN_ALG_MISMATCH:
    'The algorithm in the signed protected header (label 1) is not one the entry\'s trusted verification key can produce, or the key registry\'s declared algorithm contradicts the key material itself. Tamper class: the header alg or the key registry was rewritten. Treat the entry as forged; obtain the verification keys out of band and re-run.',
  CHAIN_UNSUPPORTED_ALGORITHM:
    'The entry\'s trusted verification key commits to a signature algorithm that could not be computed, either because this verifier build does not implement it or because the host runtime refused it (an active OpenSSL FIPS provider carries no EdDSA). The chain is NOT verified, and this is NOT tamper evidence: the signature was never checked. Upgrade the verifier, or re-run on a host without the restriction. Never treat this result as a pass.',
  CHAIN_SIGNING_KEY_DRIFT:
    'The entry\'s signingKeyId column names a different key than the signature-covered kid in the COSE protected header. The column is a denormalized convenience and was rewritten after signing (possibly to point verification at another key). Trust the signed kid; treat the row as tampered.',
  CHAIN_ACTOR_ATTRIBUTION_MISMATCH:
    'The entry\'s actorId / actorOwnerId columns name a different actor than the signature-covered actor claim in the COSE protected header (CWT_Claims label 15, private label -65539). The columns are the projection a report displays and they were rewritten after signing, re-attributing the action to another actor. Trust the signed claim; treat the row as tampered and re-obtain the export from the operator.',
  CHAIN_AGENT_SIGNATURE_INVALID:
    'The agent signature sealed in predicate.on_behalf_of.agent_signature does not verify under the supplied key whose RFC 7638 thumbprint the entry itself names, or is sealed in a shape nothing can verify. The engine checks this signature at intake and the envelope signature says the engine wrote it, so this is not a caller mistake: treat the agent attribution of this entry as unproven and escalate to the operator.',
  CHAIN_ENTRY_UNSIGNED:
    'The entry carries no signing key id where the install could not have written an unsigned entry: after a signed entry in the same chain, or at or after the earliest activation time in the signing key set (retired keys included). From that instant every writer holds a registered key, so this is what a writer without one leaves on the chain, or a signed row whose key id was nulled. Treat the entry as forged and escalate to the operator. Unsigned entries from before the first key activation stay reduced signature coverage, not a break.',
  CHAIN_SIGNING_KEY_UNANCHORED:
    'The entry is signed by a key that no signed key statement links to a trust anchor you pinned. Anything with write access to the Server\'s database can register a key and sign entries with it; what it cannot write is a statement signed by a key you trust. Treat the entry as forged. If the key is one you vouch for, pin it (trustAnchors) from a source outside the Server, never from the document that served it.',
  CHAIN_KEY_WINDOW_DRIFT:
    'A key registry column (activatedAt, retiredAt or status in a dump row or key document) differs from the value its signed key statements carry. The signed value is the one entries are graded against; the column was rewritten, or the retirement was written without its closure statement. Treat the registry as tampered and compare it with the Server\'s own scan (key_window_drift). Where the detail names a distrust entry the listing says the Server applies (distrustedFrom, VAULT_DISTRUSTED_KEYS), the listed retirement may be that entry\'s cut, which the verifier was not given or was given at another instant; the listing\'s word is unsigned, so it stays tampering until the Server\'s operator confirms the entry.',
  CHECKPOINT_ROW_MISSING:
    'A signed checkpoint anchors a position that has no matching chain row. The chain was truncated below a checkpoint (out-of-band DELETE/TRUNCATE). The checkpoint is proof of the missing rows.',
  CHECKPOINT_HASH_MISMATCH:
    'A checkpoint\'s payloadHash does not match the chain row at its position. The chain diverged from what was checkpointed. Treat the chain as tampered.',
  CHECKPOINT_SIGNATURE_INVALID:
    'A checkpoint\'s COSE_Sign1 signature did not verify. The checkpoint was forged or altered. Re-run with out-of-band verification keys.',
  CHECKPOINT_UNSIGNED:
    'A checkpoint carries no signing key id but was written at or after the earliest activation time in the signing key set (retired keys included), when every writer holds a registered key. The checkpoint was forged or its key id nulled, and nothing it anchors can be trusted. Escalate to the operator.',
  CHECKPOINT_KEY_UNANCHORED:
    'A vault checkpoint is signed by a key that no signed key statement links to a trust anchor you pinned. Nothing it anchors can be trusted; treat it as forged (see CHAIN_SIGNING_KEY_UNANCHORED).',
  CHECKPOINT_CLAIM_MISMATCH:
    'The claim signed inside a vault checkpoint envelope does not decode, or says something the checkpoint row\'s columns do not (chain position, chain tip hash, subject digest or signed kid). A column was rewritten beside an intact envelope. Trust the signed claim, treat the checkpoint row as tampered, and obtain the dump from the operator again.',
  TENANT_READ_LEAF_HASH_MISMATCH:
    'An org_admin_reads leaf_hash does not match the RFC 9162 leaf hash of its envelope, sha256(0x00 || cose_sign1). The read-log leaf was altered after recording.',
  TENANT_READ_LEAF_INDEX_GAP:
    'org_admin_reads leaf indices are not gap-free for this org. A read-log entry was removed. Obtain the complete log.',
  TENANT_READ_SIGNATURE_INVALID:
    'An org_admin_reads leaf\'s COSE_Sign1 signature did not verify. The read-log leaf was forged or altered.',
  TENANT_READ_LEAF_UNSIGNED:
    'An org_admin_reads leaf carries the unsigned kid where the install could not have written one: after a signed leaf in the same org log, or at or after the earliest activation time in the signing key set. Treat the leaf as forged and escalate to the operator.',
  TENANT_READ_KEY_UNANCHORED:
    'An org_admin_reads leaf is signed by a key that no signed key statement links to a trust anchor you pinned. Treat the leaf as forged (see CHAIN_SIGNING_KEY_UNANCHORED).',
  TENANT_READ_CLAIM_MISMATCH:
    'The claim signed inside an org_admin_reads leaf envelope does not decode, or says something the leaf row\'s columns do not (position, previous_hash, record_id or subject digest). A column was rewritten beside an intact envelope. Trust the signed claim and treat the read-log leaf as tampered.',
  TENANT_CHECKPOINT_LEAF_COUNT_MISMATCH:
    'A signed tree head commits to more leaves than the dump contains. The read log was truncated below a checkpoint.',
  TENANT_CHECKPOINT_ROOT_MISMATCH:
    'The RFC 9162 Merkle root recomputed over the leaves does not match the signed root_hash. The read log diverged from what was checkpointed.',
  TENANT_CHECKPOINT_SIGNATURE_INVALID:
    'A signed-tree-head COSE_Sign1 signature did not verify. The STH was forged or altered.',
  TENANT_CHECKPOINT_UNSIGNED:
    'An org_admin_reads signed tree head carries no signing key id but was written at or after the earliest activation time in the signing key set. The tree head was forged or its key id nulled; escalate to the operator.',
  TENANT_CHECKPOINT_KEY_UNANCHORED:
    'An org_admin_reads signed tree head is signed by a key that no signed key statement links to a trust anchor you pinned. Treat it as forged (see CHAIN_SIGNING_KEY_UNANCHORED).',
  TENANT_CHECKPOINT_CLAIM_MISMATCH:
    'The claim signed inside an org_admin_reads tree-head envelope does not decode, or says something the tree-head row\'s columns do not (position, chain_tip_hash, leaf count, subject digest or signed kid). A column was rewritten beside an intact envelope. Trust the signed claim and treat the tree-head row as tampered.',
  TENANT_CHECKPOINT_FORK:
    'Two signed tree heads at the same tree_size carry different roots. This is an engine fork or signing-key compromise. Escalate immediately.',
  KEY_STATEMENT_INVALID:
    'A key statement does not verify, disagrees with the columns it was stored under, touches no anchored key, or was signed by a key after its closure or after the key was already admitted. It admits nothing. One that does not verify, or that a key signed after its closure, is what a writer with database access or a leaked retired key produces: have the operator retire that key with force and add it to VAULT_DISTRUSTED_KEYS, and pass the same entry as distrustedKeys.',
  KEY_CLOSURE_INVALID:
    'A key is retired with no closure that counts for it, or a closure is signed by a key the walk does not anchor, by a key after its own retirement, or dates a retirement before its subject was activated, or is signed by a key the walk reaches but does not anchor and retires an anchored key earlier, or with force, than any closure a published key signed (so a walk over the published key documents reads that key differently). A closure that still counts ends its subject\'s window whoever wrote it; if its signer leaked, have the operator add it to VAULT_DISTRUSTED_KEYS and pass the same entry as distrustedKeys.',
};

/** The actionable next step for a failure code. */
export function suggestion(code: FailureCode): string {
  return SUGGESTIONS[code];
}
