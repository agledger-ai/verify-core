/**
 * Self-contained crypto + canonicalization primitives.
 *
 * Mirrors the AGLedger engine-side implementations:
 *   - COSE_Sign1 verify (RFC 9052 §4.4): audit-vault/encoders/cose-sign1.ts
 *   - Merkle: audit-vault/merkle.ts
 *
 * Re-implemented here (not imported from any engine/SDK code) so the verifier
 * has zero engine dependency — the load-bearing property of an offline
 * auditor: the engine could be compromised and this still verifies correctly.
 * The only runtime dependency is `cborg`, a general-purpose CBOR library (not
 * AGLedger code), and Node's built-in `crypto`. No network, no filesystem.
 *
 * If the engine-side primitives ever change shape, both implementations must be
 * updated together; the conformance corpus (real engine output) is the
 * regression net that catches divergence.
 */
import { createPublicKey, hash, verify } from 'node:crypto';
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';

// --- SHA-256 ---

/** sha256 over arbitrary bytes -> lowercase hex. */
export function sha256Hex(bytes: Buffer | Uint8Array): string {
  return hash('sha256', bytes, 'hex');
}

/** sha256 over a string (UTF-8) -> lowercase hex. */
export function sha256HexString(s: string): string {
  return hash('sha256', s, 'hex');
}

// --- Ed25519 verification (raw bytes) ---

/**
 * Verify an Ed25519 signature over raw bytes.
 * `publicKeyBase64` is the SPKI DER public key, base64-encoded
 * (matches the engine's vault_signing_keys.public_key column).
 */
export function verifyEd25519Bytes(
  publicKeyBase64: string,
  input: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    const publicKeyObj = createPublicKey({
      key: Buffer.from(publicKeyBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    return verify(null, input, publicKeyObj, signature);
  } catch {
    return false;
  }
}

// --- COSE_Sign1 (RFC 9052 §4.4) verification ---

/** CBOR tag 18 — tagged COSE_Sign1 envelope. */
const COSE_SIGN1_TAG = 18;
const SIG_STRUCTURE_CONTEXT = 'Signature1';

/**
 * Decode a tagged COSE_Sign1 envelope into its three load-bearing parts.
 * Returns null on any structural failure — the caller surfaces it as
 * CHAIN_COSE_DECODE_FAILED.
 */
export interface CoseSign1Parts {
  protectedBstr: Uint8Array;
  payloadBstr: Uint8Array;
  signature: Uint8Array;
}

export function decodeCoseSign1(bytes: Uint8Array): CoseSign1Parts | null {
  try {
    const decoded = cborDecode(bytes, {
      useMaps: true,
      tags: { [COSE_SIGN1_TAG]: (control: () => unknown) => control() },
    }) as unknown;
    if (!Array.isArray(decoded) || decoded.length !== 4) return null;
    const [protectedBstr, , payloadBstr, signature] = decoded as [
      unknown,
      unknown,
      unknown,
      unknown,
    ];
    if (!(protectedBstr instanceof Uint8Array)) return null;
    if (!(payloadBstr instanceof Uint8Array)) return null;
    if (!(signature instanceof Uint8Array)) return null;
    return { protectedBstr, payloadBstr, signature };
  } catch {
    return null;
  }
}

/**
 * Verify a tagged COSE_Sign1 envelope's signature against the given public key.
 *
 * Reconstructs Sig_structure = ["Signature1", protected_bstr, h'' (empty
 * external_aad), payload_bstr] per RFC 9052 §4.4, deterministically CBOR-
 * encodes it (RFC 8949 §4.2.1), and runs Ed25519 verify. The producer used the
 * exact same construction, so byte-equality is required.
 *
 * Returns:
 *   - 'ok'           if the signature verifies
 *   - 'decode-fail'  if the envelope is malformed
 *   - 'invalid'      if the signature does not verify
 *   - 'unsigned'     if the signature slot is all-zero (engine booted without
 *                    VAULT_SIGNING_KEY at write time — chain integrity falls
 *                    back to the hash-link layer)
 */
export type CoseVerifyOutcome = 'ok' | 'decode-fail' | 'invalid' | 'unsigned';

export function verifyCoseSign1(
  coseSign1: Uint8Array,
  publicKeyBase64: string,
): CoseVerifyOutcome {
  const parts = decodeCoseSign1(coseSign1);
  if (!parts) return 'decode-fail';

  // Unsigned-mode envelopes carry 64 zero bytes in the signature slot. Detected
  // here so the caller can distinguish "engine booted without a signing key"
  // from "signature didn't verify."
  if (parts.signature.length === 64 && parts.signature.every((b) => b === 0)) {
    return 'unsigned';
  }

  const sigStructure: unknown[] = [
    SIG_STRUCTURE_CONTEXT,
    parts.protectedBstr,
    new Uint8Array(0),
    parts.payloadBstr,
  ];
  const toBeSigned = cborEncode(sigStructure, rfc8949EncodeOptions);
  return verifyEd25519Bytes(publicKeyBase64, toBeSigned, parts.signature) ? 'ok' : 'invalid';
}

/**
 * Extract the chain-mechanics private claim (`-65537`) from a COSE_Sign1
 * protected header. Returns the decoded `{ position, previous_hash }` or null
 * if the claim is missing/malformed. The caller cross-checks it against the
 * row's `chainPosition` / `previousHash` columns — a divergence means the row
 * was renumbered after signing.
 */
export interface ChainClaim {
  position: number;
  previous_hash: string | null;
}

const AGLEDGER_LABEL_CHAIN = -65537;
const CHAIN_SUBLABEL_POSITION = 1;
const CHAIN_SUBLABEL_PREVIOUS_HASH = 2;

export function extractChainClaim(protectedBstr: Uint8Array): ChainClaim | null {
  try {
    const ph = cborDecode(protectedBstr, { useMaps: true }) as Map<number, unknown>;
    const chain = ph.get(AGLEDGER_LABEL_CHAIN);
    if (!(chain instanceof Map)) return null;
    const position = chain.get(CHAIN_SUBLABEL_POSITION);
    const prev = chain.get(CHAIN_SUBLABEL_PREVIOUS_HASH);
    if (typeof position !== 'number' && typeof position !== 'bigint') return null;
    const positionNumber = typeof position === 'bigint' ? Number(position) : position;
    if (!Number.isInteger(positionNumber) || positionNumber < 1) return null;
    if (prev === null) return { position: positionNumber, previous_hash: null };
    if (!(prev instanceof Uint8Array)) return null;
    return { position: positionNumber, previous_hash: Buffer.from(prev).toString('hex') };
  } catch {
    return null;
  }
}

// --- Optional envelope extensions (OIDC on-behalf-of, traceparent) ---

const TRACEPARENT_REGEX = /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;

/**
 * Extract the OIDC on-behalf-of context from a COSE_Sign1 payload bstr. The
 * payload IS the in-toto v1 Statement; `predicate.on_behalf_of` carries the RFC
 * 8693 claim set. Returns the decoded object or null if absent/malformed.
 */
export function extractOnBehalfOfClaim(
  payloadBstr: Uint8Array,
): Record<string, unknown> | null {
  try {
    const stmt = cborDecode(payloadBstr, { useMaps: false }) as Record<string, unknown>;
    const predicate = stmt['predicate'];
    if (predicate === null || typeof predicate !== 'object' || Array.isArray(predicate)) {
      return null;
    }
    const block = (predicate as Record<string, unknown>)['on_behalf_of'];
    if (block === undefined || block === null) return null;
    if (typeof block !== 'object' || Array.isArray(block)) return null;
    return block as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Extract the W3C `traceparent` string from a COSE_Sign1 payload bstr. Reads
 * `predicate.traceparent` off the in-toto Statement; validates the v00 wire
 * shape and returns null for any non-conforming value so callers never see a
 * partially-trusted string.
 */
export function extractTraceparentClaim(payloadBstr: Uint8Array): string | null {
  try {
    const stmt = cborDecode(payloadBstr, { useMaps: false }) as Record<string, unknown>;
    const predicate = stmt['predicate'];
    if (predicate === null || typeof predicate !== 'object' || Array.isArray(predicate)) {
      return null;
    }
    const tp = (predicate as Record<string, unknown>)['traceparent'];
    if (typeof tp !== 'string') return null;
    return TRACEPARENT_REGEX.test(tp) ? tp : null;
  } catch {
    return null;
  }
}

// --- in-toto v1 predicate extraction + binding-integrity projection ---

/**
 * Decode the predicate object from a COSE_Sign1 payload bstr. The payload IS
 * the in-toto v1 Statement; the predicate body lives at `payload.predicate`.
 * Returns null on any decode failure. Used by the binding-integrity check — the
 * row's denormalised `payload` jsonb is a convenience view projected from this
 * predicate at write time; if the view was altered after signing,
 * `buildPredicateForRow(...) !== decodePredicate(...)`.
 */
export function decodePredicate(payloadBstr: Uint8Array): Record<string, unknown> | null {
  try {
    const stmt = cborDecode(payloadBstr, { useMaps: false }) as Record<string, unknown>;
    const predicate = stmt['predicate'];
    if (predicate === null || typeof predicate !== 'object' || Array.isArray(predicate)) {
      return null;
    }
    return predicate as Record<string, unknown>;
  } catch {
    return null;
  }
}

const SCHEMA_EVENT_TYPES: ReadonlySet<string> = new Set([
  'SCHEMA_REGISTERED',
  'SCHEMA_IMPORTED',
  'SCHEMA_DIGEST_MISMATCH',
]);
const SCHEMA_EVENT_OUTCOMES: Record<string, string> = {
  SCHEMA_REGISTERED: 'REGISTERED',
  SCHEMA_IMPORTED: 'IMPORTED',
  SCHEMA_DIGEST_MISMATCH: 'DIGEST_MISMATCH',
};

const RECORD_STATE_RESERVED_KEYS: ReadonlySet<string> = new Set([
  'from',
  'to',
  'state_transition',
  'traces',
  'on_behalf_of',
  'traceparent',
]);

/**
 * Re-project (record_id, entry_type, payload) -> predicate body using the SAME
 * logic the engine uses at write time (engine-side: audit-vault/
 * build-vault-claim.ts). This is the verifier-side mirror.
 *
 * Returns null when the row's payload is structurally insufficient (e.g.
 * SCHEMA_REGISTERED missing manifestDigest) — the caller surfaces null as a
 * binding mismatch rather than throwing, so an attacker who zeros out payload
 * can't crash the verifier.
 */
export function buildPredicateForRow(
  recordId: string | null,
  entryType: string,
  payload: Record<string, unknown>,
): Record<string, unknown> | null {
  if (SCHEMA_EVENT_TYPES.has(entryType)) {
    return buildSchemaEventPredicateForRow(entryType, payload);
  }
  if (recordId === null) return null;
  return buildRecordStatePredicateForRow(recordId, entryType, payload);
}

function buildRecordStatePredicateForRow(
  recordId: string,
  entryType: string,
  payload: Record<string, unknown>,
): Record<string, unknown> {
  const transition = extractStateTransitionForRow(payload);

  const passthrough: Record<string, unknown> = {};
  for (const key of Object.keys(payload)) {
    if (RECORD_STATE_RESERVED_KEYS.has(key)) continue;
    passthrough[key] = payload[key];
  }

  const predicate: Record<string, unknown> = {
    record_id: recordId,
    entry_type: entryType,
  };
  if (transition !== undefined) predicate['state_transition'] = transition;
  if (Object.keys(passthrough).length > 0) predicate['payload'] = passthrough;

  const traces = payload['traces'];
  if (traces && typeof traces === 'object' && !Array.isArray(traces)) {
    predicate['traces'] = traces;
  }
  return predicate;
}

function extractStateTransitionForRow(
  payload: Record<string, unknown>,
): { from: string | null; to: string } | undefined {
  const explicit = payload['state_transition'];
  if (explicit && typeof explicit === 'object' && !Array.isArray(explicit)) {
    const t = explicit as { from?: unknown; to?: unknown };
    if (typeof t.to === 'string') {
      return { from: typeof t.from === 'string' ? t.from : null, to: t.to };
    }
  }
  const from = payload['from'];
  const to = payload['to'];
  if (typeof to === 'string') {
    return { from: typeof from === 'string' ? from : null, to };
  }
  return undefined;
}

function buildSchemaEventPredicateForRow(
  entryType: string,
  payload: Record<string, unknown>,
): Record<string, unknown> | null {
  const orgId = payload['orgId'];
  const schemaType = payload['type'] ?? payload['schemaType'] ?? payload['schema_type'];
  const rawSchemaVersion =
    payload['version'] ?? payload['schemaVersion'] ?? payload['schema_version'];
  const schemaVersion =
    typeof rawSchemaVersion === 'number' && Number.isFinite(rawSchemaVersion)
      ? String(rawSchemaVersion)
      : rawSchemaVersion;
  const manifestDigest = payload['manifestDigest'] ?? payload['manifest_digest'];
  const source = payload['source'];

  if (typeof schemaType !== 'string') return null;
  if (typeof schemaVersion !== 'string') return null;
  if (typeof manifestDigest !== 'string') return null;
  const outcome = SCHEMA_EVENT_OUTCOMES[entryType];
  if (outcome === undefined) return null;

  const predicate: Record<string, unknown> = {
    org_id: typeof orgId === 'string' ? orgId : null,
    schema_type: schemaType,
    schema_version: schemaVersion,
    manifest_digest: manifestDigest,
    outcome,
  };
  if (typeof source === 'string') predicate['source'] = source;
  return predicate;
}

/**
 * Order-insensitive deep equality over plain JSON-shaped values. Used by the
 * binding-integrity check — the rebuilt and decoded predicates may serialize
 * keys in different order across writer/reader paths.
 */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (Array.isArray(b)) return false;
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const aKeys = Object.keys(ao);
  const bKeys = Object.keys(bo);
  if (aKeys.length !== bKeys.length) return false;
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(bo, k)) return false;
    if (!deepEqual(ao[k], bo[k])) return false;
  }
  return true;
}

/**
 * Strip envelope-level sibling fields (`on_behalf_of`, `traceparent`) from a
 * decoded predicate. They ride alongside per-kind predicate fields on the wire
 * but the engine's `buildPredicateOnly` — and our `buildPredicateForRow`
 * mirror — exclude them from the rebuilt predicate. Stripping here makes the
 * two shapes deep-equalable; envelope-level integrity is covered by the
 * signature and the OIDC-actor cross-check.
 */
export function stripEnvelopeExtensions(
  predicate: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(predicate)) {
    if (k === 'on_behalf_of' || k === 'traceparent') continue;
    out[k] = predicate[k];
  }
  return out;
}

// --- RFC 9162 Merkle (SCITT Receipt verifiable data structure) ---

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

function sha256Bytes(input: Uint8Array): Uint8Array {
  return new Uint8Array(hash('sha256', input, 'buffer'));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/** RFC 9162 §2.1.1 leaf hash: SHA-256(0x00 || d). */
export function rfc9162LeafHash(leafData: Uint8Array): Uint8Array {
  return sha256Bytes(concat(LEAF_PREFIX, leafData));
}

/** RFC 9162 §2.1.1 internal-node hash: SHA-256(0x01 || left || right). */
export function rfc9162NodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256Bytes(concat(NODE_PREFIX, left, right));
}

/**
 * Verify a RFC 9162 §2.1.3.2 inclusion proof. Mirrors the engine-side
 * implementation; reproduced here so the verifier stays engine-free.
 */
export function verifyRfc9162Inclusion(
  leafHashBytes: Uint8Array,
  leafIndex: number,
  treeSize: number,
  path: readonly Uint8Array[],
  expectedRoot: Uint8Array,
): boolean {
  if (leafIndex < 0 || leafIndex >= treeSize) return false;
  if (treeSize === 1) return path.length === 0 && bytesEqual(leafHashBytes, expectedRoot);
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHashBytes;
  let i = 0;
  for (; i < path.length; i += 1) {
    if (sn === 0) return false;
    const p = path[i]!;
    if ((fn & 1) === 1 || fn === sn) {
      r = rfc9162NodeHash(p, r);
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>>= 1;
        sn >>>= 1;
      }
    } else {
      r = rfc9162NodeHash(r, p);
    }
    fn >>>= 1;
    sn >>>= 1;
    if (sn === 0) {
      i += 1;
      break;
    }
  }
  if (sn !== 0) return false;
  if (i !== path.length) return false;
  return bytesEqual(r, expectedRoot);
}

// --- SCITT Receipt verifiable-data-proof extraction (label 396, key -1) ---

const COSE_HEADER_VDP = 396;
const VDP_INCLUSION_PROOF_KEY = -1;

export interface ReceiptInclusionProof {
  treeSize: number;
  leafIndex: number;
  auditPath: Uint8Array[];
}

/**
 * Extract the RFC 9162 inclusion proof from a COSE_Sign1 Receipt's unprotected
 * header. Returns null when the structure is wrong or the label is absent.
 */
export function extractReceiptInclusionProof(
  receiptBytes: Uint8Array,
): ReceiptInclusionProof | null {
  try {
    const decoded = cborDecode(receiptBytes, {
      useMaps: true,
      tags: { [COSE_SIGN1_TAG]: (control: () => unknown) => control() },
    }) as unknown;
    if (!Array.isArray(decoded) || decoded.length !== 4) return null;
    const [, unprotected] = decoded as [unknown, unknown];
    if (!(unprotected instanceof Map)) return null;
    const vdp = unprotected.get(COSE_HEADER_VDP);
    if (!(vdp instanceof Map)) return null;
    const proof = vdp.get(VDP_INCLUSION_PROOF_KEY);
    if (!Array.isArray(proof) || proof.length !== 3) return null;
    const [treeSizeRaw, leafIndexRaw, pathRaw] = proof as [unknown, unknown, unknown];
    const treeSize =
      typeof treeSizeRaw === 'bigint'
        ? Number(treeSizeRaw)
        : typeof treeSizeRaw === 'number'
          ? treeSizeRaw
          : NaN;
    const leafIndex =
      typeof leafIndexRaw === 'bigint'
        ? Number(leafIndexRaw)
        : typeof leafIndexRaw === 'number'
          ? leafIndexRaw
          : NaN;
    if (!Number.isInteger(treeSize) || !Number.isInteger(leafIndex)) return null;
    if (!Array.isArray(pathRaw)) return null;
    const auditPath: Uint8Array[] = [];
    for (const seg of pathRaw) {
      if (!(seg instanceof Uint8Array)) return null;
      auditPath.push(seg);
    }
    return { treeSize, leafIndex, auditPath };
  } catch {
    return null;
  }
}

/**
 * Full end-to-end Receipt verification: decode envelope, verify TS signature
 * against `tsPublicKey`, extract VDP, recompute the Merkle root from
 * `signedStatementBytes`, assert it matches the COSE payload (the signed root).
 *
 * Returns:
 *   - 'ok'                — TS sig valid AND reconstructed root matches
 *   - 'decode-fail'       — envelope or VDP malformed
 *   - 'signature-invalid' — TS signature fails (root cannot be trusted)
 *   - 'root-mismatch'     — reconstructed root != COSE payload (proof lies about
 *                           which tree the leaf belongs to)
 */
export type ReceiptVerifyOutcome = 'ok' | 'decode-fail' | 'signature-invalid' | 'root-mismatch';

export function verifyReceipt(
  receiptBytes: Uint8Array,
  signedStatementBytes: Uint8Array,
  tsPublicKeyBase64: string,
): ReceiptVerifyOutcome {
  const parts = decodeCoseSign1(receiptBytes);
  if (!parts) return 'decode-fail';
  const sigOk = verifyCoseSign1(receiptBytes, tsPublicKeyBase64);
  if (sigOk !== 'ok') return 'signature-invalid';

  const vdp = extractReceiptInclusionProof(receiptBytes);
  if (!vdp) return 'decode-fail';
  // The Receipt payload IS the signed Merkle root the TS committed to.
  const signedRoot = parts.payloadBstr;
  const leaf = rfc9162LeafHash(signedStatementBytes);
  const ok = verifyRfc9162Inclusion(leaf, vdp.leafIndex, vdp.treeSize, vdp.auditPath, signedRoot);
  return ok ? 'ok' : 'root-mismatch';
}

// --- Merkle tree (org_admin_reads) ---

/**
 * Tree shape mirrors the engine's merkle.ts: balance-by-duplicating-last-leaf,
 * sha256(hex(left) || hex(right)) over hex strings, no RFC 6962 leaf prefix.
 */
function hashPair(left: string, right: string): string {
  return hash('sha256', left + right, 'hex');
}

export function merkleRoot(leaves: readonly string[]): string {
  if (leaves.length === 0) return hash('sha256', '', 'hex');
  let level: string[] = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i] ?? '';
      const right = level[i + 1] ?? left;
      next.push(hashPair(left, right));
    }
    level = next;
  }
  return level[0] ?? '';
}

export function verifyInclusion(
  leafHash: string,
  leafIndex: number,
  treeSize: number,
  path: readonly string[],
  expectedRoot: string,
): boolean {
  if (leafIndex < 0 || leafIndex >= treeSize) return false;
  let current = leafHash;
  let index = leafIndex;
  let levelSize = treeSize;
  let pathPos = 0;
  while (levelSize > 1) {
    const sibling = path[pathPos++];
    if (sibling === undefined) return false;
    current = index % 2 === 0 ? hashPair(current, sibling) : hashPair(sibling, current);
    index = Math.floor(index / 2);
    levelSize = Math.ceil(levelSize / 2);
  }
  return current === expectedRoot && pathPos === path.length;
}
