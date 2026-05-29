/**
 * The shared per-chain verification walk.
 *
 * This is the single body of logic the SDK /verify, CLI, MCP server, and
 * @agledger/verify all run — replacing four hand-vendored copies. It walks ONE
 * hash chain (a single record's lifecycle, or a single per-org schema-event
 * chain) over a normalized entry shape and emits the canonical failure
 * taxonomy.
 *
 * Two input surfaces feed it through thin adapters:
 *   - the live `/audit-export` JSON (per-record; see audit-export.ts)
 *   - the offline NDJSON vault dump (full-vault; @agledger/verify)
 *
 * Checks split into two tiers:
 *   - ALWAYS-RUN (every surface): position monotonicity, payloadHash =
 *     sha256(cose_sign1), previous-hash link, COSE_Sign1 decode, the signed
 *     protected-header chain-claim cross-check, and the Ed25519 signature.
 *   - INPUT-GATED (only when the normalized entry carries the inputs — i.e. the
 *     dump path): binding-integrity, OIDC-actor cross-check, temporal
 *     key-validity. The `/audit-export` wire does NOT carry the inputs these
 *     need (the API re-projects the export payload from the signed bytes and
 *     omits the synthesized flag), so running them there would either no-op
 *     silently or compare signed bytes to a derivative of themselves. They are
 *     therefore reported as `skipped_no_input` on the export path — NEVER folded
 *     into a green verdict.
 *
 * Failure ordering is fixed so `brokenAt` is deterministic. The null-key
 * signature skip happens LAST, after the binding/OIDC checks, so a row written
 * without a signing key is still subject to every structural check.
 */
import {
  buildPredicateForRow,
  decodeCoseSign1,
  decodePredicate,
  deepEqual,
  extractChainClaim,
  extractOnBehalfOfClaim,
  sha256Hex,
  stripEnvelopeExtensions,
  verifyCoseSign1,
} from './primitives.js';
import type { FailureCode } from './failures.js';

/** Where a verification key came from — the trust-anchor provenance. */
export type KeySource = 'out-of-band' | 'embedded';

/** A public key the walk can verify signatures against. */
export interface VerificationKey {
  keyId: string;
  /** SPKI DER, base64-encoded (the engine's vault_signing_keys.public_key shape). */
  spkiBase64: string;
  /**
   * `out-of-band` = supplied by the caller from a trusted source (e.g.
   * /v1/verification-keys, /.well-known/scitt-keys). `embedded` = shipped inside
   * the artifact being verified (the export/dump the engine produced). Surfaced
   * in the result so a caller can tell whether it verified the engine against an
   * independent key or against the engine's own answer key.
   */
  source: KeySource;
  /** Optional temporal-validity window (present on the dump path only). */
  activatedAt?: string;
  retiredAt?: string | null;
}

export type KeyRegistry = ReadonlyMap<string, VerificationKey>;

export function buildKeyRegistry(keys: readonly VerificationKey[]): KeyRegistry {
  const map = new Map<string, VerificationKey>();
  for (const k of keys) map.set(k.keyId, k);
  return map;
}

/** Inputs the input-gated checks consume; present only on the dump path. */
export interface NormalizedEntry {
  /** Identity for messages — recordId (export) or chainKey (dump). */
  scopeId: string;
  chainPosition: number;
  payloadHash: string;
  previousHash: string | null;
  /** Base64-encoded canonical COSE_Sign1 envelope. */
  coseSign1: string;
  signingKeyId: string | null;
  /** ISO-8601 write time, for temporal key-validity (dump path). */
  createdAt?: string;
  /** Inputs for the binding-integrity check (dump path). */
  binding?: {
    recordId: string | null;
    entryType: string;
    payload: Record<string, unknown>;
  };
  /** Inputs for the OIDC-actor cross-check (dump path). */
  oidcActor?: {
    iss: string | null;
    sub: string | null;
    synthesized: boolean | undefined;
  };
}

export type OptionalCheck = 'payload_binding' | 'oidc_actor' | 'key_temporal';
export type CheckApplicability = 'applied' | 'skipped_no_input';

export interface SignatureOutcome {
  /**
   * - `ok` / `invalid` / `decode-fail` — the signature was checked (and passed,
   *   failed, or the envelope would not decode).
   * - `unsigned` — the entry carries no signature by design.
   * - `skipped` — the chain is intact but this entry has no signing key, so the
   *   signature check was deliberately not run (engine booted without a key).
   * - `not-checked` — a structural/chain check failed at or before this entry,
   *   so verification short-circuited before reaching the signature. Reads as a
   *   consequence of an upstream break, never as a benign skip.
   */
  state: 'ok' | 'invalid' | 'unsigned' | 'skipped' | 'not-checked' | 'decode-fail';
  /** Provenance of the key the signature was checked against ('ok' / 'invalid'). */
  keySource?: KeySource;
}

export interface ChainEntryResult {
  scopeId: string;
  position: number;
  valid: boolean;
  failure?: { code: FailureCode; detail: string };
  signature: SignatureOutcome['state'];
  keySource?: KeySource;
}

export interface ChainResult {
  scopeId: string;
  valid: boolean;
  totalEntries: number;
  verifiedEntries: number;
  brokenAt?: { position: number; code: FailureCode; detail: string };
  entries: ChainEntryResult[];
  signatureCoverage: { signed: number; unsigned: number; skipped: number; total: number };
  /** Which input-gated checks actually ran on this chain vs were skipped for absent input. */
  optionalChecks: Record<OptionalCheck, CheckApplicability>;
  /** How many signature checks resolved against out-of-band vs embedded keys. */
  keyProvenance: { outOfBand: number; embedded: number };
}

export interface VerifyChainOptions {
  /** Require every entry's signingKeyId to equal this id (else CHAIN_KEY_POLICY_VIOLATION). */
  requireKeyId?: string;
  /**
   * High-assurance auditor mode: refuse to verify against keys shipped inside
   * the artifact. An entry whose only available key is `embedded` fails
   * CHAIN_KEY_POLICY_VIOLATION. Forces the caller to supply keys out of band.
   */
  requireOutOfBandKeys?: boolean;
}

/**
 * Verify a single hash chain. `entries` are all the entries for one scope; they
 * are sorted by chainPosition internally (so a reordered export array still
 * validates the true chain — tampering surfaces through the hash links).
 */
export function verifyChain(
  entries: readonly NormalizedEntry[],
  keys: KeyRegistry,
  options: VerifyChainOptions = {},
): ChainResult {
  const scopeId = entries[0]?.scopeId ?? '(empty)';
  const sorted = [...entries].sort((a, b) => a.chainPosition - b.chainPosition);

  const entryResults: ChainEntryResult[] = [];
  const coverage = { signed: 0, unsigned: 0, skipped: 0, total: sorted.length };
  const optionalChecks: Record<OptionalCheck, CheckApplicability> = {
    payload_binding: 'skipped_no_input',
    oidc_actor: 'skipped_no_input',
    key_temporal: 'skipped_no_input',
  };
  const keyProvenance = { outOfBand: 0, embedded: 0 };
  let verifiedEntries = 0;
  let brokenAt: ChainResult['brokenAt'];

  if (sorted.length === 0) {
    return {
      scopeId,
      valid: false,
      totalEntries: 0,
      verifiedEntries: 0,
      brokenAt: { position: 0, code: 'CHAIN_EMPTY', detail: 'No entries to verify.' },
      entries: [],
      signatureCoverage: coverage,
      optionalChecks,
      keyProvenance,
    };
  }

  let previousHash: string | null = null;
  for (let i = 0; i < sorted.length; i++) {
    const entry = sorted[i]!;
    const expectedPosition = i + 1;
    const result = verifyEntry(
      entry,
      expectedPosition,
      previousHash,
      keys,
      options,
      optionalChecks,
    );
    entryResults.push(result);

    if (result.valid) verifiedEntries++;
    else if (!brokenAt && result.failure) {
      brokenAt = { position: result.position, code: result.failure.code, detail: result.failure.detail };
    }

    switch (result.signature) {
      case 'ok':
        coverage.signed++;
        if (result.keySource === 'out-of-band') keyProvenance.outOfBand++;
        else if (result.keySource === 'embedded') keyProvenance.embedded++;
        break;
      case 'unsigned':
        coverage.unsigned++;
        break;
      case 'skipped':
        coverage.skipped++;
        break;
      // 'not-checked' / 'invalid' / 'decode-fail' are failure states — the entry
      // is already counted as broken, so it contributes to no coverage bucket.
    }

    previousHash = entry.payloadHash;
  }

  return {
    scopeId,
    valid: verifiedEntries === sorted.length,
    totalEntries: sorted.length,
    verifiedEntries,
    brokenAt,
    entries: entryResults,
    signatureCoverage: coverage,
    optionalChecks,
    keyProvenance,
  };
}

function fail(
  scopeId: string,
  position: number,
  code: FailureCode,
  detail: string,
  signature: SignatureOutcome['state'] = 'not-checked',
): ChainEntryResult {
  return { scopeId, position, valid: false, failure: { code, detail }, signature };
}

function verifyEntry(
  entry: NormalizedEntry,
  expectedPosition: number,
  expectedPrevHash: string | null,
  keys: KeyRegistry,
  options: VerifyChainOptions,
  optionalChecks: Record<OptionalCheck, CheckApplicability>,
): ChainEntryResult {
  const { scopeId } = entry;

  if (entry.chainPosition !== expectedPosition) {
    return fail(
      scopeId,
      entry.chainPosition,
      'CHAIN_POSITION_GAP',
      `Expected chainPosition ${expectedPosition}, got ${entry.chainPosition}.`,
    );
  }

  if (!entry.coseSign1 || !entry.payloadHash) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_MALFORMED_ENTRY',
      'Entry is missing coseSign1 or payloadHash.',
    );
  }

  const envelopeBytes = Buffer.from(entry.coseSign1, 'base64');
  const recomputed = sha256Hex(envelopeBytes);
  if (recomputed !== entry.payloadHash) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_HASH_MISMATCH',
      `sha256(cose_sign1) ${recomputed.slice(0, 16)}... does not match stored payloadHash ${entry.payloadHash.slice(0, 16)}...`,
    );
  }

  const expectedPrev = expectedPosition === 1 ? null : expectedPrevHash;
  if (entry.previousHash !== expectedPrev) {
    return fail(
      scopeId,
      expectedPosition,
      expectedPosition === 1 ? 'CHAIN_GENESIS_INVALID' : 'CHAIN_LINK_BROKEN',
      `Expected previousHash=${expectedPrev ?? 'null'}, got ${entry.previousHash ?? 'null'}.`,
    );
  }

  const parts = decodeCoseSign1(envelopeBytes);
  if (!parts) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_COSE_DECODE_FAILED',
      'COSE_Sign1 envelope failed to decode.',
      'decode-fail',
    );
  }

  // Cross-check the signed protected-header chain claim against the verifier's
  // OWN expected position/prev-hash (not the attacker-controllable row columns),
  // so this check stands on its own rather than depending on the position/link
  // checks above having already constrained the columns.
  const chainClaim = extractChainClaim(parts.protectedBstr);
  if (
    !chainClaim ||
    chainClaim.position !== expectedPosition ||
    chainClaim.previous_hash !== expectedPrev
  ) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_COSE_HEADER_MISMATCH',
      `Signed protected-header chain claim (position=${chainClaim?.position ?? 'null'}, prev=${chainClaim?.previous_hash ?? 'null'}) diverges from row columns (position=${entry.chainPosition}, prev=${entry.previousHash ?? 'null'}).`,
    );
  }

  // Input-gated: binding-integrity. Runs whenever the row payload is present —
  // the dump always carries it, and the export now carries it too (engine ≥ v0.26.x).
  if (entry.binding) {
    optionalChecks.payload_binding = 'applied';
    const decodedRaw = decodePredicate(parts.payloadBstr);
    const rebuilt = buildPredicateForRow(
      entry.binding.recordId,
      entry.binding.entryType,
      entry.binding.payload,
    );
    const decoded = decodedRaw !== null ? stripEnvelopeExtensions(decodedRaw) : null;
    if (decoded === null || rebuilt === null || !deepEqual(rebuilt, decoded)) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_PAYLOAD_BINDING_MISMATCH',
        'Denormalised row payload no longer matches the canonical projection of the signed predicate.',
      );
    }
  }

  // Input-gated: OIDC-actor cross-check. Only when the dump carried the columns.
  if (entry.oidcActor) {
    optionalChecks.oidc_actor = 'applied';
    const oidcFailure = checkOidcActor(entry.oidcActor, parts.payloadBstr, scopeId, expectedPosition);
    if (oidcFailure) return oidcFailure;
  }

  // Signature (last, so a null-key row still ran every structural check above).
  if (!entry.signingKeyId) {
    // Fail closed under a key policy: a high-assurance run that requires a
    // specific key (or out-of-band keys) must NOT accept an unsigned/null-key
    // entry as valid — otherwise an attacker forges an entry, nulls its
    // signingKeyId, and slips past the policy the auditor explicitly set.
    if (options.requireKeyId || options.requireOutOfBandKeys) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_KEY_POLICY_VIOLATION',
        'Entry has no signingKeyId but this run requires a signed entry (requireKeyId / requireOutOfBandKeys).',
      );
    }
    return { scopeId, position: expectedPosition, valid: true, signature: 'skipped' };
  }

  if (options.requireKeyId && entry.signingKeyId !== options.requireKeyId) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_KEY_POLICY_VIOLATION',
      `Entry signingKeyId=${entry.signingKeyId} does not match required key id ${options.requireKeyId}.`,
    );
  }

  const key = keys.get(entry.signingKeyId);
  if (!key) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_SIGNATURE_MISSING_KEY',
      `No public key available for signingKeyId=${entry.signingKeyId}.`,
    );
  }

  if (options.requireOutOfBandKeys && key.source !== 'out-of-band') {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_KEY_POLICY_VIOLATION',
      `Key ${entry.signingKeyId} is embedded in the artifact; this run requires out-of-band keys.`,
    );
  }

  // Input-gated: temporal key-validity. Only when both the key window and the
  // entry write time are present (dump path).
  if (entry.createdAt && (key.activatedAt || key.retiredAt)) {
    optionalChecks.key_temporal = 'applied';
    const expiredDetail = temporalKeyFailure(entry.createdAt, key);
    if (expiredDetail) {
      return fail(scopeId, expectedPosition, 'CHAIN_KEY_EXPIRED', expiredDetail);
    }
  }

  const outcome = verifyCoseSign1(envelopeBytes, key.spkiBase64);
  if (outcome === 'unsigned') {
    return { scopeId, position: expectedPosition, valid: true, signature: 'unsigned' };
  }
  if (outcome === 'ok') {
    return { scopeId, position: expectedPosition, valid: true, signature: 'ok', keySource: key.source };
  }
  return fail(
    scopeId,
    expectedPosition,
    'CHAIN_SIGNATURE_INVALID',
    `COSE_Sign1 signature did not verify against key ${entry.signingKeyId}.`,
    outcome === 'decode-fail' ? 'decode-fail' : 'invalid',
  );
}

function checkOidcActor(
  oidc: NonNullable<NormalizedEntry['oidcActor']>,
  payloadBstr: Uint8Array,
  scopeId: string,
  position: number,
): ChainEntryResult | null {
  const rowIss = oidc.iss ?? null;
  const rowSub = oidc.sub ?? null;
  const { synthesized } = oidc;

  // synthesized=true (or legacy undefined with populated columns): the row
  // columns MUST equal the identity signed in predicate.on_behalf_of.oidc.
  if (synthesized === true || (synthesized === undefined && (rowIss !== null || rowSub !== null))) {
    const obo = extractOnBehalfOfClaim(payloadBstr);
    const signedOidc =
      obo !== null && typeof obo['oidc'] === 'object' && obo['oidc'] !== null
        ? (obo['oidc'] as Record<string, unknown>)
        : null;
    const signedIss =
      signedOidc !== null && typeof signedOidc['iss'] === 'string' ? signedOidc['iss'] : null;
    const signedSub =
      signedOidc !== null && typeof signedOidc['sub'] === 'string' ? signedOidc['sub'] : null;
    if (rowIss !== signedIss || rowSub !== signedSub) {
      return fail(
        scopeId,
        position,
        'CHAIN_OIDC_ACTOR_MISMATCH',
        `Row actor OIDC iss/sub (${rowIss ?? 'null'}/${rowSub ?? 'null'}) diverges from signed predicate.on_behalf_of.oidc (${signedIss ?? 'null'}/${signedSub ?? 'null'}).`,
      );
    }
    return null;
  }

  // synthesized=false: engine writers leave the columns null. Any populated
  // state is a DB-level CHECK-constraint bypass.
  if (synthesized === false && (rowIss !== null || rowSub !== null)) {
    return fail(
      scopeId,
      position,
      'CHAIN_OIDC_ACTOR_MISMATCH',
      `actor_oidc_synthesized=false but iss/sub populated (${rowIss ?? 'null'}/${rowSub ?? 'null'}).`,
    );
  }
  return null;
}

function temporalKeyFailure(createdAt: string, key: VerificationKey): string | null {
  const written = Date.parse(createdAt);
  if (Number.isNaN(written)) return null;
  if (key.activatedAt) {
    const activated = Date.parse(key.activatedAt);
    if (!Number.isNaN(activated) && written < activated) {
      return `Entry written ${createdAt} predates key ${key.keyId} activation ${key.activatedAt}.`;
    }
  }
  if (key.retiredAt) {
    const retired = Date.parse(key.retiredAt);
    if (!Number.isNaN(retired) && written > retired) {
      return `Entry written ${createdAt} postdates key ${key.keyId} retirement ${key.retiredAt}.`;
    }
  }
  return null;
}
