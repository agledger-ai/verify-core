/**
 * The shared per-chain verification walk.
 *
 * This is the single body of logic the SDK /verify, CLI, MCP server, and
 * @agledger/verify all run, replacing four hand-vendored copies. It walks ONE
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
 *   - INPUT-GATED (only when the normalized entry, or the caller, supplies the
 *     inputs): binding-integrity, OIDC-actor cross-check, temporal
 *     key-validity, the agent-signature re-check, and key anchoring (a
 *     registry marked by `applyKeyTrust`). The first three run on
 *     the dump and on any export from an engine that ships the row fields
 *     (>= v0.26.x). The agent-signature check needs the cert's public key,
 *     which neither surface carries, so it runs only when the caller passes
 *     `agentKeys`. A check without its input is reported `skipped_no_input`,
 *     NEVER folded into a green verdict.
 *
 * Failure ordering is fixed so `brokenAt` is deterministic. The null-key
 * branch comes LAST, after the binding/OIDC checks, so a row written without a
 * signing key is still subject to every structural check, and a tamper finding
 * on it is reported under its own code rather than as CHAIN_ENTRY_UNSIGNED.
 * That branch grades the entry the way the engine does: an unsigned entry
 * after a signed one in its chain, or written at or after the earliest key
 * activation (`signingSince`), is CHAIN_ENTRY_UNSIGNED; an earlier one is a
 * `skipped` signature, reduced coverage rather than a break.
 */
import {
  buildPredicateForRow,
  decodeCoseSign1,
  decodePredicate,
  deepEqual,
  describeUnsupportedAlgorithm,
  ed25519JwkThumbprint,
  ed25519JwkToSpki,
  extractAgentSignatureClaim,
  extractActorClaim,
  extractChainClaim,
  extractKid,
  extractOnBehalfOfClaim,
  resolveKeyAlgorithm,
  sha256Hex,
  stripEnvelopeExtensions,
  envelopeExtensionsMatch,
  verifyAgentSignature,
  verifyCoseSign1,
  type AgentPublicKeyJwk,
} from './primitives.js';
import type { FailureCode } from './failures.js';
import { instantMs, rfc3339Ms } from './instant.js';
import { assertKnownOptions } from './options.js';

/**
 * Where a verification key came from. `supplied`: the caller passed it (from
 * `GET /v1/verification-keys`, `/.well-known/scitt-keys`, its own records).
 * `embedded`: the artifact under verification shipped it. Neither says the key
 * is trusted: a key the Server serves comes from its database, which is what
 * a key-registry attacker writes to. Trust comes from walking the signed key
 * statements from a pinned anchor (`trustAnchors`, see `computeKeyTrust`),
 * reported per key as `trust`.
 */
export type KeySource = 'supplied' | 'embedded';

/**
 * What the key-statement walk concluded about a key (see `applyKeyTrust`).
 * `anchored`: signed statements link it to a pinned anchor. `unanchored`:
 * nothing signed does, so entries under it fail CHAIN_SIGNING_KEY_UNANCHORED.
 * `undecided`: the only link runs through a signature this host cannot
 * compute, so entries under it are CHAIN_UNSUPPORTED_ALGORITHM, not tamper.
 */
export type KeyTrustState = 'anchored' | 'unanchored' | 'undecided';

/** A public key the walk can verify signatures against. */
export interface VerificationKey {
  keyId: string;
  /** SPKI DER, base64-encoded (the engine's vault_signing_keys.public_key shape). */
  spkiBase64: string;
  /**
   * `supplied` = passed by the caller. `embedded` = shipped inside the
   * artifact being verified (the export or dump the engine produced). Surfaced
   * in the result so a caller can tell whether it verified against a key it
   * brought or against the artifact's own answer key.
   */
  source: KeySource;
  /**
   * Algorithm the key registry DECLARES for this key (the engine's
   * `vault_signing_keys.algorithm` column), when the input surface carries it.
   * Cross-checked against the algorithm the SPKI key material actually commits
   * to: a divergence means the registry row lies about its own key and fails
   * CHAIN_ALG_MISMATCH. The declared string never selects the verification
   * code path; only the key material does.
   */
  algorithm?: string;
  /** Optional temporal-validity window. */
  activatedAt?: string;
  retiredAt?: string | null;
  /**
   * The instant from which `distrustedKeys` (`VAULT_DISTRUSTED_KEYS` on the
   * Server) voids what this key signs, set by `applyKeyTrust` when it ends the
   * window before `retiredAt`. Entries written after it fail CHAIN_KEY_EXPIRED
   * worded as past the distrust cutoff: the key was not retired there.
   */
  distrustCutoff?: string;
  /**
   * The key-statement walk's verdict on this key, set by `applyKeyTrust`.
   * Absent when no walk ran (no `trustAnchors`), and the result then reports
   * `optionalChecks.key_anchoring: skipped_no_input`; with a walk and no
   * entry reaching the check, `not_checked`.
   */
  trust?: KeyTrustState;
}

export type KeyRegistry = ReadonlyMap<string, VerificationKey>;

/**
 * Index keys by key id. A key whose `spkiBase64` is not a non-empty string
 * carries no key material (a registry row with its public key nulled), so it
 * is left out: an entry naming it fails CHAIN_SIGNATURE_MISSING_KEY.
 */
export function buildKeyRegistry(keys: readonly VerificationKey[]): KeyRegistry {
  const map = new Map<string, VerificationKey>();
  for (const k of keys) {
    if (typeof k.spkiBase64 !== 'string' || k.spkiBase64 === '') continue;
    map.set(k.keyId, k);
  }
  return map;
}

/**
 * Agent cert keys for the agent-signature check, indexed by the RFC 7638
 * thumbprint (`sha256:<hex>`) the engine seals as
 * `predicate.on_behalf_of.cert.thumbprint`. Values are SPKI DER, base64.
 */
export type AgentKeyRegistry = ReadonlyMap<string, string>;

/**
 * Index caller-supplied agent cert keys by thumbprint. A key is matched to an
 * entry only through the thumbprint that entry signed, so a key supplied for
 * the wrong cert is never checked against it: it simply matches nothing.
 * That is also why the source of a key needs no trust: the signed thumbprint
 * is what binds it. Throws `TypeError` on anything that is not an Ed25519 JWK.
 */
export function buildAgentKeyRegistry(jwks: readonly AgentPublicKeyJwk[]): AgentKeyRegistry {
  if (!Array.isArray(jwks)) {
    throw new TypeError('agentKeys must be an array of Ed25519 JWKs ({ kty: "OKP", crv: "Ed25519", x }).');
  }
  const map = new Map<string, string>();
  jwks.forEach((jwk, i) => {
    const thumbprint = ed25519JwkThumbprint(jwk);
    const spki = ed25519JwkToSpki(jwk);
    if (thumbprint === null || spki === null) {
      throw new TypeError(
        `agentKeys[${i}] is not an Ed25519 public-key JWK. Expected { kty: "OKP", crv: "Ed25519", x: <base64url of 32 bytes> }, the publicKeyJwk sent at cert exchange (also the cnf.jwk claim inside the certJws).`,
      );
    }
    map.set(thumbprint, spki);
  });
  return map;
}

/** One chain entry, plus the inputs the input-gated checks consume when the surface carries them. */
export interface NormalizedEntry {
  /** Identity for messages: recordId (export) or chainKey (dump). */
  scopeId: string;
  chainPosition: number;
  payloadHash: string;
  previousHash: string | null;
  /** Base64-encoded canonical COSE_Sign1 envelope. */
  coseSign1: string;
  signingKeyId: string | null;
  /**
   * ISO-8601 write time, for temporal key-validity and the unsigned-entry
   * rule. The engine writes one on every entry, so wherever the walk needs it
   * (the entry's key carries a window, or the entry is unsigned and the key
   * set dates the start of signing) a missing or unparseable value fails
   * CHAIN_MALFORMED_ENTRY rather than skipping the check.
   */
  createdAt?: string | null;
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
  /**
   * Inputs for the actor-attribution cross-check: the row columns a report
   * displays as "who did this". The export carries them as `actorId` /
   * `actorRole` / `actorOwnerId`, the dump as `actor_key_id` / `actor_role` /
   * `actor_owner_id`. Absent on older artifacts, which skips the check.
   */
  actorAttribution?: {
    actorId: string | null;
    actorRole: string | null;
    actorOwnerId: string | null;
  };
}

/**
 * Checks that run only when their input is present. `agent_signature` is
 * applied when at least one entry carrying an engine-validated agent signature
 * had its cert key supplied by the caller (`agentKeys`); neither the export
 * nor the dump carries cert public keys.
 */
export type OptionalCheck =
  | 'payload_binding'
  | 'oidc_actor'
  | 'actor_attribution'
  | 'key_temporal'
  | 'agent_signature'
  | 'key_anchoring';
/**
 * `applied`: the check ran. `skipped_no_input`: the input it needs is absent.
 * `not_checked`: the input was given but no entry reached the check, because
 * the chain broke before it or no entry was signed. Only `key_anchoring` has
 * a caller-level input and so can be `not_checked`.
 */
export type CheckApplicability = 'applied' | 'skipped_no_input' | 'not_checked';

export interface SignatureOutcome {
  /**
   * - `ok` / `invalid` / `decode-fail`: the signature was checked (and passed,
   *   failed, or the envelope would not decode).
   * - `unsigned`: retained for type compatibility; `verifyChain` no longer
   *   produces it. An all-zero signature on an entry that names a key is
   *   `invalid` (CHAIN_SIGNATURE_INVALID), as the engine grades it.
   * - `skipped`: the chain is intact but this entry has no signing key, so the
   *   signature check was deliberately not run. Only an entry written before
   *   the install began signing gets here: before any signed entry in its
   *   chain and before the earliest key activation. Any other unsigned entry
   *   fails CHAIN_ENTRY_UNSIGNED.
   * - `not-checked`: a structural/chain check failed at or before this entry,
   *   so verification short-circuited before reaching the signature. Reads as a
   *   consequence of an upstream break, never as a benign skip.
   * - `unsupported`: the signature could not be computed at all, either
   *   because this build does not implement the algorithm or because the host
   *   runtime refused it (an active OpenSSL FIPS provider carries no EdDSA).
   *   CHAIN_UNSUPPORTED_ALGORITHM. A failure state, never a benign skip, and
   *   never tamper evidence: distinguishing it from `invalid` is the whole
   *   point, since only `invalid` means a signature was checked and failed.
   */
  state: 'ok' | 'invalid' | 'unsigned' | 'skipped' | 'not-checked' | 'decode-fail' | 'unsupported';
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
  /** How many signature checks resolved against supplied vs embedded keys. */
  keyProvenance: { supplied: number; embedded: number };
  /**
   * Agent signatures on this chain. `present` counts entries that passed
   * every other check and whose signed payload carries
   * `predicate.on_behalf_of.agent_signature`; `verified`
   * counts those re-checked against a caller-supplied cert key and found
   * good. `present > verified` on a valid chain means some were not checked
   * (no key supplied, or the identity was a caller assertion), never that
   * they failed.
   */
  agentSignatures: { present: number; verified: number };
}

export interface VerifyChainOptions {
  /** Require every entry's signingKeyId to equal this id (else CHAIN_KEY_POLICY_VIOLATION). */
  requireKeyId?: string;
  /**
   * Refuse to verify against keys shipped inside the artifact: an entry whose
   * only available key is `embedded` fails CHAIN_KEY_POLICY_VIOLATION. This
   * says where a key came from, not that it is trusted; a key the Server
   * serves comes from its database. Anchor keys with `computeKeyTrust` /
   * `applyKeyTrust` for that.
   */
  requireSuppliedKeys?: boolean;
  /**
   * Agent cert keys (see `buildAgentKeyRegistry`). When an entry's signed
   * payload carries an engine-validated `on_behalf_of.agent_signature` and its
   * sealed cert thumbprint matches a key here, the signature is re-verified
   * offline; a failure is CHAIN_AGENT_SIGNATURE_INVALID.
   */
  agentKeys?: AgentKeyRegistry;
  /**
   * The instant this install began signing: the earliest `activatedAt` across
   * its whole signing key set, retired keys included. An entry with a null
   * `signingKeyId` whose `createdAt` is at or after it fails
   * CHAIN_ENTRY_UNSIGNED.
   *
   * Omitted, it is derived from `keys` (`earliestKeyActivation`), which is
   * right whenever `keys` is the whole key set, as it is on the dump path.
   * Pass it when the caller knows windows for keys it has no public key for.
   * `null` says the key set carries no activation time, so only the other
   * half of the rule (an unsigned entry after a signed one) applies. A string
   * that does not parse as a date throws `TypeError` rather than silently
   * switching the check off.
   */
  signingSince?: string | null;
}

/**
 * The earliest `activatedAt` among `keys`, as the ISO string it was given in,
 * or `null` when no key carries a parseable one. This is the instant from
 * which the engine treats every chain entry and checkpoint as required to be
 * signed; pass every key the verifier knows, retired ones included, since the
 * engine reads it as `min(activated_at)` over its whole key registry.
 */
export function earliestKeyActivation(
  keys: Iterable<{ activatedAt?: string | null }>,
): string | null {
  let earliest: { at: number; iso: string } | null = null;
  for (const k of keys) {
    if (typeof k.activatedAt !== 'string') continue;
    const at = instantMs(k.activatedAt);
    if (Number.isNaN(at)) continue;
    if (earliest === null || at < earliest.at) earliest = { at, iso: k.activatedAt };
  }
  return earliest?.iso ?? null;
}

/**
 * Whether a row with no signing key id, written at `writtenAt`, falls inside
 * the era in which the install signs everything: at or after `signingSince`
 * (see `earliestKeyActivation`). This is the rule for an unsigned checkpoint
 * (CHECKPOINT_UNSIGNED) and an unsigned read-log leaf or tree head, and the
 * time half of the rule for an unsigned entry (CHAIN_ENTRY_UNSIGNED).
 *
 * False when `signingSince` is absent or unparseable: with no instant from
 * which the install signs, nothing has to be signed. True when `signingSince`
 * is known and `writtenAt` is missing or not strict RFC 3339: the engine times every
 * row, so a row with no readable time was edited, and it cannot be placed
 * before signing began. It fails closed rather than reading as early history.
 */
export function writtenWhileSigning(
  writtenAt: unknown,
  signingSince: string | null | undefined,
): boolean {
  if (typeof signingSince !== 'string') return false;
  const since = instantMs(signingSince);
  if (Number.isNaN(since)) return false;
  const written = typeof writtenAt === 'string' ? rfc3339Ms(writtenAt) : Number.NaN;
  if (Number.isNaN(written)) return true;
  return written >= since;
}

/** Whether `value` is a strict RFC 3339 instant the walk can place. */
function isInstant(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(rfc3339Ms(value));
}

/**
 * The order the walk sorts entries in: by `chainPosition`, an entry whose
 * position is not a safe integer after every one whose is, ties in input
 * order. Such an entry then fails CHAIN_POSITION_GAP at its place.
 */
function positionKey(position: unknown): number {
  return Number.isSafeInteger(position) ? (position as number) : Number.POSITIVE_INFINITY;
}

/** What the walk knows about whether an unsigned entry was allowed at this point. */
interface MustSign {
  /** An earlier entry in this chain carries a signing key id. */
  signedBefore: boolean;
  /** `VerifyChainOptions.signingSince`, resolved. */
  signingSince: string | null;
}

/**
 * Verify a single hash chain. `entries` are all the entries for one scope; they
 * are sorted by chainPosition internally (so a reordered export array still
 * validates the true chain; tampering surfaces through the hash links).
 */
export function verifyChain(
  entries: readonly NormalizedEntry[],
  keys: KeyRegistry,
  options: VerifyChainOptions = {},
): ChainResult {
  assertKnownOptions('verifyChain', options, ['requireKeyId', 'requireSuppliedKeys', 'agentKeys', 'signingSince'] satisfies ReadonlyArray<keyof VerifyChainOptions>);
  const scopeId = entries[0]?.scopeId ?? '(empty)';
  const sorted = entries
    .map((entry, at) => ({ entry, at, key: positionKey(entry.chainPosition) }))
    .sort((a, b) => (a.key === b.key ? a.at - b.at : a.key < b.key ? -1 : 1))
    .map(({ entry }) => entry);

  const entryResults: ChainEntryResult[] = [];
  const coverage = { signed: 0, unsigned: 0, skipped: 0, total: sorted.length };
  const optionalChecks: Record<OptionalCheck, CheckApplicability> = {
    payload_binding: 'skipped_no_input',
    oidc_actor: 'skipped_no_input',
    actor_attribution: 'skipped_no_input',
    key_temporal: 'skipped_no_input',
    agent_signature: 'skipped_no_input',
    key_anchoring: 'skipped_no_input',
  };
  const keyProvenance = { supplied: 0, embedded: 0 };
  const agentSignatures = { present: 0, verified: 0 };
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
      agentSignatures,
    };
  }

  let signingSince: string | null;
  if (options.signingSince === undefined) {
    signingSince = earliestKeyActivation(keys.values());
  } else {
    signingSince = options.signingSince;
    if (signingSince !== null && Number.isNaN(instantMs(signingSince))) {
      throw new TypeError(`signingSince must be an RFC 3339 instant or null (got ${JSON.stringify(signingSince)}).`);
    }
  }
  const mustSign: MustSign = { signedBefore: false, signingSince };

  let previousHash: string | null = null;
  for (let i = 0; i < sorted.length; i++) {
    const entry = sorted[i]!;
    const expectedPosition = i + 1;
    let result = verifyEntry(
      entry,
      expectedPosition,
      previousHash,
      keys,
      options,
      optionalChecks,
      mustSign,
    );
    // As the engine's walk does: any earlier row naming a key, whatever its own
    // verdict, means this chain was already being signed.
    if (entry.signingKeyId !== null) mustSign.signedBefore = true;
    if (result.valid) {
      result = checkAgentSignature(entry, result, options.agentKeys, optionalChecks, agentSignatures);
    }
    entryResults.push(result);

    if (result.valid) verifiedEntries++;
    else if (!brokenAt && result.failure) {
      brokenAt = { position: result.position, code: result.failure.code, detail: result.failure.detail };
    }

    switch (result.signature) {
      case 'ok':
        coverage.signed++;
        if (result.keySource === 'supplied') keyProvenance.supplied++;
        else if (result.keySource === 'embedded') keyProvenance.embedded++;
        break;
      case 'unsigned':
        coverage.unsigned++;
        break;
      case 'skipped':
        coverage.skipped++;
        break;
      // 'not-checked' / 'invalid' / 'decode-fail' / 'unsupported' are failure
      // states: the entry is already counted as broken, so it contributes to
      // no coverage bucket.
    }

    previousHash = entry.payloadHash;
  }

  // The caller walked the key statements (every key carries a verdict), but no
  // entry got as far as the anchoring check.
  if (optionalChecks.key_anchoring === 'skipped_no_input' && [...keys.values()].some((k) => k.trust !== undefined)) {
    optionalChecks.key_anchoring = 'not_checked';
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
    agentSignatures,
  };
}

/**
 * Offline re-check of a sealed agent signature, on an entry that already
 * passed every other check (so its payload is the engine's signed bytes).
 *
 * Runs only on an engine-validated identity (`on_behalf_of.validated: true`).
 * On a caller-asserted one, entries written before the engine sealed these
 * fields itself carry them as caller passthrough, and the marker telling the
 * two apart is a column neither the export nor the dump publishes, so a
 * failure there could not be told from a claim nobody ever checked.
 */
function checkAgentSignature(
  entry: NormalizedEntry,
  result: ChainEntryResult,
  agentKeys: AgentKeyRegistry | undefined,
  optionalChecks: Record<OptionalCheck, CheckApplicability>,
  counts: { present: number; verified: number },
): ChainEntryResult {
  const parts = decodeCoseSign1(Buffer.from(entry.coseSign1, 'base64'));
  if (!parts) return result;
  const claim = extractAgentSignatureClaim(parts.payloadBstr);
  if (claim === null) return result;
  counts.present++;
  if (!claim.validated || !agentKeys || claim.certThumbprint === null) return result;
  const spki = agentKeys.get(claim.certThumbprint);
  if (spki === undefined) return result;

  optionalChecks.agent_signature = 'applied';
  const outcome = verifyAgentSignature(spki, claim);
  if (outcome === 'ok') {
    counts.verified++;
    return result;
  }
  const certLabel = claim.certId ?? claim.certThumbprint;
  if (outcome === 'unsupported') {
    return fail(
      entry.scopeId,
      result.position,
      'CHAIN_UNSUPPORTED_ALGORITHM',
      `Agent signature for cert ${certLabel} could not be checked: this host cannot compute Ed25519 (an active OpenSSL FIPS provider carries no EdDSA). Not verified, and not tamper evidence.`,
      result.signature,
    );
  }
  return fail(
    entry.scopeId,
    result.position,
    'CHAIN_AGENT_SIGNATURE_INVALID',
    outcome === 'malformed'
      ? `Sealed agent_signature for cert ${certLabel} has a shape nothing can verify (alg must be EdDSA, content_hash sha256:<hex64>, signature 64 bytes of standard base64).`
      : `Sealed agent_signature for cert ${certLabel} does not verify under the supplied key with thumbprint ${claim.certThumbprint}.`,
    result.signature,
  );
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
  mustSign: MustSign,
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

  if (typeof entry.coseSign1 !== 'string' || typeof entry.payloadHash !== 'string' || !entry.coseSign1 || !entry.payloadHash) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_MALFORMED_ENTRY',
      'Entry is missing coseSign1 or payloadHash, or carries one that is not a string.',
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

  // Input-gated: actor attribution. The row's actorId/actorOwnerId columns are
  // the projection a report displays as "who did this", and the engine's own
  // export guide names them as the trustworthy attribution while listing only
  // actorDisplayName / actorOwnerType / humanReadableLabel as unsigned. They
  // are signature-covered, at CWT_Claims label 15 -> private label -65539, so
  // a rewritten column is a re-attribution of the action to another actor and
  // must not verify. Same shape as the signed-kid check above: compare the
  // column against the signed claim, and skip only when one side is absent
  // (an older engine that never carried the claim, or an artifact that does
  // not carry the columns).
  const attribution = entry.actorAttribution;
  if (attribution) {
    const actorClaim = extractActorClaim(parts.protectedBstr);
    if (actorClaim) {
      optionalChecks.actor_attribution = 'applied';
      const mismatches: string[] = [];
      if (attribution.actorId !== null && attribution.actorId !== actorClaim.key_id) {
        mismatches.push(`actorId=${attribution.actorId} vs signed ${actorClaim.key_id}`);
      }
      if (attribution.actorOwnerId !== null && attribution.actorOwnerId !== actorClaim.owner_id) {
        mismatches.push(`actorOwnerId=${attribution.actorOwnerId} vs signed ${actorClaim.owner_id}`);
      }
      if (attribution.actorRole !== null && attribution.actorRole !== actorClaim.role) {
        mismatches.push(`actorRole=${attribution.actorRole} vs signed ${actorClaim.role}`);
      }
      if (mismatches.length > 0) {
        return fail(
          scopeId,
          expectedPosition,
          'CHAIN_ACTOR_ATTRIBUTION_MISMATCH',
          `Row actor columns diverge from the signature-covered actor claim (${mismatches.join('; ')}).`,
        );
      }
    }
  }

  // Input-gated: binding-integrity. Runs whenever the row payload is present:
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
    if (
      decodedRaw === null ||
      decoded === null ||
      rebuilt === null ||
      !deepEqual(rebuilt, decoded) ||
      !envelopeExtensionsMatch(entry.binding.payload, decodedRaw)
    ) {
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
  // Only a true null is the engine's unsigned-mode marker. Any other value,
  // including the empty string no engine emits, must resolve in the registry
  // and fails CHAIN_SIGNATURE_MISSING_KEY below: a truthiness shortcut here
  // would let a tampered signingKeyId:"" row skip its signature check.
  if (entry.signingKeyId === null) {
    // Engine mirror of `signature_missing`. An unsigned entry is reduced
    // coverage only where the install had not yet begun to sign: before any
    // signed entry in this chain, and before the earliest key activation.
    // Anywhere else no process of the install could have written it; it is
    // what a writer holding no key leaves on the tip, or a signed row whose
    // key id was nulled. Checked ahead of the caller's key policy because it
    // is evidence about the chain itself, whatever policy the run applies.
    if (mustSign.signedBefore) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_ENTRY_UNSIGNED',
        'Entry has no signingKeyId but follows a signed entry in the same chain.',
      );
    }
    // The engine times every entry. Without a time the walk can read, an
    // unsigned entry cannot be placed before signing began, so it is not
    // early history: it fails closed.
    if (mustSign.signingSince !== null && !isInstant(entry.createdAt)) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_MALFORMED_ENTRY',
        `Entry has no signingKeyId and no parseable createdAt, so it cannot be placed before the earliest signing key activation ${mustSign.signingSince}.`,
      );
    }
    if (writtenWhileSigning(entry.createdAt, mustSign.signingSince)) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_ENTRY_UNSIGNED',
        `Entry has no signingKeyId but was written ${entry.createdAt}, at or after the earliest signing key activation ${mustSign.signingSince}.`,
      );
    }
    // Fail closed under a key policy: a high-assurance run that requires a
    // specific key (or supplied keys) must NOT accept an unsigned/null-key
    // entry as valid; otherwise an attacker forges an entry, nulls its
    // signingKeyId, and slips past the policy the auditor explicitly set.
    if (options.requireKeyId || options.requireSuppliedKeys) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_KEY_POLICY_VIOLATION',
        'Entry has no signingKeyId but this run requires a signed entry (requireKeyId / requireSuppliedKeys).',
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

  if (options.requireSuppliedKeys && key.source !== 'supplied') {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_KEY_POLICY_VIOLATION',
      `Key ${entry.signingKeyId} is embedded in the artifact; this run requires supplied keys.`,
    );
  }

  // Signed-kid binding (engine mirror: signing_key_drift), ahead of every
  // question about the key, as the engine orders it. The row's signingKeyId
  // column selected the key above, but the column is a denormalized
  // convenience; the kid at protected-header label 4 is signature-covered. A
  // divergence means the column was rewritten after signing, e.g. to point
  // verification at a key the tamperer controls.
  const signedKid = extractKid(parts.protectedBstr);
  if (signedKid !== null && signedKid !== entry.signingKeyId) {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_SIGNING_KEY_DRIFT',
      `Row signingKeyId=${entry.signingKeyId} does not match the signature-covered kid ${signedKid} in the protected header.`,
    );
  }

  // Input-gated: key anchoring (engine mirror: signing_key_unanchored). Runs
  // when a key-statement walk marked the registry. A key nothing signed links
  // to a pinned anchor is one anything with write access to the Server's
  // database can register, so an entry under it is a forgery until shown
  // otherwise, whatever its signature says.
  if (key.trust !== undefined) {
    optionalChecks.key_anchoring = 'applied';
    if (key.trust === 'unanchored') {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_SIGNING_KEY_UNANCHORED',
        `Key ${entry.signingKeyId} is not linked by any signed key statement to a pinned trust anchor.`,
      );
    }
    if (key.trust === 'undecided') {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_UNSUPPORTED_ALGORITHM',
        `Key ${entry.signingKeyId} is linked to a pinned anchor only through a key statement signed under an algorithm this host cannot compute, and ${describeUnsupportedAlgorithm(key.spkiBase64)}`,
        'unsupported',
      );
    }
  }

  // Registry self-consistency: when the input surface declares an algorithm for
  // this key (vault_signing_keys.algorithm), it must agree with what the SPKI
  // key material commits to. A registry row that lies about its own key is the
  // signature of a mis-registered key (the pre-guard P-256 corruption shape) or
  // a rewritten registry, and nothing verified against it can be trusted.
  if (typeof key.algorithm === 'string') {
    const keyAlg = resolveKeyAlgorithm(key.spkiBase64);
    if (
      typeof keyAlg === 'object' &&
      keyAlg.name.toLowerCase() !== key.algorithm.toLowerCase()
    ) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_ALG_MISMATCH',
        `Key registry declares algorithm=${key.algorithm} for key ${entry.signingKeyId}, but the key material is ${keyAlg.name}.`,
      );
    }
  }

  // Input-gated: temporal key-validity, whenever the key carries a window.
  // Compared at millisecond precision, the precision of an entry's write time,
  // truncating a microsecond window edge the way the engine does. The engine
  // times every entry, so an entry with no time the walk can read cannot be
  // placed inside the window, and fails closed rather than skipping it.
  if (typeof key.activatedAt === 'string' || typeof key.retiredAt === 'string' || typeof key.distrustCutoff === 'string') {
    optionalChecks.key_temporal = 'applied';
    // A window edge that is not RFC 3339 cannot place anything either, and
    // the check fails closed on it rather than skipping that edge.
    for (const [edge, value] of [['activatedAt', key.activatedAt], ['retiredAt', key.retiredAt], ['distrustCutoff', key.distrustCutoff]] as const) {
      if (typeof value === 'string' && !isInstant(value)) {
        return fail(
          scopeId,
          expectedPosition,
          'CHAIN_MALFORMED_ENTRY',
          `Key ${entry.signingKeyId}'s ${edge} ${JSON.stringify(value)} is not an RFC 3339 instant, so the entry cannot be placed inside its window.`,
        );
      }
    }
    if (!isInstant(entry.createdAt)) {
      return fail(
        scopeId,
        expectedPosition,
        'CHAIN_MALFORMED_ENTRY',
        `Entry has no parseable createdAt, so it cannot be placed inside key ${entry.signingKeyId}'s window.`,
      );
    }
    const temporal = temporalKeyFailure(entry.createdAt, key);
    if (temporal) {
      return fail(scopeId, expectedPosition, temporal.code, temporal.detail);
    }
  }

  const outcome = verifyCoseSign1(envelopeBytes, key.spkiBase64);
  if (outcome === 'unsigned') {
    // An all-zero signature slot on an entry that CLAIMS a signing key. The
    // engine writes a key id only beside a signature it made with that key,
    // and fails this shape `signature_invalid`, so it is a forged or wiped
    // signature, never an unsigned entry. (A genuinely unsigned entry carries
    // a null signingKeyId and is graded above.)
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_SIGNATURE_INVALID',
      `Entry claims signingKeyId=${entry.signingKeyId} but carries an all-zero signature.`,
      'invalid',
    );
  }
  if (outcome === 'ok') {
    return { scopeId, position: expectedPosition, valid: true, signature: 'ok', keySource: key.source };
  }
  if (outcome === 'alg-mismatch') {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_ALG_MISMATCH',
      `Protected-header alg (label 1) is absent or is not an algorithm key ${entry.signingKeyId} can produce. Tamper class: a rewritten alg must read as forgery, never as an upgrade notice.`,
      'invalid',
    );
  }
  if (outcome === 'unsupported-key-algorithm') {
    return fail(
      scopeId,
      expectedPosition,
      'CHAIN_UNSUPPORTED_ALGORITHM',
      `Key ${entry.signingKeyId} ${describeUnsupportedAlgorithm(key.spkiBase64)}`,
      'unsupported',
    );
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

/**
 * Temporal key-validity, split by direction. Both directions used to report
 * `CHAIN_KEY_EXPIRED`, so a consumer branching on the code saw "expired" for a
 * key that had not started yet and would reason about rotation or retention
 * when the real condition is clock skew or backdating. Those are different
 * investigations, and the activation side is the security-relevant one.
 */
function temporalKeyFailure(
  createdAt: string,
  key: VerificationKey,
): { code: 'CHAIN_KEY_NOT_YET_ACTIVE' | 'CHAIN_KEY_EXPIRED'; detail: string } | null {
  const written = rfc3339Ms(createdAt);
  if (Number.isNaN(written)) return null;
  if (typeof key.activatedAt === 'string' && key.activatedAt) {
    const activated = instantMs(key.activatedAt);
    if (!Number.isNaN(activated) && written < activated) {
      return {
        code: 'CHAIN_KEY_NOT_YET_ACTIVE',
        detail: `Entry written ${createdAt} predates key ${key.keyId} activation ${key.activatedAt}.`,
      };
    }
  }
  if (typeof key.distrustCutoff === 'string' && key.distrustCutoff) {
    const cutoff = instantMs(key.distrustCutoff);
    if (!Number.isNaN(cutoff) && written > cutoff) {
      return {
        code: 'CHAIN_KEY_EXPIRED',
        detail: `Entry written ${createdAt} postdates ${key.distrustCutoff}, the instant distrustedKeys (VAULT_DISTRUSTED_KEYS on the Server) gives for key ${key.keyId}; the key was not retired then.`,
      };
    }
  }
  if (typeof key.retiredAt === 'string' && key.retiredAt) {
    const retired = instantMs(key.retiredAt);
    if (!Number.isNaN(retired) && written > retired) {
      return {
        code: 'CHAIN_KEY_EXPIRED',
        detail: `Entry written ${createdAt} postdates key ${key.keyId} retirement ${key.retiredAt}.`,
      };
    }
  }
  return null;
}
