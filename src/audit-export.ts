/**
 * Adapter: verify a live `/audit-export` JSON document (one record's chain).
 *
 * This is the customer/developer path: `client.records.getAuditExport(id)`
 * then `verifyAuditExport(...)`. It maps the export wire shape onto the shared
 * normalized entry and runs `verifyChain`.
 *
 * The three row-level input-gated checks run on the export path when the wire
 * carries their inputs (engine ≥ v0.26.x): the `actorOidcSynthesized` flag +
 * `actorOidcIss/Sub` enable the OIDC-actor cross-check; `signingKeyWindows` +
 * per-entry `createdAt` enable temporal key-validity; and the per-entry
 * denormalized `payload` + `entryType` enable binding-integrity, the export's
 * own verificationGuide step 4. The binding check defends against post-export
 * tampering of the human-readable `payload`/`criteria` view: the verifier
 * re-decodes the signed predicate from `coseSign1` and deep-equals it against
 * the row `payload`, so a rewritten `payload` with an intact envelope fails
 * CHAIN_PAYLOAD_BINDING_MISMATCH (validated against a real engine v0.26.4
 * export; `buildPredicateForRow` reconstructs the signed predicate exactly).
 * Older exports without these fields stay `skipped_no_input`, surfaced in the
 * result so a caller never mistakes "not checked here" for "checked and passed".
 */
import {
  buildAgentKeyRegistry,
  buildKeyRegistry,
  earliestKeyActivation,
  verifyChain,
  type CheckApplicability,
  type NormalizedEntry,
  type OptionalCheck,
  type SignatureOutcome,
  type VerificationKey,
} from './chain.js';
import type { FailureCode } from './failures.js';
import type { AgentPublicKeyJwk } from './primitives.js';
import {
  applyKeyTrust,
  computeKeyTrust,
  keyStatementsFromExport,
  reportKeyTrust,
  type DistrustedKey,
  type KeyStatementInput,
  type KeyTrustReport,
  type PublishedKeyStatement,
  type TrustKeyInput,
} from './key-statements.js';

/** One entry of a `/audit-export` document. */
export interface AuditExportEntryInput {
  /** 1-based chain position. Current exports emit `chainPosition`; pre-v0.25 used `position`. */
  chainPosition?: number;
  /** Legacy alias for `chainPosition`. */
  position?: number;
  /** ISO-8601 write time. Engine ≥ v0.26.x; gates the temporal key-validity check. */
  createdAt?: string;
  /** OIDC issuer the actor was synthesized from (engine ≥ v0.26.x). */
  actorOidcIss?: string | null;
  /** OIDC subject the actor was synthesized from (engine ≥ v0.26.x). */
  actorOidcSub?: string | null;
  /** Tri-state from `audit_vault.actor_oidc_synthesized` (engine ≥ v0.26.x). Marker for the OIDC-actor check. */
  actorOidcSynthesized?: boolean | null;
  /**
   * API-key id of the credential that performed this state-change, mirroring
   * the row's `actor_key_id`. Signature-covered at CWT_Claims label 15 ->
   * private label -65539; present → the actor-attribution check runs.
   */
  actorId?: string | null;
  /** Role of that credential (`admin` / `agent` / `platform`), mirroring `actor_role`. */
  actorRole?: string | null;
  /** Owner id of that credential, mirroring `actor_owner_id`. */
  actorOwnerId?: string | null;
  /** The record this entry belongs to; pairs with `payload`/`entryType` to drive the binding check. */
  recordId?: string | null;
  /** The audit-vault entry type (e.g. `RECORD_CREATED`); drives the binding check's predicate reconstruction. */
  entryType?: string;
  /** Denormalized row `payload` jsonb. Present → the binding-integrity check runs (verificationGuide step 4). */
  payload?: Record<string, unknown>;
  integrity: {
    payloadHash: string;
    previousHash: string | null;
    /** Base64-encoded canonical COSE_Sign1 envelope (RFC 9052). */
    coseSign1: string;
    signingKeyId: string | null;
  };
}

/** Per-key activation/retirement window; drives temporal key-validity (engine ≥ v0.26.x). */
export interface SigningKeyWindow {
  activatedAt: string;
  retiredAt: string | null;
}

/** A `/audit-export` document (only the fields the verifier reads). */
export interface RecordAuditExportInput {
  exportMetadata: {
    recordId: string;
    exportFormatVersion?: string;
    canonicalization?: string;
    signingPublicKeys?: Record<string, string>;
    /** keyId → activation/retirement window, the values the key statements sign. */
    signingKeyWindows?: Record<string, SigningKeyWindow>;
    /** keyId → the signed key statements admitting that key (API 2.0). Walked from `trustAnchors`. */
    signingKeyStatements?: Record<string, PublishedKeyStatement[]>;
    /**
     * `sha256:<hex>` of the exporting Server's own key. Reported against the
     * caller's anchors, never used as one: it is the artifact's word.
     */
    anchoredFrom?: string | null;
  };
  entries: AuditExportEntryInput[];
  /**
   * Self-describing verification guidance the engine ships in the export.
   * `unsignedFields` lists per-entry fields that are UNSIGNED display projections
   * (e.g. `actorDisplayName`) resolved at export time, not covered by the COSE_Sign1
   * signature. A PASS does NOT vouch for these labels. The attribution the guide
   * points at instead, `actorOwnerId`/`actorId`, IS signature-covered and IS
   * cross-checked here (`actor_attribution`). Surfaced on the result so a verdict
   * can say which labels it does not stand behind.
   */
  verificationGuide?: {
    unsignedFields?: string[];
  };
}

/**
 * Structural shape for a single supplied key in array form. Matches the SDK's
 * `VerificationKey` (the `.data[]` from `client.verificationKeys.list()`) plus
 * the SCITT COSE_KeySet (`/.well-known/scitt-keys`) entry shape; extra fields
 * are ignored. `publicKey` must be SPKI DER base64.
 */
export interface SuppliedKeyEntry {
  keyId: string;
  publicKey: string;
  /** Optional activation timestamp; feeds temporal key-validity when present. */
  activatedAt?: string;
  /** Optional retirement timestamp; `null` means "active, no scheduled retirement". */
  retiredAt?: string | null;
  /**
   * The key's signed statements, as `/v1/verification-keys` lists them. Walked
   * with the export's own when `trustAnchors` is given.
   */
  statements?: PublishedKeyStatement[];
}

export interface VerifyExportOptions {
  /**
   * Public keys the caller supplies (GET /v1/verification-keys,
   * /.well-known/scitt-keys, its own records). These override any key
   * embedded in the export under the same id. A key the Server serves comes
   * from its database, so supplying keys says where they came from, not that
   * they are trusted: pin `trustAnchors` for that.
   *
   * Accepts either form:
   *   - `Record<keyId, base64SpkiDer>`: the compact map shape
   *   - `SuppliedKeyEntry[]`: the natural shape returned by
   *     `client.verificationKeys.list().data` and SCITT COSE_KeySet listings
   *
   * Anything else throws `TypeError` at the boundary.
   */
  publicKeys?: Record<string, string> | ReadonlyArray<SuppliedKeyEntry>;
  /** Require every entry to reference this keyId (else CHAIN_KEY_POLICY_VIOLATION). */
  requireKeyId?: string;
  /**
   * Refuse keys embedded in the export: an entry whose only key is
   * export-embedded fails CHAIN_KEY_POLICY_VIOLATION.
   */
  requireSuppliedKeys?: boolean;
  /**
   * SPKI digests (`sha256:<64 hex>`) of vault keys pinned out of band: the
   * installer prints one, and the Server's `signing-key-digest.js` derives it
   * from a key. With at least one, the signed key statements the export
   * carries (`exportMetadata.signingKeyStatements`, plus any `statements` on
   * supplied keys) are walked from these anchors, every key is graded
   * anchored or not, an entry signed by a key the walk does not anchor fails
   * CHAIN_SIGNING_KEY_UNANCHORED, and each anchored key's window is the one
   * its statements sign. Without anchors the result says so in `keyTrust` and
   * `optionalChecks.key_anchoring`, and every key is taken on the word of
   * whoever embedded or supplied it. Malformed entries throw `TypeError`.
   */
  trustAnchors?: readonly string[];
  /**
   * Keys distrusted from outside the database, in the Server's
   * `VAULT_DISTRUSTED_KEYS` form (`sha256:<64 hex>`, optionally
   * `@<RFC 3339 instant>`): what such a key stored at or after the instant
   * (with none, from the retirement a trusted key signed for it, and with
   * neither, ever) counts for nothing in the walk. Give auditors the entries
   * the operator set. Used only with `trustAnchors`.
   */
  distrustedKeys?: ReadonlyArray<string | DistrustedKey>;
  /**
   * Ed25519 public keys of agent ephemeral certs, as JWKs: the `publicKeyJwk`
   * the agent sent to `POST /v1/auth/oidc/cert`, which is also the `cnf.jwk`
   * claim inside the returned `certJws`. The export does not carry them.
   *
   * When an entry's signed payload carries an engine-validated
   * `predicate.on_behalf_of.agent_signature` and its sealed cert thumbprint
   * matches one of these keys, the signature is re-verified offline, proving
   * the cert holder signed that request-body hash without trusting the
   * engine's word for it. A key is matched only through the thumbprint the
   * entry signed, so where a key came from does not need to be trusted.
   * Anything that is not an Ed25519 JWK throws `TypeError`.
   */
  agentKeys?: ReadonlyArray<AgentPublicKeyJwk>;
}

export interface EntryVerificationResult {
  position: number;
  valid: boolean;
  code?: FailureCode;
  detail?: string;
  signature?: SignatureOutcome['state'];
}

export interface VerifyExportResult {
  valid: boolean;
  totalEntries: number;
  verifiedEntries: number;
  brokenAt?: { position: number; code: FailureCode; detail?: string };
  entries: EntryVerificationResult[];
  recordId: string;
  signatureCoverage: { signed: number; unsigned: number; skipped: number; total: number };
  /**
   * Which input-gated checks ran on this export.
   *
   * - `actor_attribution` flips to `applied` when the export carries the
   *   `actorId` / `actorRole` / `actorOwnerId` columns and the envelope carries
   *   the signed actor claim, which is every current export.
   * - `payload_binding`, `oidc_actor` and `key_temporal` flip to `applied`
   *   when the export wire carries their inputs (engine >= v0.26.x: per-entry
   *   `payload` + `entryType`, `actorOidcSynthesized`, `createdAt`, and
   *   `signingKeyWindows` in exportMetadata). Older exports without those
   *   fields stay `skipped_no_input`.
   * - `agent_signature` is `applied` only when `agentKeys` supplied the cert
   *   key for at least one engine-validated agent signature on the chain.
   *
   * The applicability is surfaced so a caller never mistakes "not checked
   * here" for "checked and passed".
   */
  optionalChecks: Record<OptionalCheck, CheckApplicability>;
  /**
   * How many signature checks resolved against supplied vs export-embedded
   * keys. Provenance only; whether a key is trusted is `keyTrust`.
   */
  keyProvenance: { supplied: number; embedded: number };
  /**
   * Whether the keys were anchored, and to what. `status: 'no_anchor'` means
   * no `trustAnchors` were given: the verdict then rests on keys nobody
   * pinned, which is not a clean verdict whatever `valid` says. Findings on
   * the key statements themselves (KEY_STATEMENT_INVALID, KEY_CLOSURE_INVALID,
   * CHAIN_KEY_WINDOW_DRIFT) are listed here and make `valid` false.
   */
  keyTrust: KeyTrustReport;
  /**
   * Per-entry fields the export self-describes as UNSIGNED display projections
   * (from `verificationGuide.unsignedFields`), e.g. `actorDisplayName`.
   * A valid signature does NOT cover these; the attribution that IS covered,
   * `actorOwnerId`/`actorId`, is cross-checked against the signed actor claim
   * (see `optionalChecks.actor_attribution`). Empty when the export carries no
   * such guidance. A caller surfacing a PASS should warn that these labels are
   * not vouched for.
   */
  unsignedProjectionFields: string[];
  /** Agent signatures present on the chain vs re-verified offline (see `agentKeys`). */
  agentSignatures: { present: number; verified: number };
}

const SUPPORTED_FORMAT_VERSION = '2.0';
const SUPPORTED_CANONICALIZATION = 'RFC8949-CDE';

export function verifyAuditExport(
  exportData: RecordAuditExportInput,
  options: VerifyExportOptions = {},
): VerifyExportResult {
  const meta = exportData.exportMetadata;
  const entries = exportData.entries ?? [];

  if (meta.exportFormatVersion && meta.exportFormatVersion !== SUPPORTED_FORMAT_VERSION) {
    return earlyFailure(
      meta.recordId,
      entries.length,
      `Unsupported exportFormatVersion ${meta.exportFormatVersion} (this verifier reads ${SUPPORTED_FORMAT_VERSION}).`,
    );
  }
  if (meta.canonicalization && meta.canonicalization !== SUPPORTED_CANONICALIZATION) {
    return earlyFailure(
      meta.recordId,
      entries.length,
      `Unsupported canonicalization ${meta.canonicalization} (only ${SUPPORTED_CANONICALIZATION} supported).`,
    );
  }

  const resolvedKeys = resolveKeys(exportData, options);
  let keys = buildKeyRegistry(resolvedKeys);
  // When the install began signing, for CHAIN_ENTRY_UNSIGNED. The engine reads
  // it as min(activated_at) over its whole key registry, retired keys included,
  // and `signingKeyWindows` publishes that whole registry. So the instant is
  // taken over every key the verifier holds (with each key's window resolved
  // under the trust hierarchy in resolveKeys) plus every window the export
  // lists for a key it carries no public key for. With no window anywhere
  // (an older export, or caller keys without activatedAt and no export
  // windows), it is null and only the signed-before half of the rule applies.
  const windowOnly = Object.entries(meta.signingKeyWindows ?? {})
    .filter(([keyId, window]) => !keys.has(keyId) && window !== null && typeof window === 'object')
    .map(([, window]) => window);
  const signingSince = earliestKeyActivation([...resolvedKeys, ...windowOnly]);
  const agentKeys =
    options.agentKeys !== undefined ? buildAgentKeyRegistry(options.agentKeys) : undefined;
  const trust =
    options.trustAnchors !== undefined && options.trustAnchors.length > 0
      ? computeKeyTrust({
          keys: trustKeysOf(exportData, options),
          statements: trustStatementsOf(exportData, options),
          trustAnchors: options.trustAnchors,
          ...(options.distrustedKeys !== undefined ? { distrustedKeys: options.distrustedKeys } : {}),
        })
      : null;
  if (trust !== null) keys = applyKeyTrust(keys, trust);
  const keyTrust = reportKeyTrust(keys, trust, meta.anchoredFrom ?? null);
  const normalized: NormalizedEntry[] = entries.map((e) => {
    const base: NormalizedEntry = {
      scopeId: meta.recordId,
      chainPosition: e.chainPosition ?? e.position ?? -1,
      payloadHash: e.integrity.payloadHash,
      previousHash: e.integrity.previousHash,
      coseSign1: e.integrity.coseSign1,
      signingKeyId: e.integrity.signingKeyId,
    };
    // Binding-integrity: when the export carries the denormalized row `payload`
    // (engine ≥ v0.26.x), cross-check it against the predicate decoded from the
    // signed bytes, the export's own verificationGuide step 4. The threat is
    // post-export tampering of the human-readable `payload`/`criteria` view: an
    // attacker rewrites `payload` and leaves `coseSign1` intact. The verifier
    // re-decodes the signed predicate and compares, catching the divergence
    // (CHAIN_PAYLOAD_BINDING_MISMATCH) regardless of how the server derived
    // `payload`. Older exports without `payload` stay `skipped_no_input`.
    if (e.payload !== undefined && e.entryType !== undefined) {
      base.binding = {
        recordId: e.recordId ?? null,
        entryType: e.entryType,
        payload: e.payload,
      };
    }
    // Actor attribution: the export's own guide tells an auditor that
    // `actorId`/`actorOwnerId` ARE the trustworthy attribution (only
    // actorDisplayName / actorOwnerType / humanReadableLabel are listed as
    // unsigned projections), so those columns are cross-checked against the
    // signed actor claim rather than displayed on trust. Any one of the three
    // present is enough to run the check on what is there.
    if (e.actorId !== undefined || e.actorOwnerId !== undefined || e.actorRole !== undefined) {
      base.actorAttribution = {
        actorId: e.actorId ?? null,
        actorRole: e.actorRole ?? null,
        actorOwnerId: e.actorOwnerId ?? null,
      };
    }
    if (e.createdAt) base.createdAt = e.createdAt;
    // The synthesized flag is the marker that the export carries the OIDC
    // wire shape at all. Older exports omit it entirely; new exports always
    // include it (false/null/true). Setting `oidcActor` flips `oidc_actor`
    // to `applied` in the chain result; never `applied` for old exports.
    if (e.actorOidcSynthesized !== undefined) {
      base.oidcActor = {
        iss: e.actorOidcIss ?? null,
        sub: e.actorOidcSub ?? null,
        synthesized: e.actorOidcSynthesized ?? undefined,
      };
    }
    return base;
  });

  const chain = verifyChain(normalized, keys, {
    requireKeyId: options.requireKeyId,
    requireSuppliedKeys: options.requireSuppliedKeys,
    agentKeys,
    signingSince,
  });
  // A finding on the key statements has no chain position; it is reported
  // at position 0, the place for findings that precede the walk.
  const registryFinding = keyTrust.findings[0];
  const brokenAt = chain.brokenAt
    ? { position: chain.brokenAt.position, code: chain.brokenAt.code, detail: chain.brokenAt.detail }
    : registryFinding
      ? { position: 0, code: registryFinding.code, detail: registryFinding.detail }
      : undefined;

  return {
    valid: chain.valid && keyTrust.findings.length === 0,
    totalEntries: chain.totalEntries,
    verifiedEntries: chain.verifiedEntries,
    brokenAt,
    entries: chain.entries.map((r) => ({
      position: r.position,
      valid: r.valid,
      code: r.failure?.code,
      detail: r.failure?.detail,
      signature: r.signature,
    })),
    recordId: meta.recordId,
    signatureCoverage: chain.signatureCoverage,
    optionalChecks: chain.optionalChecks,
    keyProvenance: chain.keyProvenance,
    unsignedProjectionFields: exportData.verificationGuide?.unsignedFields ?? [],
    agentSignatures: chain.agentSignatures,
    keyTrust,
  };
}

/**
 * The keys the walk reads: the export's own, with the windows it lists as the
 * columns the drift check holds against the signed values, and the supplied
 * keys as key material only (the caller's catalogue is not the artifact).
 */
function trustKeysOf(exportData: RecordAuditExportInput, options: VerifyExportOptions): TrustKeyInput[] {
  const meta = exportData.exportMetadata;
  const out: TrustKeyInput[] = [];
  for (const [keyId, publicKey] of Object.entries(meta.signingPublicKeys ?? {})) {
    const window = meta.signingKeyWindows?.[keyId];
    out.push(
      window && typeof window === 'object'
        ? { keyId, publicKey, activatedAt: window.activatedAt, retiredAt: window.retiredAt, status: window.retiredAt === null ? 'active' : 'retired' }
        : { keyId, publicKey },
    );
  }
  for (const k of normalizeSuppliedKeys(options.publicKeys) ?? []) {
    out.push({ keyId: k.keyId, publicKey: k.spkiBase64 });
  }
  return out;
}

/** The export's key statements, plus any a supplied key carries (a /v1/verification-keys `data[]`). */
function trustStatementsOf(exportData: RecordAuditExportInput, options: VerifyExportOptions): KeyStatementInput[] {
  const out = keyStatementsFromExport(exportData.exportMetadata.signingKeyStatements);
  if (Array.isArray(options.publicKeys)) {
    const byKey: Record<string, PublishedKeyStatement[]> = {};
    for (const k of options.publicKeys as ReadonlyArray<SuppliedKeyEntry>) {
      if (k !== null && typeof k === 'object' && Array.isArray(k.statements)) byKey[k.keyId] = [...(byKey[k.keyId] ?? []), ...k.statements];
    }
    out.push(...keyStatementsFromExport(byKey).map((s) => ({ ...s, id: `supplied:${s.id ?? ''}` })));
  }
  return out;
}

function earlyFailure(recordId: string, totalEntries: number, detail: string): VerifyExportResult {
  return {
    valid: false,
    totalEntries,
    verifiedEntries: 0,
    brokenAt: { position: 0, code: 'UNSUPPORTED_FORMAT', detail },
    entries: [{ position: 0, valid: false, code: 'UNSUPPORTED_FORMAT', detail }],
    recordId,
    signatureCoverage: { signed: 0, unsigned: 0, skipped: 0, total: totalEntries },
    optionalChecks: {
      payload_binding: 'skipped_no_input',
      oidc_actor: 'skipped_no_input',
      actor_attribution: 'skipped_no_input',
      key_temporal: 'skipped_no_input',
      agent_signature: 'skipped_no_input',
      key_anchoring: 'skipped_no_input',
    },
    keyProvenance: { supplied: 0, embedded: 0 },
    unsignedProjectionFields: [],
    agentSignatures: { present: 0, verified: 0 },
    keyTrust: reportKeyTrust(new Map(), null, null),
  };
}

function resolveKeys(
  exportData: RecordAuditExportInput,
  options: VerifyExportOptions,
): VerificationKey[] {
  const byId = new Map<string, VerificationKey>();
  const meta = exportData.exportMetadata;
  if (meta.signingPublicKeys) {
    for (const [keyId, spkiBase64] of Object.entries(meta.signingPublicKeys)) {
      byId.set(keyId, { keyId, spkiBase64, source: 'embedded' });
    }
  }
  // Supplied keys override embedded keys of the same id, but inherit the
  // previously-seen activation/retirement window if the supplied entry didn't
  // carry its own.
  const supplied = normalizeSuppliedKeys(options.publicKeys);
  if (supplied) {
    for (const entry of supplied) {
      const existing = byId.get(entry.keyId);
      const activatedAt = entry.activatedAt ?? existing?.activatedAt;
      const retiredAt = entry.retiredAt !== undefined ? entry.retiredAt : existing?.retiredAt;
      byId.set(entry.keyId, {
        keyId: entry.keyId,
        spkiBase64: entry.spkiBase64,
        source: 'supplied',
        ...(activatedAt !== undefined ? { activatedAt } : {}),
        ...(retiredAt !== undefined ? { retiredAt } : {}),
      });
    }
  }
  // Attach activation/retirement windows from exportMetadata (engine ≥ v0.26.x).
  // Older exports omit signingKeyWindows; keys stay without a window and
  // verifyChain reports `key_temporal` as `skipped_no_input`.
  const windows = meta.signingKeyWindows;
  if (windows) {
    for (const [keyId, window] of Object.entries(windows)) {
      const existing = byId.get(keyId);
      if (!existing) continue;
      // Trust hierarchy on the temporal axis: when the caller supplied this
      // key AND brought their own activation/retirement window, the export's
      // (untrusted) signingKeyWindows MUST NOT overwrite it. A compromised
      // export could otherwise hide a retirement by setting retiredAt:null.
      // When the caller did not carry a window, we fall through to the
      // export's. With trustAnchors, an anchored key's window is the one its
      // statements sign, whichever of these it carried.
      const suppliedCarriesWindow =
        existing.source === 'supplied' &&
        (existing.activatedAt !== undefined || existing.retiredAt !== undefined);
      if (suppliedCarriesWindow) continue;
      byId.set(keyId, {
        ...existing,
        activatedAt: window.activatedAt,
        retiredAt: window.retiredAt,
      });
    }
  }
  return [...byId.values()];
}

interface NormalizedSuppliedEntry {
  keyId: string;
  spkiBase64: string;
  activatedAt?: string;
  retiredAt?: string | null;
}

/**
 * Normalize `options.publicKeys` into a uniform array of entries, or throw
 * `TypeError` at the boundary if the shape is wrong. Fail-closed by design:
 * a key argument that silently falls back to embedded keys would lie about
 * which keys the verdict rests on.
 *
 * Accepts:
 *   - `Record<keyId, base64SpkiDer>`: compact map (string-keyed object whose
 *     values are all strings)
 *   - `SuppliedKeyEntry[]`: natural SDK shape from `verificationKeys.list()`,
 *     or COSE_KeySet shape from `/.well-known/scitt-keys`
 *
 * Returns `null` when no keys were supplied; otherwise an array of normalized
 * entries ready to merge into the registry.
 */
function normalizeSuppliedKeys(
  publicKeys: VerifyExportOptions['publicKeys'],
): NormalizedSuppliedEntry[] | null {
  if (publicKeys === undefined || publicKeys === null) return null;

  if (Array.isArray(publicKeys)) {
    return publicKeys.map((entry, i) => {
      if (entry === null || typeof entry !== 'object') {
        throw new TypeError(
          `verifyAuditExport: publicKeys[${i}] is not an object (got ${typeof entry}). ` +
            `Expected { keyId, publicKey } entries, e.g. the .data[] from client.verificationKeys.list().`,
        );
      }
      const keyId = (entry as { keyId?: unknown }).keyId;
      const publicKey = (entry as { publicKey?: unknown }).publicKey;
      if (typeof keyId !== 'string' || typeof publicKey !== 'string') {
        throw new TypeError(
          `verifyAuditExport: publicKeys[${i}] is missing required string fields { keyId, publicKey } ` +
            `(got keyId=${typeof keyId}, publicKey=${typeof publicKey}). ` +
            `Expected the SDK VerificationKey shape: publicKey must be SPKI DER base64.`,
        );
      }
      const out: NormalizedSuppliedEntry = { keyId, spkiBase64: publicKey };
      const activatedAt = (entry as { activatedAt?: unknown }).activatedAt;
      const retiredAt = (entry as { retiredAt?: unknown }).retiredAt;
      if (typeof activatedAt === 'string') out.activatedAt = activatedAt;
      if (retiredAt === null || typeof retiredAt === 'string') out.retiredAt = retiredAt;
      return out;
    });
  }

  if (typeof publicKeys !== 'object') {
    throw new TypeError(
      `verifyAuditExport: publicKeys must be a Record<keyId, base64SpkiDer> or an array of ` +
        `{ keyId, publicKey } entries (got ${typeof publicKeys}).`,
    );
  }

  const entries: NormalizedSuppliedEntry[] = [];
  for (const [keyId, value] of Object.entries(publicKeys)) {
    if (typeof value !== 'string') {
      throw new TypeError(
        `verifyAuditExport: publicKeys["${keyId}"] is not a base64 string (got ${typeof value}). ` +
          `If you passed the .data[] from client.verificationKeys.list(), pass it as an array, ` +
          `not via Object.fromEntries on the raw list.`,
      );
    }
    entries.push({ keyId, spkiBase64: value });
  }
  return entries;
}
