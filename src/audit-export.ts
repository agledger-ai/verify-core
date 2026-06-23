/**
 * Adapter: verify a live `/audit-export` JSON document (one record's chain).
 *
 * This is the customer/developer path — `client.records.getAuditExport(id)`
 * then `verifyAuditExport(...)`. It maps the export wire shape onto the shared
 * normalized entry and runs `verifyChain`.
 *
 * All three input-gated checks now run on the export path when the wire carries
 * their inputs (engine ≥ v0.26.x): the `actorOidcSynthesized` flag +
 * `actorOidcIss/Sub` enable the OIDC-actor cross-check; `signingKeyWindows` +
 * per-entry `createdAt` enable temporal key-validity; and the per-entry
 * denormalized `payload` + `entryType` enable binding-integrity — the export's
 * own verificationGuide step 4. The binding check defends against post-export
 * tampering of the human-readable `payload`/`criteria` view: the verifier
 * re-decodes the signed predicate from `coseSign1` and deep-equals it against
 * the row `payload`, so a rewritten `payload` with an intact envelope fails
 * CHAIN_PAYLOAD_BINDING_MISMATCH (validated against a real engine v0.26.4
 * export — `buildPredicateForRow` reconstructs the signed predicate exactly).
 * Older exports without these fields stay `skipped_no_input`, surfaced in the
 * result so a caller never mistakes "not checked here" for "checked and passed".
 */
import {
  buildKeyRegistry,
  verifyChain,
  type CheckApplicability,
  type NormalizedEntry,
  type OptionalCheck,
  type SignatureOutcome,
  type VerificationKey,
} from './chain.js';
import type { FailureCode } from './failures.js';

/** One entry of a `/audit-export` document. */
export interface AuditExportEntryInput {
  /** 1-based chain position. Current exports emit `chainPosition`; pre-v0.25 used `position`. */
  chainPosition?: number;
  /** Legacy alias for `chainPosition`. */
  position?: number;
  /** ISO-8601 write time. Engine ≥ v0.26.x — gates the temporal key-validity check. */
  createdAt?: string;
  /** OIDC issuer the actor was synthesized from (engine ≥ v0.26.x). */
  actorOidcIss?: string | null;
  /** OIDC subject the actor was synthesized from (engine ≥ v0.26.x). */
  actorOidcSub?: string | null;
  /** Tri-state from `audit_vault.actor_oidc_synthesized` (engine ≥ v0.26.x). Marker for the OIDC-actor check. */
  actorOidcSynthesized?: boolean | null;
  /** The record this entry belongs to — pairs with `payload`/`entryType` to drive the binding check. */
  recordId?: string | null;
  /** The audit-vault entry type (e.g. `RECORD_CREATED`) — drives the binding check's predicate reconstruction. */
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

/** Per-key activation/retirement window — drives temporal key-validity (engine ≥ v0.26.x). */
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
    /** keyId → activation/retirement window (engine ≥ v0.26.x). */
    signingKeyWindows?: Record<string, SigningKeyWindow>;
  };
  entries: AuditExportEntryInput[];
  /**
   * Self-describing verification guidance the engine ships in the export (api#769).
   * `unsignedFields` lists per-entry fields that are UNSIGNED display projections
   * (e.g. `actorDisplayName`) resolved at export time, not covered by the COSE_Sign1
   * signature. A PASS does NOT vouch for these labels — signed attribution is the
   * `actorOwnerId`/`actorId` UUID. Surfaced on the result so a verdict can say so.
   */
  verificationGuide?: {
    unsignedFields?: string[];
  };
}

/**
 * Structural shape for a single out-of-band key in array form. Matches the SDK's
 * `VerificationKey` (the `.data[]` from `client.verificationKeys.list()`) plus
 * the SCITT COSE_KeySet (`/.well-known/scitt-keys`) entry shape — extra fields
 * are ignored. `publicKey` must be SPKI DER base64.
 */
export interface OutOfBandKeyEntry {
  keyId: string;
  publicKey: string;
  /** Optional activation timestamp — feeds temporal key-validity when present. */
  activatedAt?: string;
  /** Optional retirement timestamp; `null` means "active, no scheduled retirement". */
  retiredAt?: string | null;
}

export interface VerifyExportOptions {
  /**
   * Public keys supplied OUT OF BAND from a trusted source (GET
   * /v1/verification-keys, /.well-known/scitt-keys). These override any key
   * embedded in the export. For a real independent audit, supply keys here
   * rather than trusting the export's own `signingPublicKeys`.
   *
   * Accepts either form:
   *   - `Record<keyId, base64SpkiDer>` — the compact map shape
   *   - `OutOfBandKeyEntry[]` — the natural shape returned by
   *     `client.verificationKeys.list().data` and SCITT COSE_KeySet listings
   *
   * Anything else throws `TypeError` at the boundary. Fail-closed: the verifier
   * never silently falls back to embedded keys when the caller meant to defeat
   * trust in them. See agledger-agents#77 (F-698).
   */
  publicKeys?: Record<string, string> | ReadonlyArray<OutOfBandKeyEntry>;
  /** Require every entry to reference this keyId (else CHAIN_KEY_POLICY_VIOLATION). */
  requireKeyId?: string;
  /**
   * High-assurance: refuse keys embedded in the export. An entry whose only key
   * is export-embedded fails CHAIN_KEY_POLICY_VIOLATION — verifying the engine
   * against its own embedded key is not an independent audit.
   */
  requireOutOfBandKeys?: boolean;
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
   * - `oidc_actor` and `key_temporal` flip to `applied` when the export wire
   *   carries their inputs (engine ≥ v0.26.x: `actorOidcSynthesized` per
   *   entry, `signingKeyWindows` in exportMetadata, `createdAt` per entry).
   * - `payload_binding` stays `skipped_no_input` here by design — the export
   *   re-projects payload from the signed bytes, so this check is dump-only
   *   (run `@agledger/verify` over a full vault dump to exercise it).
   *
   * Older exports without the new fields stay `skipped_no_input` for all three.
   * The applicability is surfaced so a caller never mistakes "not checked
   * here" for "checked and passed".
   */
  optionalChecks: Record<OptionalCheck, CheckApplicability>;
  /**
   * How many signature checks resolved against out-of-band vs export-embedded
   * keys. `embedded > 0` means the verdict trusts keys shipped by the engine
   * that produced the export — supply out-of-band keys for an independent audit.
   */
  keyProvenance: { outOfBand: number; embedded: number };
  /**
   * Per-entry fields the export self-describes as UNSIGNED display projections
   * (from `verificationGuide.unsignedFields`, api#769) — e.g. `actorDisplayName`.
   * A valid signature does NOT cover these; signed attribution is the
   * `actorOwnerId`/`actorId` UUID. Empty when the export carries no such guidance.
   * A caller surfacing a PASS should warn that these labels are not vouched for.
   */
  unsignedProjectionFields: string[];
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

  const keys = buildKeyRegistry(resolveKeys(exportData, options));
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
    // signed bytes — the export's own verificationGuide step 4. The threat is
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
    if (e.createdAt) base.createdAt = e.createdAt;
    // The synthesized flag is the marker that the export carries the OIDC
    // wire shape at all. Older exports omit it entirely; new exports always
    // include it (false/null/true). Setting `oidcActor` flips `oidc_actor`
    // to `applied` in the chain result — never `applied` for old exports.
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
    requireOutOfBandKeys: options.requireOutOfBandKeys,
  });

  return {
    valid: chain.valid,
    totalEntries: chain.totalEntries,
    verifiedEntries: chain.verifiedEntries,
    brokenAt: chain.brokenAt
      ? { position: chain.brokenAt.position, code: chain.brokenAt.code, detail: chain.brokenAt.detail }
      : undefined,
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
  };
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
      key_temporal: 'skipped_no_input',
    },
    keyProvenance: { outOfBand: 0, embedded: 0 },
    unsignedProjectionFields: [],
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
  // Out-of-band keys override embedded keys of the same id, but inherit the
  // previously-seen activation/retirement window if the OOB entry didn't carry
  // its own.
  const oob = normalizeOutOfBandKeys(options.publicKeys);
  if (oob) {
    for (const entry of oob) {
      const existing = byId.get(entry.keyId);
      const activatedAt = entry.activatedAt ?? existing?.activatedAt;
      const retiredAt = entry.retiredAt !== undefined ? entry.retiredAt : existing?.retiredAt;
      byId.set(entry.keyId, {
        keyId: entry.keyId,
        spkiBase64: entry.spkiBase64,
        source: 'out-of-band',
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
      // key out-of-band AND brought their own activation/retirement window,
      // the export's (untrusted) signingKeyWindows MUST NOT overwrite it.
      // A compromised export could otherwise hide a retirement by setting
      // retiredAt:null, reopening F-698 on the temporal axis. When the OOB
      // caller did not carry a window, we still fall through to the export's
      // window — most auditors trust the engine's published key-rotation log
      // even when they bring their own key catalogue.
      const oobCarriesWindow =
        existing.source === 'out-of-band' &&
        (existing.activatedAt !== undefined || existing.retiredAt !== undefined);
      if (oobCarriesWindow) continue;
      byId.set(keyId, {
        ...existing,
        activatedAt: window.activatedAt,
        retiredAt: window.retiredAt,
      });
    }
  }
  return [...byId.values()];
}

interface NormalizedOobEntry {
  keyId: string;
  spkiBase64: string;
  activatedAt?: string;
  retiredAt?: string | null;
}

/**
 * Normalize `options.publicKeys` into a uniform array of entries, or throw
 * `TypeError` at the boundary if the shape is wrong. Fail-closed by design:
 * an OOB-key argument that silently falls back to embedded keys would lie
 * about the audit-independence claim (see agledger-agents#77 / F-698).
 *
 * Accepts:
 *   - `Record<keyId, base64SpkiDer>` — compact map (string-keyed object whose
 *     values are all strings)
 *   - `OutOfBandKeyEntry[]` — natural SDK shape from `verificationKeys.list()`,
 *     or COSE_KeySet shape from `/.well-known/scitt-keys`
 *
 * Returns `null` when no keys were supplied; otherwise an array of normalized
 * entries ready to merge into the registry.
 */
function normalizeOutOfBandKeys(
  publicKeys: VerifyExportOptions['publicKeys'],
): NormalizedOobEntry[] | null {
  if (publicKeys === undefined || publicKeys === null) return null;

  if (Array.isArray(publicKeys)) {
    return publicKeys.map((entry, i) => {
      if (entry === null || typeof entry !== 'object') {
        throw new TypeError(
          `verifyAuditExport: publicKeys[${i}] is not an object (got ${typeof entry}). ` +
            `Expected { keyId, publicKey } entries — e.g. the .data[] from client.verificationKeys.list().`,
        );
      }
      const keyId = (entry as { keyId?: unknown }).keyId;
      const publicKey = (entry as { publicKey?: unknown }).publicKey;
      if (typeof keyId !== 'string' || typeof publicKey !== 'string') {
        throw new TypeError(
          `verifyAuditExport: publicKeys[${i}] is missing required string fields { keyId, publicKey } ` +
            `(got keyId=${typeof keyId}, publicKey=${typeof publicKey}). ` +
            `Expected the SDK VerificationKey shape — publicKey must be SPKI DER base64.`,
        );
      }
      const out: NormalizedOobEntry = { keyId, spkiBase64: publicKey };
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

  const entries: NormalizedOobEntry[] = [];
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
