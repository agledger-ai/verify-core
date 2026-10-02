/**
 * Vault key statements and the trust walk over them.
 *
 * A vault key is trusted only when signed key statements link it to a key the
 * verifier pinned out of band (`trustAnchors`). The Server's database stores
 * the statements and never vouches for them: anything with write access to it
 * can add a `vault_signing_keys` row and a statement row, and neither makes a
 * key trusted, because every edge below is a signature that writer cannot
 * produce. This is the engine's `computeKeyTrust`
 * (audit-vault/key-statements.ts), re-implemented so the verifier has no engine
 * dependency. Where the two could disagree, this one must never trust a key the
 * engine refuses.
 *
 * **Format.** Each statement is one or two COSE_Sign1 (RFC 9052, tag 18) over
 * the SAME deterministic-CBOR (RFC 8949 §4.2.1) payload, protected header
 * `{1: alg, 3: cty, 4: kid}` with `cty` = {@link KEY_STATEMENT_CTY}. The
 * payload is a text-keyed map:
 *
 *   typ        'succession' | 'closure' | 'genesis'
 *   iss        the Server's issuer URL (informational)
 *   subject    { kid, spkiSha256, alg, spki (bstr), activatedAt, retiredAt? }
 *   endorser   { kid, spkiSha256 }            absent on genesis
 *   iat        epoch seconds, informational only, never used for ordering
 *   forced     bool                           closure only
 *
 * `activatedAt` / `retiredAt` are RFC 3339 UTC instants at microsecond
 * precision. A succession is signed by the endorser and then by the subject; a
 * closure by a key other than its subject; a genesis by its subject alone, and
 * it grants no trust.
 *
 * **Write order.** The rule orders statements by the database's write order,
 * `created_at` then the row `id`, never by an instant a statement signs. A
 * dump carries it (`created_at` at milliseconds, then the file's own row
 * order, which the producer writes as `created_at, id`). Every key document
 * (`GET /v1/verification-keys`, `/.well-known/agledger-vault-keys.json`, an
 * export's `exportMetadata.signingKeyStatements`) carries it too, as each
 * statement's `id` and `createdAt` at microseconds, and lists under a trusted
 * key its admission, every later genesis or succession it signed, and its
 * counting closures. A walk over a document therefore dates a window and
 * cuts an edge back as the engine does, except where the document does not
 * carry a key the engine verified a statement with (the endorser of a later
 * succession, the signer of a closure): that statement is
 * KEY_STATEMENT_INVALID or KEY_CLOSURE_INVALID here, the window is wider than
 * the engine's, and the listed `activatedAt` or `retiredAt` reports it as
 * CHAIN_KEY_WINDOW_DRIFT (a listed retirement no counting closure signs, as
 * KEY_CLOSURE_INVALID).
 *
 * A document from a Server that published neither field is ordered by the
 * instant each statement signs (a genesis or succession by
 * `subject.activatedAt`, a closure by `subject.retiredAt`). For an honest
 * document the two orders agree, because the Server signs the instant it
 * writes. What the signed order cannot do is hold a leaked key to the time it
 * actually wrote a statement: a key retired without `forced` whose private
 * half later leaks can date a statement before its retirement. Such a
 * statement is only ever in a document that did not come from the Server. A
 * forced closure voids every edge out of its key whatever the order.
 */
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import {
  algorithmByName,
  resolveKeyAlgorithm,
  runtimeCanCompute,
  sha256Hex,
  verifySignatureBytes,
  type KeyAlgorithm,
} from './primitives.js';
import { instantMs, instantUs, rfc3339Ms } from './instant.js';
import type { KeyRegistry, KeyTrustState, VerificationKey } from './chain.js';

/** Content type of a key statement's COSE_Sign1 (protected header label 3). */
export const KEY_STATEMENT_CTY = 'application/vnd.agledger.key-statement+cbor';

export const KEY_STATEMENT_KINDS = ['succession', 'closure', 'genesis'] as const;
export type KeyStatementKind = (typeof KEY_STATEMENT_KINDS)[number];

/**
 * The COSE `alg` a statement signature must carry for its key's algorithm.
 * Exactly one per algorithm, as the engine signs and checks them; the chain
 * envelope's wider acceptance (RFC 9864 fully-specified code points) does not
 * apply to statements.
 */
const STATEMENT_COSE_ALG: Readonly<Record<string, number>> = Object.freeze({ Ed25519: -8, ES256: -7 });

const COSE_HEADER_ALG = 1;
const COSE_HEADER_CTY = 3;
const COSE_HEADER_KID = 4;
const COSE_SIGN1_TAG = 18;
const COSE_SIGN1_TAG_PREFIX = 0xd2;
const SIG_STRUCTURE_CONTEXT = 'Signature1';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{16}$/;
/** RFC 3339 UTC at microsecond precision, the shape the statements sign. */
const INSTANT_US = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

// --- Inputs ---

/**
 * One key statement as a source carries it. A dump row maps onto it with
 * {@link keyStatementFromDumpRow}; a key document's `statements` with
 * {@link keyStatementsFromVerificationKeys} or
 * {@link keyStatementsFromExport}.
 */
export interface KeyStatementInput {
  /**
   * Row id (the dump's or a key document's `id`), named in findings. Under the
   * write order it breaks a tie between two statements whose `createdAt` are
   * the same microsecond, as the engine's `created_at, id` does.
   */
  id?: string | null;
  /** The source's own `kind` column, bound to the signed `typ`. */
  kind: string;
  /** The key id the source files the statement under, bound to the signed `subject.kid`. */
  subjectKeyId?: string;
  /**
   * The source's `endorser_key_id` column, bound to the signed `endorser.kid`
   * (`null` for a genesis). Omitted when the source carries no such column, as
   * the key documents do not.
   */
  endorserKeyId?: string | null;
  /**
   * Where the statement was read from. `dump`: a row of a dump's
   * `vault_key_statements.ndjson` ({@link keyStatementFromDumpRow} sets it),
   * whose `created_at` the walk holds a distrusted key's statements to, as the
   * engine does. Anything else, absent included, is a key document's (an
   * export's or a supplied `/v1/verification-keys` entry's): its `createdAt`
   * orders it but never keeps an edge out of a distrusted key.
   */
  source?: 'dump' | 'document';
  /** The COSE_Sign1 signatures, base64 or bytes, in signing order. */
  cose: ReadonlyArray<string | Uint8Array>;
  /**
   * The database write time (the dump's `created_at`, a key document's
   * `createdAt`). Give it for every statement or for none: with it the walk
   * applies the write order, without it the signed order (see the module
   * comment). Statements are ordered by it at the precision given, then, for
   * two at the same microsecond, by `id`, and otherwise in input order. Under
   * the write order a statement whose `createdAt` is not a strict RFC 3339
   * instant (a `T`, an offset or `Z`, a real calendar date) cannot be placed,
   * and is KEY_STATEMENT_INVALID (the adapters give `''` for a row or
   * document statement without one).
   */
  createdAt?: string;
}

/**
 * A key the source lists, the walk's fallback for the material of an endorser
 * no statement names as its subject, and the columns the drift check holds
 * against the signed window. Window and status fields are compared only when
 * given.
 */
export interface TrustKeyInput {
  keyId: string;
  /** SPKI DER, base64. */
  publicKey: string;
  algorithm?: string | null;
  status?: 'active' | 'retired' | null;
  activatedAt?: string | null;
  retiredAt?: string | null;
}

/**
 * A key distrusted from outside the database, the verifier-side mirror of the
 * Server's `VAULT_DISTRUSTED_KEYS`. See {@link parseDistrustedKeys}.
 */
export interface DistrustedKey {
  /** Full SHA-256 of the key's SPKI DER, lowercase hex. */
  spkiSha256: string;
  /**
   * RFC 3339 UTC instant at microsecond precision from which what the key
   * signs counts for nothing. Null: the earliest `retiredAt` a counting
   * closure by a key that is not distrusted signs for it, and when there is
   * none the key is trusted for nothing.
   */
  cutoff: string | null;
}

export interface ComputeKeyTrustInput {
  keys: readonly TrustKeyInput[];
  statements: readonly KeyStatementInput[];
  /** `sha256:<64 hex>` SPKI digests pinned out of band. At least one. */
  trustAnchors: readonly string[];
  /** `VAULT_DISTRUSTED_KEYS` entries (strings) or parsed {@link DistrustedKey}s. */
  distrustedKeys?: ReadonlyArray<string | DistrustedKey>;
}

// --- Outputs ---

export type KeyRegistryFindingCode = 'KEY_STATEMENT_INVALID' | 'KEY_CLOSURE_INVALID' | 'CHAIN_KEY_WINDOW_DRIFT';

/** A finding about the key registry itself, not about any chain entry. */
export interface KeyRegistryFinding {
  code: KeyRegistryFindingCode;
  keyId: string | null;
  statementId: string | null;
  detail: string;
}

/** What the walk concludes about one key. */
export interface KeyTrustEntry {
  keyId: string;
  spkiSha256: string;
  /** Anchored: reached from `trustAnchors` over edges that count. */
  trusted: boolean;
  /**
   * Reached only through a statement signed under an algorithm this host
   * cannot compute, and the key's own algorithm is one of those. Entries
   * signed by it cannot be verified here, which is not tamper evidence.
   */
  undecided: boolean;
  /** The signed lower edge, or null when no counting statement signs one. */
  activatedAt: string | null;
  /** The signed upper edge, or null when no counting closure signs one. */
  retiredAt: string | null;
  /**
   * The instant from which `distrustedKeys` voids what this key signs, when it
   * ends the key's window before its signed retirement, else null. The key is
   * not retired there: entries written after it fail CHAIN_KEY_EXPIRED as
   * past the distrust cutoff, not as past a retirement.
   */
  distrustCutoff: string | null;
}

export interface KeyTrust {
  /**
   * `written` when every statement carried `createdAt` (a dump, or a key
   * document from a Server that publishes each statement's write time), else
   * `signed` (an older document; see the module comment).
   */
  order: 'written' | 'signed';
  /** The anchors walked from, as `sha256:<hex>`. */
  anchors: string[];
  /** Every key the walk saw, by full SPKI SHA-256 (hex). */
  byDigest: ReadonlyMap<string, KeyTrustEntry>;
  /** SPKI digests of the trusted keys. */
  trusted: ReadonlySet<string>;
  /** SPKI digests of the undecided keys. */
  undecided: ReadonlySet<string>;
  findings: KeyRegistryFinding[];
  statements: { total: number; valid: number; invalid: number; unverifiable: number };
}

// --- Parsing the out-of-band inputs ---

/** The full SHA-256 of a base64 SPKI DER, lowercase hex. */
export function spkiSha256(spkiBase64: string): string {
  return sha256Hex(Buffer.from(spkiBase64, 'base64'));
}

function listOf(raw: string | readonly string[]): string[] {
  return (typeof raw === 'string' ? raw.split(',') : [...raw]).map((p) => {
    if (typeof p !== 'string') throw new TypeError(`expected a string entry (got ${typeof p}).`);
    return p.trim();
  }).filter((p) => p !== '');
}

/**
 * Parse trust anchors: `sha256:<64 hex>` entries, as an array or a comma list
 * (the Server's `VAULT_TRUST_ANCHORS` form). Returns the bare lowercase hex
 * digests. Throws `TypeError` naming any entry in another shape.
 */
export function parseTrustAnchors(raw: string | readonly string[]): string[] {
  const out: string[] = [];
  for (const entry of listOf(raw)) {
    const digest = /^sha256:([0-9a-f]{64})$/.exec(entry.toLowerCase())?.[1];
    if (digest === undefined) {
      throw new TypeError(
        `trustAnchors entry "${entry}" is not sha256:<64 hex>. Each anchor is the full SHA-256 of a vault public key's SPKI DER, `
        + 'taken out of band: the installer prints it, and the Server\'s signing-key-digest.js derives it from the key.',
      );
    }
    if (!out.includes(digest)) out.push(digest);
  }
  return out;
}

/** RFC 3339 with a `Z` or numeric offset and up to microsecond fractions. */
const RFC3339 = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d{1,6}|)(Z|[+-]\d{2}:\d{2})$/;

/**
 * Parse distrusted keys in the Server's `VAULT_DISTRUSTED_KEYS` form, as an
 * array or a comma list: `sha256:<64 hex>`, each optionally `@<RFC 3339
 * instant>`, the instant from which what the key signs counts for nothing.
 * The instant comes back in UTC at microsecond precision. Throws `TypeError`
 * naming any other entry, or a key named twice.
 */
export function parseDistrustedKeys(raw: string | readonly string[]): DistrustedKey[] {
  const out: DistrustedKey[] = [];
  for (const entry of listOf(raw)) {
    const at = entry.indexOf('@');
    const digest = /^sha256:([0-9a-f]{64})$/.exec((at === -1 ? entry : entry.slice(0, at)).toLowerCase())?.[1];
    const instant = at === -1 ? null : RFC3339.exec(entry.slice(at + 1).toUpperCase());
    // Date.parse rolls an impossible date over (February 30 reads as March 2),
    // so the fields must read back as written.
    const fields = instant?.[1] === undefined ? NaN : Date.parse(`${instant[1]}Z`);
    const calendar = instant?.[1] !== undefined && !Number.isNaN(fields) && new Date(fields).toISOString().startsWith(instant[1]);
    const whole = instant && calendar ? Date.parse(`${instant[1]}${instant[3]}`) : NaN;
    if (digest === undefined || (at !== -1 && (instant === null || Number.isNaN(whole)))) {
      throw new TypeError(
        `distrustedKeys entry "${entry}" is not sha256:<64 hex>, optionally followed by @<RFC 3339 instant> `
        + '(2026-09-01T00:00:00Z). Each entry is the full SHA-256 of a vault public key\'s SPKI DER, as in the Server\'s VAULT_DISTRUSTED_KEYS.',
      );
    }
    const cutoff = instant ? `${new Date(whole).toISOString().slice(0, 19)}.${(instant[2] ?? '').slice(1).padEnd(6, '0')}Z` : null;
    if (out.some((d) => d.spkiSha256 === digest)) {
      throw new TypeError(`distrustedKeys names sha256:${digest} twice. Give each key one entry, with the earliest instant it may have leaked.`);
    }
    out.push({ spkiSha256: digest, cutoff });
  }
  return out;
}

function normalizeDistrusted(raw: ReadonlyArray<string | DistrustedKey> | undefined): DistrustedKey[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new TypeError('distrustedKeys must be an array.');
  const strings = raw.filter((d): d is string => typeof d === 'string');
  const parsed = parseDistrustedKeys(strings);
  for (const d of raw) {
    if (typeof d === 'string') continue;
    if (d === null || typeof d !== 'object' || typeof d.spkiSha256 !== 'string' || !HEX64.test(d.spkiSha256)
      || (d.cutoff !== null && (typeof d.cutoff !== 'string' || !INSTANT_US.test(d.cutoff)))) {
      throw new TypeError('distrustedKeys entry is not { spkiSha256: <64 lowercase hex>, cutoff: <microsecond RFC 3339 UTC instant> | null }.');
    }
    if (parsed.some((p) => p.spkiSha256 === d.spkiSha256)) {
      throw new TypeError(`distrustedKeys names sha256:${d.spkiSha256} twice. Give each key one entry, with the earliest instant it may have leaked.`);
    }
    parsed.push({ spkiSha256: d.spkiSha256, cutoff: d.cutoff });
  }
  return parsed;
}

// --- Statement decoding and signatures ---

interface KeyRef {
  kid: string;
  spkiSha256: string;
}

interface KeyStatementPayload {
  typ: KeyStatementKind;
  iss: string;
  subject: KeyRef & { alg: string; spki: string; activatedAt: string; retiredAt?: string };
  endorser?: KeyRef;
  iat: number;
  forced?: boolean;
}

interface Sign1 {
  protectedBstr: Uint8Array;
  payloadBstr: Uint8Array;
  signature: Uint8Array;
  alg: number | null;
  cty: unknown;
  kid: string | null;
}

function toBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string' && BASE64.test(v)) return new Uint8Array(Buffer.from(v, 'base64'));
  return null;
}

function decodeSign1(raw: unknown): Sign1 | null {
  const bytes = toBytes(raw);
  if (bytes === null || bytes.length === 0 || bytes[0] !== COSE_SIGN1_TAG_PREFIX) return null;
  try {
    const decoded = cborDecode(bytes, {
      useMaps: true,
      tags: { [COSE_SIGN1_TAG]: (control: () => unknown) => control() },
    }) as unknown;
    if (!Array.isArray(decoded) || decoded.length !== 4) return null;
    const [p, , payload, sig] = decoded as [unknown, unknown, unknown, unknown];
    if (!(p instanceof Uint8Array) || !(payload instanceof Uint8Array) || !(sig instanceof Uint8Array)) return null;
    const header = cborDecode(p, { useMaps: true }) as unknown;
    if (!(header instanceof Map)) return null;
    const alg = header.get(COSE_HEADER_ALG);
    const kid = header.get(COSE_HEADER_KID);
    return {
      protectedBstr: p,
      payloadBstr: payload,
      signature: sig,
      alg: typeof alg === 'number' ? alg : null,
      cty: header.get(COSE_HEADER_CTY),
      kid: kid instanceof Uint8Array ? Buffer.from(kid).toString('hex') : null,
    };
  } catch {
    return null;
  }
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Uint8Array)
    ? (v as Record<string, unknown>)
    : null;
}

function readKeyRef(v: unknown): KeyRef | null {
  const r = asRecord(v);
  if (!r) return null;
  const kid = r['kid'];
  const digest = r['spkiSha256'];
  if (typeof kid !== 'string' || !HEX16.test(kid) || typeof digest !== 'string' || !HEX64.test(digest)) return null;
  return { kid, spkiSha256: digest };
}

/**
 * Decode and shape-check payload bytes. Null when anything is missing,
 * mistyped, not canonical, or inconsistent (the subject's digest must be the
 * SHA-256 of the spki it carries, and its kid the first 16 hex of that digest).
 */
function decodeKeyStatementPayload(bytes: Uint8Array): KeyStatementPayload | null {
  let raw: unknown;
  try {
    raw = cborDecode(bytes, { useMaps: false });
  } catch {
    return null;
  }
  // Canonical bytes only: two encodings of one payload would carry two digests.
  try {
    if (Buffer.compare(Buffer.from(cborEncode(raw, rfc8949EncodeOptions)), Buffer.from(bytes)) !== 0) return null;
  } catch {
    return null;
  }
  const r = asRecord(raw);
  if (!r) return null;
  const typ = r['typ'];
  if (typeof typ !== 'string' || !(KEY_STATEMENT_KINDS as readonly string[]).includes(typ)) return null;
  const iss = r['iss'];
  const iat = r['iat'];
  if (typeof iss !== 'string' || typeof iat !== 'number' || !Number.isInteger(iat)) return null;
  const s = asRecord(r['subject']);
  if (!s) return null;
  const ref = readKeyRef(s);
  const spki = s['spki'];
  const alg = s['alg'];
  const activatedAt = s['activatedAt'];
  const retiredAt = s['retiredAt'];
  if (!ref || !(spki instanceof Uint8Array) || typeof alg !== 'string' || typeof activatedAt !== 'string' || !INSTANT_US.test(activatedAt)) return null;
  if (retiredAt !== undefined && (typeof retiredAt !== 'string' || !INSTANT_US.test(retiredAt))) return null;
  if (sha256Hex(spki) !== ref.spkiSha256 || ref.kid !== ref.spkiSha256.slice(0, 16)) return null;
  const payload: KeyStatementPayload = {
    typ: typ as KeyStatementKind,
    iss,
    iat,
    subject: {
      ...ref,
      alg,
      spki: Buffer.from(spki).toString('base64'),
      activatedAt,
      ...(retiredAt !== undefined ? { retiredAt: retiredAt as string } : {}),
    },
  };
  if (r['endorser'] !== undefined) {
    const e = readKeyRef(r['endorser']);
    if (!e) return null;
    payload.endorser = e;
  }
  if (r['forced'] !== undefined) {
    if (typeof r['forced'] !== 'boolean') return null;
    payload.forced = r['forced'];
  }
  return payload;
}

function sigStructure(protectedBstr: Uint8Array, payloadBstr: Uint8Array): Uint8Array {
  return cborEncode([SIG_STRUCTURE_CONTEXT, protectedBstr, new Uint8Array(0), payloadBstr], rfc8949EncodeOptions);
}

type KeyMaterial = { spki: string; alg: KeyAlgorithm | 'unsupported' | 'invalid' };

/** The statement algorithm the key material commits to, when it is one statements are signed under. */
function statementAlgorithmOf(spki: string): KeyAlgorithm | null {
  const resolved = resolveKeyAlgorithm(spki);
  return typeof resolved === 'object' && STATEMENT_COSE_ALG[resolved.name] !== undefined ? resolved : null;
}

/**
 * The algorithm to verify a key's signatures under. The key material decides
 * wherever it parses; `strict` is for a statement's own subject, whose signed
 * `alg` must then agree with it. An endorser's declared algorithm comes from
 * wherever its key was found and is consulted only when the material does not
 * parse (an Ed25519 key on a FIPS host). A host that cannot compute the
 * algorithm makes the key `unsupported`, never `invalid`.
 */
function materialFor(spki: string, declared: string | null, strict = false): KeyMaterial {
  const derived = statementAlgorithmOf(spki);
  if (derived) {
    if (strict && declared !== derived.name) return { spki, alg: 'invalid' };
    return { spki, alg: runtimeCanCompute(derived) ? derived : 'unsupported' };
  }
  const named = declared !== null ? algorithmByName(declared) : null;
  if (named && STATEMENT_COSE_ALG[named.name] !== undefined && !runtimeCanCompute(named)) return { spki, alg: 'unsupported' };
  return { spki, alg: 'invalid' };
}

function checkSignature(sign1: Sign1, key: KeyMaterial, expectKid: string): 'ok' | 'bad' | 'unsupported' {
  if (key.alg === 'unsupported') return 'unsupported';
  if (key.alg === 'invalid') return 'bad';
  if (sign1.cty !== KEY_STATEMENT_CTY || sign1.kid !== expectKid || sign1.alg !== STATEMENT_COSE_ALG[key.alg.name]) return 'bad';
  if (sign1.signature.every((b) => b === 0)) return 'bad';
  return verifySignatureBytes(key.spki, sigStructure(sign1.protectedBstr, sign1.payloadBstr), sign1.signature) ? 'ok' : 'bad';
}

/** How one statement fared against its own bytes and the keys it names. */
interface CheckedKeyStatement {
  input: KeyStatementInput;
  id: string | null;
  /** `valid`: every signature verifies. `unverifiable`: one is under an algorithm this host cannot compute. */
  verdict: 'valid' | 'invalid' | 'unverifiable';
  detail: string | null;
  payload: KeyStatementPayload | null;
}

function checkKeyStatement(
  input: KeyStatementInput,
  keyByDigest: ReadonlyMap<string, { spki: string; alg: string | null }>,
): CheckedKeyStatement {
  const id = input.id ?? null;
  const invalid = (detail: string, payload: KeyStatementPayload | null = null): CheckedKeyStatement =>
    ({ input, id, verdict: 'invalid', detail, payload });
  const cose: readonly unknown[] = Array.isArray(input.cose) ? input.cose : [];
  const sigs = cose.map((b) => decodeSign1(b));
  if (sigs.length === 0 || sigs.some((s) => s === null)) return invalid('a signature does not decode as a tagged COSE_Sign1');
  const parts = sigs.filter((x): x is Sign1 => x !== null);
  const first = parts[0]!;
  if (!parts.every((p) => Buffer.from(p.payloadBstr).equals(Buffer.from(first.payloadBstr)))) {
    return invalid('the signatures do not cover the same payload');
  }
  const payload = decodeKeyStatementPayload(first.payloadBstr);
  if (!payload) return invalid('the payload does not decode as a key statement');
  if (payload.typ !== input.kind
    || (input.subjectKeyId !== undefined && payload.subject.kid !== input.subjectKeyId)
    || (input.endorserKeyId !== undefined && (payload.endorser?.kid ?? null) !== input.endorserKeyId)) {
    return invalid('the row columns disagree with the signed payload', payload);
  }
  const subject = materialFor(payload.subject.spki, payload.subject.alg, true);
  const endorserRef = payload.endorser ?? null;
  let endorser: KeyMaterial | null = null;
  if (endorserRef) {
    const known = keyByDigest.get(endorserRef.spkiSha256);
    if (!known) return invalid('the endorser key is unknown to the registry and to every statement', payload);
    if (endorserRef.kid !== endorserRef.spkiSha256.slice(0, 16)) return invalid('the endorser kid is not its key fingerprint', payload);
    endorser = materialFor(known.spki, known.alg);
  }

  const expected: Array<{ key: KeyMaterial; kid: string }> = [];
  switch (payload.typ) {
    case 'genesis':
      if (endorserRef) return invalid('a genesis names an endorser', payload);
      expected.push({ key: subject, kid: payload.subject.kid });
      break;
    case 'succession':
      if (!endorser || !endorserRef) return invalid('a succession names no endorser', payload);
      if (endorserRef.spkiSha256 === payload.subject.spkiSha256) return invalid('a succession endorses its own key', payload);
      expected.push({ key: endorser, kid: endorserRef.kid }, { key: subject, kid: payload.subject.kid });
      break;
    case 'closure':
      if (!endorser || !endorserRef) return invalid('a closure names no signer', payload);
      if (endorserRef.spkiSha256 === payload.subject.spkiSha256) return invalid('a closure is signed by the key it closes', payload);
      if (payload.subject.retiredAt === undefined || payload.forced === undefined) {
        return invalid('a closure carries no retiredAt or forced', payload);
      }
      expected.push({ key: endorser, kid: endorserRef.kid });
      break;
  }
  if (payload.typ !== 'closure' && payload.forced !== undefined) return invalid('only a closure carries forced', payload);
  if (parts.length !== expected.length) {
    return invalid(`a ${payload.typ} carries ${expected.length} signature(s), this one carries ${parts.length}`, payload);
  }
  let unsupported = false;
  for (const [i, want] of expected.entries()) {
    const outcome = checkSignature(parts[i]!, want.key, want.kid);
    if (outcome === 'bad') return invalid(`signature ${i + 1} does not verify under the key it names`, payload);
    if (outcome === 'unsupported') unsupported = true;
  }
  return { input, id, verdict: unsupported ? 'unverifiable' : 'valid', detail: null, payload };
}

// --- The walk ---

/** A statement whose signatures did not fail, with its place in write order. */
interface Statement {
  check: CheckedKeyStatement;
  payload: KeyStatementPayload;
  subject: string;
  endorser: string | null;
  /** Position in write order (total: ties keep input order). */
  at: number;
  /** When it was stored, in ms: `createdAt`, or under the signed order the instant it signs. */
  storedMs: number;
}

/** One way trust flows: `from` vouches for `to` through statement `via`. */
interface Edge {
  from: string;
  to: string;
  via: Statement;
  /** A backward half pass 2 takes: the subject's sole admission. Pass 1 takes every backward half. */
  counts: boolean;
}

function reach(anchors: ReadonlySet<string>, edges: readonly Edge[]): Set<string> {
  const out = new Set(anchors);
  for (let grew = true; grew;) {
    grew = false;
    for (const e of edges) {
      if (out.has(e.from) && !out.has(e.to)) {
        out.add(e.to);
        grew = true;
      }
    }
  }
  return out;
}

/** The instant a statement signs, which orders it when the source carries no write time. */
function signedInstantOf(c: CheckedKeyStatement): string | null {
  if (c.payload === null) return null;
  return c.payload.typ === 'closure' ? c.payload.subject.retiredAt ?? null : c.payload.subject.activatedAt;
}

/**
 * Walk the key statements from `trustAnchors` and decide which keys are
 * trusted and what window each carries. Two passes, no fixpoint:
 *
 *  1. Reach every key from the anchors over every edge, ignoring closures.
 *  2. Apply every closure whose signer pass 1 reaches: a key's window ends at
 *     the earliest `retiredAt` among them, a forced one voids every edge out
 *     of the key, forward and back, and any edge out of the key stored after
 *     its first such closure is void.
 *  3. Reach again without the void edges, taking a key's edge back only
 *     through its sole admission. That set is the trusted set.
 *
 * The edges: a succession E->K links E forward to K and K back to E. A key's
 * admission is the first genesis or succession naming it; pass 3 takes K's
 * edge back only when the succession is K's admission and K has exactly one.
 *
 * Closures only remove edges and shorten windows, so a closure signed by a
 * leaked key is at worst a denial of service, never a key trusted that was
 * not before. A distrusted key is the one thing that makes a closure stop
 * counting: what it stores at or after its cutoff counts for nothing.
 *
 * Throws `TypeError` on malformed anchors or distrusted keys, on no anchors
 * at all, and when some statements carry `createdAt` and others do not.
 */
export function computeKeyTrust(input: ComputeKeyTrustInput): KeyTrust {
  const anchorDigests = parseTrustAnchors(input.trustAnchors);
  if (anchorDigests.length === 0) {
    throw new TypeError('computeKeyTrust needs at least one trust anchor (sha256:<64 hex>). With none, no key can be trusted.');
  }
  const anchors = new Set(anchorDigests);
  const distrustedKeys = normalizeDistrusted(input.distrustedKeys);
  if (!Array.isArray(input.statements) || !Array.isArray(input.keys)) {
    throw new TypeError('computeKeyTrust takes arrays of keys and statements.');
  }

  const withTime = input.statements.filter((s) => typeof s.createdAt === 'string').length;
  if (withTime !== 0 && withTime !== input.statements.length) {
    throw new TypeError('Key statements must all carry createdAt (a dump) or none (a key document); this input mixes them.');
  }
  // A listed key with no key material (a dump row whose public_key was nulled)
  // vouches for nothing and is no endorser's fallback.
  const listedKeys = input.keys.filter((k) => typeof k.publicKey === 'string' && k.publicKey !== '');
  const order: KeyTrust['order'] = input.statements.length > 0 && withTime === input.statements.length ? 'written' : 'signed';
  // One stored row, read from two sources (an export and a key document), is
  // one statement. With no write time and no row id, two identical
  // statements are one; with them, a row is its id and write time, and a copy
  // of a row under another id is a second row, as the engine reads it.
  const seen = new Set<string>();
  const statementInputs = input.statements.filter((s) => {
    const cose: readonly unknown[] = Array.isArray(s.cose) ? s.cose : [];
    const bytes = cose.map((c) => {
      const b = toBytes(c);
      return b === null ? `?${String(c)}` : Buffer.from(b).toString('base64');
    }).join('|');
    if (order === 'written' && typeof s.id !== 'string') return true;
    // The same row however its time and id are spelled: `Z` or `+00:00`, a
    // uuid in either case.
    const at = instantUs(s.createdAt ?? '');
    const key = order === 'written' ? JSON.stringify([s.id.toLowerCase(), Number.isNaN(at.us) ? s.createdAt : at.us, bytes]) : bytes;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const findings: KeyRegistryFinding[] = [];
  // An endorser's key material, by digest. A statement's subject SPKI is bound
  // to its digest by the payload check and its algorithm is signed, so it is
  // taken first; a listed key is the fallback for a key no statement names as
  // its subject (one anchored only by a pin). The listed algorithm is the
  // source's word, and a statement never turns invalid because it was rewritten.
  const keyByDigest = new Map<string, { spki: string; alg: string | null }>();
  for (const st of statementInputs) {
    const sign1 = Array.isArray(st.cose) && st.cose.length > 0 ? decodeSign1(st.cose[0]) : null;
    const payload = sign1 ? decodeKeyStatementPayload(sign1.payloadBstr) : null;
    if (payload && !keyByDigest.has(payload.subject.spkiSha256)) {
      keyByDigest.set(payload.subject.spkiSha256, { spki: payload.subject.spki, alg: payload.subject.alg });
    }
  }
  for (const key of listedKeys) {
    const digest = spkiSha256(key.publicKey);
    if (!keyByDigest.has(digest)) keyByDigest.set(digest, { spki: key.publicKey, alg: typeof key.algorithm === 'string' ? key.algorithm : null });
  }

  // Under the write order a statement with no write time cannot be placed:
  // the Server writes one on every row, so it was edited, and it admits nothing.
  const checked = statementInputs.map((st) => {
    const c = checkKeyStatement(st, keyByDigest);
    if (order !== 'written' || !Number.isNaN(rfc3339Ms(st.createdAt!))) return c;
    return { ...c, verdict: 'invalid' as const, detail: 'the row has no parseable created_at to order it by' };
  });
  // Under the write order: `createdAt` at the precision given, then `id` for
  // two stored in the same microsecond (the engine's `created_at, id`), then
  // input order, which a dump writes as `created_at, id` at the microseconds
  // its milliseconds hide.
  type Placed = { c: CheckedKeyStatement; i: number; k: number | string; micro: boolean; r: number };
  const place = (c: CheckedKeyStatement, i: number): Placed => {
    if (order === 'written') {
      const at = instantUs(c.input.createdAt!);
      return { c, i, k: Number.isNaN(at.us) ? Number.POSITIVE_INFINITY : at.us, micro: at.micro, r: 0 };
    }
    return { c, i, k: signedInstantOf(c) ?? '￿', micro: false, r: closureLast(c) };
  };
  const tieById = (a: Placed, b: Placed): number => {
    const x = a.c.input.id;
    const y = b.c.input.id;
    if (!a.micro || !b.micro || typeof x !== 'string' || typeof y !== 'string') return 0;
    const [lx, ly] = [x.toLowerCase(), y.toLowerCase()];
    return lx < ly ? -1 : lx > ly ? 1 : 0;
  };
  // Under the signed order a closure sorts after every admission that signs
  // the same instant, whatever order the document lists them in. A rotation
  // signs the successor's activatedAt and the predecessor's retiredAt as one
  // instant, and the Server writes the succession first. This lets no
  // statement past a closure that the order did not already let through: the
  // closure still voids every edge its key signs at any later instant, a
  // forced one or a distrusted key voids them all, and a document that did
  // not come from the Server could list the succession first anyway.
  const closureLast = (c: CheckedKeyStatement): number => (order === 'signed' && c.payload?.typ === 'closure' ? 1 : 0);
  const inWriteOrder: Statement[] = checked
    .map(place)
    .sort((a, b) => (a.k < b.k ? -1 : a.k > b.k ? 1 : a.r - b.r || tieById(a, b) || a.i - b.i))
    .flatMap(({ c, k }, at) => c.verdict === 'invalid' || c.payload === null ? [] : [{
      check: c,
      payload: c.payload,
      subject: c.payload.subject.spkiSha256,
      endorser: c.payload.endorser?.spkiSha256 ?? null,
      at,
      storedMs: typeof k === 'number' ? rfc3339Ms(c.input.createdAt!) : instantMs(k),
    }]);
  const valid = inWriteOrder.filter((s) => s.check.verdict === 'valid');

  // Each key's admission: the first genesis or succession naming it, over
  // every statement whose signatures did not fail. A second admission is its
  // private half in someone else's hands, so the edge back from a key runs
  // only while it has exactly one, and its window opens at the latest
  // instant any of them signs.
  const admissions = new Map<string, Statement>();
  const admittedTwice = new Set<string>();
  const activatedAt = new Map<string, string>();
  for (const s of inWriteOrder) {
    if (s.payload.typ === 'closure') continue;
    if (admissions.has(s.subject)) admittedTwice.add(s.subject);
    else admissions.set(s.subject, s);
    const signed = s.payload.subject.activatedAt;
    if (s.check.verdict === 'valid' && (activatedAt.get(s.subject) ?? signed) <= signed) activatedAt.set(s.subject, signed);
  }

  const edgesOf = (s: Statement): Edge[] => {
    const e = s.endorser;
    if (e === null || s.payload.typ !== 'succession') return [];
    return [
      { from: e, to: s.subject, via: s, counts: true },
      { from: s.subject, to: e, via: s, counts: admissions.get(s.subject) === s && !admittedTwice.has(s.subject) },
    ];
  };
  const edges = valid.flatMap(edgesOf);

  // Distrusted keys and the instant each one's statements stop counting from.
  const distrust = new Set(distrustedKeys.map((d) => d.spkiSha256));
  const cutoffs = new Map<string, { at: number; instant: string } | null>();
  if (distrust.size > 0) {
    const clear = reach(anchors, edges.filter((e) => !distrust.has(e.from)));
    for (const d of distrustedKeys) {
      let instant = d.cutoff;
      if (instant === null) {
        for (const s of valid) {
          if (s.subject !== d.spkiSha256 || s.payload.typ !== 'closure') continue;
          const by = s.endorser;
          const retiredAt = s.payload.subject.retiredAt;
          if (by === null || distrust.has(by) || !clear.has(by) || retiredAt === undefined) continue;
          if (instant === null || retiredAt < instant) instant = retiredAt;
        }
      }
      cutoffs.set(d.spkiSha256, instant === null ? null : { at: instantMs(instant), instant });
    }
  }
  /**
   * Signed by a distrusted key at or after its cutoff: counts for nothing.
   * Only a dump row's write time is held against the cutoff, and only as far
   * as the dump came from the Server. A key document's `createdAt` is the
   * word of whoever holds the file, and under the signed order the instant a
   * statement signs is the leaked key's own word. So for any statement that
   * is not a dump row, every edge out of a distrusted key is void whatever
   * time it carries, and every closure it signed still counts: dropping an
   * edge or keeping a closure only ever takes trust away. Narrower than the
   * engine, never wider. The write order still orders such statements.
   */
  const distrusted = (s: Statement, signer: string | null): boolean => {
    if (signer === null || !cutoffs.has(signer)) return false;
    if (order === 'signed' || s.check.input.source !== 'dump') return s.payload.typ !== 'closure';
    const cutoff = cutoffs.get(signer);
    return cutoff === null || cutoff === undefined || s.storedMs >= cutoff.at;
  };

  // Pass 1, then the closures it lets count.
  const pass1 = reach(anchors, edges.filter((e) => !distrusted(e.via, e.from)));
  const counting = valid.filter((s) => s.payload.typ === 'closure' && s.endorser !== null
    && pass1.has(s.endorser) && !distrusted(s, s.endorser));
  const closedAt = new Map<string, number>();
  const closedWindow = new Map<string, string>();
  const forced = new Set<string>();
  for (const c of counting) {
    if (!closedAt.has(c.subject)) closedAt.set(c.subject, c.at);
    const retiredAt = c.payload.subject.retiredAt;
    if (retiredAt !== undefined && (closedWindow.get(c.subject) ?? retiredAt) >= retiredAt) closedWindow.set(c.subject, retiredAt);
    if (c.payload.forced === true) forced.add(c.subject);
  }
  const voided = (edge: Edge): boolean => {
    if (!edge.counts || forced.has(edge.from) || distrusted(edge.via, edge.from)) return true;
    const closed = closedAt.get(edge.from);
    return closed !== undefined && edge.via.at > closed;
  };

  // Pass 2: the trusted set.
  const trusted = reach(anchors, edges.filter((e) => !voided(e)));
  const untrusted = [...cutoffs].filter(([, c]) => c === null).map(([d]) => d);
  for (const d of untrusted) trusted.delete(d);

  // Keys this host cannot decide: reached only through a statement signed
  // under an algorithm it cannot compute, and of such an algorithm themselves.
  // A key it can compute, reached only through a half it cannot check, is
  // reached through bytes anyone with database access writes as easily as the
  // Server: it is unanchored.
  const undecided = new Set<string>();
  const unverifiable = inWriteOrder.filter((s) => s.check.verdict === 'unverifiable');
  if (unverifiable.length > 0) {
    const all = [...edges, ...unverifiable.flatMap(edgesOf)].filter((e) => !voided(e));
    for (const d of reach(anchors, all)) if (!trusted.has(d)) undecided.add(d);
    for (const d of untrusted) undecided.delete(d);
    for (const d of undecided) {
      const known = keyByDigest.get(d);
      if (!known || materialFor(known.spki, known.alg).alg !== 'unsupported') undecided.delete(d);
    }
  }

  // Each trusted key's window. It opens at the latest `activatedAt` its
  // verified admissions sign, so a statement added later only narrows it.
  const byDigest = new Map<string, KeyTrustEntry>();
  const entryFor = (digest: string): KeyTrustEntry => {
    const existing = byDigest.get(digest);
    if (existing) return existing;
    const created: KeyTrustEntry = {
      keyId: digest.slice(0, 16), spkiSha256: digest, trusted: trusted.has(digest), undecided: undecided.has(digest), activatedAt: null, retiredAt: null, distrustCutoff: null,
    };
    byDigest.set(digest, created);
    return created;
  };
  for (const key of listedKeys) entryFor(spkiSha256(key.publicKey));
  for (const d of undecided) entryFor(d);
  for (const d of trusted) {
    const entry = entryFor(d);
    entry.activatedAt = activatedAt.get(d) ?? null;
    entry.retiredAt = closedWindow.get(d) ?? null;
    const cutoff = cutoffs.get(d)?.instant;
    if (cutoff !== undefined && (entry.retiredAt === null || cutoff < entry.retiredAt)) entry.distrustCutoff = cutoff;
  }

  // Findings on statements.
  const finding = (code: KeyRegistryFindingCode, s: Statement, detail: string) =>
    findings.push({ code, keyId: s.payload.subject.kid, statementId: s.check.id, detail });
  for (const c of checked) {
    if (c.verdict === 'invalid') {
      findings.push({
        code: 'KEY_STATEMENT_INVALID',
        keyId: c.payload?.subject.kid ?? c.input.subjectKeyId ?? null,
        statementId: c.id,
        detail: c.detail ?? 'invalid',
      });
    }
  }
  // The earliest activation any admission signs for a key: a later admission
  // (the key's own half, leaked) can move the window's lower edge, and must not
  // make an honest closure read as dated before it.
  const firstActivation = new Map<string, string>();
  for (const s of valid) {
    if (s.payload.typ === 'closure') continue;
    const from = s.payload.subject.activatedAt;
    if ((firstActivation.get(s.subject) ?? from) >= from) firstActivation.set(s.subject, from);
  }
  for (const s of valid) {
    const e = s.endorser;
    const by = s.payload.endorser?.kid ?? '';
    if (e !== null && distrusted(s, e)) {
      const cutoff = cutoffs.get(e);
      const closed = s.payload.subject.retiredAt;
      const now = byDigest.get(s.subject);
      const ends = now?.distrustCutoff ?? now?.retiredAt ?? null;
      // Dropping a closure the distrusted key signed reopens its subject.
      const reopened = s.payload.typ === 'closure' && closed !== undefined && now?.trusted === true
        && (ends === null || ends > closed)
        ? ` It retired ${s.payload.subject.kid} at ${closed}, and no closure that counts retires it that early now; if ${s.payload.subject.kid} leaked as well, add sha256:${s.subject} to distrustedKeys too.`
        : '';
      finding(s.payload.typ === 'closure' ? 'KEY_CLOSURE_INVALID' : 'KEY_STATEMENT_INVALID', s,
        `a ${s.payload.typ} by ${by}, which distrustedKeys distrusts ${cutoff ? `from ${cutoff.instant}` : 'entirely'}; it counts for nothing.${reopened}`);
      continue;
    }
    if (s.payload.typ === 'closure') {
      const retiredAt = s.payload.subject.retiredAt ?? '';
      const activated = byDigest.get(s.subject)?.trusted === true ? firstActivation.get(s.subject) ?? null : null;
      const signerClosed = e === null ? undefined : closedAt.get(e);
      const distrustHint = `If ${by} leaked or was retired, distrustedKeys sha256:${e ?? ''} (VAULT_DISTRUSTED_KEYS on the Server) makes what it signed from its retirement on count for nothing.`;
      if (e === null || !pass1.has(e)) finding('KEY_CLOSURE_INVALID', s, 'the closure is signed by a key that is not anchored');
      else if (signerClosed !== undefined && s.at > signerClosed) {
        finding('KEY_CLOSURE_INVALID', s, `the closure is signed by ${by} after its own retirement, and still counts: it ends ${s.payload.subject.kid}'s window at ${retiredAt}. ${distrustHint}`);
      } else if (activated !== null && retiredAt < activated) {
        finding('KEY_CLOSURE_INVALID', s, `the closure retires ${s.payload.subject.kid} at ${retiredAt}, before the ${activated} it was activated, and still counts. ${distrustHint}`);
      }
      continue;
    }
    if (!trusted.has(s.subject) && (e === null || !trusted.has(e))) {
      finding('KEY_STATEMENT_INVALID', s, `a ${s.payload.typ} that touches no anchored key`);
    } else if (s.at > (closedAt.get(s.subject) ?? Infinity)) {
      finding('KEY_STATEMENT_INVALID', s, `a ${s.payload.typ} of a key stored after its closure; it admits nothing`);
    } else if (admissions.get(s.subject) !== s) {
      finding('KEY_STATEMENT_INVALID', s, `a ${s.payload.typ} its subject signed after it was already admitted`);
    } else if (e !== null && trusted.has(e)) {
      const closed = closedAt.get(e);
      if (closed !== undefined && s.at > closed) finding('KEY_STATEMENT_INVALID', s, `a ${s.payload.typ} by ${by} stored after its closure`);
    }
  }

  // Keys an admission names that this walk could not verify. A key document
  // carries a key's admissions but not every endorser, so the walk can date a
  // trusted key's window earlier than the engine did, or not at all.
  const unverifiedAdmission = new Set(checked
    .filter((c) => c.verdict === 'invalid' && c.payload !== null && c.payload.typ !== 'closure')
    .map((c) => c.payload!.subject.spkiSha256));

  // Findings on listed keys: their columns against the signed values, compared
  // at millisecond precision, the precision a dump or key document carries.
  for (const key of listedKeys) {
    const entry = entryFor(spkiSha256(key.publicKey));
    if (!entry.trusted || key.keyId !== entry.keyId) continue;
    if (entry.activatedAt !== null && typeof key.activatedAt === 'string' && instantMs(key.activatedAt) !== instantMs(entry.activatedAt)) {
      findings.push({ code: 'CHAIN_KEY_WINDOW_DRIFT', keyId: key.keyId, statementId: null, detail: `activatedAt ${key.activatedAt} differs from the signed ${entry.activatedAt}` });
    } else if (entry.activatedAt === null && typeof key.activatedAt === 'string' && unverifiedAdmission.has(entry.spkiSha256)) {
      // The window then has no lower edge here, which is wider than the
      // listed one: the same drift, read the other way.
      findings.push({ code: 'CHAIN_KEY_WINDOW_DRIFT', keyId: key.keyId, statementId: null, detail: `activatedAt ${key.activatedAt} is signed by no admission this walk could verify` });
    }
    if (entry.distrustCutoff !== null) {
      // The cutoff is no retirement, so a listed key left active is no drift;
      // one listed retired earlier than the cutoff is graded more loosely here
      // than where it was listed (a closure this walk could not verify).
      if (typeof key.retiredAt === 'string' && instantMs(key.retiredAt) < instantMs(entry.distrustCutoff)) {
        findings.push({ code: 'CHAIN_KEY_WINDOW_DRIFT', keyId: key.keyId, statementId: null, detail: `retiredAt ${key.retiredAt} is earlier than ${entry.distrustCutoff}, the distrust cutoff this walk ends the key at, and no closure it could verify signs it` });
      }
      continue;
    }
    if (key.status === 'retired') {
      if (entry.retiredAt === null) {
        findings.push({ code: 'KEY_CLOSURE_INVALID', keyId: key.keyId, statementId: null, detail: 'the key is listed as retired and no counting closure signs its retirement' });
      } else if (typeof key.retiredAt !== 'string' || instantMs(key.retiredAt) !== instantMs(entry.retiredAt)) {
        findings.push({ code: 'CHAIN_KEY_WINDOW_DRIFT', keyId: key.keyId, statementId: null, detail: `retiredAt ${key.retiredAt ?? 'null'} differs from the signed ${entry.retiredAt}` });
      }
    } else if (key.status === 'active' && entry.retiredAt !== null) {
      findings.push({ code: 'CHAIN_KEY_WINDOW_DRIFT', keyId: key.keyId, statementId: null, detail: `the key is listed as active but a counting statement signs its retirement at ${entry.retiredAt}` });
    }
  }

  return {
    order,
    anchors: anchorDigests.map((d) => `sha256:${d}`),
    byDigest,
    trusted,
    undecided,
    findings,
    statements: {
      total: checked.length,
      valid: checked.filter((c) => c.verdict === 'valid').length,
      invalid: checked.filter((c) => c.verdict === 'invalid').length,
      unverifiable: checked.filter((c) => c.verdict === 'unverifiable').length,
    },
  };
}

// --- Source adapters ---

/** A `vault_key_statements.ndjson` row, as the dump writes it. */
export interface DumpKeyStatementRow {
  id: string;
  kind: string;
  subject_key_id: string;
  endorser_key_id: string | null;
  statement: string[];
  created_at: string;
}

/**
 * Map a dump statement row onto the walk's input, binding every column. The
 * Server writes `subject_key_id` and `created_at` on every row, so one that is
 * missing or not a string maps to `''`, which matches no signed key id and
 * places the statement nowhere: it is KEY_STATEMENT_INVALID.
 */
export function keyStatementFromDumpRow(row: DumpKeyStatementRow): KeyStatementInput {
  return {
    id: row.id,
    kind: row.kind,
    subjectKeyId: typeof row.subject_key_id === 'string' ? row.subject_key_id : '',
    endorserKeyId: row.endorser_key_id,
    cose: Array.isArray(row.statement) ? row.statement : [],
    createdAt: typeof row.created_at === 'string' ? row.created_at : '',
    source: 'dump',
  };
}

/** A `vault_signing_keys.ndjson` row, as the dump writes it. */
export interface DumpSigningKeyRow {
  key_id: string;
  public_key: string;
  algorithm?: string | null;
  status?: string | null;
  activated_at?: string | null;
  retired_at?: string | null;
}

/** Map a dump key row onto the walk's input. */
export function trustKeyFromDumpRow(row: DumpSigningKeyRow): TrustKeyInput {
  return {
    keyId: row.key_id,
    publicKey: row.public_key,
    algorithm: typeof row.algorithm === 'string' ? row.algorithm : null,
    status: row.status === 'active' || row.status === 'retired' ? row.status : null,
    activatedAt: row.activated_at ?? null,
    retiredAt: row.retired_at ?? null,
  };
}

/**
 * A key's statement as the key documents list it. A Server that publishes
 * write order gives each its row `id` and `createdAt` (RFC 3339 UTC at
 * microsecond precision); an older one gives neither.
 */
export interface PublishedKeyStatement {
  /** The statement row's id (a uuid): the write order's tie-break. */
  id?: string;
  kind: string;
  /** When the database stored the statement: the write order. */
  createdAt?: string;
  cose: string[];
}

/**
 * The statements of a document keyed by key id. When any statement of the
 * document carries `createdAt`, the document publishes write order, so one
 * without it (or with another type) maps to `''` and is KEY_STATEMENT_INVALID
 * rather than turning the whole document back to the signed order. A
 * statement with no `id` is named `<prefix><keyId>#<index>`. Internal: the
 * export path reads supplied keys' statements with it; not re-exported.
 */
export function statementsFromMap(byKey: Iterable<[string, unknown]>, source: string, prefix = ''): KeyStatementInput[] {
  const entries = [...byKey];
  for (const [keyId, list] of entries) {
    if (list !== undefined && list !== null && !Array.isArray(list)) throw new TypeError(`${source}: the statements for key ${keyId} are not an array.`);
  }
  const timed = entries.some(([, list]) => Array.isArray(list) && list.some((st: unknown) => asRecord(st)?.['createdAt'] !== undefined));
  const out: KeyStatementInput[] = [];
  for (const [keyId, list] of entries) {
    if (!Array.isArray(list)) continue;
    list.forEach((st: unknown, i) => {
      const r = asRecord(st);
      if (!r || typeof r['kind'] !== 'string' || !Array.isArray(r['cose'])) {
        throw new TypeError(`${source}: statement ${i} for key ${keyId} is not { kind, cose: [base64...] }.`);
      }
      const id = typeof r['id'] === 'string' ? r['id'] : `${prefix}${keyId}#${i}`;
      const createdAt = r['createdAt'];
      out.push({
        id,
        kind: r['kind'],
        subjectKeyId: keyId,
        source: 'document',
        cose: r['cose'] as string[],
        ...(timed ? { createdAt: typeof createdAt === 'string' ? createdAt : '' } : {}),
      });
    });
  }
  return out;
}

/** The key statements of an audit export's `exportMetadata.signingKeyStatements`. */
export function keyStatementsFromExport(
  signingKeyStatements: Readonly<Record<string, readonly PublishedKeyStatement[]>> | undefined | null,
): KeyStatementInput[] {
  if (signingKeyStatements === undefined || signingKeyStatements === null) return [];
  if (typeof signingKeyStatements !== 'object' || Array.isArray(signingKeyStatements)) {
    throw new TypeError('signingKeyStatements must be an object keyed by key id.');
  }
  return statementsFromMap(Object.entries(signingKeyStatements), 'signingKeyStatements');
}

/** The `/v1/verification-keys` document, as far as the walk reads it. */
export interface VerificationKeysDocument {
  data: ReadonlyArray<{
    keyId: string;
    publicKey: string;
    algorithm?: string | null;
    status?: string | null;
    activatedAt?: string | null;
    retiredAt?: string | null;
    statements?: readonly PublishedKeyStatement[];
  }>;
  anchoredFrom?: string | null;
  keyStatementFormat?: string;
}

/**
 * The walk's inputs from a `/v1/verification-keys` document: its keys and
 * the statements each carries. Throws `TypeError` when the document names a
 * statement format this verifier does not read.
 */
export function keyStatementsFromVerificationKeys(doc: VerificationKeysDocument): { keys: TrustKeyInput[]; statements: KeyStatementInput[] } {
  if (doc === null || typeof doc !== 'object' || !Array.isArray(doc.data)) {
    throw new TypeError('Expected the /v1/verification-keys document: { data: [...], keyStatementFormat, anchoredFrom }.');
  }
  if (doc.keyStatementFormat !== undefined && doc.keyStatementFormat !== KEY_STATEMENT_CTY) {
    throw new TypeError(`keyStatementFormat ${JSON.stringify(doc.keyStatementFormat)} is not ${KEY_STATEMENT_CTY}; upgrade the verifier.`);
  }
  const keys: TrustKeyInput[] = doc.data.map((k) => ({
    keyId: k.keyId,
    publicKey: k.publicKey,
    algorithm: k.algorithm ?? null,
    status: k.status === 'active' || k.status === 'retired' ? k.status : null,
    activatedAt: k.activatedAt ?? null,
    retiredAt: k.retiredAt ?? null,
  }));
  const statements = statementsFromMap(doc.data.map((k) => [k.keyId, k.statements] as [string, unknown]), 'verification-keys');
  return { keys, statements };
}

/**
 * Mark every key of a registry with the walk's verdict, and give each anchored
 * key the window its statements sign in place of whatever window it carried,
 * as the engine grades entries. An anchored key no statement dates carries no
 * edge on that side. A key is anchored only when its key id is the
 * fingerprint of its own SPKI: a row filed under another key's id names that
 * key's entries, and is anchored to nothing.
 */
export function applyKeyTrust(registry: KeyRegistry, trust: KeyTrust): KeyRegistry {
  const out = new Map<string, VerificationKey>();
  for (const [keyId, key] of registry) {
    const digest = typeof key.spkiBase64 === 'string' ? spkiSha256(key.spkiBase64) : '';
    const bound = keyId === digest.slice(0, 16) && key.keyId === keyId;
    const anchored = bound && trust.trusted.has(digest);
    const state: KeyTrustState = anchored ? 'anchored' : bound && trust.undecided.has(digest) ? 'undecided' : 'unanchored';
    const { activatedAt: _a, retiredAt: _r, ...rest } = key;
    const next: VerificationKey = { ...rest, trust: state };
    const signed = trust.byDigest.get(digest);
    if (anchored && signed) {
      if (signed.activatedAt !== null) next.activatedAt = signed.activatedAt;
      if (signed.retiredAt !== null) next.retiredAt = signed.retiredAt;
      if (signed.distrustCutoff !== null) next.distrustCutoff = signed.distrustCutoff;
    } else {
      if (_a !== undefined) next.activatedAt = _a;
      if (_r !== undefined) next.retiredAt = _r;
    }
    out.set(keyId, next);
  }
  return out;
}

/**
 * Whether a verification can be read as trusted.
 *
 * - `walked`: the key statements were walked from the caller's anchors and at
 *   least one signature verified under a key they anchor. The one status a
 *   passing result is trusted on.
 * - `no_anchor`: no `trustAnchors` were given, so no key was anchored and
 *   every key was taken on the word of whoever embedded or supplied it. A
 *   pass is not a trusted verdict.
 * - `no_anchored_signature`: the walk ran, but no signature in the artifact
 *   verified under a key it anchors (every entry is unsigned history, or the
 *   chain broke first). An unsigned entry proves nothing about who wrote it,
 *   so a pass is not a trusted verdict either.
 *
 * Every surface reads `no_anchor` and `no_anchored_signature` alike: a pass
 * on either is `unanchored`, never `trusted`.
 */
export type KeyTrustStatus = 'walked' | 'no_anchor' | 'no_anchored_signature';

/** What a verification result says about key anchoring. */
export interface KeyTrustReport {
  /** See {@link KeyTrustStatus}. */
  status: KeyTrustStatus;
  detail: string;
  /** The anchors walked from, as `sha256:<hex>`. */
  anchors: string[];
  /** The artifact's own claim of the key it was anchored from (`sha256:<hex>`), when it carries one. */
  anchoredFrom: string | null;
  /** Whether `anchoredFrom` is one of `anchors`; null when either is absent. */
  anchoredFromPinned: boolean | null;
  /** How the statements were ordered (see `computeKeyTrust`); null when no walk ran. */
  order: 'written' | 'signed' | null;
  anchoredKeyIds: string[];
  unanchoredKeyIds: string[];
  undecidedKeyIds: string[];
  findings: KeyRegistryFinding[];
}

/**
 * Summarize a registry after `applyKeyTrust` (or with `trust` null when no
 * walk ran). A walked report says `walked` until the caller settles it with
 * {@link settleKeyTrust}, once it knows whether any signature verified under
 * an anchored key. `anchoredFrom` that is not a string is read as absent.
 */
export function reportKeyTrust(registry: KeyRegistry, trust: KeyTrust | null, anchoredFrom: string | null): KeyTrustReport {
  const ids = (state: KeyTrustState) => [...registry.values()].filter((k) => k.trust === state).map((k) => k.keyId).sort();
  if (typeof anchoredFrom !== 'string') anchoredFrom = null;
  if (trust === null) {
    return {
      status: 'no_anchor',
      detail: 'No trustAnchors were given, so no key was anchored and this is not a trusted verdict: every key was taken on the word of whoever embedded or supplied it, and a key written into the Server\'s database alone would verify. Pin the SPKI digest of a vault key you hold or took out of band (sha256:<hex>) as trustAnchors.',
      anchors: [],
      anchoredFrom,
      anchoredFromPinned: null,
      order: null,
      anchoredKeyIds: [],
      unanchoredKeyIds: [],
      undecidedKeyIds: [],
      findings: [],
    };
  }
  const unanchored = ids('unanchored');
  return {
    status: 'walked',
    detail: unanchored.length === 0
      ? `Every key is linked by signed key statements to ${trust.anchors.join(', ')}.`
      : `Keys ${unanchored.join(', ')} are not linked by any signed key statement to ${trust.anchors.join(', ')}; entries they signed fail CHAIN_SIGNING_KEY_UNANCHORED.`,
    anchors: trust.anchors,
    anchoredFrom,
    anchoredFromPinned: anchoredFrom === null ? null : trust.anchors.includes(anchoredFrom.toLowerCase()),
    order: trust.order,
    anchoredKeyIds: ids('anchored'),
    unanchoredKeyIds: unanchored,
    undecidedKeyIds: ids('undecided'),
    findings: trust.findings,
  };
}

/**
 * Settle a walked report once the caller has counted the signatures that
 * verified under an anchored key (an export's or a dump's entries whose
 * signature checked out, since under a walk every such key is anchored).
 * With none, the report becomes `no_anchored_signature`: the pin was walked,
 * but nothing in the artifact is signed by a key it anchors, so a pass is not
 * a trusted verdict. Any other report is returned as it is.
 */
export function settleKeyTrust(report: KeyTrustReport, anchoredSignatures: number): KeyTrustReport {
  if (report.status !== 'walked' || anchoredSignatures > 0) return report;
  return {
    ...report,
    status: 'no_anchored_signature',
    detail: `The key statements were walked from ${report.anchors.join(', ')}, but no signature here verified under a key they anchor, so this is not a trusted verdict: an entry written before the install began signing carries no signature, and proves nothing about who wrote it.`,
  };
}
