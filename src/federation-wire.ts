/**
 * The sealed federation message on a receiving Server's chain entry.
 *
 * When a peer's signed message (a state transition, a settlement signal, a
 * dispute leg, a co-sign request) is accepted, the receiver's chain entry for
 * it carries `payload.wire`: the message as the sender signed it, with the
 * sender's registered key, the recipient hub id, the method, path, body hash,
 * timestamp, nonce, signature, and a copy of the body the hash covers. The
 * receiver's own vault signature covers all of that, so the entry proves what
 * the receiver accepted; verifying the sealed signature under the sender's
 * federation key proves what the sender asserted, from the receiver's export
 * alone.
 *
 * The recipe is the Server's `federationPeerAuth` check, re-run offline:
 *
 *   bodyHash  = sha256 hex over the RFC 8785 (JCS) canonical JSON of `body`
 *   signInput = `<scheme>:<recipientHubId>:<method>:<path>:<bodyHash>:<timestamp>:<nonce>`
 *   verify `signature` (hex Ed25519) over the UTF-8 sign-input under `senderPublicKey`
 *
 * then the entry's own fields against the body it sealed (the state the entry
 * projects is the state the body carried, and so on). Entries from before the
 * Server sealed messages, and entries a direct projection wrote, carry no
 * `wire`; absent is not a failure.
 */
import { createHash } from 'node:crypto';
import { rfc3339Ms } from './instant.js';
import { algorithmByName, runtimeCanCompute, verifyEd25519Bytes } from './primitives.js';

export const FEDERATION_WIRE_SCHEME = 'agledger.federation.v2';

/** The sealed message as the receiver stores it under `payload.wire`. */
export interface FederationWire {
  scheme: string;
  senderHubId: string;
  /** The sender's Ed25519 key as registered at handshake: base64 SPKI DER, or base64 of the raw 32 bytes. */
  senderPublicKey: string;
  recipientHubId: string;
  method: string;
  path: string;
  /** SHA-256 hex over the RFC 8785 canonical JSON of `body`. */
  bodyHash: string;
  timestamp: string;
  nonce: string;
  /** Hex Ed25519 signature over the sign-input. */
  signature: string;
  /** The request body as received, the bytes `bodyHash` covers. */
  body: Record<string, unknown>;
}

/** The domain a federation key statement's signatures sign under. */
export const FEDERATION_KEY_STATEMENT_DOMAIN = 'agledger.federation.key-statement.v1';

/** One statement of a {@link FederationKeyHistoryDocument}, as served. */
export interface FederationKeyHistoryStatement {
  id: string;
  kind: string;
  /** The RFC 8785 (JCS) bytes both signatures cover, after the domain and a colon. */
  payload: string;
  subjectSignature: string;
  predecessorSignature: string | null;
  createdAt?: string;
}

/**
 * A publisher's `GET /.well-known/agledger-federation-keys.json`, as served.
 * Only `hubId`, `statementDomain` and the signed `statements` are read: the
 * `keys` summary is the publisher's own unsigned reading of them, so the
 * windows are taken from the statements instead.
 */
export interface FederationKeyHistoryDocument {
  hubId: string | null;
  statementDomain: string;
  statements: ReadonlyArray<FederationKeyHistoryStatement>;
  anchoredFrom?: string | null;
  keys?: unknown;
}

/**
 * One federation key a sender hub is trusted under, base64 SPKI DER, with the
 * window its signed statements give it. Both bounds are null for a key given
 * without a history: it is trusted at any time, as before histories existed.
 */
export interface FederationTrustedKey {
  publicKey: string;
  /** When the key took over; null when no signed statement bounds it from below. */
  activatedAt: string | null;
  /** When the next key took over; null while no succession signed by this key and its successor ends it. */
  retiredAt: string | null;
}

/**
 * Sender hub id to the federation keys its messages are trusted under, as
 * `buildFederationKeyRegistry` builds it: each pinned key, and with a history
 * every key linked to a pin by successions both keys signed.
 */
export type FederationKeyRegistry = ReadonlyMap<string, ReadonlyArray<FederationTrustedKey>>;

/**
 * One sender's federation key, the list shape `buildFederationKeyRegistry`
 * takes. `publicKey` is a key you hold for the hub by other means (the
 * `signingPublicKey` your peer row holds, or one its operator confirmed);
 * with `history`, the publisher's key-history document, every earlier or later
 * key a chain of successions links to it is trusted too, inside its window. A
 * hub may be named more than once, to pin keys no succession links (a key
 * listed `linked: false`).
 */
export interface FederationKeyEntry {
  hubId: string;
  publicKey: string;
  history?: FederationKeyHistoryDocument;
}

/** The 12-byte SPKI prefix of an Ed25519 key: SEQUENCE { AlgorithmIdentifier(id-Ed25519), BIT STRING }. */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * A federation key as base64 SPKI DER, from either form the Server's peer
 * table holds: SPKI DER, or the raw 32-byte key. Returns null for anything
 * that is neither (so a caller refuses it by name rather than verifying
 * nothing under it).
 */
export function normalizeFederationKey(publicKeyBase64: string): string | null {
  if (typeof publicKeyBase64 !== 'string' || publicKeyBase64.length === 0) return null;
  let bytes: Buffer;
  try {
    bytes = Buffer.from(publicKeyBase64, 'base64');
  } catch {
    return null;
  }
  if (bytes.length === 32) return Buffer.concat([ED25519_SPKI_PREFIX, bytes]).toString('base64');
  if (bytes.length === 44 && bytes.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) return bytes.toString('base64');
  return null;
}

const INSTANT_US = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX_SIG = /^[0-9a-f]{128}$/i;

function spkiSha256(spkiBase64: string): string {
  return createHash('sha256').update(Buffer.from(spkiBase64, 'base64')).digest('hex');
}

interface KeyRef {
  publicKey: string;
  spkiSha256: string;
}

interface StatementPayload {
  typ: 'genesis' | 'succession';
  subject: KeyRef & { activatedAt: string | null };
  predecessor?: KeyRef & { retiredAt: string };
}

function keyRef(value: unknown, extra: string): (KeyRef & Record<string, unknown>) | null {
  if (!isRecord(value)) return null;
  if (Object.keys(value).some((k) => k !== 'publicKey' && k !== 'spkiSha256' && k !== extra)) return null;
  const { publicKey, spkiSha256: digest } = value;
  if (typeof publicKey !== 'string' || typeof digest !== 'string' || !HEX64.test(digest)) return null;
  if (normalizeFederationKey(publicKey) !== publicKey || spkiSha256(publicKey) !== digest) return null;
  return value as KeyRef & Record<string, unknown>;
}

function verifyStatementSignature(publicKey: string, signature: string, payload: string): boolean {
  if (!HEX_SIG.test(signature)) return false;
  return verifyEd25519Bytes(publicKey, Buffer.from(`${FEDERATION_KEY_STATEMENT_DOMAIN}:${payload}`, 'utf8'), Buffer.from(signature, 'hex'));
}

/**
 * The payload of one served key statement when it holds as the Server holds
 * it, else why not. Holds: the payload is its own JCS form with only the
 * statement fields, names `hubId`, its `typ` is the statement's `kind`, the
 * keys are Ed25519 SPKI DER matching their digests, the instants are
 * microsecond RFC 3339, a succession hands over at the instant its subject
 * takes over and carries the predecessor's signature, a genesis carries none,
 * and every signature verifies.
 */
function verifyKeyStatement(stmt: FederationKeyHistoryStatement, hubId: string): StatementPayload | string {
  if (!isRecord(stmt) || typeof stmt.payload !== 'string') return 'it carries no payload string';
  let parsed: unknown;
  try {
    parsed = JSON.parse(stmt.payload);
  } catch {
    return 'its payload is not JSON';
  }
  if (!isRecord(parsed) || canonicalizeJson(parsed) !== stmt.payload) return 'its payload is not in its RFC 8785 canonical form';
  if (Object.keys(parsed).some((k) => !['typ', 'hubId', 'subject', 'predecessor'].includes(k))) return 'its payload carries a field a statement does not';
  const typ = parsed.typ;
  if (typ !== 'genesis' && typ !== 'succession') return `its typ is ${JSON.stringify(typ)}`;
  if (stmt.kind !== typ) return `its kind ${JSON.stringify(stmt.kind)} is not its payload's typ ${typ}`;
  if (parsed.hubId !== hubId) return `it names hub ${JSON.stringify(parsed.hubId)}`;
  const subject = keyRef(parsed.subject, 'activatedAt');
  if (subject === null) return 'its subject is not an Ed25519 key with its digest';
  const activatedAt = subject.activatedAt;
  if (!(activatedAt === null || (typeof activatedAt === 'string' && INSTANT_US.test(activatedAt)))) return 'its subject.activatedAt is not a microsecond RFC 3339 instant or null';
  let predecessor: StatementPayload['predecessor'];
  if (parsed.predecessor !== undefined) {
    const pred = keyRef(parsed.predecessor, 'retiredAt');
    if (pred === null) return 'its predecessor is not an Ed25519 key with its digest';
    if (typeof pred.retiredAt !== 'string' || pred.retiredAt !== activatedAt) return 'its predecessor.retiredAt is not its subject.activatedAt';
    if (pred.spkiSha256 === subject.spkiSha256) return 'it names one key as its own predecessor';
    predecessor = { publicKey: pred.publicKey, spkiSha256: pred.spkiSha256, retiredAt: pred.retiredAt };
  } else if (activatedAt !== null) {
    return 'it activates a key at a signed instant without naming a predecessor';
  }
  if (typ === 'succession' && predecessor === undefined) return 'it is a succession with no predecessor';
  if (!verifyStatementSignature(subject.publicKey, String(stmt.subjectSignature), stmt.payload)) return 'its subjectSignature does not verify under its subject key';
  if (typ === 'succession') {
    if (typeof stmt.predecessorSignature !== 'string' || !verifyStatementSignature(predecessor!.publicKey, stmt.predecessorSignature, stmt.payload)) {
      return 'its predecessorSignature does not verify under its predecessor key';
    }
  } else if (stmt.predecessorSignature !== null && stmt.predecessorSignature !== undefined) {
    return 'it is a genesis carrying a predecessorSignature';
  }
  return {
    typ,
    subject: { publicKey: subject.publicKey, spkiSha256: subject.spkiSha256, activatedAt },
    ...(predecessor ? { predecessor } : {}),
  };
}

/**
 * The keys a pin and the histories given for its hub trust: the pin, and
 * every key a chain of successions links to it, each succession counted only
 * when it is the statement admitting its subject (the first in write order),
 * as the Server walks it. A genesis names its predecessor without that key's
 * signature, so it links nothing.
 */
function trustedKeysFromHistory(
  hubId: string,
  pins: ReadonlyArray<{ spki: string; label: string }>,
  histories: ReadonlyArray<{ doc: FederationKeyHistoryDocument; label: string }>,
): FederationTrustedKey[] {
  if (algorithmByName('Ed25519') === null || !runtimeCanCompute(algorithmByName('Ed25519')!)) {
    throw new TypeError(`The federation key history for hub ${hubId} cannot be checked: this host cannot compute Ed25519 (an active OpenSSL FIPS provider carries no EdDSA).`);
  }
  const statements: StatementPayload[] = [];
  const seenIds = new Set<string>();
  for (const { doc, label } of histories) {
    if (!isRecord(doc) || !Array.isArray(doc.statements)) throw new TypeError(`${label} is not a federation key-history document (no statements array).`);
    if (doc.hubId !== hubId) throw new TypeError(`${label} is the key history of hub ${JSON.stringify(doc.hubId)}, not ${hubId}.`);
    if (doc.statementDomain !== FEDERATION_KEY_STATEMENT_DOMAIN) {
      throw new TypeError(`${label} signs under ${JSON.stringify(doc.statementDomain)}, not ${FEDERATION_KEY_STATEMENT_DOMAIN}.`);
    }
    doc.statements.forEach((stmt, j) => {
      const id = isRecord(stmt) && typeof stmt.id === 'string' ? stmt.id : `#${j}`;
      if (seenIds.has(id)) return;
      seenIds.add(id);
      const verified = verifyKeyStatement(stmt, hubId);
      if (typeof verified === 'string') {
        throw new TypeError(`${label}.statements[${j}] (${id}) does not hold: ${verified}. A served history lists only statements that verify, so this document was altered.`);
      }
      statements.push(verified);
    });
  }

  const admission = new Map<string, StatementPayload>();
  for (const st of statements) if (!admission.has(st.subject.spkiSha256)) admission.set(st.subject.spkiSha256, st);
  const publicKeyOf = new Map<string, string>();
  for (const st of statements) {
    publicKeyOf.set(st.subject.spkiSha256, st.subject.publicKey);
    if (st.predecessor) publicKeyOf.set(st.predecessor.spkiSha256, st.predecessor.publicKey);
  }
  const links = new Map<string, string[]>();
  const retiredAt = new Map<string, string>();
  for (const st of statements) {
    if (st.typ !== 'succession' || admission.get(st.subject.spkiSha256) !== st || !st.predecessor) continue;
    const a = st.predecessor.spkiSha256;
    const b = st.subject.spkiSha256;
    links.set(a, [...(links.get(a) ?? []), b]);
    links.set(b, [...(links.get(b) ?? []), a]);
    if (!retiredAt.has(a)) retiredAt.set(a, st.predecessor.retiredAt);
  }

  const trusted = new Set<string>();
  for (const { spki, label } of pins) {
    const digest = spkiSha256(spki);
    if (!publicKeyOf.has(digest)) {
      throw new TypeError(`${label}: the key pinned for hub ${hubId} appears in none of the key histories given for it, so the history is not linked to anything you hold.`);
    }
    const queue = [digest];
    while (queue.length > 0) {
      const k = queue.pop()!;
      if (trusted.has(k)) continue;
      trusted.add(k);
      queue.push(...(links.get(k) ?? []));
    }
  }
  return [...trusted].map((digest) => ({
    publicKey: publicKeyOf.get(digest)!,
    activatedAt: admission.get(digest)?.subject.activatedAt ?? null,
    retiredAt: retiredAt.get(digest) ?? null,
  }));
}

/**
 * Build the registry from `{ [hubId]: publicKey }` or
 * `[{ hubId, publicKey, history? }]`. Throws `TypeError` naming the entry on
 * any key that is not an Ed25519 key in one of the two forms, and on a history
 * that is another hub's, carries a statement that does not verify, or does not
 * reach the pinned key, so a bad input is refused before any verification
 * runs rather than reported as a signature failure.
 */
export function buildFederationKeyRegistry(
  input: Readonly<Record<string, string>> | ReadonlyArray<FederationKeyEntry>,
): FederationKeyRegistry {
  const entries: ReadonlyArray<{ hubId: string; key: unknown; history: unknown; label: string }> = Array.isArray(input)
    ? (input as ReadonlyArray<FederationKeyEntry>).map((e, i) => ({
        hubId: typeof e?.hubId === 'string' ? e.hubId : '',
        key: e?.publicKey,
        history: e?.history,
        label: `federationKeys[${i}]`,
      }))
    : Object.entries(input as Readonly<Record<string, string>>).map(([hubId, key]) => ({
        hubId,
        key,
        history: undefined,
        label: `federationKeys[${JSON.stringify(hubId)}]`,
      }));
  const byHub = new Map<string, { pins: { spki: string; label: string }[]; histories: { doc: FederationKeyHistoryDocument; label: string }[] }>();
  for (const { hubId, key, history, label } of entries) {
    if (hubId.length === 0) throw new TypeError(`${label} names no hubId.`);
    const spki = typeof key === 'string' ? normalizeFederationKey(key) : null;
    if (spki === null) {
      throw new TypeError(`${label} is not an Ed25519 public key (base64 SPKI DER, or base64 of the raw 32 bytes).`);
    }
    const hub = byHub.get(hubId) ?? { pins: [], histories: [] };
    hub.pins.push({ spki, label });
    if (history !== undefined) hub.histories.push({ doc: history as FederationKeyHistoryDocument, label: `${label}.history` });
    byHub.set(hubId, hub);
  }
  const out = new Map<string, ReadonlyArray<FederationTrustedKey>>();
  for (const [hubId, { pins, histories }] of byHub) {
    if (histories.length === 0) {
      out.set(hubId, [...new Set(pins.map((p) => p.spki))].map((publicKey) => ({ publicKey, activatedAt: null, retiredAt: null })));
    } else {
      out.set(hubId, trustedKeysFromHistory(hubId, pins, histories));
    }
  }
  return out;
}

/**
 * RFC 8785 (JCS) canonical JSON, as the Server's `canonicalize` writes it:
 * object keys sorted by code unit, no whitespace, `undefined` members dropped
 * (an array element that is `undefined` serializes as `null`), `-0` as `0`,
 * non-finite numbers as `null`. Numbers take JavaScript's own shortest form,
 * which is what RFC 8785 specifies.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return 'null';
    if (Object.is(value, -0)) return '0';
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalizeJson).join(',') + ']';
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalizeJson(obj[k])).join(',') + '}';
  }
  return 'null';
}

/** The sign-input the Server builds, a colon-joined line under the scheme. */
export function federationSignInput(wire: FederationWire): string {
  return `${wire.scheme}:${wire.recipientHubId}:${wire.method}:${wire.path}:${wire.bodyHash}:${wire.timestamp}:${wire.nonce}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * The `wire` a row payload carries, or null when it carries none. A `wire`
 * that is present but is not an object is returned as `malformed`, so the
 * caller fails it rather than reading an edited row as one with no message.
 */
export function extractFederationWire(payload: Record<string, unknown>): FederationWire | 'malformed' | null {
  if (!('wire' in payload) || payload.wire === undefined) return null;
  const w = payload.wire;
  if (!isRecord(w)) return 'malformed';
  for (const k of ['scheme', 'senderHubId', 'senderPublicKey', 'recipientHubId', 'method', 'path', 'bodyHash', 'timestamp', 'nonce', 'signature'] as const) {
    if (typeof w[k] !== 'string') return 'malformed';
  }
  if (!isRecord(w.body)) return 'malformed';
  return w as unknown as FederationWire;
}

export type FederationWireOutcome =
  /**
   * The hash, the entry's fields and, under a supplied key, the signature all
   * hold. `afterRetirement`: the key the message is sealed under was retired,
   * by a succession it signed, before the receiver wrote the entry. The
   * receiver accepts the old key until it revokes the peer, so a publisher
   * process not yet restarted onto the new key sends exactly this; it is in
   * order when the receiver's `federation.peer_revoked` audit row for the
   * publisher comes after the entry.
   */
  | { outcome: 'ok'; signatureChecked: boolean; afterRetirement: boolean }
  /** No key was supplied for `senderHubId`; the hash and the entry's fields hold, the signature was not checked. */
  | { outcome: 'unchecked' }
  | { outcome: 'invalid'; detail: string }
  /** A key was supplied but this host cannot compute Ed25519. */
  | { outcome: 'unsupported'; detail: string };

/**
 * Which entry payload fields must equal which body fields, per entry type.
 * The receiver projects these from the message, so a disagreement means the
 * entry says something the sender did not sign.
 */
const FIELD_PAIRS: Readonly<Record<string, ReadonlyArray<readonly [string, string]>>> = {
  FEDERATION_STATE_SYNC: [
    ['state', 'state'],
    ['recordType', 'type'],
    ['disputeId', 'disputeId'],
    ['action', 'action'],
  ],
  FEDERATION_SIGNAL_RECEIVED: [['recommendation', 'recommendation']],
  FEDERATION_CO_SIGN_RESPONDED: [
    ['recommendation', 'recommendation'],
    ['state', 'state'],
    ['outcomeHash', 'outcomeHash'],
    ['idempotencyKey', 'idempotencyKey'],
  ],
};

/**
 * Check one sealed message against the entry that carries it, and under the
 * sender's key when `keys` has one for `wire.senderHubId`.
 *
 * Runs on an entry that already passed every other check, so `payload` is
 * what the receiver signed. `recordId` is the entry's record; the body names
 * the same record on every message type that carries one. `receivedAt` is the
 * entry's `createdAt` on the receiver's chain, which places the message in a
 * key's window when the sender's keys came with a history.
 */
export function checkFederationWire(
  entryType: string,
  recordId: string | null,
  payload: Record<string, unknown>,
  wire: FederationWire,
  keys: FederationKeyRegistry | undefined,
  receivedAt?: string | null,
): FederationWireOutcome {
  if (wire.scheme !== FEDERATION_WIRE_SCHEME) {
    return { outcome: 'invalid', detail: `Sealed message scheme is ${JSON.stringify(wire.scheme)}, not ${FEDERATION_WIRE_SCHEME}.` };
  }
  const bodyHash = createHash('sha256').update(canonicalizeJson(wire.body), 'utf8').digest('hex');
  if (bodyHash !== wire.bodyHash.toLowerCase()) {
    return { outcome: 'invalid', detail: 'Sealed body does not hash to the bodyHash the sender signed: the body copy was edited after the message was verified.' };
  }
  if (typeof payload.peerHubId === 'string' && payload.peerHubId !== wire.senderHubId) {
    return { outcome: 'invalid', detail: `Entry names peer ${payload.peerHubId}, the sealed message was sent by ${wire.senderHubId}.` };
  }
  const bodyRecordId = wire.body.recordId;
  if (recordId !== null && typeof bodyRecordId === 'string' && bodyRecordId !== recordId) {
    return { outcome: 'invalid', detail: `Entry is on record ${recordId}, the sealed message names record ${bodyRecordId}.` };
  }
  for (const [entryField, bodyField] of FIELD_PAIRS[entryType] ?? []) {
    const mine = payload[entryField];
    const theirs = wire.body[bodyField];
    if (mine === undefined || theirs === undefined || mine === null || theirs === null) continue;
    if (canonicalizeJson(mine) !== canonicalizeJson(theirs)) {
      return {
        outcome: 'invalid',
        detail: `Entry ${entryField} is ${canonicalizeJson(mine)}, the sealed message's ${bodyField} is ${canonicalizeJson(theirs)}: the entry asserts what the sender did not sign.`,
      };
    }
  }

  const trusted = keys?.get(wire.senderHubId);
  if (trusted === undefined) return { outcome: 'unchecked' };
  const sealed = normalizeFederationKey(wire.senderPublicKey);
  const key = trusted.find((k) => k.publicKey === sealed);
  if (key === undefined) {
    const withHistory = trusted.some((k) => k.activatedAt !== null || k.retiredAt !== null);
    return {
      outcome: 'invalid',
      detail: withHistory
        ? `The sealed senderPublicKey for ${wire.senderHubId} is not a federation key its history links to the key you pinned: the receiver verified this message under a key no succession from your pin reaches. A key listed linked: false sits behind a genesis that named it without its signature; pin it too once its operator confirms it.`
        : `The sealed senderPublicKey for ${wire.senderHubId} is not the federation key supplied for that hub: the receiver verified this message under a key the sender's operator did not give you. If the sender changed its federation key, supply its key history (GET /.well-known/agledger-federation-keys.json on the sender) with the key you pinned.`,
    };
  }
  let afterRetirement = false;
  if (key.activatedAt !== null || key.retiredAt !== null) {
    const at = typeof receivedAt === 'string' ? rfc3339Ms(receivedAt) : Number.NaN;
    if (Number.isNaN(at)) {
      return { outcome: 'invalid', detail: `Entry has no parseable createdAt, so the sealed message from ${wire.senderHubId} cannot be placed in its key's window.` };
    }
    if (key.activatedAt !== null && at < rfc3339Ms(key.activatedAt)) {
      return {
        outcome: 'invalid',
        detail: `Entry written ${receivedAt} seals a message from ${wire.senderHubId} under a federation key its history activates at ${key.activatedAt}, after the receiver says it took the message.`,
      };
    }
    afterRetirement = key.retiredAt !== null && at > rfc3339Ms(key.retiredAt);
  }
  const ed25519 = algorithmByName('Ed25519');
  if (ed25519 === null || !runtimeCanCompute(ed25519)) {
    return { outcome: 'unsupported', detail: `Sealed message from ${wire.senderHubId} could not be checked: this host cannot compute Ed25519 (an active OpenSSL FIPS provider carries no EdDSA). Not verified, and not tamper evidence.` };
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(wire.signature, 'hex');
  } catch {
    signature = Buffer.alloc(0);
  }
  if (signature.length !== 64 || !/^[0-9a-f]{128}$/i.test(wire.signature)) {
    return { outcome: 'invalid', detail: `Sealed signature from ${wire.senderHubId} is not 64 bytes of hex.` };
  }
  const ok = verifyEd25519Bytes(key.publicKey, Buffer.from(federationSignInput(wire), 'utf8'), signature);
  if (!ok) {
    return { outcome: 'invalid', detail: `Sealed signature from ${wire.senderHubId} does not verify under that hub's federation key over the sign-input the entry seals.` };
  }
  return { outcome: 'ok', signatureChecked: true, afterRetirement };
}
