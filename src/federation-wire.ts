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

/**
 * Sender hub id to the sender's Ed25519 public key, base64 SPKI DER, as
 * `buildFederationKeyRegistry` normalizes it. A key given as the raw 32 bytes
 * (base64) is wrapped in the SPKI header the receiver also accepts.
 */
export type FederationKeyRegistry = ReadonlyMap<string, string>;

/** One sender's federation key, the list shape `buildFederationKeyRegistry` takes. */
export interface FederationKeyEntry {
  hubId: string;
  publicKey: string;
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

/**
 * Build the registry from `{ [hubId]: publicKey }` or `[{ hubId, publicKey }]`.
 * Throws `TypeError` naming the entry on any key that is not an Ed25519 key in
 * one of the two forms, so a mistyped key is refused before any verification
 * runs rather than reported as a signature failure.
 */
export function buildFederationKeyRegistry(
  input: Readonly<Record<string, string>> | ReadonlyArray<FederationKeyEntry>,
): FederationKeyRegistry {
  const out = new Map<string, string>();
  const entries: ReadonlyArray<readonly [string, unknown, string]> = Array.isArray(input)
    ? (input as ReadonlyArray<FederationKeyEntry>).map((e, i) => [
        typeof e?.hubId === 'string' ? e.hubId : '',
        e?.publicKey,
        `federationKeys[${i}]`,
      ] as const)
    : Object.entries(input as Readonly<Record<string, string>>).map(([hubId, key]) => [hubId, key, `federationKeys[${JSON.stringify(hubId)}]`] as const);
  for (const [hubId, key, label] of entries) {
    if (hubId.length === 0) throw new TypeError(`${label} names no hubId.`);
    const spki = typeof key === 'string' ? normalizeFederationKey(key) : null;
    if (spki === null) {
      throw new TypeError(`${label} is not an Ed25519 public key (base64 SPKI DER, or base64 of the raw 32 bytes).`);
    }
    out.set(hubId, spki);
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
  /** The hash, the entry's fields and, under a supplied key, the signature all hold. */
  | { outcome: 'ok'; signatureChecked: boolean }
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
 * the same record on every message type that carries one.
 */
export function checkFederationWire(
  entryType: string,
  recordId: string | null,
  payload: Record<string, unknown>,
  wire: FederationWire,
  keys: FederationKeyRegistry | undefined,
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

  const supplied = keys?.get(wire.senderHubId);
  if (supplied === undefined) return { outcome: 'unchecked' };
  const sealed = normalizeFederationKey(wire.senderPublicKey);
  if (sealed !== supplied) {
    return {
      outcome: 'invalid',
      detail: `The sealed senderPublicKey for ${wire.senderHubId} is not the federation key supplied for that hub: the receiver verified this message under a key the sender's operator did not give you.`,
    };
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
  const ok = verifyEd25519Bytes(supplied, Buffer.from(federationSignInput(wire), 'utf8'), signature);
  if (!ok) {
    return { outcome: 'invalid', detail: `Sealed signature from ${wire.senderHubId} does not verify under that hub's federation key over the sign-input the entry seals.` };
  }
  return { outcome: 'ok', signatureChecked: true };
}
