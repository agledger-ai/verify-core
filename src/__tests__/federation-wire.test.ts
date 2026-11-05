/**
 * The sealed federation message on a receiving Server's chain entry
 * (`payload.wire`): its body hash and its agreement with the entry on every
 * sealed message, and its signature under the sender's federation key when
 * one is supplied. A wire is sealed here the way the Server seals it, from a
 * test sender key the walk under test never saw.
 */
import { createHash, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import { verifyAuditExport, type RecordAuditExportInput } from '../audit-export.js';
import {
  buildFederationKeyRegistry,
  canonicalizeJson,
  type FederationKeyHistoryDocument,
  federationSignInput,
  normalizeFederationKey,
  type FederationWire,
} from '../federation-wire.js';
import { buildPredicateForRow } from '../primitives.js';
import { load } from './export-fixtures.js';
import { makeKey, type TestKey } from './key-statements-helpers.js';

const SENDER_HUB = 'hub-sender';
const RECIPIENT_HUB = 'hub-receiver';

/** A message sealed the way the Server's peer-auth hook seals it. */
function sealed(sender: TestKey, body: Record<string, unknown>, over: Partial<FederationWire> = {}): FederationWire {
  const bodyHash = createHash('sha256').update(canonicalizeJson(body), 'utf8').digest('hex');
  const wire: FederationWire = {
    scheme: 'agledger.federation.v2',
    senderHubId: SENDER_HUB,
    senderPublicKey: sender.publicKey,
    recipientHubId: RECIPIENT_HUB,
    method: 'POST',
    path: '/federation/v1/state-transition',
    bodyHash,
    timestamp: '2026-10-22T18:00:00.000Z',
    nonce: 'a1b2c3d4e5f60718a1b2c3d4e5f60718',
    signature: '',
    body,
    ...over,
  };
  const priv = { key: Buffer.from(sender.privateKey, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
  wire.signature = sign(null, Buffer.from(federationSignInput(wire), 'utf8'), priv).toString('hex');
  return { ...wire, ...over };
}

/**
 * valid.json with entry `at` rewritten as a FEDERATION_STATE_SYNC that seals
 * `wire` (its predicate rebuilt from the new row, extension fields kept), then
 * every entry re-signed under `vault` and the chain relinked. What a
 * receiving Server's export looks like, under a key this test holds.
 */
function exportWithWire(vault: TestKey, at: number, payload: Record<string, unknown>, createdAt?: string): RecordAuditExportInput {
  const exp = load('valid.json');
  if (createdAt !== undefined) exp.entries[at]!.createdAt = createdAt;
  const priv = { key: Buffer.from(vault.privateKey, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
  let prev: Buffer | null = null;
  exp.entries.forEach((e, i) => {
    const [prot0, , payload0] = cborDecode(Buffer.from(e.integrity.coseSign1, 'base64').subarray(1), { useMaps: true }) as [Uint8Array, unknown, Uint8Array];
    let payloadBstr = payload0;
    if (i === at) {
      const stmt = cborDecode(payload0, { useMaps: false }) as Record<string, unknown>;
      const signed = stmt['predicate'] as Record<string, unknown>;
      const rebuilt = buildPredicateForRow(e.recordId ?? null, 'FEDERATION_STATE_SYNC', payload)!;
      for (const k of ['on_behalf_of', 'traceparent']) if (k in signed) rebuilt[k] = signed[k];
      stmt['predicate'] = rebuilt;
      payloadBstr = cborEncode(stmt, rfc8949EncodeOptions);
      e.entryType = 'FEDERATION_STATE_SYNC';
      e.payload = payload;
    }
    const header = cborDecode(prot0, { useMaps: true }) as Map<number, unknown>;
    header.set(4, Uint8Array.from(Buffer.from(vault.kid, 'hex')));
    (header.get(-65537) as Map<number, unknown>).set(2, prev === null ? null : Uint8Array.from(prev));
    const prot = cborEncode(header, rfc8949EncodeOptions);
    const sig = sign(null, cborEncode(['Signature1', prot, new Uint8Array(0), payloadBstr], rfc8949EncodeOptions), priv);
    const envelope = Buffer.concat([Buffer.from([0xd2]), Buffer.from(cborEncode([prot, new Map(), payloadBstr, Uint8Array.from(sig)], rfc8949EncodeOptions))]);
    const hash = createHash('sha256').update(envelope).digest();
    e.integrity.coseSign1 = envelope.toString('base64');
    e.integrity.payloadHash = hash.toString('hex');
    e.integrity.previousHash = prev === null ? null : prev.toString('hex');
    e.integrity.signingKeyId = vault.kid;
    prev = hash;
  });
  const m = exp.exportMetadata;
  m.signingPublicKeys = { [vault.kid]: vault.publicKey };
  m.signingKeyWindows = { [vault.kid]: { activatedAt: '2026-09-01T00:00:00.000Z', retiredAt: null } };
  delete m.signingKeyStatements;
  delete m.anchoredFrom;
  return exp;
}

const vault = makeKey();
const sender = makeKey();
const stranger = makeKey();
const AT = 1;
const recordId = load('valid.json').entries[AT]!.recordId!;
const body = {
  recordId,
  state: 'FULFILLED',
  type: 'principal-gate-generic-v1',
  idempotencyKey: '0199a8f0-0000-7000-8000-00000000c0de',
  schemaRef: { type: 'principal-gate-generic-v1', manifestDigest: 'sha256:' + 'ab'.repeat(32) },
  principalAgentId: '0199a8f0-0000-7000-8000-000000000001',
  performerAgentId: '0199a8f0-0000-7000-8000-000000000002',
};
const projection = (wire: FederationWire, over: Record<string, unknown> = {}) => ({
  peerHubId: SENDER_HUB,
  recordType: 'principal-gate-generic-v1',
  state: 'FULFILLED',
  principalAgentId: body.principalAgentId,
  performerAgentId: body.performerAgentId,
  schemaRef: body.schemaRef,
  outcome: 'inserted',
  wire,
  ...over,
});
/** The raw 32 bytes of an SPKI DER Ed25519 key, base64: the other form the peer table holds. */
const raw32 = (spki: string) => Buffer.from(spki, 'base64').subarray(12).toString('base64');

describe('a sealed federation message on a receiver\'s chain', () => {
  it('is held to its body hash and its entry without any key, and counted as present, not verified', () => {
    const exp = exportWithWire(vault, AT, projection(sealed(sender, body)));
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(true);
    expect(r.optionalChecks.federation_wire).toBe('applied');
    expect(r.federationWire).toEqual({ present: 1, verified: 0, failed: 0, afterRetirement: 0 });
  });

  it('is verified under the sender\'s federation key, given as SPKI DER or as the raw 32 bytes', () => {
    const exp = exportWithWire(vault, AT, projection(sealed(sender, body)));
    for (const key of [sender.publicKey, raw32(sender.publicKey)]) {
      const r = verifyAuditExport(exp, { federationKeys: { [SENDER_HUB]: key } });
      expect(r.valid).toBe(true);
      expect(r.federationWire).toEqual({ present: 1, verified: 1, failed: 0, afterRetirement: 0 });
    }
    const listed = verifyAuditExport(exp, { federationKeys: [{ hubId: SENDER_HUB, publicKey: sender.publicKey }] });
    expect(listed.federationWire).toEqual({ present: 1, verified: 1, failed: 0, afterRetirement: 0 });
  });

  it('a key for another hub checks nothing here', () => {
    const exp = exportWithWire(vault, AT, projection(sealed(sender, body)));
    const r = verifyAuditExport(exp, { federationKeys: { 'hub-other': stranger.publicKey } });
    expect(r.valid).toBe(true);
    expect(r.federationWire).toEqual({ present: 1, verified: 0, failed: 0, afterRetirement: 0 });
  });

  it('fails when the sealed sender key is not the key the sender\'s operator supplied', () => {
    // The receiver accepted the message under some key; the auditor holds the
    // sender's real one. A receiver that registered a key of its own choosing
    // could seal messages it wrote itself.
    const exp = exportWithWire(vault, AT, projection(sealed(sender, body)));
    const r = verifyAuditExport(exp, { federationKeys: { [SENDER_HUB]: stranger.publicKey } });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: AT + 1, code: 'CHAIN_FEDERATION_WIRE_INVALID' });
    expect(r.brokenAt?.detail).toContain('not the federation key supplied');
    expect(r.federationWire).toEqual({ present: 1, verified: 0, failed: 1, afterRetirement: 0 });
  });

  it('fails when the signature does not verify under the supplied key', () => {
    // Sealed under the sender's key id but signed by someone else: the
    // receiver is asserting a message the sender never signed.
    const forged = sealed(stranger, body, { senderPublicKey: sender.publicKey });
    const exp = exportWithWire(vault, AT, projection(forged));
    expect(verifyAuditExport(exp).valid).toBe(true);
    const r = verifyAuditExport(exp, { federationKeys: { [SENDER_HUB]: sender.publicKey } });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: AT + 1, code: 'CHAIN_FEDERATION_WIRE_INVALID' });
    expect(r.brokenAt?.detail).toContain('does not verify');
    expect(r.federationWire).toEqual({ present: 1, verified: 0, failed: 1, afterRetirement: 0 });
  });

  it('fails when the sealed body no longer hashes to what was signed, with or without a key', () => {
    const wire = sealed(sender, body);
    const edited = { ...wire, body: { ...body, state: 'CANCELLED' } };
    const exp = exportWithWire(vault, AT, projection(edited, { state: 'CANCELLED' }));
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: AT + 1, code: 'CHAIN_FEDERATION_WIRE_INVALID' });
    expect(r.brokenAt?.detail).toContain('does not hash');
    expect(r.federationWire).toEqual({ present: 1, verified: 0, failed: 1, afterRetirement: 0 });
  });

  it('fails when the entry asserts a state the sealed body does not carry', () => {
    const exp = exportWithWire(vault, AT, projection(sealed(sender, body), { state: 'CANCELLED' }));
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.code).toBe('CHAIN_FEDERATION_WIRE_INVALID');
    expect(r.brokenAt?.detail).toContain('Entry state is "CANCELLED"');
  });

  it('fails when the entry names a peer other than the sealed sender', () => {
    const exp = exportWithWire(vault, AT, projection(sealed(sender, body), { peerHubId: 'hub-other' }));
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.detail).toContain('names peer hub-other');
  });

  it('fails a wire that is not a sealed message at all', () => {
    const exp = exportWithWire(vault, AT, projection(sealed(sender, body), { wire: 'yes' }));
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.code).toBe('CHAIN_FEDERATION_WIRE_INVALID');
  });

  it('an export with no sealed message reports the check as not applicable', () => {
    const r = verifyAuditExport(load('valid.json'));
    expect(r.valid).toBe(true);
    expect(r.optionalChecks.federation_wire).toBe('skipped_no_input');
    expect(r.federationWire).toEqual({ present: 0, verified: 0, failed: 0, afterRetirement: 0 });
  });

  it('refuses a federation key that is not an Ed25519 key before verifying anything', () => {
    expect(() => buildFederationKeyRegistry({ [SENDER_HUB]: 'not a key' })).toThrow(TypeError);
    expect(() => buildFederationKeyRegistry({ [SENDER_HUB]: makeKey('ES256').publicKey })).toThrow(/not an Ed25519 public key/);
    expect(() => buildFederationKeyRegistry([{ hubId: '', publicKey: sender.publicKey }])).toThrow(/names no hubId/);
    expect(() => verifyAuditExport(load('valid.json'), { federationKeys: { [SENDER_HUB]: 'nope' } })).toThrow(TypeError);
  });
});

describe('normalizeFederationKey', () => {
  it('maps the raw 32 bytes onto the SPKI DER form and keeps SPKI DER as it is', () => {
    expect(normalizeFederationKey(raw32(sender.publicKey))).toBe(sender.publicKey);
    expect(normalizeFederationKey(sender.publicKey)).toBe(sender.publicKey);
    expect(normalizeFederationKey(makeKey('ES256').publicKey)).toBeNull();
    expect(normalizeFederationKey('')).toBeNull();
  });
});

describe('canonicalizeJson', () => {
  it('produces the RFC 8785 test vector', () => {
    // RFC 8785 section 3.3's sample, as JSON.parse reads it.
    const input = JSON.parse('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\u002f","literals":[null,true,false]}');
    expect(canonicalizeJson(input)).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  it('drops undefined members, writes -0 as 0 and sorts keys by code unit', () => {
    expect(canonicalizeJson({ b: 1, a: undefined, c: -0, 'Z': [undefined, NaN] })).toBe('{"Z":[null,null],"b":1,"c":0}');
  });
});


/**
 * Key histories served by a real Server (`GET /.well-known/agledger-federation-keys.json`)
 * booted on K1, then K2 with K1 as AGLEDGER_FEDERATION_SIGNING_KEY_PREVIOUS,
 * then K3 with K2 (`succession.json`), then K4 naming K3 only by
 * AGLEDGER_FEDERATION_SIGNING_KEY_PREVIOUS_SPKI_SHA256 (`genesis-by-digest.json`).
 * `keys.json` holds the four test keys, so a message can be sealed under each.
 *
 * Windows in succession.json: K1 from the start to 04:22:03.323630Z, K2 to
 * 04:22:09.386169Z, K3 after.
 */
describe('a sealed federation message under a key the sender has since changed', () => {
  const dir = new URL('./fixtures/federation-key-history/', import.meta.url);
  const read = <T>(name: string): T => JSON.parse(readFileSync(new URL(name, dir), 'utf8')) as T;
  const fedKeys = read<Record<string, { privateKey: string; publicKey: string }> & { instanceId: string }>('keys.json');
  const hub = fedKeys.instanceId;
  const k = (name: 'K1' | 'K2' | 'K3' | 'K4'): TestKey => ({ ...(fedKeys[name] as { privateKey: string; publicKey: string }), kid: '' }) as TestKey;
  const succession = read<FederationKeyHistoryDocument>('succession.json');
  const byDigest = read<FederationKeyHistoryDocument>('genesis-by-digest.json');

  const exportUnder = (key: TestKey, receivedAt: string) => {
    const wire = sealed(key, body, { senderHubId: hub });
    // `sealed` signs before the override lands; re-sign over the real sender hub.
    const priv = { key: Buffer.from(key.privateKey, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
    wire.signature = sign(null, Buffer.from(federationSignInput(wire), 'utf8'), priv).toString('hex');
    return exportWithWire(vault, AT, projection(wire, { peerHubId: hub }), receivedAt);
  };

  it('verifies an entry sealed under an earlier key, linked to the key you pinned by successions', () => {
    const r = verifyAuditExport(exportUnder(k('K1'), '2026-11-05T04:22:02.000Z'), {
      federationKeys: [{ hubId: hub, publicKey: k('K3').publicKey, history: succession }],
    });
    expect(r.valid).toBe(true);
    expect(r.federationWire).toEqual({ present: 1, verified: 1, failed: 0, afterRetirement: 0 });
  });

  it('walks forward too: a pin on the oldest key trusts the keys it handed over to', () => {
    const r = verifyAuditExport(exportUnder(k('K3'), '2026-11-05T04:22:10.000Z'), {
      federationKeys: [{ hubId: hub, publicKey: k('K1').publicKey, history: succession }],
    });
    expect(r.valid).toBe(true);
    expect(r.federationWire.verified).toBe(1);
  });

  it('without the history, the earlier key is not the key you pinned, and the failure says what to supply', () => {
    const r = verifyAuditExport(exportUnder(k('K1'), '2026-11-05T04:22:02.000Z'), { federationKeys: { [hub]: k('K3').publicKey } });
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.code).toBe('CHAIN_FEDERATION_WIRE_INVALID');
    expect(r.brokenAt?.detail).toMatch(/agledger-federation-keys\.json/);
  });

  it('fails a message the receiver took before its key was activated', () => {
    const r = verifyAuditExport(exportUnder(k('K2'), '2026-11-05T04:22:01.000Z'), {
      federationKeys: [{ hubId: hub, publicKey: k('K3').publicKey, history: succession }],
    });
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.detail).toMatch(/activates at 2026-11-05T04:22:03\.323630Z/);
  });

  it('verifies but counts a message the receiver took after its key was retired', () => {
    const r = verifyAuditExport(exportUnder(k('K1'), '2026-11-05T04:22:05.000Z'), {
      federationKeys: [{ hubId: hub, publicKey: k('K3').publicKey, history: succession }],
    });
    expect(r.valid).toBe(true);
    expect(r.federationWire).toEqual({ present: 1, verified: 1, failed: 0, afterRetirement: 1 });
  });

  it('reads windows from the signed statements, never from the unsigned keys summary', () => {
    const doctored = structuredClone(succession) as FederationKeyHistoryDocument & { keys: Array<{ activatedAt: string | null }> };
    for (const key of doctored.keys) key.activatedAt = null;
    const r = verifyAuditExport(exportUnder(k('K2'), '2026-11-05T04:22:01.000Z'), {
      federationKeys: [{ hubId: hub, publicKey: k('K3').publicKey, history: doctored }],
    });
    expect(r.valid).toBe(false);
  });

  it('a genesis naming its predecessor by digest links nothing; pin the older key too to trust it', () => {
    const k3msg = exportUnder(k('K3'), '2026-11-05T04:22:10.000Z');
    const onlyNew = verifyAuditExport(k3msg, { federationKeys: [{ hubId: hub, publicKey: k('K4').publicKey, history: byDigest }] });
    expect(onlyNew.valid).toBe(false);
    expect(onlyNew.brokenAt?.detail).toMatch(/linked: false/);
    const both = [
      { hubId: hub, publicKey: k('K4').publicKey, history: byDigest },
      { hubId: hub, publicKey: k('K3').publicKey },
    ];
    expect(verifyAuditExport(k3msg, { federationKeys: both }).valid).toBe(true);
    // K1 sits behind K3 by successions both keys signed.
    expect(verifyAuditExport(exportUnder(k('K1'), '2026-11-05T04:22:02.000Z'), { federationKeys: both }).valid).toBe(true);
  });

  it('refuses, before verifying anything, a history that was altered, is another hub\'s, or never reaches the pin', () => {
    const altered = structuredClone(succession);
    const stmt = altered.statements[1]!;
    (altered.statements as Array<typeof stmt>)[1] = { ...stmt, payload: stmt.payload.replace('04:22:03', '04:21:03') };
    expect(() => buildFederationKeyRegistry([{ hubId: hub, publicKey: k('K3').publicKey, history: altered }])).toThrow(/does not hold/);
    expect(() => buildFederationKeyRegistry([{ hubId: 'another-hub', publicKey: k('K3').publicKey, history: succession }])).toThrow(/key history of hub/);
    expect(() => buildFederationKeyRegistry([{ hubId: hub, publicKey: stranger.publicKey, history: succession }])).toThrow(/appears in none of the key histories/);
  });
});
