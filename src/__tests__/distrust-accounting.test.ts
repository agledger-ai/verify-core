import { createHash, sign } from 'node:crypto';
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import { describe, expect, it } from 'vitest';
import { buildKeyRegistry, chainOfScope, verifyChain, type NormalizedEntry } from '../chain.js';
import { applyKeyTrust, computeKeyTrust, reportKeyTrust, type DistrustedKey, type KeyStatementInput } from '../key-statements.js';
import { load } from './export-fixtures.js';
import { T0, makeKey, row, statement, type TestKey } from './key-statements-helpers.js';

/**
 * Entries of a dump a distrusted key signed, outside what it is trusted for
 * and before a key the walk trusts retired it: accounted for, listed as
 * CHAIN_SIGNED_BY_DISTRUSTED_KEY, never a failure. The engine's scan lists
 * the same entries as `distrustedEntries`.
 */

const at = (m: number) => `2026-09-02T00:${String(m).padStart(2, '0')}:00.000000Z`;
const written = (m: number, s = 30) => `2026-09-02T00:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}.000Z`;

/** valid.json's three entries, each signed under the key given for it and written at the time given. */
function chain(signers: Array<{ key: TestKey; createdAt: string; corrupt?: boolean }>, scopeId = '7b1c0f6e-0000-4000-8000-000000000001'): NormalizedEntry[] {
  const exp = load('valid.json');
  let prev: Buffer | null = null;
  return exp.entries.slice(0, signers.length).map((e, i) => {
    const { key, createdAt, corrupt } = signers[i]!;
    const priv = { key: Buffer.from(key.privateKey, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
    const [prot0, , payload] = cborDecode(Buffer.from(e.integrity.coseSign1, 'base64').subarray(1), { useMaps: true }) as [Uint8Array, unknown, Uint8Array];
    const header = cborDecode(prot0, { useMaps: true }) as Map<number, unknown>;
    header.set(4, Uint8Array.from(Buffer.from(key.kid, 'hex')));
    (header.get(-65537) as Map<number, unknown>).set(2, prev === null ? null : Uint8Array.from(prev));
    const prot = cborEncode(header, rfc8949EncodeOptions);
    const sig = sign(null, cborEncode(['Signature1', prot, new Uint8Array(0), payload], rfc8949EncodeOptions), priv);
    if (corrupt) sig[0]! ^= 0xff;
    const envelope = Buffer.concat([Buffer.from([0xd2]), Buffer.from(cborEncode([prot, new Map(), payload, Uint8Array.from(sig)], rfc8949EncodeOptions))]);
    const hash = createHash('sha256').update(envelope).digest();
    const entry: NormalizedEntry = {
      scopeId,
      chainPosition: i + 1,
      payloadHash: hash.toString('hex'),
      previousHash: prev === null ? null : prev.toString('hex'),
      coseSign1: envelope.toString('base64'),
      signingKeyId: key.kid,
      createdAt,
    };
    prev = hash;
    return entry;
  });
}

function registry(keys: TestKey[], statements: KeyStatementInput[], anchors: TestKey[], distrustedKeys: DistrustedKey[], rows = keys.map((k) => row(k, T0))) {
  const trust = computeKeyTrust({ keys: rows, statements, trustAnchors: anchors.map((k) => `sha256:${k.digest}`), distrustedKeys });
  const reg = applyKeyTrust(buildKeyRegistry(keys.map((k) => ({ keyId: k.kid, spkiBase64: k.publicKey, source: 'embedded' as const, activatedAt: T0, retiredAt: null }))), trust);
  return { trust, reg };
}

describe('a dump entry signed by a distrusted key', () => {
  // P leaked; the attacker staged S from it and force-retired P from S. The
  // operator's N runs under a fresh genesis with P pinned, retires P with
  // force, distrusts S from its closure, and retires S with force at 00:05.
  const p = makeKey();
  const s = makeKey();
  const n = makeKey();
  const base = [
    statement('genesis', p, { signers: [p], activatedAt: T0, createdAt: T0 }),
    statement('succession', s, { endorser: p, signers: [p, s], activatedAt: at(1), createdAt: at(1) }),
    statement('closure', p, { endorser: s, signers: [s], retiredAt: at(2), forced: true, createdAt: at(2) }),
    statement('genesis', n, { signers: [n], activatedAt: at(3), createdAt: at(3) }),
    statement('closure', p, { endorser: n, signers: [n], retiredAt: at(2), forced: true, createdAt: at(4) }),
  ];
  const retireS = statement('closure', s, { endorser: n, signers: [n], retiredAt: at(5), forced: true, createdAt: at(5) });
  const distrusted = [{ spkiSha256: s.digest, cutoff: at(2) }];
  const rows = [row(p, T0, at(2)), row(s, at(1), at(5)), row(n, at(3))];

  it('before a trusted key retired it is accounted for and listed, and the chain passes', () => {
    const { trust, reg } = registry([p, s, n], [...base, retireS], [p, n], distrusted, rows);
    expect(trust.findings).toEqual([]);
    expect(reg.get(s.kid)).toMatchObject({ trust: 'unanchored', distrustSpan: { cutoff: at(2), retiredAt: at(5) } });
    const r = verifyChain(chain([{ key: s, createdAt: written(2) }, { key: s, createdAt: written(4) }, { key: n, createdAt: written(6) }]), reg);
    expect(r.valid).toBe(true);
    expect(r.verifiedEntries).toBe(1);
    expect(r.signatureCoverage.signed).toBe(1);
    expect(r.entries.map((e) => e.signature)).toEqual(['accounted', 'accounted', 'ok']);
    expect(r.accounted).toEqual([
      expect.objectContaining({ code: 'CHAIN_SIGNED_BY_DISTRUSTED_KEY', chain: 'record', recordId: r.scopeId, orgId: null, position: 1, keyId: s.kid }),
      expect.objectContaining({ code: 'CHAIN_SIGNED_BY_DISTRUSTED_KEY', position: 2, keyId: s.kid }),
    ]);
    expect(reportKeyTrust(reg, trust, null).accounted).toEqual(trust.accounted);
  });

  it('after that retirement, or with a signature that does not verify, fails as before', () => {
    const { reg } = registry([p, s, n], [...base, retireS], [p, n], distrusted, rows);
    const late = verifyChain(chain([{ key: s, createdAt: written(5, 1) }]), reg);
    expect(late.brokenAt?.code).toBe('CHAIN_SIGNING_KEY_UNANCHORED');
    expect(late.accounted).toEqual([]);
    const forged = verifyChain(chain([{ key: s, createdAt: written(2), corrupt: true }]), reg);
    expect(forged.brokenAt?.code).toBe('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('under a distrusted key no trusted key has retired fails as before, and the key is a finding', () => {
    const { trust, reg } = registry([p, s, n], base, [p, n], distrusted, [rows[0]!, row(s, at(1)), rows[2]!]);
    expect(trust.findings.map((f) => [f.code, f.keyId])).toContainEqual(['KEY_CLOSURE_INVALID', s.kid]);
    const r = verifyChain(chain([{ key: s, createdAt: written(2) }]), reg);
    expect(r.brokenAt?.code).toBe('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('is never accounted for on a key document: the same statements from an export leave the key unmarked', () => {
    const doc = [...base, retireS].map(({ source: _s, ...st }) => ({ ...st, source: 'document' as const }));
    const { reg } = registry([p, s, n], doc, [p, n], distrusted, [p, s, n].map((k) => ({ keyId: k.kid, publicKey: k.publicKey })));
    expect(reg.get(s.kid)!.distrustSpan).toBeUndefined();
    expect(verifyChain(chain([{ key: s, createdAt: written(2) }]), reg).brokenAt?.code).toBe('CHAIN_SIGNING_KEY_UNANCHORED');
  });
});

describe('a dump entry signed by a pinned key distrusted from an instant', () => {
  // C is pinned for its history and distrusted from 00:02; the operator's N,
  // pinned too, retires C with force at 00:05.
  const c = makeKey();
  const n = makeKey();
  const statements = [
    statement('genesis', c, { signers: [c], activatedAt: T0, createdAt: T0 }),
    statement('genesis', n, { signers: [n], activatedAt: at(1), createdAt: at(1) }),
    statement('closure', c, { endorser: n, signers: [n], retiredAt: at(5), forced: true, createdAt: at(5) }),
  ];
  const { trust, reg } = registry([c, n], statements, [c, n], [{ spkiSha256: c.digest, cutoff: at(2) }], [row(c, T0, at(5)), row(n, at(1))]);

  it('verifies before the instant, is accounted for from it until the retirement, and fails after', () => {
    expect(trust.findings).toEqual([]);
    expect(reg.get(c.kid)).toMatchObject({ trust: 'anchored', distrustCutoff: at(2), distrustSpan: { cutoff: at(2), retiredAt: at(5) } });
    const r = verifyChain(chain([{ key: c, createdAt: written(1) }, { key: c, createdAt: written(3) }, { key: c, createdAt: written(5, 1) }]), reg);
    expect(r.entries.map((e) => e.signature)).toEqual(['ok', 'accounted', 'not-checked']);
    expect(r.accounted.map((a) => a.position)).toEqual([2]);
    expect(r.brokenAt).toMatchObject({ position: 3, code: 'CHAIN_KEY_EXPIRED' });
    const forged = verifyChain(chain([{ key: c, createdAt: written(1) }, { key: c, createdAt: written(3), corrupt: true }]), reg);
    expect(forged.brokenAt).toMatchObject({ position: 2, code: 'CHAIN_SIGNATURE_INVALID' });
    expect(forged.accounted).toEqual([]);
  });
});

describe('chainOfScope', () => {
  it('names a chain as the engine does', () => {
    expect(chainOfScope('7b1c0f6e-0000-4000-8000-000000000001')).toEqual({ chain: 'record', recordId: '7b1c0f6e-0000-4000-8000-000000000001', orgId: null });
    expect(chainOfScope('00000000-0000-0000-0000-000000000000')).toEqual({ chain: 'admin', recordId: null, orgId: null });
    expect(chainOfScope('schema:4a0e7f00-0000-4000-8000-000000000002')).toEqual({ chain: 'schema', recordId: null, orgId: '4a0e7f00-0000-4000-8000-000000000002' });
    expect(chainOfScope('schema:__platform__')).toEqual({ chain: 'schema', recordId: null, orgId: null });
  });
});
