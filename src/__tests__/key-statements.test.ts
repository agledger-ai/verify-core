import { sign as cryptoSign } from 'node:crypto';
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import { describe, expect, it } from 'vitest';
import { buildKeyRegistry, type KeyRegistry } from '../chain.js';
import {
  applyKeyTrust,
  computeKeyTrust,
  keyStatementsFromVerificationKeys,
  parseDistrustedKeys,
  parseTrustAnchors,
  type DistrustedKey,
  type KeyStatementInput,
  type KeyTrust,
  type TrustKeyInput,
  type VerificationKeysDocument,
} from '../key-statements.js';
import {
  T0, T1, T2, T3,
  asDocument,
  encodePayload,
  makeKey,
  nextId,
  row,
  signStatement,
  statement,
  type Payload,
  type Stored,
  type TestKey,
} from './key-statements-helpers.js';

/**
 * The trust walk, ported case for case from the engine's key-statements.test.ts
 * so the two are held to the same behaviour. Registry findings carry this
 * package's codes: key_statement_invalid is KEY_STATEMENT_INVALID,
 * key_closure_invalid is KEY_CLOSURE_INVALID, key_window_drift is
 * CHAIN_KEY_WINDOW_DRIFT.
 */

function walk(
  keys: TrustKeyInput[],
  statements: KeyStatementInput[],
  anchors: readonly string[],
  distrusted?: DistrustedKey[],
): KeyTrust {
  return computeKeyTrust({
    keys,
    statements,
    trustAnchors: anchors.map((d) => `sha256:${d}`),
    ...(distrusted ? { distrustedKeys: distrusted } : {}),
  });
}

function anchoredKids(trust: KeyTrust): string[] {
  return [...trust.trusted].map((d) => d.slice(0, 16)).sort();
}

const codes = (trust: KeyTrust) => trust.findings.map((f) => [f.code, f.statementId]);

describe('key statement trust walk', () => {
  it('a rolling key change anchors both keys from either side', () => {
    const c = makeKey();
    const n = makeKey();
    const genesis = statement('genesis', c, { signers: [c], activatedAt: T0 });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    for (const anchor of [c, n]) {
      const trust = walk([row(c, T0), row(n, T1)], [genesis, succ], [anchor.digest]);
      expect(anchoredKids(trust)).toEqual([c.kid, n.kid].sort());
      expect(trust.findings).toEqual([]);
      expect(trust.byDigest.get(n.digest)!.activatedAt).toBe(T1);
      expect(trust.byDigest.get(c.digest)!.activatedAt).toBe(T0);
    }
  });

  it('after a routine closure, both pins still reach both keys and the closed key carries the signed window', () => {
    const c = makeKey();
    const n = makeKey();
    const genesis = statement('genesis', c, { signers: [c] });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const closure = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2 });
    for (const anchor of [c, n]) {
      const trust = walk([row(c, T0, T2), row(n, T1)], [genesis, succ, closure], [anchor.digest]);
      expect(anchoredKids(trust)).toEqual([c.kid, n.kid].sort());
      expect(trust.byDigest.get(c.digest)!.retiredAt).toBe(T2);
      expect(trust.findings).toEqual([]);
    }
  });

  it('a planted key with its own genesis stays unanchored and the statement is a finding', () => {
    const c = makeKey();
    const x = makeKey();
    const genesis = statement('genesis', c, { signers: [c] });
    const planted = statement('genesis', x, { signers: [x] });
    const trust = walk([row(c, T0), row(x, T0)], [genesis, planted], [c.digest]);
    expect(anchoredKids(trust)).toEqual([c.kid]);
    expect(codes(trust)).toEqual([['KEY_STATEMENT_INVALID', planted.id]]);
  });

  it('forged successions naming the real endorser stay unanchored and each is a finding', () => {
    const c = makeKey();
    const x = makeKey();
    const genesis = statement('genesis', c, { signers: [c] });
    const selfOnly = statement('succession', x, { endorser: c, signers: [x] });
    const wrongSigner = statement('succession', x, { endorser: c, signers: [x, x] });
    const garbage = statement('succession', x, { endorser: c, signers: [c, x] });
    const first = garbage.cose[0] as Buffer;
    garbage.cose = [Buffer.from(first.map((b, i, a) => (i === a.length - 1 ? b ^ 0xff : b))), garbage.cose[1]!];
    const trust = walk([row(c, T0), row(x, T0)], [genesis, selfOnly, wrongSigner, garbage], [c.digest]);
    expect(anchoredKids(trust)).toEqual([c.kid]);
    expect(trust.findings.filter((f) => f.code === 'KEY_STATEMENT_INVALID').map((f) => f.statementId).sort())
      .toEqual([selfOnly.id, wrongSigner.id, garbage.id].sort());
  });

  it('a column that differs from the signed value is drift, compared at millisecond precision', () => {
    const k = makeKey();
    const r = makeKey();
    const genesis = statement('genesis', r, { signers: [r], activatedAt: '2026-09-01T00:00:00.123456Z', createdAt: T0 });
    const succ = statement('succession', k, { endorser: r, signers: [r, k], activatedAt: T1, createdAt: T1 });
    const close = statement('closure', r, { endorser: k, signers: [k], retiredAt: T2, createdAt: T2 });
    // The honest dump column is the signed instant truncated to the millisecond.
    const honest = walk([row(k, T1), row(r, '2026-09-01T00:00:00.123456Z', T2)], [genesis, succ, close], [k.digest]);
    expect(honest.findings).toEqual([]);
    const drifted = { ...row(r, T0, T2), activatedAt: '2026-08-01T00:00:00.000Z' };
    const trust = walk([row(k, T1), drifted], [genesis, succ, close], [k.digest]);
    expect(anchoredKids(trust)).toEqual([k.kid, r.kid].sort());
    expect(trust.byDigest.get(r.digest)).toMatchObject({ activatedAt: '2026-09-01T00:00:00.123456Z', retiredAt: T2 });
    expect(trust.findings.map((f) => [f.code, f.keyId])).toEqual([['CHAIN_KEY_WINDOW_DRIFT', r.kid]]);
  });

  it('a statement of a kind outside succession, closure and genesis is a finding and admits nothing', () => {
    const k = makeKey();
    const r = makeKey();
    const genesis = statement('genesis', k, { signers: [k], createdAt: T1 });
    const unknown = statement('adoption', r, { endorser: k, signers: [k], activatedAt: T0, retiredAt: T0, createdAt: T2 });
    const trust = walk([row(r, T0, T0)], [genesis, unknown], [k.digest]);
    expect(anchoredKids(trust)).toEqual([k.kid]);
    expect(trust.findings.map((f) => [f.code, f.statementId, f.detail])).toEqual([
      ['KEY_STATEMENT_INVALID', unknown.id, 'the payload does not decode as a key statement'],
    ]);
  });

  it('a retired anchored row with no signed retirement is KEY_CLOSURE_INVALID', () => {
    const c = makeKey();
    const genesis = statement('genesis', c, { signers: [c] });
    const trust = walk([row(c, T0, T2)], [genesis], [c.digest]);
    expect(trust.findings.map((f) => [f.code, f.keyId])).toEqual([['KEY_CLOSURE_INVALID', c.kid]]);
    expect(trust.byDigest.get(c.digest)!.retiredAt).toBeNull();
  });

  it('a closure by a key nothing anchors closes nothing, and several counting closures end the window at the earliest', () => {
    const c = makeKey();
    const n = makeKey();
    const x = makeKey();
    const genesis = statement('genesis', c, { signers: [c] });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const byStranger = statement('closure', c, { endorser: x, signers: [x], retiredAt: T0, forced: true });
    const later = statement('closure', c, { endorser: n, signers: [n], retiredAt: T3 });
    const earlier = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2 });
    const trust = walk([row(x, T0)], [genesis, succ, byStranger, later, earlier], [c.digest]);
    expect(anchoredKids(trust)).toEqual([c.kid, n.kid].sort());
    expect(trust.byDigest.get(c.digest)!.retiredAt).toBe(T2);
    expect(codes(trust)).toEqual([['KEY_CLOSURE_INVALID', byStranger.id]]);
  });

  it('crosses algorithms: an Ed25519 key hands over to an ES256 key', () => {
    const c = makeKey();
    const n = makeKey('ES256');
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const trust = walk([row(c, T0), row(n, T1)], [succ], [n.digest]);
    expect(anchoredKids(trust)).toEqual([c.kid, n.kid].sort());
  });

  it('a second admission is a finding, dates nothing earlier, and cuts the key\'s edge back', () => {
    const c = makeKey();
    const n = makeKey();
    const genesis = statement('genesis', c, { signers: [c], createdAt: T0 });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1, createdAt: T1 });
    const redate = statement('genesis', n, { signers: [n], activatedAt: T0, createdAt: T2 });
    const fromC = walk([], [genesis, succ, redate], [c.digest]);
    expect(anchoredKids(fromC)).toEqual([c.kid, n.kid].sort());
    expect(fromC.byDigest.get(n.digest)!.activatedAt).toBe(T1);
    expect(codes(fromC)).toEqual([['KEY_STATEMENT_INVALID', redate.id]]);
    expect(anchoredKids(walk([], [genesis, succ, redate], [n.digest]))).toEqual([n.kid]);
  });

  it('a signature under a COSE alg the statement format does not use is refused', () => {
    // The chain envelope accepts -19 for Ed25519; a statement carries -8 only.
    const c = makeKey();
    const g = statement('genesis', c, { signers: [c] });
    const bytes = encodePayload(g.payload);
    const good = signStatement(bytes, c);
    // Re-sign with header alg -19 by hand.
    const header = new Map<number, unknown>([[1, -19], [3, 'application/vnd.agledger.key-statement+cbor'], [4, Uint8Array.from(Buffer.from(c.kid, 'hex'))]]);
    const p = cborEncode(header, rfc8949EncodeOptions);
    const tbs = cborEncode(['Signature1', p, new Uint8Array(0), bytes], rfc8949EncodeOptions);
    const sig = cryptoSign(null, tbs, { key: Buffer.from(c.privateKey, 'base64'), format: 'der', type: 'pkcs8' });
    const bad = Buffer.concat([Buffer.from([0xd2]), Buffer.from(cborEncode([p, new Map(), bytes, sig], rfc8949EncodeOptions))]);
    expect(walk([], [{ ...g, cose: [good] }], [c.digest]).findings).toEqual([]);
    expect(codes(walk([], [{ ...g, cose: [bad] }], [c.digest]))).toEqual([['KEY_STATEMENT_INVALID', g.id]]);
  });
});

describe('each statement check holds on its own', () => {
  // Every statement below is signed for real; each breaks exactly one rule,
  // beside a twin that keeps it and walks clean.
  const genesisPayload = (k: TestKey, over: Partial<Payload['subject']> = {}): Payload => ({
    typ: 'genesis',
    iss: 'https://ledger.example',
    subject: { kid: k.kid, spkiSha256: k.digest, alg: k.alg, spki: k.publicKey, activatedAt: T0, ...over },
    iat: 1,
  });
  const filed = (kind: string, subjectKeyId: string, cose: Buffer[]): KeyStatementInput => ({ id: nextId(), kind, subjectKeyId, cose });
  const refused = (k: TestKey, st: KeyStatementInput) => {
    expect(codes(walk([], [st], [k.digest]))).toEqual([['KEY_STATEMENT_INVALID', st.id]]);
  };
  const clean = (k: TestKey, st: KeyStatementInput) => {
    expect(walk([], [st], [k.digest]).findings).toEqual([]);
  };

  it('the protected header carries the key statement content type', () => {
    const c = makeKey();
    const bytes = encodePayload(genesisPayload(c));
    clean(c, filed('genesis', c.kid, [signStatement(bytes, c)]));
    refused(c, filed('genesis', c.kid, [signStatement(bytes, c, { cty: 'application/cbor' })]));
    refused(c, filed('genesis', c.kid, [signStatement(bytes, c, { cty: 60 })]));
  });

  it('the protected header names the key that signed', () => {
    const c = makeKey();
    const other = makeKey();
    refused(c, filed('genesis', c.kid, [signStatement(encodePayload(genesisPayload(c)), c, { kid: other.kid })]));
  });

  it('the payload is deterministic CBOR: the same map in another key order is refused', () => {
    const c = makeKey();
    const canonical = encodePayload(genesisPayload(c));
    const decoded = cborDecode(canonical, { useMaps: true }) as Map<string, unknown>;
    const reordered = cborEncode(new Map([...decoded].reverse()), { mapSorter: () => 0 });
    expect(Buffer.from(reordered).equals(Buffer.from(canonical))).toBe(false);
    expect(cborDecode(reordered)).toEqual(cborDecode(canonical));
    clean(c, filed('genesis', c.kid, [signStatement(canonical, c)]));
    refused(c, filed('genesis', c.kid, [signStatement(reordered, c)]));
  });

  it('the subject kid is its SPKI fingerprint', () => {
    const c = makeKey();
    const kid = c.kid === 'aaaaaaaaaaaaaaaa' ? 'bbbbbbbbbbbbbbbb' : 'aaaaaaaaaaaaaaaa';
    refused(c, filed('genesis', kid, [signStatement(encodePayload(genesisPayload(c, { kid })), c, { kid })]));
  });

  it('the subject alg names the algorithm its SPKI commits to', () => {
    const c = makeKey();
    refused(c, filed('genesis', c.kid, [signStatement(encodePayload(genesisPayload(c, { alg: 'ES256' })), c)]));
    const e = makeKey('ES256');
    clean(e, filed('genesis', e.kid, [signStatement(encodePayload(genesisPayload(e)), e)]));
    refused(e, filed('genesis', e.kid, [signStatement(encodePayload(genesisPayload(e, { alg: 'Ed25519' })), e)]));
  });

  it('a statement carries exactly the signatures its kind takes', () => {
    const c = makeKey();
    const n = makeKey();
    const bytes = encodePayload(genesisPayload(c));
    refused(c, filed('genesis', c.kid, [signStatement(bytes, c), signStatement(bytes, c)]));
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const extra = { ...succ, cose: [...succ.cose, succ.cose[1]!] };
    expect(walk([], [statement('genesis', c, { signers: [c] }), succ], [c.digest]).findings).toEqual([]);
    expect(codes(walk([], [extra], [c.digest]))).toEqual([['KEY_STATEMENT_INVALID', extra.id]]);
  });

  it('the kind a statement is filed under is the kind it signs', () => {
    const c = makeKey();
    const g = statement('genesis', c, { signers: [c] });
    expect(walk([], [g], [c.digest]).findings).toEqual([]);
    for (const kind of ['succession', 'closure']) {
      expect(codes(walk([], [{ ...g, kind }], [c.digest]))).toEqual([['KEY_STATEMENT_INVALID', g.id]]);
    }
  });

  it('a succession does not endorse its own key, and a closure is not signed by the key it closes', () => {
    const c = makeKey();
    const selfSucc = statement('succession', c, { endorser: c, signers: [c, c], activatedAt: T1 });
    expect(codes(walk([], [selfSucc], [c.digest]))).toEqual([['KEY_STATEMENT_INVALID', selfSucc.id]]);
    const selfClose = statement('closure', c, { endorser: c, signers: [c], retiredAt: T2 });
    const trust = walk([row(c, T0)], [selfClose], [c.digest]);
    expect(codes(trust)).toEqual([['KEY_STATEMENT_INVALID', selfClose.id]]);
    expect(trust.byDigest.get(c.digest)!.retiredAt).toBeNull();
  });
});

describe('a registry row is anchored only under its own fingerprint', () => {
  it('a trusted key\'s SPKI filed under another key id is unanchored', () => {
    const c = makeKey();
    const trust = walk([], [statement('genesis', c, { signers: [c] })], [c.digest]);
    const key = { spkiBase64: c.publicKey, source: 'embedded' as const };
    const other = c.kid === 'ffffffffffffffff' ? 'eeeeeeeeeeeeeeee' : 'ffffffffffffffff';
    expect(applyKeyTrust(buildKeyRegistry([{ keyId: c.kid, ...key }]), trust).get(c.kid)!.trust).toBe('anchored');
    expect(applyKeyTrust(buildKeyRegistry([{ keyId: other, ...key }]), trust).get(other)!.trust).toBe('unanchored');
    // A map key that disagrees with the entry's own keyId binds nothing either.
    const mismatched: KeyRegistry = new Map([[c.kid, { keyId: other, ...key }]]);
    expect(applyKeyTrust(mismatched, trust).get(c.kid)!.trust).toBe('unanchored');
  });
});

describe('a leaked key', () => {
  function history() {
    const c = makeKey();
    const n = makeKey();
    const genesis = statement('genesis', c, { signers: [c], createdAt: T0 });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1, createdAt: T1 });
    return { c, n, genesis, succ };
  }

  it('after a routine retirement cannot admit a key, whatever time it claims, from any pin', () => {
    const { c, n, genesis, succ } = history();
    const x = makeKey();
    const closure = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2, createdAt: T2 });
    const leak = statement('succession', x, { endorser: c, signers: [c, x], activatedAt: T0, iat: Math.floor(Date.parse(T0) / 1000), createdAt: T3 });
    for (const anchor of [c, n]) {
      const trust = walk([], [genesis, succ, closure, leak], [anchor.digest]);
      expect(anchoredKids(trust)).toEqual([c.kid, n.kid].sort());
      expect(codes(trust)).toEqual([['KEY_STATEMENT_INVALID', leak.id]]);
    }
  });

  it('cannot admit a key by signing it in as its own predecessor, retired or not', () => {
    const { c, n, genesis, succ } = history();
    const x = makeKey();
    const closure = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2, createdAt: T2 });
    const back = statement('succession', c, { endorser: x, signers: [x, c], createdAt: T3 });
    for (const statements of [[genesis, succ, back], [genesis, succ, closure, back]]) {
      const trust = walk([row(x, T3)], statements, [n.digest]);
      expect(anchoredKids(trust)).toEqual([c.kid, n.kid].sort());
      expect(codes(trust)).toEqual([['KEY_STATEMENT_INVALID', back.id]]);
    }
  });

  it('before detection admits a key, and a forced retirement voids everything it admitted', () => {
    const { c, n, genesis, succ } = history();
    const x = makeKey();
    const y = makeKey();
    const leak = statement('succession', x, { endorser: c, signers: [c, x], createdAt: T1 });
    const onward = statement('succession', y, { endorser: x, signers: [x, y], createdAt: T2 });
    const before = walk([], [genesis, succ, leak, onward], [n.digest]);
    expect(anchoredKids(before)).toEqual([c.kid, n.kid, x.kid, y.kid].sort());

    const forced = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2, forced: true, createdAt: T3 });
    const after = walk([], [genesis, succ, leak, onward, forced], [n.digest]);
    expect(anchoredKids(after)).toEqual([c.kid, n.kid].sort());
    expect(after.byDigest.get(c.digest)).toMatchObject({ activatedAt: T0, retiredAt: T2 });
    expect(after.findings.filter((f) => f.statementId === leak.id)).toEqual([]);
    expect(anchoredKids(walk([], [genesis, succ, leak, onward, forced], [c.digest]))).toEqual([c.kid]);
  });

  it('anchored with no admission of its own, cannot keep a key it signed in as its predecessor past a forced retirement', () => {
    const p = makeKey();
    const n = makeKey();
    const x = makeKey();
    const succ = statement('succession', n, { endorser: p, signers: [p, n], activatedAt: T1, createdAt: T1 });
    const back = statement('succession', p, { endorser: x, signers: [x, p], activatedAt: T0, createdAt: T2 });
    const forced = statement('closure', p, { endorser: n, signers: [n], retiredAt: T2, forced: true, createdAt: T3 });
    expect(anchoredKids(walk([row(x, T0)], [succ, back], [n.digest]))).toEqual([n.kid, p.kid, x.kid].sort());
    for (const [pin, want] of [[n, [n.kid, p.kid]], [p, [p.kid]]] as const) {
      expect(anchoredKids(walk([row(x, T0)], [succ, back, forced], [pin.digest]))).toEqual([...want].sort());
    }
  });

  it('closes keys only to take trust away: its closures shorten windows and cut edges, never add a key', () => {
    const { c, n, genesis, succ } = history();
    const m = makeKey();
    const x = makeKey();
    const succM = statement('succession', m, { endorser: n, signers: [n, m], activatedAt: T2, createdAt: T2 });
    const closeN = statement('closure', n, { endorser: c, signers: [c], retiredAt: T1, forced: true, createdAt: T3 });
    const leak = statement('succession', x, { endorser: c, signers: [c, x], createdAt: T3 });
    const forced = statement('closure', c, { endorser: m, signers: [m], retiredAt: T3, forced: true, createdAt: T3 });
    const honest = walk([], [genesis, succ, succM, forced], [m.digest]);
    const attacked = walk([], [genesis, succ, succM, closeN, leak, forced], [m.digest]);
    expect(anchoredKids(honest)).toEqual([c.kid, n.kid, m.kid].sort());
    expect(anchoredKids(attacked)).toEqual([n.kid, m.kid].sort());
    expect(attacked.byDigest.get(n.digest)!.retiredAt).toBe(T1);
    expect(anchoredKids(walk([], [genesis, succ, succM, closeN, leak, forced], [n.digest]))).toEqual([n.kid]);
  });

  it('leaked before it was registered, cannot pull a key in through an admission stored ahead of the honest one', () => {
    const h = makeKey();
    const k = makeKey();
    const a = makeKey();
    const genesis = statement('genesis', h, { signers: [h], createdAt: T0 });
    const early = statement('succession', k, { endorser: a, signers: [a, k], activatedAt: '2000-01-01T00:00:00.000000Z', createdAt: T1 });
    const honest = statement('succession', k, { endorser: h, signers: [h, k], activatedAt: T2, createdAt: T2 });
    const forced = statement('closure', k, { endorser: h, signers: [h], retiredAt: T3, forced: true, createdAt: T3 });
    for (const statements of [[genesis, early, honest], [genesis, early, honest, forced]]) {
      for (const pin of [h, k]) {
        const trust = walk([row(a, T0)], statements, [pin.digest]);
        expect(anchoredKids(trust)).not.toContain(a.kid);
        expect(trust.byDigest.get(k.digest)!.activatedAt).toBe(T2);
      }
    }
  });

  it('keeps rows stored in the same millisecond in write order: an edge stored after the closure in one insert is void', () => {
    const { c, n, genesis, succ } = history();
    const x = makeKey();
    const closure = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2, createdAt: T2 });
    const leak = statement('succession', x, { endorser: c, signers: [c, x], createdAt: T2 });
    expect(anchoredKids(walk([], [genesis, succ, closure, leak], [n.digest]))).toEqual([c.kid, n.kid].sort());
  });
});

describe('distrusted keys (the Server\'s VAULT_DISTRUSTED_KEYS)', () => {
  const EPOCH_ZERO = '1970-01-01T00:00:00.000000Z';

  it('retired on schedule and leaked, its closure of the key that retired it counts until it is distrusted', () => {
    const r = makeKey();
    const h = makeKey();
    const h2 = makeKey();
    const statements = [
      statement('genesis', r, { signers: [r], activatedAt: T0, createdAt: T0 }),
      statement('succession', h, { endorser: r, signers: [r, h], activatedAt: T1, createdAt: T1 }),
      statement('closure', r, { endorser: h, signers: [h], retiredAt: T2, createdAt: T2 }),
    ];
    const evil = statement('closure', h, { endorser: r, signers: [r], retiredAt: EPOCH_ZERO, forced: true, createdAt: T3 });
    statements.push(
      evil,
      statement('closure', r, { endorser: h, signers: [h], retiredAt: T2, forced: true, createdAt: T3 }),
      statement('succession', h2, { endorser: h, signers: [h, h2], activatedAt: T3, createdAt: T3 }),
    );
    for (const pin of [h, h2]) {
      const attacked = walk([], statements, [pin.digest]);
      expect(attacked.byDigest.get(h.digest)!.retiredAt).toBe(EPOCH_ZERO);
      expect(attacked.findings).toContainEqual(expect.objectContaining({ code: 'KEY_CLOSURE_INVALID', statementId: evil.id, detail: expect.stringContaining(`distrustedKeys sha256:${r.digest}`) }));
      const healed = walk([], statements, [pin.digest], [{ spkiSha256: r.digest, cutoff: null }]);
      expect(healed.byDigest.get(h.digest)).toMatchObject({ activatedAt: T1, retiredAt: null });
      expect(healed.byDigest.get(r.digest)).toMatchObject({ trusted: true, retiredAt: T2 });
      expect(healed.findings).toContainEqual(expect.objectContaining({ code: 'KEY_CLOSURE_INVALID', statementId: evil.id, detail: expect.stringContaining('distrustedKeys') }));
    }
  });

  it('keeps what it signed before its cutoff: its closure of its predecessor stays in force', () => {
    const p = makeKey();
    const d = makeKey();
    const n = makeKey();
    const x = makeKey();
    const leak = statement('succession', x, { endorser: d, signers: [d, x], activatedAt: T0, createdAt: T3 });
    const trust = walk([], [
      statement('genesis', p, { signers: [p], activatedAt: T0, createdAt: T0 }),
      statement('succession', d, { endorser: p, signers: [p, d], activatedAt: T0, createdAt: T0 }),
      statement('closure', p, { endorser: d, signers: [d], retiredAt: T1, createdAt: T1 }),
      statement('succession', n, { endorser: d, signers: [d, n], activatedAt: T1, createdAt: T1 }),
      statement('closure', d, { endorser: n, signers: [n], retiredAt: T2, createdAt: T2 }),
      leak,
    ], [n.digest], [{ spkiSha256: d.digest, cutoff: null }]);
    expect(anchoredKids(trust)).toEqual([p.kid, d.kid, n.kid].sort());
    expect(trust.byDigest.get(p.digest)!.retiredAt).toBe(T1);
    expect(trust.byDigest.get(d.digest)!.retiredAt).toBe(T2);
    expect(codes(trust)).toEqual([['KEY_STATEMENT_INVALID', leak.id]]);
  });

  it('with an instant, ends its window there and voids what it stored from then; with no instant and no retirement, trusts it for nothing', () => {
    const c = makeKey();
    const n = makeKey();
    const m = makeKey();
    const succM = statement('succession', m, { endorser: n, signers: [n, m], activatedAt: T2, createdAt: T2 });
    const statements = [
      statement('genesis', c, { signers: [c], activatedAt: T0, createdAt: T0 }),
      statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T0, createdAt: T0 }),
      succM,
    ];
    const cut = walk([row(n, T0)], statements, [c.digest], [{ spkiSha256: n.digest, cutoff: T1 }]);
    expect(anchoredKids(cut)).toEqual([c.kid, n.kid].sort());
    // The cutoff ends the window without retiring the key.
    expect(cut.byDigest.get(n.digest)).toMatchObject({ activatedAt: T0, retiredAt: null, distrustCutoff: T1 });
    const applied = applyKeyTrust(buildKeyRegistry([{ keyId: n.kid, spkiBase64: n.publicKey, source: 'embedded' }]), cut).get(n.kid)!;
    expect(applied).toMatchObject({ trust: 'anchored', activatedAt: T0, distrustCutoff: T1 });
    expect(applied.retiredAt).toBeUndefined();
    expect(codes(cut)).toEqual([['KEY_STATEMENT_INVALID', succM.id]]);
    expect(anchoredKids(walk([], statements, [c.digest], [{ spkiSha256: n.digest, cutoff: null }]))).toEqual([c.kid]);
  });

  it('names the key a dropped closure reopens, and with that key listed too, what it signed after its retirement stays void', () => {
    const o = makeKey();
    const p = makeKey();
    const a = makeKey();
    const b = makeKey();
    const q = makeKey();
    const LEAK = '2026-09-02T06:00:00.000000Z';
    const at = (h: number) => `2026-09-02T${String(h).padStart(2, '0')}:00:00.000000Z`;
    const statements = [
      statement('genesis', o, { signers: [o], activatedAt: T0, createdAt: T0 }),
      statement('succession', p, { endorser: o, signers: [o, p], activatedAt: T0, createdAt: T0 }),
      statement('closure', o, { endorser: p, signers: [p], retiredAt: T1, createdAt: T1 }),
      statement('succession', a, { endorser: p, signers: [p, a], activatedAt: T1, createdAt: T1 }),
      statement('closure', p, { endorser: a, signers: [a], retiredAt: at(12), forced: true, createdAt: at(12) }),
      statement('succession', q, { endorser: p, signers: [p, q], activatedAt: at(13), createdAt: at(13) }),
      statement('succession', b, { endorser: a, signers: [a, b], activatedAt: at(14), createdAt: at(14) }),
      statement('closure', a, { endorser: b, signers: [b], retiredAt: at(15), createdAt: at(15) }),
    ];
    const onlyA = walk([], statements, [b.digest], [{ spkiSha256: a.digest, cutoff: LEAK }]);
    expect(onlyA.findings).toContainEqual(expect.objectContaining({ code: 'KEY_CLOSURE_INVALID', detail: expect.stringContaining(`add sha256:${p.digest} to distrustedKeys too`) }));
    const both = walk([], statements, [b.digest], [{ spkiSha256: a.digest, cutoff: LEAK }, { spkiSha256: p.digest, cutoff: LEAK }]);
    expect(both.trusted.has(q.digest)).toBe(false);
    expect(both.byDigest.get(p.digest)).toMatchObject({ retiredAt: null, distrustCutoff: LEAK });
  });

  it('does not blame an honest closure when its subject\'s leaked half redates it later', () => {
    const a = makeKey();
    const b = makeKey();
    const trust = walk([], [
      statement('genesis', a, { signers: [a], activatedAt: T0, createdAt: T0 }),
      statement('succession', b, { endorser: a, signers: [a, b], activatedAt: T1, createdAt: T1 }),
      statement('closure', a, { endorser: b, signers: [b], retiredAt: T2, createdAt: T2 }),
      statement('genesis', a, { signers: [a], activatedAt: T3, createdAt: T3 }),
    ], [b.digest]);
    expect(trust.findings.filter((f) => f.code === 'KEY_CLOSURE_INVALID')).toEqual([]);
  });

  it('is dated only by a key reached without it: a key it admitted cannot move its cutoff', () => {
    const c = makeKey();
    const d = makeKey();
    const x = makeKey();
    const trust = walk([], [
      statement('genesis', c, { signers: [c], activatedAt: T0, createdAt: T0 }),
      statement('succession', d, { endorser: c, signers: [c, d], activatedAt: T0, createdAt: T0 }),
      statement('succession', x, { endorser: d, signers: [d, x], createdAt: T1 }),
      statement('closure', d, { endorser: x, signers: [x], retiredAt: EPOCH_ZERO, createdAt: T1 }),
    ], [c.digest], [{ spkiSha256: d.digest, cutoff: null }]);
    expect(anchoredKids(trust)).toEqual([c.kid]);
  });
});

describe('the cutoff of a distrusted key with no instant', () => {
  it('is the earliest retirement a counting closure signs for it, not the latest', () => {
    const a = makeKey();
    const d = makeKey();
    const x = makeKey();
    const T2b = '2026-09-03T12:00:00.000000Z';
    const statements = [
      statement('genesis', a, { signers: [a], activatedAt: T0, createdAt: T0 }),
      statement('succession', d, { endorser: a, signers: [a, d], activatedAt: T0, createdAt: T0 }),
      // Stored before either closure, and inside d's later retirement but not its earlier one.
      statement('succession', x, { endorser: d, signers: [d, x], activatedAt: T2, createdAt: T2 }),
      statement('closure', d, { endorser: a, signers: [a], retiredAt: T1, createdAt: T3 }),
      statement('closure', d, { endorser: a, signers: [a], retiredAt: T2b, createdAt: T3 }),
    ];
    expect(walk([], statements, [a.digest]).trusted.has(x.digest)).toBe(true);
    const trust = walk([], statements, [a.digest], [{ spkiSha256: d.digest, cutoff: null }]);
    expect(trust.trusted.has(x.digest)).toBe(false);
    expect(trust.byDigest.get(d.digest)!.retiredAt).toBe(T1);
  });

  it('is never dated by a closure another distrusted key signed', () => {
    const a = makeKey();
    const d = makeKey();
    const e = makeKey();
    const statements = [
      statement('genesis', a, { signers: [a], activatedAt: T0, createdAt: T0 }),
      statement('succession', d, { endorser: a, signers: [a, d], activatedAt: T0, createdAt: T0 }),
      statement('succession', e, { endorser: a, signers: [a, e], activatedAt: T0, createdAt: T0 }),
      statement('closure', d, { endorser: e, signers: [e], retiredAt: T1, createdAt: T1 }),
    ];
    const distrust = [{ spkiSha256: d.digest, cutoff: null }, { spkiSha256: e.digest, cutoff: T3 }];
    const trust = walk([], statements, [a.digest], distrust);
    // e's closure counts as a closure, but it cannot vouch for when d stopped counting.
    expect(trust.trusted.has(d.digest)).toBe(false);
    expect(trust.trusted.has(e.digest)).toBe(true);
    // Distrust e from the start of time and the closure is still no date for d.
    expect(walk([], statements, [a.digest], [{ spkiSha256: d.digest, cutoff: null }, { spkiSha256: e.digest, cutoff: T0 }]).trusted.has(d.digest)).toBe(false);
  });
});

describe('a key admitted only by a distrusted key', () => {
  it('cannot close a key: its closure is not signed by an anchored key', () => {
    const a = makeKey();
    const d = makeKey();
    const x = makeKey();
    const y = makeKey();
    const closure = statement('closure', y, { endorser: x, signers: [x], retiredAt: T3, createdAt: T3 });
    const statements = [
      statement('genesis', a, { signers: [a], activatedAt: T0, createdAt: T0 }),
      statement('succession', d, { endorser: a, signers: [a, d], activatedAt: T0, createdAt: T0 }),
      statement('succession', y, { endorser: a, signers: [a, y], activatedAt: T0, createdAt: T0 }),
      statement('succession', x, { endorser: d, signers: [d, x], activatedAt: T2, createdAt: T2 }),
      closure,
    ];
    expect(walk([], statements, [a.digest]).byDigest.get(y.digest)!.retiredAt).toBe(T3);
    const trust = walk([], statements, [a.digest], [{ spkiSha256: d.digest, cutoff: T1 }]);
    expect(trust.trusted.has(x.digest)).toBe(false);
    expect(trust.byDigest.get(y.digest)!.retiredAt).toBeNull();
    expect(trust.findings.filter((f) => f.statementId === closure.id).map((f) => f.code)).toEqual(['KEY_CLOSURE_INVALID']);
  });
});

describe('a statement row that holds no signature', () => {
  it('is a finding and does not stop the walk over the rest', () => {
    const c = makeKey();
    const genesis = statement('genesis', c, { signers: [c] });
    const empty = { ...genesis, id: nextId(), cose: [null as unknown as string] };
    const nested = { ...genesis, id: nextId(), cose: [[genesis.cose[0]] as unknown as string] };
    const trust = walk([row(c, T0)], [genesis, empty, nested], [c.digest]);
    expect(anchoredKids(trust)).toEqual([c.kid]);
    expect(codes(trust).sort()).toEqual([
      ['KEY_STATEMENT_INVALID', empty.id],
      ['KEY_STATEMENT_INVALID', nested.id],
    ].sort());
  });
});

describe('a walk over an older key document (no write order)', () => {
  it('orders by the instants the statements sign, and agrees with the dump on an honest rotation from either pin', () => {
    const c = makeKey();
    const n = makeKey();
    const m = makeKey();
    const statements = [
      statement('genesis', c, { signers: [c], activatedAt: T0, createdAt: T0 }),
      statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1, createdAt: T1 }),
      statement('closure', c, { endorser: n, signers: [n], retiredAt: T2, createdAt: T2 }),
      statement('succession', m, { endorser: n, signers: [n, m], activatedAt: T2, createdAt: T2 }),
      statement('closure', n, { endorser: m, signers: [m], retiredAt: T3, forced: false, createdAt: T3 }),
    ];
    // A document lists each key's statements under it, newest key first.
    const doc = asDocument([...statements].reverse());
    for (const pin of [c, n, m]) {
      const dump = walk([], statements, [pin.digest]);
      const fromDoc = walk([], doc, [pin.digest]);
      expect(fromDoc.order).toBe('signed');
      expect(dump.order).toBe('written');
      expect(anchoredKids(fromDoc)).toEqual(anchoredKids(dump));
      expect(anchoredKids(fromDoc)).toEqual([c.kid, n.kid, m.kid].sort());
      for (const d of [c, n, m]) expect(fromDoc.byDigest.get(d.digest)).toEqual(dump.byDigest.get(d.digest));
      expect(fromDoc.findings).toEqual([]);
    }
  });

  it('orders a closure after a succession that signs the same instant, whichever the document lists first', () => {
    const p = makeKey();
    const c = makeKey();
    const g = statement('genesis', p, { signers: [p], activatedAt: T0 });
    const s = statement('succession', c, { endorser: p, signers: [p, c], activatedAt: T1 });
    const cl = statement('closure', p, { endorser: c, signers: [c], retiredAt: T1 });
    for (const order of [[g, s, cl], [g, cl, s], [cl, s, g], [s, cl, g]]) {
      for (const pin of [p, c]) {
        const trust = walk([row(p, T0, T1), row(c, T1)], asDocument(order), [pin.digest]);
        expect(anchoredKids(trust)).toEqual([p.kid, c.kid].sort());
        expect(trust.findings).toEqual([]);
        expect(trust.byDigest.get(p.digest)!.retiredAt).toBe(T1);
      }
    }
    // One microsecond later, the succession is after the closure in any listing, and admits nothing.
    const late = statement('succession', c, { endorser: p, signers: [p, c], activatedAt: '2026-09-02T00:00:00.000001Z' });
    for (const order of [[g, late, cl], [g, cl, late]]) {
      expect(walk([], asDocument(order), [p.digest]).trusted.has(c.digest)).toBe(false);
    }
  });

  it('counts a statement listed twice once', () => {
    const c = makeKey();
    const n = makeKey();
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    // As a dump row copied, a second admission cuts the edge back; as a
    // document listing, with no row to tell them apart, it is the same statement.
    const keys = [{ keyId: c.kid, publicKey: c.publicKey }];
    expect(anchoredKids(walk(keys, [succ, { ...succ, id: nextId() }], [n.digest]))).toEqual([n.kid]);
    expect(anchoredKids(walk(keys, asDocument([succ, succ]), [n.digest]))).toEqual([c.kid, n.kid].sort());
  });

  it('refuses statements that mix a write time with none', () => {
    const c = makeKey();
    const g = statement('genesis', c, { signers: [c] });
    expect(() => walk([], [g, ...asDocument([g])], [c.digest])).toThrow(TypeError);
  });

  it('a forced closure voids the forward edge whatever instant the leaked key signs', () => {
    const { c, n, genesis, succ } = (() => {
      const c = makeKey();
      const n = makeKey();
      return {
        c, n,
        genesis: statement('genesis', c, { signers: [c], activatedAt: T0 }),
        succ: statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 }),
      };
    })();
    const x = makeKey();
    const backdated = statement('succession', x, { endorser: c, signers: [c, x], activatedAt: T0 });
    const forced = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2, forced: true });
    const trust = walk([], asDocument([genesis, succ, backdated, forced]), [n.digest]);
    expect(trust.trusted.has(x.digest)).toBe(false);
  });
});

/**
 * A key document as a Server that publishes write order lists it: each key
 * with the statements filed under it, each statement with its row id and its
 * write time at microseconds. `at` gives each statement's write time.
 */
function publish(
  keys: Array<{ key: TestKey; activatedAt: string; retiredAt?: string | null; statements: Stored[] }>,
  at: ReadonlyMap<Stored, string>,
): VerificationKeysDocument {
  return {
    data: keys.map((k) => ({
      keyId: k.key.kid,
      publicKey: k.key.publicKey,
      algorithm: k.key.alg,
      status: k.retiredAt ? 'retired' : 'active',
      activatedAt: `${k.activatedAt.slice(0, 23)}Z`,
      retiredAt: k.retiredAt ? `${k.retiredAt.slice(0, 23)}Z` : null,
      statements: k.statements.map((st) => ({
        id: st.id,
        kind: st.kind,
        createdAt: at.get(st) ?? T1,
        cose: st.cose.map((b) => Buffer.from(b as Uint8Array).toString('base64')),
      })),
    })),
  };
}

function walkDocument(doc: VerificationKeysDocument, anchors: readonly TestKey[]): KeyTrust {
  return computeKeyTrust({ ...keyStatementsFromVerificationKeys(doc), trustAnchors: anchors.map((k) => `sha256:${k.digest}`) });
}

describe('a walk over a key document that publishes write order', () => {
  it('reads each statement\'s id and createdAt, so the walk applies the write order and names the row in findings', () => {
    const c = makeKey();
    const g = statement('genesis', c, { signers: [c], activatedAt: T0 });
    const planted = statement('genesis', makeKey(), { signers: [makeKey()] });
    const doc = publish([{ key: c, activatedAt: T0, statements: [g, planted] }], new Map([[g, T0], [planted, T1]]));
    const { statements } = keyStatementsFromVerificationKeys(doc);
    expect(statements.map((st) => [st.id, st.createdAt])).toEqual([[g.id, T0], [planted.id, T1]]);
    const trust = walkDocument(doc, [c]);
    expect(trust.order).toBe('written');
    expect(trust.findings.map((f) => [f.code, f.statementId])).toEqual([['KEY_STATEMENT_INVALID', planted.id]]);
  });

  it('a later admission a trusted key publishes dates its window and cuts its edge back, as the engine walks the whole registry', () => {
    const c = makeKey();
    const n = makeKey();
    const genesis = statement('genesis', c, { signers: [c], activatedAt: T0 });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const later = statement('genesis', n, { signers: [n], activatedAt: T2 });
    const at = new Map([[genesis, T0], [succ, T1], [later, T2]]);
    // The engine files the later genesis under n: from n alone the edge back
    // to c is cut, and n's window opens at T2.
    const doc = publish([{ key: n, activatedAt: T2, statements: [succ, later] }, { key: c, activatedAt: T0, statements: [genesis] }], at);
    const fromN = walkDocument(doc, [n]);
    expect(anchoredKids(fromN)).toEqual([n.kid]);
    expect(fromN.byDigest.get(n.digest)!.activatedAt).toBe(T2);
    // c's genesis now touches no anchored key, as on the whole registry.
    expect(fromN.findings.map((f) => [f.code, f.statementId])).toEqual([['KEY_STATEMENT_INVALID', genesis.id], ['KEY_STATEMENT_INVALID', later.id]]);
    const fromC = walkDocument(doc, [c]);
    expect(anchoredKids(fromC)).toEqual([c.kid, n.kid].sort());
    expect(fromC.byDigest.get(n.digest)!.activatedAt).toBe(T2);
    // A document carrying only n's first admission dates it at T1 and takes
    // the edge back the engine refuses; the listed activatedAt reads as drift.
    const firstOnly = publish([{ key: n, activatedAt: T2, statements: [succ] }, { key: c, activatedAt: T0, statements: [genesis] }], at);
    const old = walkDocument(firstOnly, [n]);
    expect(anchoredKids(old)).toEqual([c.kid, n.kid].sort());
    expect(old.findings.map((f) => f.code)).toEqual(['CHAIN_KEY_WINDOW_DRIFT']);
  });

  it('orders two statements stored in the same microsecond by id, whatever order the document lists them in', () => {
    const c = makeKey();
    const n = makeKey();
    const x = makeKey();
    const genesis = statement('genesis', c, { signers: [c], activatedAt: T0 });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const closure = statement('closure', c, { endorser: n, signers: [n], retiredAt: T2 });
    const edge = statement('succession', x, { endorser: c, signers: [c, x], activatedAt: T2 });
    const same = '2026-09-03T00:00:00.000007Z';
    const at = new Map([[genesis, T0], [succ, T1], [closure, same], [edge, same]]);
    for (const [first, second, trustsX] of [['00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b', true], ['00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000a', false]] as const) {
      // The edge out of c is void only when it sorts after c's closure.
      const e = { ...edge, id: first };
      const cl = { ...closure, id: second };
      const keys = [{ key: c, activatedAt: T0, retiredAt: T2, statements: [genesis, cl] }, { key: n, activatedAt: T1, statements: [succ] }, { key: x, activatedAt: T2, statements: [e] }];
      for (const listing of [keys, [...keys].reverse()]) {
        const trust = walkDocument(publish(listing, new Map([...at, [e, same], [cl, same]])), [n]);
        expect(trust.trusted.has(x.digest)).toBe(trustsX);
      }
    }
  });

  it('a statement the document lists without createdAt is a finding, not a document read in the signed order', () => {
    const c = makeKey();
    const n = makeKey();
    const genesis = statement('genesis', c, { signers: [c], activatedAt: T0 });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const doc = publish([{ key: n, activatedAt: T1, statements: [succ] }, { key: c, activatedAt: T0, statements: [genesis] }], new Map([[genesis, T0], [succ, T1]]));
    delete (doc.data[0]!.statements![0] as { createdAt?: string }).createdAt;
    const trust = walkDocument(doc, [c]);
    expect(trust.order).toBe('written');
    expect(anchoredKids(trust)).toEqual([c.kid]);
    expect(trust.findings).toContainEqual(expect.objectContaining({ code: 'KEY_STATEMENT_INVALID', statementId: succ.id, detail: 'the row has no parseable created_at to order it by' }));
  });

  it('a row read from two sources is one statement, and a copy of it under another id is a second', () => {
    const c = makeKey();
    const n = makeKey();
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1, createdAt: T1 });
    const keys = [{ keyId: c.kid, publicKey: c.publicKey }];
    const timed = { ...succ, createdAt: '2026-09-02T00:00:00.000123Z' };
    expect(anchoredKids(walk(keys, [timed, { ...timed }], [n.digest]))).toEqual([c.kid, n.kid].sort());
    expect(anchoredKids(walk(keys, [timed, { ...timed, id: nextId() }], [n.digest]))).toEqual([n.kid]);
  });

  it('a later succession whose endorser the document does not carry dates the window earlier than the engine, and the listed activatedAt says so', () => {
    const c = makeKey();
    const n = makeKey();
    const unpublished = makeKey();
    const genesis = statement('genesis', c, { signers: [c], activatedAt: T0 });
    const succ = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
    const later = statement('succession', n, { endorser: unpublished, signers: [unpublished, n], activatedAt: T2 });
    const at = new Map([[genesis, T0], [succ, T1], [later, T2]]);
    const doc = publish([{ key: n, activatedAt: T2, statements: [succ, later] }, { key: c, activatedAt: T0, statements: [genesis] }], at);
    const trust = walkDocument(doc, [n]);
    expect(trust.byDigest.get(n.digest)!.activatedAt).toBe(T1);
    expect(trust.findings.map((f) => f.code).sort()).toEqual(['CHAIN_KEY_WINDOW_DRIFT', 'KEY_STATEMENT_INVALID']);
    // With no admission it can verify, the key has no signed lower edge here at all.
    const only = publish([{ key: n, activatedAt: T2, statements: [later] }], at);
    const bare = walkDocument(only, [n]);
    expect(bare.byDigest.get(n.digest)!.activatedAt).toBeNull();
    expect(bare.findings).toContainEqual(expect.objectContaining({ code: 'CHAIN_KEY_WINDOW_DRIFT', keyId: n.kid, detail: `activatedAt ${T2.slice(0, 23)}Z is signed by no admission this walk could verify` }));
  });
});

describe('the source a statement is read from', () => {
  // C is pinned and distrusted from T1; C's leaked half admits X with a write
  // time before the cutoff.
  const c = makeKey();
  const x = makeKey();
  const genesis = statement('genesis', c, { signers: [c], activatedAt: T0, createdAt: T0 });
  const succ = statement('succession', x, { endorser: c, signers: [c, x], activatedAt: T2, createdAt: '2026-09-01T12:00:00.000000Z' });
  const base = { keys: [row(c, T0)], trustAnchors: [`sha256:${c.digest}`], distrustedKeys: [`sha256:${c.digest}@${T1}`] };

  it('a dump row is held to its created_at against a distrusted key\'s cutoff, as the engine holds it', () => {
    expect(computeKeyTrust({ ...base, statements: [genesis, succ] }).trusted.has(x.digest)).toBe(true);
  });

  it('a key document\'s statement, or one that names no source, never keeps an edge out of a distrusted key', () => {
    for (const source of ['document', undefined] as const) {
      const statements = [genesis, succ].map(({ source: _s, endorserKeyId: _e, ...st }) => ({ ...st, ...(source ? { source } : {}) }));
      const trust = computeKeyTrust({ ...base, statements });
      expect(trust.order).toBe('written');
      expect(trust.trusted.has(x.digest)).toBe(false);
      // Its time is before the cutoff, where the engine would count it: voided
      // here only by the source rule, it is a note, not a finding.
      expect(trust.findings).toEqual([]);
      expect(trust.notes).toEqual([expect.objectContaining({ keyId: x.kid, statementId: succ.id })]);
    }
  });
});

describe('a statement\'s createdAt', () => {
  it('that is not strict RFC 3339 cannot be placed, and is KEY_STATEMENT_INVALID', () => {
    const c = makeKey();
    const n = makeKey();
    const genesis = statement('genesis', c, { signers: [c], activatedAt: T0, createdAt: T0 });
    for (const odd of ['2026-09-01T00:00:00', '2026-09-01 00:00:00.000000Z', '1', '2026-02-30T00:00:00.000000Z']) {
      const succ = { ...statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 }), createdAt: odd };
      const trust = walk([], [genesis, succ], [c.digest]);
      expect(anchoredKids(trust), odd).toEqual([c.kid]);
      expect(codes(trust), odd).toEqual([['KEY_STATEMENT_INVALID', succ.id]]);
    }
  });

  it('names one row however it spells the instant or the id', () => {
    const c = makeKey();
    const n = makeKey();
    const succ = { ...statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 }), id: '0aa0b0c0-0000-4000-8000-00000000abcd', createdAt: '2026-09-02T00:00:00.000123Z' };
    const respelled = { ...succ, id: succ.id.toUpperCase(), createdAt: '2026-09-02T02:00:00.000123+02:00' };
    const keys = [{ keyId: c.kid, publicKey: c.publicKey }];
    // Read twice, it is still n's sole admission, so the edge back to c holds.
    expect(anchoredKids(walk(keys, [succ, respelled], [n.digest]))).toEqual([c.kid, n.kid].sort());
  });
});

describe('trustAnchors and distrustedKeys parsing', () => {
  it('trustAnchors takes sha256:<64 hex> entries and refuses anything else by name', () => {
    const d = 'a'.repeat(64);
    expect(parseTrustAnchors([` sha256:${d} `, `SHA256:${'B'.repeat(64)}`])).toEqual([d, 'b'.repeat(64)]);
    expect(parseTrustAnchors(` sha256:${d} , sha256:${d}`)).toEqual([d]);
    expect(parseTrustAnchors('')).toEqual([]);
    expect(() => parseTrustAnchors('sha256:abc')).toThrow(/sha256:abc/);
    expect(() => parseTrustAnchors(['a'.repeat(16)])).toThrow(TypeError);
  });

  it('computeKeyTrust refuses an empty anchor set', () => {
    expect(() => computeKeyTrust({ keys: [], statements: [], trustAnchors: [] })).toThrow(/at least one trust anchor/);
  });

  it('distrustedKeys takes sha256:<64 hex>, optionally @<RFC 3339 instant> normalized to UTC microseconds, and refuses anything else by name', () => {
    const d = 'a'.repeat(64);
    expect(parseDistrustedKeys(` sha256:${d} , SHA256:${'B'.repeat(64)}@2026-09-01T02:00:00.5+02:00, sha256:${'c'.repeat(64)}@2026-09-01T00:00:00.123456Z`)).toEqual([
      { spkiSha256: d, cutoff: null },
      { spkiSha256: 'b'.repeat(64), cutoff: '2026-09-01T00:00:00.500000Z' },
      { spkiSha256: 'c'.repeat(64), cutoff: '2026-09-01T00:00:00.123456Z' },
    ]);
    expect(parseDistrustedKeys('')).toEqual([]);
    expect(() => parseDistrustedKeys('sha256:abc')).toThrow(/sha256:abc/);
    expect(() => parseDistrustedKeys(`sha256:${d}@yesterday`)).toThrow(/@yesterday/);
    expect(() => parseDistrustedKeys(`sha256:${d}@2026-13-45T00:00:00Z`)).toThrow(TypeError);
    expect(() => parseDistrustedKeys(`sha256:${d}@2026-02-30T00:00:00Z`)).toThrow(/2026-02-30/);
    expect(() => parseDistrustedKeys(`sha256:${d},sha256:${d}@2026-09-01T00:00:00Z`)).toThrow(/twice/);
    expect(() => parseDistrustedKeys(`sha256:${d}@2026-02-28T24:00:00Z`)).toThrow(TypeError);
  });
});

/**
 * Random registries, ported from the engine: an honest history (a genesis,
 * rotations, routine retirements from another active key, and sometimes a key
 * anchored only by a pin) interleaved with what an attacker can store:
 * statements under keys the runtime role generates, copies of rows, and, once
 * one honest key leaks, statements under that key, stored any time after
 * every key they name was readable, before the first honest row included. The
 * leaked key is then force-retired from the current honest key.
 */
describe('the trust walk on random registries', () => {
  interface SimKey extends TestKey { name: string }
  type SimStatement = Stored & { attacker: boolean };
  const BASE = Date.parse('2026-01-01T00:00:00.000Z');
  const at = (t: number): string => `${new Date(t).toISOString().slice(0, 23)}000Z`;
  const simKey = (name: string): SimKey => ({ ...makeKey(), name });

  function prng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function sign(
    typ: string, subject: SimKey, signers: SimKey[], storedAt: number,
    o: { endorser?: SimKey; activatedAt?: number; retiredAt?: number; forced?: boolean; attacker?: boolean },
  ): SimStatement {
    const payload: Payload = {
      typ,
      iss: 'https://ledger.example',
      subject: {
        kid: subject.kid, spkiSha256: subject.digest, alg: subject.alg, spki: subject.publicKey,
        activatedAt: at(o.activatedAt ?? storedAt), ...(o.retiredAt !== undefined ? { retiredAt: at(o.retiredAt) } : {}),
      },
      ...(o.endorser ? { endorser: { kid: o.endorser.kid, spkiSha256: o.endorser.digest } } : {}),
      iat: Math.floor(storedAt / 1000) + 1,
      ...(typ === 'closure' ? { forced: o.forced ?? false } : {}),
    };
    const bytes = encodePayload(payload);
    return {
      id: nextId(),
      kind: typ, subjectKeyId: subject.kid, endorserKeyId: o.endorser?.kid ?? null,
      cose: signers.map((k) => signStatement(bytes, k)),
      createdAt: new Date(storedAt).toISOString(),
      digest: '',
      payload,
      attacker: o.attacker ?? false,
    };
  }

  const inWriteOrder = (statements: SimStatement[]): SimStatement[] =>
    [...statements].sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt) || a.id.localeCompare(b.id));

  function simWalk(statements: SimStatement[], anchors: ReadonlySet<string>, keys: SimKey[], distrusted: Array<{ key: SimKey; cutoff: string | null }> = []) {
    return walk(
      keys.map((k) => ({ keyId: k.kid, publicKey: k.publicKey, algorithm: k.alg })),
      inWriteOrder(statements),
      [...anchors],
      distrusted.map(({ key, cutoff }) => ({ spkiSha256: key.digest, cutoff })),
    );
  }

  /** The model, restated from its definition over statements whose signatures all verify. */
  function reference(statements: SimStatement[], anchors: ReadonlySet<string>) {
    const order = inWriteOrder(statements);
    const subjectOf = (s: SimStatement) => s.payload.subject.spkiSha256;
    const signerOf = (s: SimStatement) => s.payload.endorser?.spkiSha256;
    const admissions = (k: string) => order.filter((s) => (s.kind === 'genesis' || s.kind === 'succession') && subjectOf(s) === k);
    const edges: Array<{ from: string; to: string; i: number; counts: boolean }> = [];
    order.forEach((s, i) => {
      const e = signerOf(s);
      const k = subjectOf(s);
      if (e !== undefined && s.kind === 'succession') {
        edges.push({ from: e, to: k, i, counts: true }, { from: k, to: e, i, counts: admissions(k).length === 1 && admissions(k)[0] === s });
      }
    });
    const reachFrom = (es: typeof edges) => {
      const t = new Set(anchors);
      for (let n = -1; n !== t.size;) {
        n = t.size;
        for (const e of es) if (t.has(e.from)) t.add(e.to);
      }
      return t;
    };
    const pass1 = reachFrom(edges);
    const closures = order.map((s, i) => ({ s, i })).filter(({ s }) => s.kind === 'closure' && pass1.has(signerOf(s)!));
    const closuresOf = (k: string) => closures.filter(({ s }) => subjectOf(s) === k);
    const live = (e: (typeof edges)[number]) => e.counts
      && !closuresOf(e.from).some(({ s, i }) => s.payload.forced === true || i < e.i);
    const trusted = reachFrom(edges.filter(live));
    const windows = new Map<string, { activatedAt: string | null; retiredAt: string | null }>();
    for (const d of trusted) {
      const ends = closuresOf(d).map(({ s }) => s.payload.subject.retiredAt!).sort();
      const starts = admissions(d).map((s) => s.payload.subject.activatedAt).sort().reverse();
      windows.set(d, { activatedAt: starts[0] ?? null, retiredAt: ends[0] ?? null });
    }
    return { trusted, windows };
  }

  function registry(seed: number) {
    const r = prng(seed);
    const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
    let now = BASE;
    const tick = () => { now += 1000 + Math.floor(r() * 3) * 1000; };
    const statements: SimStatement[] = [];
    const attackerKeys = [simKey('A0'), simKey('A1'), simKey('A2')];
    const preStart = now - 100_000;
    now += 1000;
    const g = simKey('G');
    const honest: SimKey[] = [g];
    statements.push(sign('genesis', g, [g], now, { activatedAt: now }));
    const anchorOnly = r() < 0.3 ? simKey('P') : null;
    const active: SimKey[] = [g];
    let current = g;
    let leaked: SimKey | null = null;
    const knownAt = (k: SimKey): number => {
      if (attackerKeys.includes(k) || k === g || k === anchorOnly) return preStart + 1;
      const admitted = statements.find((x) => !x.attacker && x.payload.subject.spkiSha256 === k.digest);
      return admitted ? Date.parse(admitted.createdAt) : now;
    };

    const steps = 6 + Math.floor(r() * 10);
    for (let step = 0; step < steps; step++) {
      tick();
      const roll = r();
      if (roll < 0.25) {
        const next = simKey(`H${honest.length}`);
        honest.push(next);
        statements.push(sign('succession', next, [current, next], now, { endorser: current, activatedAt: now }));
        active.push(next);
        current = next;
      } else if (roll < 0.4) {
        const candidates = active.filter((k) => k !== current);
        if (candidates.length === 0) continue;
        const l = pick(candidates);
        const by = pick(active.filter((k) => k !== l));
        statements.push(sign('closure', l, [by], now, { endorser: by, retiredAt: now }));
        active.splice(active.indexOf(l), 1);
      } else if (roll < 0.5 && !leaked) {
        leaked = pick([...honest, ...(anchorOnly ? [anchorOnly] : [])]);
      } else if (r() < 0.15 && statements.length > 0) {
        const src = pick(statements);
        statements.push({ ...src, id: nextId(), createdAt: new Date(now).toISOString(), attacker: true });
      } else {
        const held = [...attackerKeys, ...(leaked ? [leaked] : [])];
        const typ = pick(['succession', 'closure', 'genesis', 'succession']);
        const subject = typ === 'genesis' ? pick(held) : pick([...honest, ...(anchorOnly ? [anchorOnly] : []), ...attackerKeys]);
        const endorser = pick(held);
        if ((typ !== 'genesis' && endorser === subject) || (typ === 'succession' && !held.includes(subject))) continue;
        const windowStart = pick([preStart, now - 3000, now]);
        const windowEnd = pick([preStart + 1, now - 1000, now]);
        const from = Math.max(preStart + 1, ...[subject, endorser].filter((k) => k !== leaked).map(knownAt));
        const storedAt = r() < 0.5 ? now : from + Math.floor(r() * Math.max(1, now - from));
        statements.push(sign(typ, subject, typ === 'genesis' ? [subject] : typ === 'succession' ? [endorser, subject] : [endorser], storedAt, {
          ...(typ !== 'genesis' ? { endorser } : {}),
          activatedAt: windowStart,
          ...(typ === 'closure' ? { retiredAt: Math.max(windowStart, windowEnd) } : {}),
          forced: r() < 0.5,
          attacker: true,
        }));
      }
    }
    if (leaked) {
      tick();
      if (current === leaked) {
        const next = simKey(`H${honest.length}`);
        honest.push(next);
        statements.push(sign('succession', next, [leaked, next], now, { endorser: leaked, activatedAt: now }));
        current = next;
        tick();
      }
      statements.push(sign('closure', leaked, [current], now, { endorser: current, retiredAt: now, forced: true }));
    }
    return { seed, statements, honest, anchorOnly, leaked, attackerKeys };
  }

  // KEY_TRUST_SEEDS=<first>:<count> runs a wider sweep locally.
  const [first = 1, count = 150] = (process.env['KEY_TRUST_SEEDS'] ?? '').split(':').filter(Boolean).map(Number);
  const registries = Array.from({ length: count }, (_, i) => registry(first + i));

  type Sim = ReturnType<typeof registry>;
  const anchorsFor = (sim: Sim, pin: SimKey): Set<string> =>
    new Set([pin.digest, ...(sim.anchorOnly ? [sim.anchorOnly.digest] : [])]);
  const keysOf = (sim: Sim, attacker: boolean): SimKey[] =>
    [...sim.honest, ...(sim.anchorOnly ? [sim.anchorOnly] : []), ...(attacker ? sim.attackerKeys : [])];

  it('computes what the model defines, from every honest pin', () => {
    const failures: string[] = [];
    for (const sim of registries) {
      for (const pin of sim.honest) {
        const got = simWalk(sim.statements, anchorsFor(sim, pin), keysOf(sim, true));
        if (got.statements.valid !== got.statements.total) failures.push(`seed ${sim.seed}: a statement does not verify, which the model does not cover`);
        const want = reference(sim.statements, anchorsFor(sim, pin));
        const tag = `seed ${sim.seed}, pinned on ${pin.name}`;
        if ([...got.trusted].sort().join() !== [...want.trusted].sort().join()) failures.push(`${tag}: trusted set differs`);
        for (const [d, w] of want.windows) {
          const e = got.byDigest.get(d);
          if (e?.activatedAt !== w.activatedAt || e.retiredAt !== w.retiredAt) failures.push(`${tag}: window of ${d.slice(0, 8)} is ${e?.activatedAt}..${e?.retiredAt}, the model says ${w.activatedAt}..${w.retiredAt}`);
        }
      }
    }
    expect(failures).toEqual([]);
  }, 120_000);

  function widenings(tag: string, attacked: KeyTrust, base: KeyTrust): string[] {
    const out: string[] = [];
    for (const d of attacked.trusted) {
      if (!base.trusted.has(d)) {
        out.push(`${tag}: ${d.slice(0, 8)} is trusted only because of the attacker's rows`);
        continue;
      }
      const a = attacked.byDigest.get(d)!;
      const b = base.byDigest.get(d)!;
      if (b.activatedAt !== null && (a.activatedAt === null || a.activatedAt < b.activatedAt)) out.push(`${tag}: ${d.slice(0, 8)} activates at ${a.activatedAt}, before ${b.activatedAt}`);
      const aEnds = a.distrustCutoff ?? a.retiredAt;
      const bEnds = b.distrustCutoff ?? b.retiredAt;
      if (bEnds !== null && (aEnds === null || aEnds > bEnds)) out.push(`${tag}: ${d.slice(0, 8)} retires at ${aEnds}, past ${bEnds}`);
    }
    return out;
  }

  it('after a forced closure of the leaked key, nothing the attacker stored adds a key or widens a window, from any honest pin', () => {
    const failures: string[] = [];
    for (const sim of registries) {
      const honestOnly = sim.statements.filter((st) => !st.attacker);
      for (const pin of sim.honest) {
        const tag = `seed ${sim.seed}, pinned on ${pin.name}, leaked ${sim.leaked?.name ?? 'none'}`;
        failures.push(...widenings(tag, simWalk(sim.statements, anchorsFor(sim, pin), keysOf(sim, true)), simWalk(honestOnly, anchorsFor(sim, pin), keysOf(sim, false))));
      }
    }
    expect(failures).toEqual([]);
  }, 120_000);

  it('with the leaked key distrusted, nothing the attacker stored adds a key or widens a window, from any honest pin', () => {
    const failures: string[] = [];
    let covered = 0;
    for (const sim of registries) {
      const leaked = sim.leaked;
      if (!leaked) continue;
      const byLeaked = sim.statements.filter((st) => st.attacker && [st.payload.endorser?.spkiSha256, st.payload.subject.spkiSha256].includes(leaked.digest));
      const leakedFrom = byLeaked.map((st) => Date.parse(st.createdAt)).sort((a, b) => a - b)[0];
      if (leakedFrom === undefined) continue;
      covered++;
      const unretired = sim.statements.filter((st) => !(st.kind === 'closure' && !st.attacker && st.payload.forced === true && st.subjectKeyId === leaked.kid));
      for (const [statements, cutoff] of [[sim.statements, null], [unretired, at(leakedFrom)]] as const) {
        const honestOnly = statements.filter((st) => !st.attacker);
        for (const pin of sim.honest) {
          if (pin === leaked) continue;
          const tag = `seed ${sim.seed}, pinned on ${pin.name}, ${leaked.name} distrusted${cutoff === null ? '' : ` from ${cutoff}, never retired`}`;
          const distrusted = [{ key: leaked, cutoff }];
          failures.push(...widenings(tag,
            simWalk(statements, anchorsFor(sim, pin), keysOf(sim, true), distrusted),
            simWalk(honestOnly, anchorsFor(sim, pin), keysOf(sim, false), distrusted)));
        }
      }
    }
    expect(covered).toBeGreaterThan(0);
    expect(failures).toEqual([]);
  }, 120_000);

  it('over the honest history alone, a key document (signed order) walks to what the dump (write order) walks to', () => {
    const failures: string[] = [];
    for (const sim of registries) {
      const honestOnly = inWriteOrder(sim.statements.filter((st) => !st.attacker));
      for (const pin of sim.honest) {
        const dump = simWalk(honestOnly, anchorsFor(sim, pin), keysOf(sim, false));
        const doc = walk(keysOf(sim, false).map((k) => ({ keyId: k.kid, publicKey: k.publicKey, algorithm: k.alg })), asDocument([...honestOnly].reverse()), [...anchorsFor(sim, pin)]);
        const tag = `seed ${sim.seed}, pinned on ${pin.name}`;
        if ([...doc.trusted].sort().join() !== [...dump.trusted].sort().join()) failures.push(`${tag}: trusted set differs`);
        for (const d of dump.trusted) {
          if (JSON.stringify(doc.byDigest.get(d)) !== JSON.stringify(dump.byDigest.get(d))) failures.push(`${tag}: window of ${d.slice(0, 8)} differs`);
        }
      }
    }
    expect(failures).toEqual([]);
  }, 120_000);
});

describe('distrusted keys over a key document (no write order)', () => {
  it('a leaked key cannot date a statement before its cutoff: every edge out of it is void', () => {
    const d = makeKey();
    const x = makeKey();
    const g = statement('genesis', d, { signers: [d], activatedAt: T0, createdAt: T0 });
    const backdated = statement('succession', x, { endorser: d, signers: [d, x], activatedAt: T1, createdAt: T3 });
    const cutoff = [{ spkiSha256: d.digest, cutoff: T2 }];
    expect(walk([], [g, backdated], [d.digest], cutoff).trusted.has(x.digest)).toBe(false);
    expect(walk([], asDocument([g, backdated]), [d.digest], cutoff).trusted.has(x.digest)).toBe(false);
  });

  it('a routinely closed key, distrusted from its closure, cannot admit a key by signing an earlier instant', () => {
    const c = makeKey();
    const n = makeKey();
    const x = makeKey();
    const statements = [
      statement('genesis', c, { signers: [c], activatedAt: T0, createdAt: T0 }),
      statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1, createdAt: T1 }),
      statement('closure', c, { endorser: n, signers: [n], retiredAt: T2, createdAt: T2 }),
      statement('succession', x, { endorser: c, signers: [c, x], activatedAt: '2026-09-02T12:00:00.000000Z', createdAt: T3 }),
    ];
    const distrust = [{ spkiSha256: c.digest, cutoff: null }];
    expect(walk([], statements, [n.digest], distrust).trusted.has(x.digest)).toBe(false);
    expect(walk([], asDocument(statements), [n.digest], distrust).trusted.has(x.digest)).toBe(false);
  });
});
