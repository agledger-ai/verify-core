import { describe, it, expect } from 'vitest';
import { verifyAuditExport, type RecordAuditExportInput } from '../audit-export.js';
import { load, published, resignedUnder, underAdmittedKey } from './export-fixtures.js';
import { T0, T1, T2, makeKey, statement, type TestKey } from './key-statements-helpers.js';

/**
 * trustAnchors on the export path, over the corpus's real exports: the
 * statements an export carries are walked from the caller's pin, entries
 * under a key the walk does not anchor fail, and a result with no pin says
 * so rather than reading as clean.
 */

const pinOf = (exp: RecordAuditExportInput): string => {
  const pin = exp.exportMetadata.anchoredFrom;
  if (!pin) throw new Error('the corpus export carries anchoredFrom');
  return pin;
};
const STRANGER = `sha256:${'ab'.repeat(32)}`;
/** A key nothing else names, with its genesis, as an older key document lists it. */
const strangerGenesis = () => {
  const k = makeKey();
  const g = statement('genesis', k, { signers: [k] });
  return { keyId: k.kid, publicKey: k.publicKey, statement: { kind: g.kind, cose: g.cose.map((b) => Buffer.from(b as Uint8Array).toString('base64')) } };
};

describe('verifyAuditExport with trustAnchors', () => {
  it('without anchors, the result says no key was anchored and the anchoring check did not run', () => {
    const r = verifyAuditExport(load('valid.json'));
    expect(r.valid).toBe(true);
    expect(r.optionalChecks.key_anchoring).toBe('skipped_no_input');
    expect(r.keyTrust.status).toBe('no_anchor');
    expect(r.keyTrust.detail).toMatch(/No trustAnchors/);
    expect(r.keyTrust.anchoredFrom).toBe(pinOf(load('valid.json')));
    expect(r.keyTrust.anchoredFromPinned).toBeNull();
  });

  it('pinned on the vault key, every entry is anchored', () => {
    const exp = load('valid.json');
    const r = verifyAuditExport(exp, { trustAnchors: [pinOf(exp)] });
    expect(r.valid).toBe(true);
    expect(r.optionalChecks.key_anchoring).toBe('applied');
    expect(r.keyTrust).toMatchObject({ status: 'walked', order: 'written', anchoredFromPinned: true, unanchoredKeyIds: [], findings: [] });
    expect(r.keyTrust.anchoredKeyIds).toEqual([exp.entries[0]!.integrity.signingKeyId]);
  });

  it('pinned on a key nothing links to, every signed entry fails CHAIN_SIGNING_KEY_UNANCHORED', () => {
    const r = verifyAuditExport(load('valid.json'), { trustAnchors: [STRANGER] });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_SIGNING_KEY_UNANCHORED' });
    expect(r.entries.every((e) => e.code === 'CHAIN_SIGNING_KEY_UNANCHORED')).toBe(true);
    expect(r.keyTrust.anchoredFromPinned).toBe(false);
  });

  it('an embedded key with no statement is unanchored: the key-substitution fixture fails without a key policy', () => {
    const exp = load('key-substitution.json');
    expect(verifyAuditExport(exp).valid).toBe(true);
    const r = verifyAuditExport(exp, { trustAnchors: [pinOf(exp)] });
    expect(r.brokenAt).toMatchObject({ position: 2, code: 'CHAIN_SIGNING_KEY_UNANCHORED' });
    expect(r.keyTrust.unanchoredKeyIds).toEqual([exp.entries[1]!.integrity.signingKeyId]);
  });

  it('walks a three-key history across an algorithm change from the Server\'s current key', () => {
    const exp = load('valid-es256.json');
    const r = verifyAuditExport(exp, { publicKeys: load('keys-oob-es256.json') as unknown as Record<string, string>, trustAnchors: [pinOf(exp)] });
    expect(r.valid).toBe(true);
    expect(r.keyTrust.anchoredKeyIds).toHaveLength(3);
    expect(r.keyTrust.findings).toEqual([]);
  });

  it('a statement that does not verify is KEY_STATEMENT_INVALID and fails the verdict', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    const genesis = exp.exportMetadata.signingKeyStatements![keyId]![0]!;
    const bytes = Buffer.from(genesis.cose[0]!, 'base64');
    bytes[bytes.length - 1]! ^= 0xff;
    genesis.cose[0] = bytes.toString('base64');
    const r = verifyAuditExport(exp, { trustAnchors: [pinOf(exp)] });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: 0, code: 'KEY_STATEMENT_INVALID' });
    // The pin is the key itself, so the entries stay anchored.
    expect(r.entries.every((e) => e.valid)).toBe(true);
  });

  it('entries are graded against the signed window, and a column that says otherwise is a finding', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    // The column claims the key was retired before the first entry.
    exp.exportMetadata.signingKeyWindows![keyId] = { activatedAt: exp.exportMetadata.signingKeyWindows![keyId]!.activatedAt, retiredAt: '2000-01-01T00:00:00.000Z' };
    expect(verifyAuditExport(exp).brokenAt?.code).toBe('CHAIN_KEY_EXPIRED');
    const r = verifyAuditExport(exp, { trustAnchors: [pinOf(exp)] });
    expect(r.entries.every((e) => e.valid)).toBe(true);
    expect(r.keyTrust.findings.map((f) => f.code)).toEqual(['KEY_CLOSURE_INVALID']);
    expect(r.valid).toBe(false);

    const drifted = load('valid.json');
    drifted.exportMetadata.signingKeyWindows![keyId] = { activatedAt: '2026-01-01T00:00:00.000Z', retiredAt: null };
    expect(verifyAuditExport(drifted, { trustAnchors: [pinOf(drifted)] }).keyTrust.findings.map((f) => f.code)).toEqual(['CHAIN_KEY_WINDOW_DRIFT']);
  });

  it('walks the statements a supplied /v1/verification-keys entry carries', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    const statements = exp.exportMetadata.signingKeyStatements![keyId]!;
    delete exp.exportMetadata.signingKeyStatements;
    const publicKeys = [{ keyId, publicKey: exp.exportMetadata.signingPublicKeys![keyId]!, statements }];
    const r = verifyAuditExport(exp, { publicKeys, trustAnchors: [pinOf(load('valid.json'))], requireSuppliedKeys: true });
    expect(r.valid).toBe(true);
    expect(r.keyProvenance).toEqual({ supplied: 3, embedded: 0 });
  });

  it('a statement the export and a supplied key both carry is one row, so it is no second admission', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    const statements = structuredClone(exp.exportMetadata.signingKeyStatements![keyId]!);
    expect(statements.every((st) => typeof st.id === 'string' && typeof st.createdAt === 'string')).toBe(true);
    const publicKeys = [{ keyId, publicKey: exp.exportMetadata.signingPublicKeys![keyId]!, statements }];
    const r = verifyAuditExport(exp, { publicKeys, trustAnchors: [pinOf(exp)] });
    expect(r.valid).toBe(true);
    expect(r.keyTrust).toMatchObject({ order: 'written', findings: [] });
  });

  it('a supplied key document from a Server that published no write order is read with the export\'s statements', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    const older = exp.exportMetadata.signingKeyStatements![keyId]!.map(({ kind, cose }) => ({ kind, cose: [...cose] }));
    const publicKeys = [{ keyId, publicKey: exp.exportMetadata.signingPublicKeys![keyId]!, statements: older }];
    // The same rows: the export's write order stands.
    const same = verifyAuditExport(exp, { publicKeys, trustAnchors: [pinOf(exp)] });
    expect(same.valid).toBe(true);
    expect(same.keyTrust).toMatchObject({ order: 'written', findings: [] });
    // A statement only the older document carries has no write time to place
    // it by, so the walk falls back to the signed order for all of them.
    const stranger = strangerGenesis();
    const extra = [{ keyId: stranger.keyId, publicKey: stranger.publicKey, statements: [stranger.statement] }, ...publicKeys];
    const mixed = verifyAuditExport(exp, { publicKeys: extra, trustAnchors: [pinOf(exp)] });
    expect(mixed.keyTrust.order).toBe('signed');
    expect(mixed.entries.every((e) => e.valid)).toBe(true);
  });

  it('refuses a key that is both pinned and distrusted, as the Server refuses to start with it', () => {
    const exp = load('valid.json');
    for (const distrust of [pinOf(exp), `${pinOf(exp)}@2026-09-01T00:00:00Z`, pinOf(exp).toUpperCase().replace('SHA256', 'sha256')]) {
      expect(() => verifyAuditExport(exp, { trustAnchors: [pinOf(exp)], distrustedKeys: [distrust] })).toThrow(/both a trust anchor and a distrusted key/);
    }
  });

  it('a distrusted key with no instant and no retirement is trusted for nothing, though its admitting root is pinned', () => {
    const { exp, pin, key } = underAdmittedKey();
    expect(verifyAuditExport(exp, { trustAnchors: [pin] }).valid).toBe(true);
    const r = verifyAuditExport(exp, { trustAnchors: [pin], distrustedKeys: [`sha256:${key.digest}`] });
    expect(r.brokenAt?.code).toBe('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('a key distrusted from an instant and never retired fails what it wrote after, worded as the distrust cutoff', () => {
    const { exp, pin, key } = underAdmittedKey();
    // Between the first entry and the second, at microsecond precision.
    const between = (Date.parse(exp.entries[0]!.createdAt!) + Date.parse(exp.entries[1]!.createdAt!)) / 2;
    const cutoff = `${new Date(Math.floor(between)).toISOString().slice(0, 23)}000Z`;
    const r = verifyAuditExport(exp, { trustAnchors: [pin], distrustedKeys: [`sha256:${key.digest}@${cutoff}`] });
    const keyId = key.kid;
    expect(r.entries[0]!.valid).toBe(true);
    expect(r.brokenAt).toMatchObject({
      position: 2,
      code: 'CHAIN_KEY_EXPIRED',
      detail: `Entry written ${exp.entries[1]!.createdAt} postdates ${cutoff}, the instant distrustedKeys (VAULT_DISTRUSTED_KEYS on the Server) gives for key ${keyId}; the key was not retired then.`,
    });
    expect(r.brokenAt!.detail).not.toMatch(/retirement/);
    // Not a retirement, so the active registry column is no drift.
    expect(r.keyTrust.findings).toEqual([]);
  });

  it('refuses a malformed anchor or distrusted key by name', () => {
    expect(() => verifyAuditExport(load('valid.json'), { trustAnchors: ['15d63684b387235c'] })).toThrow(/15d63684b387235c/);
    expect(() => verifyAuditExport(load('valid.json'), { trustAnchors: [STRANGER], distrustedKeys: ['sha256:xyz'] })).toThrow(TypeError);
  });

  it('refuses signingKeyStatements that is not an object keyed by key id, rather than reading a list by index', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    const asList = [exp.exportMetadata.signingKeyStatements![keyId]!];
    (exp.exportMetadata as Record<string, unknown>)['signingKeyStatements'] = asList;
    expect(() => verifyAuditExport(exp, { trustAnchors: [pinOf(load('valid.json'))] })).toThrow(
      new TypeError('signingKeyStatements must be an object keyed by key id.'),
    );
    (exp.exportMetadata as Record<string, unknown>)['signingKeyStatements'] = 'statements';
    expect(() => verifyAuditExport(exp, { trustAnchors: [pinOf(load('valid.json'))] })).toThrow(
      new TypeError('signingKeyStatements must be an object keyed by key id.'),
    );
  });

  it('an empty trustAnchors is the same as none', () => {
    const exp = load('key-substitution.json');
    const r = verifyAuditExport(exp, { trustAnchors: [] });
    expect(r).toEqual(verifyAuditExport(exp));
    expect(r.keyTrust.status).toBe('no_anchor');
  });

  /** unsigned.json carrying valid.json's key and statements, so a pinned walk anchors a key its entries never use. */
  function unsignedWithAnchoredKey(): { exp: RecordAuditExportInput; pin: string; activatedAt: string } {
    const exp = load('unsigned.json');
    const signed = load('valid.json');
    exp.exportMetadata.signingPublicKeys = signed.exportMetadata.signingPublicKeys!;
    exp.exportMetadata.signingKeyStatements = signed.exportMetadata.signingKeyStatements!;
    const keyId = Object.keys(signed.exportMetadata.signingKeyWindows!)[0]!;
    return { exp, pin: pinOf(signed), activatedAt: signed.exportMetadata.signingKeyWindows![keyId]!.activatedAt };
  }

  it('pinned, unsigned entries written before the anchored key\'s signed activation stay reduced coverage', () => {
    const { exp, pin, activatedAt } = unsignedWithAnchoredKey();
    expect(exp.entries.every((e) => Date.parse(e.createdAt!) < Date.parse(activatedAt))).toBe(true);
    const r = verifyAuditExport(exp, { trustAnchors: [pin] });
    expect(r.valid).toBe(true);
    expect(r.keyTrust.anchoredKeyIds).toHaveLength(1);
    expect(r.signatureCoverage.skipped).toBe(3);
  });

  it('pinned, unsigned entries written after the anchored key\'s signed activation fail CHAIN_ENTRY_UNSIGNED with the windows stripped', () => {
    const { exp, pin, activatedAt } = unsignedWithAnchoredKey();
    for (const e of exp.entries) e.createdAt = new Date(Date.parse(activatedAt) + 3_600_000).toISOString();
    const signed = load('valid.json');
    const withWindows = structuredClone(exp);
    withWindows.exportMetadata.signingKeyWindows = signed.exportMetadata.signingKeyWindows!;
    expect(verifyAuditExport(withWindows, { trustAnchors: [pin] }).brokenAt?.code).toBe('CHAIN_ENTRY_UNSIGNED');
    // The windows are the export's unsigned word; without them the statements still date the key.
    delete exp.exportMetadata.signingKeyWindows;
    const r = verifyAuditExport(exp, { trustAnchors: [pin] });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_ENTRY_UNSIGNED' });
    // A window moved later cannot loosen it either.
    const late = structuredClone(withWindows);
    for (const w of Object.values(late.exportMetadata.signingKeyWindows!)) w.activatedAt = '2027-01-01T00:00:00.000Z';
    expect(verifyAuditExport(late, { trustAnchors: [pin] }).brokenAt?.code).toBe('CHAIN_ENTRY_UNSIGNED');
    // Without a pin nothing is signed, and nothing dates the key.
    expect(verifyAuditExport(exp).valid).toBe(true);
  });

  it('an unsigned history needs no anchor to stay reduced coverage', () => {
    const r = verifyAuditExport(load('unsigned.json'), { trustAnchors: [STRANGER] });
    expect(r.valid).toBe(true);
    expect(r.signatureCoverage.skipped).toBe(3);
  });
});

describe('a distrusted key\'s edges on the export path, whatever write time the file gives', () => {
  // Root R is pinned and admitted C; C is distrusted from T1, and whoever
  // holds C's leaked half admits X after that and signs the export under X.
  const r0 = makeKey();
  const c = makeKey();
  const x = makeKey();
  const root = statement('genesis', r0, { signers: [r0], activatedAt: T0 });
  const admitC = statement('succession', c, { endorser: r0, signers: [r0, c], activatedAt: T0 });
  const succ = statement('succession', x, { endorser: c, signers: [c, x], activatedAt: T2 });

  it.each([
    ['no write times', undefined],
    ['a write time forged before the cutoff', '2026-09-01T12:00:00.000000Z'],
    ['the true write time after the cutoff', '2026-10-02T15:00:00.000000Z'],
  ])('an export carrying the admission with %s does not anchor the key it admits', (_label, at) => {
    const exp = resignedUnder(x);
    const m = exp.exportMetadata;
    m.signingPublicKeys = { [r0.kid]: r0.publicKey, [c.kid]: c.publicKey, [x.kid]: x.publicKey };
    m.signingKeyWindows = {
      [r0.kid]: { activatedAt: '2026-09-01T00:00:00.000Z', retiredAt: null },
      [c.kid]: { activatedAt: '2026-09-01T00:00:00.000Z', retiredAt: null },
      [x.kid]: { activatedAt: '2026-09-03T00:00:00.000Z', retiredAt: null },
    };
    m.anchoredFrom = `sha256:${r0.digest}`;
    m.signingKeyStatements = {
      [r0.kid]: [published(root, at === undefined ? undefined : '2026-09-01T00:00:00.000000Z')],
      [c.kid]: [published(admitC, at === undefined ? undefined : '2026-09-01T00:00:00.000100Z')],
      [x.kid]: [published(succ, at)],
    };
    const r = verifyAuditExport(exp, { trustAnchors: [`sha256:${r0.digest}`], distrustedKeys: [`sha256:${c.digest}@${T1}`] });
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_SIGNING_KEY_UNANCHORED' });
    expect(r.keyTrust.unanchoredKeyIds).toContain(x.kid);
  });

  // The operator pins its current key N and supplies the /v1/verification-keys
  // document it fetched itself, where C was the genesis and N retired it; C is
  // distrusted.
  const genesis = statement('genesis', c, { signers: [c], activatedAt: T0 });
  const n = makeKey();
  const rot = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
  const closure = statement('closure', c, { endorser: n, signers: [n], retiredAt: T1 });
  const late = statement('succession', x, { endorser: c, signers: [c, x], activatedAt: '2026-09-01T06:00:00.000000Z' });
  const honest = {
    [c.kid]: [published(genesis, '2026-09-01T00:00:00.000100Z'), published(closure, '2026-09-02T00:00:00.000300Z')],
    [n.kid]: [published(rot, '2026-09-02T00:00:00.000200Z')],
  };
  const supplied = [
    { keyId: c.kid, publicKey: c.publicKey, activatedAt: '2026-09-01T00:00:00.000Z', retiredAt: '2026-09-02T00:00:00.000Z', statements: honest[c.kid]! },
    { keyId: n.kid, publicKey: n.publicKey, activatedAt: '2026-09-02T00:00:00.000Z', retiredAt: null, statements: honest[n.kid]! },
    { keyId: x.kid, publicKey: x.publicKey },
  ];
  const withStatements = (statements: Record<string, ReturnType<typeof published>[]>) => {
    const exp = resignedUnder(x);
    const m = exp.exportMetadata;
    m.signingPublicKeys = { [c.kid]: c.publicKey, [n.kid]: n.publicKey, [x.kid]: x.publicKey };
    m.signingKeyWindows = { [x.kid]: { activatedAt: '2026-09-01T06:00:00.000Z', retiredAt: null } };
    m.anchoredFrom = `sha256:${n.digest}`;
    m.signingKeyStatements = statements;
    return verifyAuditExport(exp, { publicKeys: supplied, trustAnchors: [`sha256:${n.digest}`], distrustedKeys: [`sha256:${c.digest}@2026-09-05T00:00:00Z`] });
  };

  it.each([
    ['its true write time', '2026-10-02T15:00:00.000000Z'],
    ['a write time forged before the closure', '2026-09-01T12:00:00.000000Z'],
  ])('beside an honest supplied document, an admission only the export carries, with %s, anchors nothing', (_label, at) => {
    const r = withStatements({ ...honest, [x.kid]: [published(late, at)] });
    expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_SIGNING_KEY_UNANCHORED' });
    expect(r.keyTrust.order).toBe('written');
    expect(r.keyTrust.anchoredKeyIds).not.toContain(x.kid);
  });

  it('an export stripped of its write times beside an honest supplied document anchors nothing either', () => {
    const stripped = Object.fromEntries(Object.entries(honest).map(([k, list]) => [k, list.map(({ kind, cose }) => ({ kind, cose }))]));
    const r = withStatements({ ...stripped, [x.kid]: [published(late)] });
    expect(r.keyTrust.order).toBe('signed');
    expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_SIGNING_KEY_UNANCHORED' });
  });
});

describe('an honest rotation from a key distrusted after it', () => {
  // Genesis C, rotation C->N, N retires C; the export is signed under N, and
  // the operator lists C in distrustedKeys from three days after the rotation.
  const c = makeKey();
  const n = makeKey();
  const genesis = statement('genesis', c, { signers: [c], activatedAt: T0 });
  const rot = statement('succession', n, { endorser: c, signers: [c, n], activatedAt: T1 });
  const closure = statement('closure', c, { endorser: n, signers: [n], retiredAt: T1 });
  const honest = {
    [c.kid]: [published(genesis, '2026-09-01T00:00:00.000100Z'), published(closure, '2026-09-02T00:00:00.000300Z')],
    [n.kid]: [published(rot, '2026-09-02T00:00:00.000200Z')],
  };
  const run = (pin: TestKey, distrustedKeys: string[]) => {
    const exp = resignedUnder(n);
    const m = exp.exportMetadata;
    m.signingPublicKeys = { [c.kid]: c.publicKey, [n.kid]: n.publicKey };
    m.signingKeyWindows = { [n.kid]: { activatedAt: '2026-09-02T00:00:00.000Z', retiredAt: null }, [c.kid]: { activatedAt: '2026-09-01T00:00:00.000Z', retiredAt: '2026-09-02T00:00:00.000Z' } };
    m.anchoredFrom = `sha256:${n.digest}`;
    m.signingKeyStatements = honest;
    const publicKeys = [
      { keyId: c.kid, publicKey: c.publicKey, activatedAt: '2026-09-01T00:00:00.000Z', retiredAt: '2026-09-02T00:00:00.000Z', statements: honest[c.kid]! },
      { keyId: n.kid, publicKey: n.publicKey, activatedAt: '2026-09-02T00:00:00.000Z', retiredAt: null, statements: honest[n.kid]! },
    ];
    return verifyAuditExport(exp, { publicKeys, trustAnchors: [`sha256:${pin.digest}`], distrustedKeys });
  };
  const distrustC = [`sha256:${c.digest}@2026-09-05T00:00:00Z`];

  it('pinned on the current key, passes as it does without distrust, and the voided rotation is a note, not a finding', () => {
    const plain = run(n, []);
    expect(plain.valid).toBe(true);
    expect(plain.keyTrust.notes).toEqual([]);
    const r = run(n, distrustC);
    expect(r.valid).toBe(true);
    expect(r.keyTrust).toMatchObject({ status: 'walked', findings: [] });
    expect(r.keyTrust.anchoredKeyIds).toEqual([c.kid, n.kid].sort());
    expect(r.keyTrust.notes).toEqual([expect.objectContaining({ keyId: n.kid, statementId: rot.id })]);
  });

  it('pinned only on the distrusted key, is refused: pin its successor', () => {
    expect(() => run(c, distrustC)).toThrow(/both a trust anchor and a distrusted key/);
  });
});

describe('key windows are RFC 3339', () => {
  const malformed = ['2026-10-02T15:03:54.500', '2026-10-02 15:03:54.5', 'Oct 2 2026 15:03:54', '2026-10-02T15:03:54.500+24:00', 'garbage', '2026-02-30T00:00:00Z', 7];

  it('a window the caller supplies that is not throws TypeError naming the key', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    const publicKey = exp.exportMetadata.signingPublicKeys![keyId]!;
    for (const bad of malformed) {
      for (const edge of ['activatedAt', 'retiredAt'] as const) {
        const entry = { keyId, publicKey, activatedAt: '2026-01-01T00:00:00Z', retiredAt: null, [edge]: bad } as unknown as { keyId: string; publicKey: string };
        expect(() => verifyAuditExport(load('valid.json'), { publicKeys: [entry] }), `${edge} ${String(bad)}`).toThrow(new RegExp(`key ${keyId}\\) has ${edge}`));
      }
    }
  });

  it('a window the export embeds that is not fails the entries under the key CHAIN_MALFORMED_ENTRY rather than skipping that edge', () => {
    for (const bad of malformed.filter((b): b is string => typeof b === 'string')) {
      for (const edge of ['activatedAt', 'retiredAt'] as const) {
        const exp = load('valid.json');
        const keyId = exp.entries[0]!.integrity.signingKeyId!;
        const window = exp.exportMetadata.signingKeyWindows![keyId]!;
        (window as Record<string, unknown>)[edge] = bad;
        const r = verifyAuditExport(exp);
        expect(r.brokenAt, `${edge} ${bad}`).toMatchObject({ position: 1, code: 'CHAIN_MALFORMED_ENTRY' });
        expect(r.brokenAt!.detail).toBe(`Key ${keyId}'s ${edge} ${JSON.stringify(bad)} is not an RFC 3339 instant, so the entry cannot be placed inside its window.`);
      }
    }
  });
});
