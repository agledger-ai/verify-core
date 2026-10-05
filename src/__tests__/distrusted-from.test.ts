import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { verifyAuditExport, type RecordAuditExportInput } from '../audit-export.js';
import { computeKeyTrust, keyStatementsFromVerificationKeys, type DistrustedKey, type KeyTrust, type TrustKeyInput } from '../key-statements.js';
import { T0, T1, T2, asDocument, makeKey, ms, statement, type Stored, type TestKey } from './key-statements-helpers.js';

/**
 * `distrustedFrom` on a listed key: the Server's VAULT_DISTRUSTED_KEYS instant,
 * where its published `retiredAt` was cut. It only words the finding the
 * window check makes anyway; every case below makes the same findings, by
 * code, key and statement, and the same trusted keys and windows, with the
 * field as without it.
 */

/** Between the successor's admission (T1) and the closure it signed (T2). */
const CUT = '2026-09-02T12:00:00.123456Z';
const LATER = '2026-09-02T18:00:00.000000Z';
const EARLIER = '2026-09-02T06:00:00.000000Z';
const AFTER_CLOSURE = '2026-09-03T06:00:00.000000Z';

/** A key as a key document lists it. */
function listed(k: TestKey, activatedAt: string, retiredAt: string | null, distrustedFrom?: string): TrustKeyInput {
  return {
    keyId: k.kid,
    publicKey: k.publicKey,
    algorithm: k.alg,
    status: retiredAt === null ? 'active' : 'retired',
    activatedAt: ms(activatedAt),
    retiredAt: retiredAt === null ? null : ms(retiredAt),
    ...(distrustedFrom !== undefined ? { distrustedFrom } : {}),
  };
}

/** The old key `k` hands over to `f`, which retires it at T2 (or never). */
function rotation(closed = true) {
  const k = makeKey();
  const f = makeKey();
  const statements: Stored[] = [
    statement('genesis', k, { signers: [k], activatedAt: T0, createdAt: T0 }),
    statement('succession', f, { endorser: k, signers: [k, f], activatedAt: T1, createdAt: T1 }),
  ];
  if (closed) statements.push(statement('closure', k, { endorser: f, signers: [f], retiredAt: T2, createdAt: T2 }));
  return { k, f, statements: asDocument(statements) };
}

function walk(r: ReturnType<typeof rotation>, kListing: TrustKeyInput, distrusted?: DistrustedKey[]): KeyTrust {
  return computeKeyTrust({
    keys: [kListing, listed(r.f, T1, null)],
    statements: r.statements,
    trustAnchors: [`sha256:${r.f.digest}`],
    ...(distrusted ? { distrustedKeys: distrusted } : {}),
  });
}

/** The wording the walk gives a listed retirement the Server's distrust entry cut. */
const lead = (k: TestKey, signed: string) => `retiredAt ${ms(CUT)} is listed as the Server's distrust cutoff for ${k.kid} (distrustedFrom ${CUT}), and ${signed}`;
const caution = (k: TestKey) => `The listing's instant is its unsigned word, so until the Server's operator confirms the entry, read the listed retirement as unexplained. Off a dump the entry also voids every admission ${k.kid} signed, so a key it admitted that nothing else reaches is no longer trusted and its window no longer graded.`;
const missing = (k: TestKey, signed: string) => `${lead(k, signed)}: the listing says the Server distrusts the key from that instant (VAULT_DISTRUSTED_KEYS), and this walk was given no distrust entry for it. If the operator confirms it, give distrustedKeys sha256:${k.digest}@${CUT}. ${caution(k)}`;
const disagree = (k: TestKey, signed: string, given: string) => `${lead(k, signed)}: the distrust entry given for it (${given}) and the one the listing says the Server applies (VAULT_DISTRUSTED_KEYS, from ${CUT}) disagree. Confirm the instant with the Server's operator. ${caution(k)}`;

const shape = (t: KeyTrust) => ({
  findings: t.findings.map((f) => [f.code, f.keyId, f.statementId]),
  trusted: [...t.trusted].sort(),
  windows: [...t.byDigest.values()].map((e) => [e.spkiSha256, e.activatedAt, e.retiredAt, e.distrustCutoff]),
});

/** The walk with and without the listing's distrustedFrom, which must differ only in wording. */
function both(r: ReturnType<typeof rotation>, retiredAt: string | null, from: string, distrusted?: DistrustedKey[]) {
  const withFrom = walk(r, listed(r.k, T0, retiredAt, from), distrusted);
  const without = walk(r, listed(r.k, T0, retiredAt), distrusted);
  expect(shape(withFrom)).toEqual(shape(without));
  // Every note the walk makes without the field it makes with it; `added` is
  // what the field says on top.
  const key = (n: KeyTrust['notes'][number]) => JSON.stringify(n);
  const before = new Set(without.notes.map(key));
  expect(without.notes.every((n) => withFrom.notes.some((m) => key(m) === key(n)))).toBe(true);
  return { withFrom, without, added: withFrom.notes.filter((n) => !before.has(key(n))) };
}

describe('a listed key carrying distrustedFrom', () => {
  it('cut at that instant, with no entry given, names the Server\'s distrust entry the walk lacks and still fails', () => {
    const r = rotation();
    const { withFrom, without, added } = both(r, CUT, CUT);
    expect(withFrom.findings).toHaveLength(1);
    expect(withFrom.findings[0]).toMatchObject({ code: 'CHAIN_KEY_WINDOW_DRIFT', keyId: r.k.kid, statementId: null });
    expect(withFrom.findings[0]!.detail).toBe(missing(r.k, `the retirement its closures sign is ${T2}`));
    expect(without.findings[0]!.detail).toBe(`retiredAt ${ms(CUT)} differs from the signed ${T2}`);
    expect(added).toEqual([]);
  });

  it('with the entry it names, passes as it did', () => {
    const r = rotation();
    const { withFrom, added } = both(r, CUT, CUT, [{ spkiSha256: r.k.digest, cutoff: CUT }]);
    expect(withFrom.findings).toEqual([]);
    expect(added).toEqual([]);
  });

  it('with an entry at a later instant than the Server\'s, says the two disagree, on either side of the signed retirement', () => {
    for (const given of [LATER, AFTER_CLOSURE]) {
      const r = rotation();
      const { withFrom, added } = both(r, CUT, CUT, [{ spkiSha256: r.k.digest, cutoff: given }]);
      expect(withFrom.findings.map((f) => [f.code, f.keyId])).toEqual([['CHAIN_KEY_WINDOW_DRIFT', r.k.kid]]);
      expect(withFrom.findings[0]!.detail).toBe(disagree(r.k, `the retirement its closures sign is ${T2}`, `from ${given}`));
      expect(added).toEqual([]);
    }
  });

  it('with an entry that has no instant, says the two disagree', () => {
    const r = rotation();
    const { withFrom } = both(r, CUT, CUT, [{ spkiSha256: r.k.digest, cutoff: null }]);
    expect(withFrom.findings.map((f) => f.code)).toEqual(['CHAIN_KEY_WINDOW_DRIFT']);
    expect(withFrom.findings[0]!.detail).toBe(disagree(r.k, `the retirement its closures sign is ${T2}`, 'with no instant'));
  });

  it('with an entry at an earlier instant, which fails nothing on the window, says so in a note that fails nothing', () => {
    const r = rotation();
    const { withFrom, added } = both(r, CUT, CUT, [{ spkiSha256: r.k.digest, cutoff: EARLIER }]);
    expect(withFrom.findings).toEqual([]);
    expect(added).toEqual([{
      keyId: r.k.kid,
      statementId: null,
      detail: `distrustedKeys gives ${r.k.kid} the instant ${EARLIER}, and the listing says the Server distrusts it from ${CUT} (distrustedFrom, VAULT_DISTRUSTED_KEYS): the auditor's entry and the one the listing gives disagree, so what the key signed between the two instants is graded differently here than on the Server. Confirm the instant with the Server's operator.`,
    }]);
  });

  it('cut where no closure retires the key, the KEY_CLOSURE_INVALID it was names the missing entry, and the entry clears it', () => {
    const r = rotation(false);
    const { withFrom } = both(r, CUT, CUT);
    expect(withFrom.findings.map((f) => [f.code, f.keyId])).toEqual([['KEY_CLOSURE_INVALID', r.k.kid]]);
    expect(withFrom.findings[0]!.detail).toBe(missing(r.k, 'no closure this walk could verify retires it'));
    expect(both(r, CUT, CUT, [{ spkiSha256: r.k.digest, cutoff: CUT }]).withFrom.findings).toEqual([]);
  });

  it('keeps the drift wording where the listed retirement is not the Server\'s instant, the walk retires the key no later, or the instant does not parse', () => {
    const r = rotation();
    // Listed earlier than distrustedFrom.
    expect(both(r, EARLIER, CUT).withFrom.findings.map((f) => f.detail)).toEqual([`retiredAt ${ms(EARLIER)} differs from the signed ${T2}`]);
    // distrustedFrom after the signed retirement, listed at it: honest, nothing to say.
    expect(both(r, T2, AFTER_CLOSURE).withFrom.findings).toEqual([]);
    // Listed at distrustedFrom, which is later than the retirement the walk signs.
    expect(both(r, AFTER_CLOSURE, AFTER_CLOSURE).withFrom.findings.map((f) => f.detail)).toEqual([`retiredAt ${ms(AFTER_CLOSURE)} differs from the signed ${T2}`]);
    // Not strict RFC 3339 (no offset).
    expect(both(r, CUT, '2026-09-02T12:00:00.123456').withFrom.findings.map((f) => f.detail)).toEqual([`retiredAt ${ms(CUT)} differs from the signed ${T2}`]);
    // A key the walk does not trust is never graded, whatever it lists.
    const stranger = makeKey();
    const t = computeKeyTrust({ keys: [listed(stranger, T0, CUT, CUT)], statements: r.statements, trustAnchors: [`sha256:${r.f.digest}`] });
    expect(t.findings).toEqual([]);
  });

  it('is read from a key document', () => {
    const r = rotation();
    const doc = keyStatementsFromVerificationKeys({
      data: [
        { keyId: r.k.kid, publicKey: r.k.publicKey, status: 'retired', activatedAt: ms(T0), retiredAt: ms(CUT), distrustedFrom: CUT },
        { keyId: r.f.kid, publicKey: r.f.publicKey, status: 'active', activatedAt: ms(T1), retiredAt: null },
      ],
    });
    expect(doc.keys[0]!.distrustedFrom).toBe(CUT);
    expect(doc.keys[1]).not.toHaveProperty('distrustedFrom');
  });
});

/**
 * An unmodified agledger-api 2.0 audit export of a record its first key K
 * signed, taken after the Server retired K with force from its successor F
 * and was restarted with VAULT_DISTRUSTED_KEYS=sha256:<K>@<instant>, an
 * instant before that retirement: signingKeyWindows lists K retired at the
 * instant, with distrustedFrom.
 */
describe('a live export after a dated distrust entry', () => {
  const load = () => JSON.parse(readFileSync(new URL('./fixtures/live-2.0.0/export-dated-distrust.json', import.meta.url), 'utf8')) as RecordAuditExportInput;
  const F = 'sha256:78e7bba47a2dccdb1dbf4f2dc81dc58a5c58735abe480de49d05081d3452aa3a';
  const K = 'b649db0ec7c5c0fd921c2cb4d40466d91f4d98252dad2f7c0243851167b2d09e';
  const FROM = '2026-10-05T23:03:51.537314Z';

  it('pinned on F alone, fails CHAIN_KEY_WINDOW_DRIFT naming the Server\'s entry; with that entry, passes; with another instant, says they disagree', () => {
    const windows = load().exportMetadata.signingKeyWindows!;
    expect(windows[K.slice(0, 16)]).toEqual({ activatedAt: '2026-10-05T23:03:18.193Z', retiredAt: '2026-10-05T23:03:51.537Z', distrustedFrom: FROM });

    const pinOnly = verifyAuditExport(load(), { trustAnchors: [F] });
    expect(pinOnly.valid).toBe(false);
    expect(pinOnly.brokenAt).toMatchObject({ position: 0, code: 'CHAIN_KEY_WINDOW_DRIFT' });
    expect(pinOnly.brokenAt!.detail).toContain(`this walk was given no distrust entry for it. If the operator confirms it, give distrustedKeys sha256:${K}@${FROM}.`);

    const matching = verifyAuditExport(load(), { trustAnchors: [F], distrustedKeys: [`sha256:${K}@${FROM}`] });
    expect(matching).toMatchObject({ valid: true, verdict: 'trusted' });
    expect(matching.keyTrust.notes).toEqual([]);

    const later = verifyAuditExport(load(), { trustAnchors: [F], distrustedKeys: [`sha256:${K}@2026-10-05T23:04:00Z`] });
    expect(later.valid).toBe(false);
    expect(later.brokenAt!.detail).toContain(`the distrust entry given for it (from 2026-10-05T23:04:00.000000Z) and the one the listing says the Server applies (VAULT_DISTRUSTED_KEYS, from ${FROM}) disagree`);

    // Without the field the export fails at the same place, worded as drift.
    const stripped = load();
    delete stripped.exportMetadata.signingKeyWindows![K.slice(0, 16)]!.distrustedFrom;
    const bare = verifyAuditExport(stripped, { trustAnchors: [F] });
    expect(bare.brokenAt).toMatchObject({ position: 0, code: 'CHAIN_KEY_WINDOW_DRIFT' });
    expect(bare.brokenAt!.detail).toBe('retiredAt 2026-10-05T23:03:51.537Z differs from the signed 2026-10-05T23:04:11.954995Z');
  });
});
