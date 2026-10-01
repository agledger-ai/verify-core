import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport, type RecordAuditExportInput } from '../audit-export.js';

/**
 * trustAnchors on the export path, over the corpus's real exports: the
 * statements an export carries are walked from the caller's pin, entries
 * under a key the walk does not anchor fail, and a result with no pin says
 * so rather than reading as clean.
 */

const EXPORT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'testdata', 'conformance', 'export');
const load = (name: string): RecordAuditExportInput =>
  JSON.parse(readFileSync(join(EXPORT_DIR, name), 'utf8')) as RecordAuditExportInput;
const pinOf = (exp: RecordAuditExportInput): string => {
  const pin = exp.exportMetadata.anchoredFrom;
  if (!pin) throw new Error('the corpus export carries anchoredFrom');
  return pin;
};
const STRANGER = `sha256:${'ab'.repeat(32)}`;

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
    expect(r.keyTrust).toMatchObject({ status: 'walked', order: 'signed', anchoredFromPinned: true, unanchoredKeyIds: [], findings: [] });
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
    const r = verifyAuditExport(exp, { publicKeys: JSON.parse(readFileSync(join(EXPORT_DIR, 'keys-oob-es256.json'), 'utf8')) as Record<string, string>, trustAnchors: [pinOf(exp)] });
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

  it('a distrusted key with no instant and no retirement is trusted for nothing, even as the pin', () => {
    const exp = load('valid.json');
    const r = verifyAuditExport(exp, { trustAnchors: [pinOf(exp)], distrustedKeys: [pinOf(exp)] });
    expect(r.brokenAt?.code).toBe('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('a key distrusted from an instant and never retired fails what it wrote after, worded as the distrust cutoff', () => {
    const exp = load('valid.json');
    const cutoff = '2026-09-30T22:06:08.770000Z';
    const r = verifyAuditExport(exp, { trustAnchors: [pinOf(exp)], distrustedKeys: [`${pinOf(exp)}@${cutoff}`] });
    const keyId = exp.entries[1]!.integrity.signingKeyId!;
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
    const { exp, pin } = unsignedWithAnchoredKey();
    for (const e of exp.entries) e.createdAt = '2026-09-30T23:00:00.000Z';
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
