import { describe, it, expect } from 'vitest';
import { verifyAuditExport, type VerifyExportOptions } from '../audit-export.js';
import { verifyChain } from '../chain.js';
import { computeKeyTrust, verdictOf } from '../key-statements.js';
import { load } from './export-fixtures.js';

/**
 * A caller upgrading from 1.x with `if (r.valid)` and the old option names
 * must not lose a check without a word: a renamed or unknown option throws,
 * and the result says in one word whether it is a trusted verdict.
 */

const pin = (): string => load('valid.json').exportMetadata.anchoredFrom!;

describe('options a verifier does not read are refused', () => {
  it('names the new option for one renamed in 2.0.0', () => {
    const opts = { requireOutOfBandKeys: true } as unknown as VerifyExportOptions;
    expect(() => verifyAuditExport(load('valid.json'), opts)).toThrow(/requireOutOfBandKeys option is now requireSuppliedKeys/);
    expect(() => verifyChain([], new Map(), { requireOutOfBandKeys: true } as never)).toThrow(/now requireSuppliedKeys/);
  });

  it('lists what it reads for a key it does not know, typos included', () => {
    const opts = { requireSupliedKeys: true } as unknown as VerifyExportOptions;
    expect(() => verifyAuditExport(load('valid.json'), opts)).toThrow(/unknown option requireSupliedKeys\. It reads publicKeys, requireKeyId, requireSuppliedKeys/);
    expect(() => computeKeyTrust({ keys: [], statements: [], trustAnchors: [pin()], anchors: [] } as never)).toThrow(/computeKeyTrust: unknown option anchors/);
  });

  it('refuses options that are not an object', () => {
    expect(() => verifyAuditExport(load('valid.json'), null as never)).toThrow(/options must be an object/);
    expect(() => verifyAuditExport(load('valid.json'), [] as never)).toThrow(/options must be an object/);
  });

  it('still enforces the renamed check under its new name', () => {
    const r = verifyAuditExport(load('valid.json'), { requireSuppliedKeys: true });
    expect(r.brokenAt?.code).toBe('CHAIN_KEY_POLICY_VIOLATION');
  });
});

describe('verdict', () => {
  it('is unanchored on a pass with no pin, trusted on a pinned pass, failed otherwise', () => {
    expect(verifyAuditExport(load('valid.json'))).toMatchObject({ valid: true, verdict: 'unanchored' });
    expect(verifyAuditExport(load('valid.json'), { trustAnchors: [pin()] })).toMatchObject({ valid: true, verdict: 'trusted' });
    expect(verifyAuditExport(load('hash-mismatch.json'), { trustAnchors: [pin()] })).toMatchObject({ valid: false, verdict: 'failed' });
    expect(verifyAuditExport(load('unsupported-version.json'))).toMatchObject({ valid: false, verdict: 'failed' });
  });

  it('is unanchored on an unsigned history pinned on any key', () => {
    const r = verifyAuditExport(load('unsigned.json'), { trustAnchors: [`sha256:${'ab'.repeat(32)}`] });
    expect(r).toMatchObject({ valid: true, verdict: 'unanchored' });
    expect(r.keyTrust.status).toBe('no_anchored_signature');
  });

  it('verdictOf reads valid and keyTrust.status alone', () => {
    expect(verdictOf({ valid: true, keyTrust: { status: 'walked' } })).toBe('trusted');
    expect(verdictOf({ valid: true, keyTrust: { status: 'no_anchor' } })).toBe('unanchored');
    expect(verdictOf({ valid: false, keyTrust: { status: 'walked' } })).toBe('failed');
  });
});

describe('publicKeys as the /v1/verification-keys body', () => {
  it('reads { data: [...] } as its array', () => {
    const exp = load('valid.json');
    const keyId = exp.entries[0]!.integrity.signingKeyId!;
    const data = [{ keyId, publicKey: exp.exportMetadata.signingPublicKeys![keyId]! }];
    const plain = verifyAuditExport(load('valid.json'), { publicKeys: data, requireSuppliedKeys: true });
    const wrapped = verifyAuditExport(load('valid.json'), { publicKeys: { data }, requireSuppliedKeys: true });
    expect(wrapped).toEqual(plain);
    expect(wrapped.keyProvenance.supplied).toBeGreaterThan(0);
  });

  it('keeps a key map whose key id is data', () => {
    expect(() => verifyAuditExport(load('valid.json'), { publicKeys: { data: 'not-a-key' } })).not.toThrow();
  });
});
