import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';

/**
 * F-698 regression: `options.publicKeys` accepts BOTH the compact
 * `Record<keyId, b64SPKI>` shape AND the SDK-natural `VerificationKey[]`
 * shape (the .data list from `client.verificationKeys.list()`). A wrong
 * shape must throw `TypeError` at the boundary — never silently fall
 * through to the export's embedded keys, which would lie about the
 * audit-independence claim (`keyProvenance.outOfBand === 0` with `valid: true`).
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPORT_DIR = join(HERE, '..', '..', 'testdata', 'conformance', 'export');

function loadValid(): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'valid.json'), 'utf8')) as RecordAuditExportInput;
}

function loadOobKeys(): Record<string, string> {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'keys-oob.json'), 'utf8')) as Record<string, string>;
}

/** The SDK-natural shape: an array of { keyId, publicKey, ... } entries. */
function oobAsSdkArray(): Array<{ keyId: string; publicKey: string; activatedAt?: string; retiredAt?: string | null }> {
  const map = loadOobKeys();
  return Object.entries(map).map(([keyId, publicKey]) => ({ keyId, publicKey }));
}

describe('F-698: verifyAuditExport publicKeys polymorphism', () => {
  it('accepts Record<keyId, b64SPKI> form and routes signatures to OOB keys', () => {
    const result = verifyAuditExport(loadValid(), { publicKeys: loadOobKeys() });
    expect(result.valid).toBe(true);
    expect(result.keyProvenance.outOfBand).toBeGreaterThan(0);
    expect(result.keyProvenance.embedded).toBe(0);
  });

  it('accepts the natural SDK VerificationKey[] shape and routes signatures to OOB keys', () => {
    const result = verifyAuditExport(loadValid(), { publicKeys: oobAsSdkArray() });
    expect(result.valid).toBe(true);
    expect(result.keyProvenance.outOfBand).toBeGreaterThan(0);
    expect(result.keyProvenance.embedded).toBe(0);
  });

  it('throws TypeError when an array entry is missing keyId', () => {
    const bad = [{ publicKey: 'AAA=' }] as unknown as Parameters<typeof verifyAuditExport>[1] extends infer O
      ? O extends { publicKeys?: infer P } ? P : never : never;
    expect(() => verifyAuditExport(loadValid(), { publicKeys: bad })).toThrow(TypeError);
  });

  it('throws TypeError when an array entry is missing publicKey', () => {
    const bad = [{ keyId: 'k1' }] as unknown as Parameters<typeof verifyAuditExport>[1] extends infer O
      ? O extends { publicKeys?: infer P } ? P : never : never;
    expect(() => verifyAuditExport(loadValid(), { publicKeys: bad })).toThrow(TypeError);
  });

  it('throws TypeError when an array entry is null/primitive', () => {
    const bad = [null] as unknown as Parameters<typeof verifyAuditExport>[1] extends infer O
      ? O extends { publicKeys?: infer P } ? P : never : never;
    expect(() => verifyAuditExport(loadValid(), { publicKeys: bad })).toThrow(TypeError);
  });

  it('throws TypeError when a Record value is not a base64 string', () => {
    const bad = { k1: 12345 } as unknown as Parameters<typeof verifyAuditExport>[1] extends infer O
      ? O extends { publicKeys?: infer P } ? P : never : never;
    expect(() => verifyAuditExport(loadValid(), { publicKeys: bad })).toThrow(TypeError);
  });

  it('throws TypeError on a non-object, non-array publicKeys', () => {
    const bad = 'not-a-key-map' as unknown as Parameters<typeof verifyAuditExport>[1] extends infer O
      ? O extends { publicKeys?: infer P } ? P : never : never;
    expect(() => verifyAuditExport(loadValid(), { publicKeys: bad })).toThrow(TypeError);
  });
});

/**
 * F-698 temporal-axis regression: when the caller supplies a key out of band,
 * the export's own (untrusted) `signingKeyWindows` MUST NOT overwrite that
 * key's activation/retirement window. A compromised export could otherwise
 * hide a retirement by setting `retiredAt: null` and silently pass entries
 * signed by a key the auditor knows to be retired.
 */
describe('F-698 temporal axis: signingKeyWindows must not clobber OOB keys', () => {
  it('OOB retiredAt survives export signingKeyWindows and fires CHAIN_KEY_EXPIRED', () => {
    const exp = loadValid();
    const map = loadOobKeys();
    const keyId = Object.keys(map)[0]!;
    // Pre-condition: the valid fixture carries signingKeyWindows for this
    // keyId with retiredAt:null. If it ever stops, this test is no longer
    // exercising the clobber bug — make sure the fixture still triggers it.
    const exportWindow = exp.exportMetadata?.signingKeyWindows?.[keyId];
    expect(exportWindow).toBeDefined();
    expect(exportWindow?.retiredAt).toBeNull();
    // Auditor's OOB anchor says the key was retired before the entries were
    // signed. Without the fix, the export's signingKeyWindows would overwrite
    // this and key_temporal passes. With the fix, the OOB window sticks and
    // CHAIN_KEY_EXPIRED fires — the audit-independence claim survives.
    const result = verifyAuditExport(exp, {
      publicKeys: [
        {
          keyId,
          publicKey: map[keyId]!,
          activatedAt: '2023-01-01T00:00:00.000Z',
          retiredAt: '2024-01-01T00:00:00.000Z',
        },
      ],
    });
    // keyProvenance counters increment on successful signature verify; the
    // temporal check fires earlier so no signature counter ticks here. The
    // observable signal of the fix is the temporal verdict itself.
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_EXPIRED');
    expect(result.optionalChecks.key_temporal).toBe('applied');
  });
});
