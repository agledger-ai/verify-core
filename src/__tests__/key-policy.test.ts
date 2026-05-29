import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';

/**
 * Regression guard for the null-key fail-closed fix: a high-assurance run
 * (requireKeyId / requireOutOfBandKeys) must NOT accept an entry whose
 * signingKeyId is null as valid. Without a key policy, a null-key entry is a
 * legitimate hash-chain-only ('skipped') row. This is the corpus's blind spot
 * (no real export ships a null-key entry mid-chain), so it is pinned here.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPORT_DIR = join(HERE, '..', '..', '..', '..', 'testdata', 'conformance', 'export');

function loadValid(): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'valid.json'), 'utf8')) as RecordAuditExportInput;
}

function loadOobKeys(): Record<string, string> {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'keys-oob.json'), 'utf8')) as Record<string, string>;
}

/** Null the signingKeyId of the second entry of a fresh copy of valid.json. */
function withNulledKeyAtPosition2(): RecordAuditExportInput {
  const exp = loadValid();
  const target = exp.entries[1];
  if (!target) throw new Error('fixture must have at least 2 entries');
  target.integrity = { ...target.integrity, signingKeyId: null };
  return exp;
}

/**
 * The signing-key id the real corpus uses on its signed entries. Derived from
 * the fixture (the engine mints it as a key fingerprint), not hardcoded — so
 * regenerating the corpus with a new vault key doesn't break this guard.
 */
function corpusKeyId(): string {
  const id = loadValid().entries[0]?.integrity.signingKeyId;
  if (!id) throw new Error('valid.json entry 1 must carry a signingKeyId');
  return id;
}

describe('null-key entry under a key policy fails closed', () => {
  it('passes (skipped) when no key policy is set', () => {
    const result = verifyAuditExport(withNulledKeyAtPosition2());
    expect(result.valid).toBe(true);
    expect(result.signatureCoverage.skipped).toBe(1);
  });

  it('fails CHAIN_KEY_POLICY_VIOLATION under requireKeyId', () => {
    const result = verifyAuditExport(withNulledKeyAtPosition2(), { requireKeyId: corpusKeyId() });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_POLICY_VIOLATION');
    expect(result.brokenAt?.position).toBe(2);
  });

  it('fails CHAIN_KEY_POLICY_VIOLATION under requireOutOfBandKeys', () => {
    const result = verifyAuditExport(withNulledKeyAtPosition2(), {
      publicKeys: loadOobKeys(),
      requireOutOfBandKeys: true,
    });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_POLICY_VIOLATION');
    expect(result.brokenAt?.position).toBe(2);
  });
});
