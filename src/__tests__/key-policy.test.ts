import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';

/**
 * Regression guard for the null-key fail-closed fix: a high-assurance run
 * (requireKeyId / requireSuppliedKeys) must NOT accept an entry whose
 * signingKeyId is null as valid. Without a key policy, a null-key entry
 * written before the install began signing is a legitimate hash-chain-only
 * ('skipped') row. Built on the corpus's own unsigned export, whose entries
 * were written before any key was registered.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPORT_DIR = join(HERE, '..', '..', 'testdata', 'conformance', 'export');

function load(name: string): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(EXPORT_DIR, name), 'utf8')) as RecordAuditExportInput;
}

function loadOobKeys(): Record<string, string> {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'keys-oob.json'), 'utf8')) as Record<string, string>;
}

/**
 * The signing-key id the real corpus uses on its signed entries. Derived from
 * the fixture (the engine mints it as a key fingerprint), not hardcoded, so
 * regenerating the corpus with a new vault key doesn't break this guard.
 */
function corpusKeyId(): string {
  const id = load('valid.json').entries[0]?.integrity.signingKeyId;
  if (!id) throw new Error('valid.json entry 1 must carry a signingKeyId');
  return id;
}

describe('null-key entry under a key policy fails closed', () => {
  it('passes (skipped) when no key policy is set', () => {
    const result = verifyAuditExport(load('unsigned.json'));
    expect(result.valid).toBe(true);
    expect(result.signatureCoverage.skipped).toBe(3);
  });

  it('fails CHAIN_KEY_POLICY_VIOLATION under requireKeyId', () => {
    const result = verifyAuditExport(load('unsigned.json'), { requireKeyId: corpusKeyId() });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_POLICY_VIOLATION');
    expect(result.brokenAt?.position).toBe(1);
  });

  it('fails CHAIN_KEY_POLICY_VIOLATION under requireSuppliedKeys', () => {
    const result = verifyAuditExport(load('unsigned.json'), {
      publicKeys: loadOobKeys(),
      requireSuppliedKeys: true,
    });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_POLICY_VIOLATION');
    expect(result.brokenAt?.position).toBe(1);
  });

  it('reports CHAIN_ENTRY_UNSIGNED ahead of the policy when the entry could not have been unsigned', () => {
    // An unsigned entry after a signed one is evidence about the chain itself,
    // so the run reports it under its own code whatever policy it applies.
    const exp = load('valid.json');
    const target = exp.entries[1]!;
    target.integrity = { ...target.integrity, signingKeyId: null };
    const result = verifyAuditExport(exp, { requireKeyId: corpusKeyId() });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_ENTRY_UNSIGNED');
    expect(result.brokenAt?.position).toBe(2);
  });
});
