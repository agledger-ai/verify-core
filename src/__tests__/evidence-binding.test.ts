/**
 * The fixtures under fixtures/live-2.2.0/ are unmodified
 * `/audit-export?evidence=true` responses from a scratch Server 2.2.0: a gated
 * record taken through completion, reject, dispute, dispute evidence and an
 * OVERTURNED resolution (`export-evidence.json`), and an encrypted-mode record
 * whose completion carries an AES-256-GCM envelope and a submitter-computed
 * `evidenceHash` (`export-encrypted-evidence.json`).
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { verifyAuditExport, type RecordAuditExportInput } from '../index.js';

const LIVE = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'live-2.2.0');
const load = (name: string) => JSON.parse(readFileSync(join(LIVE, name), 'utf8')) as RecordAuditExportInput;
const anchorOf = (exp: RecordAuditExportInput) => [exp.exportMetadata.anchoredFrom!];
const entryOf = (exp: RecordAuditExportInput, type: string) => exp.entries.find((e) => e.entryType === type)!;

describe('evidence bodies inlined by ?evidence=true', () => {
  it('re-binds every inlined body to the hash its entry signs', () => {
    const exp = load('export-evidence.json');
    const r = verifyAuditExport(exp, { trustAnchors: anchorOf(exp) });
    expect(r.verdict).toBe('trusted');
    expect(r.optionalChecks.evidence_binding).toBe('applied');
    expect(r.evidenceBinding).toEqual({ present: 2, verified: 2, clientHashed: 0, failed: 0 });
  });

  for (const type of ['COMPLETION_SUBMITTED', 'DISPUTE_EVIDENCE']) {
    it(`fails an edited body on ${type}, naming both hashes`, () => {
      const exp = load('export-evidence.json');
      const entry = entryOf(exp, type);
      entry.evidence = { ...entry.evidence, edited: true };
      const r = verifyAuditExport(exp, { trustAnchors: anchorOf(exp) });
      expect(r.valid).toBe(false);
      expect(r.verdict).toBe('failed');
      expect(r.brokenAt?.code).toBe('CHAIN_EVIDENCE_BINDING_MISMATCH');
      expect(r.brokenAt?.detail).toContain(String(entry.payload![type === 'DISPUTE_EVIDENCE' ? 'payloadHash' : 'evidenceHash']));
      expect(r.evidenceBinding.failed).toBe(1);
      // The entry's signature verified before the body was refused, so it still counts toward provenance.
      expect(r.keyProvenance.supplied + r.keyProvenance.embedded).toBe(r.signatureCoverage.signed);
    });
  }

  it('hashes the RFC 8785 form, so reordered keys still bind', () => {
    const exp = load('export-evidence.json');
    const entry = entryOf(exp, 'COMPLETION_SUBMITTED');
    entry.evidence = Object.fromEntries(Object.entries(entry.evidence!).reverse());
    expect(verifyAuditExport(exp).evidenceBinding.verified).toBe(2);
  });

  it('fails a body attached to an entry that binds none, and a body that is not an object', () => {
    const exp = load('export-evidence.json');
    exp.entries[0]!.evidence = { summary: 'attached where nothing signs it' };
    expect(verifyAuditExport(exp).brokenAt?.detail).toMatch(/RECORD_CREATED entry inlines an evidence body/);
    const arr = load('export-evidence.json');
    (entryOf(arr, 'DISPUTE_EVIDENCE') as { evidence: unknown }).evidence = ['x'];
    expect(verifyAuditExport(arr).brokenAt?.code).toBe('CHAIN_EVIDENCE_BINDING_MISMATCH');
  });

  it('reads a null evidence as no body, as a model that dumps absent fields writes it', () => {
    const exp = load('export-evidence.json');
    for (const e of exp.entries) if (e.evidence === undefined) (e as { evidence: unknown }).evidence = null;
    expect(verifyAuditExport(exp).evidenceBinding).toEqual({ present: 2, verified: 2, clientHashed: 0, failed: 0 });
  });

  it('counts an encrypted-mode completion as client-hashed rather than re-binding its ciphertext', () => {
    const exp = load('export-encrypted-evidence.json');
    expect(entryOf(exp, 'COMPLETION_SUBMITTED').payload!.verifiedBy).toBe('client');
    const r = verifyAuditExport(exp, { trustAnchors: anchorOf(exp) });
    expect(r.verdict).toBe('trusted');
    expect(r.evidenceBinding).toEqual({ present: 1, verified: 0, clientHashed: 1, failed: 0 });
  });

  it('an export without inlined evidence skips the check', () => {
    const exp = load('export-evidence.json');
    for (const e of exp.entries) delete e.evidence;
    const r = verifyAuditExport(exp);
    expect(r.optionalChecks.evidence_binding).toBe('skipped_no_input');
    expect(r.evidenceBinding).toEqual({ present: 0, verified: 0, clientHashed: 0, failed: 0 });
  });
});
