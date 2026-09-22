import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';
import { decodeCoseSign1, extractActorClaim } from '../primitives.js';

/**
 * Actor attribution is signature-covered, so it is verified rather than
 * displayed on trust.
 *
 * The export's own verificationGuide names `actorDisplayName`,
 * `actorOwnerType` and `humanReadableLabel` as unsigned display projections
 * and tells the auditor that attribution IS the `actorId`/`actorOwnerId`
 * UUID. Those two, plus `actorRole`, ride in the COSE protected header at
 * CWT_Claims label 15 -> private label -65539. Before this check an export
 * could be re-attributed to another actor by editing the column and still
 * verify with out-of-band keys and requireOutOfBandKeys, which made the
 * guide's own advice unverifiable.
 *
 * Both fixtures are real engine output: the conformance corpus (admin actor)
 * and a live 1.8.0 lifecycle export (agent actor).
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPORT_DIR = join(HERE, '..', '..', 'testdata', 'conformance', 'export');
const LIVE_DIR = join(HERE, 'fixtures', 'live-1.8.0');

function loadCorpus(): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'valid.json'), 'utf8')) as RecordAuditExportInput;
}

function loadOobKeys(): Record<string, string> {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'keys-oob.json'), 'utf8')) as Record<string, string>;
}

function loadLive(): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(LIVE_DIR, 'export-lifecycle.json'), 'utf8')) as RecordAuditExportInput;
}

/** Structured-clone deep copy, so a tamper never leaks into another case. */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('actor-attribution cross-check', () => {
  it('extracts the signed actor claim and it equals the row columns on real engine output', () => {
    for (const doc of [loadCorpus(), loadLive()]) {
      for (const entry of doc.entries) {
        const parts = decodeCoseSign1(Buffer.from(entry.integrity.coseSign1, 'base64'));
        expect(parts).not.toBeNull();
        const claim = extractActorClaim(parts!.protectedBstr);
        expect(claim).not.toBeNull();
        expect(claim!.key_id).toBe(entry.actorId);
        expect(claim!.role).toBe(entry.actorRole);
        expect(claim!.owner_id).toBe(entry.actorOwnerId);
      }
    }
  });

  it('flips actor_attribution to applied on a clean export and still passes', () => {
    const result = verifyAuditExport(loadCorpus(), {
      publicKeys: loadOobKeys(),
      requireOutOfBandKeys: true,
    });
    expect(result.valid).toBe(true);
    expect(result.optionalChecks.actor_attribution).toBe('applied');
  });

  it('refuses an export re-attributed to another owner, under out-of-band keys', () => {
    const doc = clone(loadCorpus());
    const original = doc.entries[0]!.actorOwnerId;
    doc.entries[0]!.actorOwnerId = '00000000-0000-7000-8000-000000000000';
    expect(doc.entries[0]!.actorOwnerId).not.toBe(original);

    const result = verifyAuditExport(doc, {
      publicKeys: loadOobKeys(),
      requireOutOfBandKeys: true,
    });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_ACTOR_ATTRIBUTION_MISMATCH');
    expect(result.brokenAt?.detail).toContain('actorOwnerId');
  });

  it('refuses a rewritten actorId and a rewritten actorRole', () => {
    for (const [field, value] of [
      ['actorId', '00000000-0000-7000-8000-000000000001'],
      ['actorRole', 'platform'],
    ] as const) {
      const doc = clone(loadLive());
      (doc.entries[0] as Record<string, unknown>)[field] = value;
      const result = verifyAuditExport(doc);
      expect(result.valid).toBe(false);
      expect(result.brokenAt?.code).toBe('CHAIN_ACTOR_ATTRIBUTION_MISMATCH');
      expect(result.brokenAt?.detail).toContain(field);
    }
  });

  it('catches a re-attribution at a later position, not only the genesis entry', () => {
    const doc = clone(loadLive());
    expect(doc.entries.length).toBeGreaterThan(2);
    doc.entries[2]!.actorOwnerId = '00000000-0000-7000-8000-000000000002';
    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_ACTOR_ATTRIBUTION_MISMATCH');
    expect(result.brokenAt?.position).toBe(3);
  });

  it('skips rather than fails when the artifact carries no actor columns', () => {
    const doc = clone(loadCorpus());
    for (const entry of doc.entries) {
      delete (entry as Record<string, unknown>)['actorId'];
      delete (entry as Record<string, unknown>)['actorRole'];
      delete (entry as Record<string, unknown>)['actorOwnerId'];
    }
    const result = verifyAuditExport(doc, {
      publicKeys: loadOobKeys(),
      requireOutOfBandKeys: true,
    });
    expect(result.valid).toBe(true);
    expect(result.optionalChecks.actor_attribution).toBe('skipped_no_input');
  });
});
