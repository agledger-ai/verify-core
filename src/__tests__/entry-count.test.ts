import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';

// A chain cut from the end still links and verifies entry by entry. Its
// length is the only thing that shows the cut, so the verifier holds it to the
// two counts the export states.

const LIVE = join(import.meta.dirname, 'fixtures', 'live-2.0.0');

function load(): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(LIVE, 'export-lifecycle.json'), 'utf8')) as RecordAuditExportInput;
}

describe('the export chain is held to the entry counts it states', () => {
  it('passes whole, and reports the counts it was held to', () => {
    const exp = load();
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(true);
    expect(result.entryCount).toEqual({ expectedEntries: null, statedEntries: 9 });
  });

  it('fails a tail cut that leaves totalEntries standing, with no checkpoint yet', () => {
    for (const cut of [1, 3, 6]) {
      const exp = load();
      exp.entries!.splice(-cut);
      const result = verifyAuditExport(exp);
      expect(result.valid, `cut ${cut}`).toBe(false);
      expect(result.verdict).toBe('failed');
      expect(result.brokenAt).toMatchObject({ position: 9 - cut + 1, code: 'CHAIN_POSITION_GAP' });
    }
  });

  it('fails a chain shorter than its checkpoint position, whatever totalEntries says', () => {
    const exp = load();
    exp.exportMetadata.expectedEntries = 7;
    exp.entries!.splice(4);
    exp.exportMetadata.totalEntries = 4;
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toMatchObject({ position: 7, code: 'CHECKPOINT_ROW_MISSING' });
    expect(result.entryCount).toEqual({ expectedEntries: 7, statedEntries: 4 });
  });

  it('passes a chain at, or grown past, its checkpoint position', () => {
    for (const expected of [9, 7, 0]) {
      const exp = load();
      exp.exportMetadata.expectedEntries = expected;
      expect(verifyAuditExport(exp).valid, `checkpoint at ${expected}`).toBe(true);
    }
  });

  it('refuses a count that is not a non-negative integer', () => {
    for (const name of ['expectedEntries', 'totalEntries'] as const) {
      for (const bad of ['7', 7.5, -1, true, {}]) {
        const exp = load();
        (exp.exportMetadata as Record<string, unknown>)[name] = bad;
        const result = verifyAuditExport(exp);
        expect(result.valid, `${name}=${JSON.stringify(bad)}`).toBe(false);
        expect(result.brokenAt).toMatchObject({ position: 0, code: 'UNSUPPORTED_FORMAT' });
      }
    }
  });

  it('holds an export that states neither count to nothing, and says so', () => {
    const exp = load();
    delete exp.exportMetadata.totalEntries;
    delete exp.exportMetadata.expectedEntries;
    exp.entries!.splice(-2);
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(true);
    expect(result.entryCount).toEqual({ expectedEntries: null, statedEntries: null });
  });

  it('reports the chain finding first when the chain itself is broken', () => {
    const exp = load();
    exp.entries!.splice(2, 1);
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.position).toBe(4);
    expect(result.brokenAt?.detail ?? '').not.toContain('The export states');
  });
});
