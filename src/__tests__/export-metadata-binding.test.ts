import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decode as cborDecode } from 'cborg';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';
import { extractChainClaim, decodePredicate } from '../primitives.js';
import { STRICT_CBOR_DECODE } from '../cbor-strict.js';
import { load } from './export-fixtures.js';

// The export's metadata is unsigned, so whoever edits it must not be able to
// change what the verdict is about or switch a check off.

const LIVE = join(import.meta.dirname, 'fixtures', 'live-2.0.0', 'export-lifecycle.json');
const live = (): RecordAuditExportInput => JSON.parse(readFileSync(LIVE, 'utf8')) as RecordAuditExportInput;
const OTHER = '11111111-2222-4333-8444-555555555555';

describe('the record id a result reports is the one the entries sign', () => {
  it('reports the signed id of an untouched export', () => {
    const exp = live();
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(true);
    expect(r.recordId).toBe(exp.exportMetadata.recordId);
  });

  it('fails when exportMetadata.recordId names another record, and reports the signed id', () => {
    const exp = live();
    const signed = exp.exportMetadata.recordId;
    exp.exportMetadata.recordId = OTHER;
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.verdict).toBe('failed');
    expect(r.brokenAt).toMatchObject({ code: 'CHAIN_PAYLOAD_BINDING_MISMATCH' });
    expect(r.recordId).toBe(signed);
  });

  it('holds the signed predicate to the id when the entries carry no recordId column or payload', () => {
    const exp = live();
    exp.exportMetadata.recordId = OTHER;
    for (const e of exp.entries) {
      delete e.recordId;
      delete e.payload;
      delete e.entryType;
    }
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });

  it('fails when the metadata names no record at all', () => {
    const exp = live();
    delete (exp.exportMetadata as Partial<typeof exp.exportMetadata>).recordId;
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.recordId).not.toBe('');
  });
});

describe('the entry count check is reported, and can be supplied out of band', () => {
  const stripped = (): RecordAuditExportInput => {
    const exp = live();
    delete exp.exportMetadata.expectedEntries;
    delete exp.exportMetadata.totalEntries;
    return exp;
  };

  it('is applied while the export states a count, and skipped_no_input once the counts are deleted', () => {
    expect(verifyAuditExport(live()).optionalChecks.entry_count).toBe('applied');
    const r = verifyAuditExport(stripped());
    expect(r.optionalChecks.entry_count).toBe('skipped_no_input');
    expect(r.entryCount).toEqual({ expectedEntries: null, statedEntries: null });
  });

  it('a truncated export with its stated counts deleted passes only as an unchecked count', () => {
    const exp = stripped();
    exp.entries.splice(-3);
    const r = verifyAuditExport(exp);
    expect(r.optionalChecks.entry_count).toBe('skipped_no_input');
  });

  it('fails a truncation against expectedEntryCount, however the metadata was edited', () => {
    const exp = stripped();
    exp.entries.splice(-3);
    const r = verifyAuditExport(exp, { expectedEntryCount: 9 });
    expect(r.valid).toBe(false);
    expect(r.optionalChecks.entry_count).toBe('applied');
    expect(r.brokenAt).toMatchObject({ position: 7, code: 'CHAIN_POSITION_GAP' });
  });

  it('fails an export with more entries than expectedEntryCount, and passes an exact match', () => {
    expect(verifyAuditExport(live(), { expectedEntryCount: 9 }).valid).toBe(true);
    const r = verifyAuditExport(live(), { expectedEntryCount: 8 });
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.code).toBe('CHAIN_POSITION_GAP');
  });

  it('throws on an expectedEntryCount that is not a non-negative integer', () => {
    for (const bad of [-1, 1.5, '9', Number.NaN, null]) {
      expect(() => verifyAuditExport(live(), { expectedEntryCount: bad as unknown as number })).toThrow(TypeError);
    }
  });
});

describe('payload and entryType cannot be deleted to skip their checks', () => {
  it('fails an entry that lost its payload while others carry theirs', () => {
    for (const field of ['payload', 'entryType'] as const) {
      const exp = live();
      if (field === 'payload') delete exp.entries[3]!.payload;
      else delete exp.entries[3]!.entryType;
      const r = verifyAuditExport(exp);
      expect(r.valid, field).toBe(false);
      expect(r.brokenAt).toMatchObject({ position: 4, code: 'CHAIN_PAYLOAD_BINDING_MISMATCH' });
      expect(r.optionalChecks.payload_binding).toBe('not_checked');
    }
  });

  it('fails an export with no payloads at all once federation keys are supplied', () => {
    const exp = live();
    for (const e of exp.entries) {
      delete e.payload;
      delete e.entryType;
    }
    expect(verifyAuditExport(exp).valid).toBe(true);
    expect(verifyAuditExport(exp).optionalChecks.payload_binding).toBe('skipped_no_input');
    const r = verifyAuditExport(exp, { federationKeys: { 'hub-a': Buffer.alloc(32, 1).toString('base64') } });
    expect(r.valid).toBe(false);
    expect(r.optionalChecks.federation_wire).toBe('not_checked');
  });

  it('fails inlined evidence on an entry with no payload', () => {
    const exp = live();
    delete exp.entries[2]!.payload;
    exp.entries[2]!.evidence = { any: 'body' };
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
  });
});

describe('the format gate refuses an export that does not state its format', () => {
  it('fails when exportFormatVersion or canonicalization is absent', () => {
    for (const field of ['exportFormatVersion', 'canonicalization'] as const) {
      const exp = live();
      if (field === 'exportFormatVersion') delete exp.exportMetadata.exportFormatVersion;
      else delete exp.exportMetadata.canonicalization;
      const r = verifyAuditExport(exp);
      expect(r.valid, field).toBe(false);
      expect(r.brokenAt?.code).toBe('UNSUPPORTED_FORMAT');
      expect(r.brokenAt?.detail).toContain(`no ${field}`);
    }
  });

  it('still reads the corpus export as the format it states', () => {
    expect(load('valid.json').exportMetadata.exportFormatVersion).toBe('2.0');
  });
});

describe('signed CBOR is decoded strictly', () => {
  const dup = Uint8Array.from([0xa2, 0x01, 0x01, 0x01, 0x02]); // {1:1, 1:2}
  const nonMinimal = Uint8Array.from([0x18, 0x05]); // 5 as a one-byte uint
  const indefinite = Uint8Array.from([0x9f, 0x01, 0xff]); // [_ 1]

  it('rejects duplicate map keys, non-minimal integers and indefinite lengths', () => {
    for (const bytes of [dup, nonMinimal, indefinite]) {
      expect(() => cborDecode(bytes, { ...STRICT_CBOR_DECODE, useMaps: true })).toThrow();
    }
  });

  it('a protected header that repeats a label is not a decodable chain claim', () => {
    const pair = [0x3a, 0x00, 0x01, 0x00, 0x00, 0xa2, 0x01, 0x01, 0x02, 0xf6]; // -65537: {1: 1, 2: null}
    expect(extractChainClaim(Uint8Array.from([0xa1, ...pair]))).toEqual({ position: 1, previous_hash: null });
    expect(extractChainClaim(Uint8Array.from([0xa2, ...pair, ...pair]))).toBeNull();
  });

  it('a statement that repeats a key does not decode', () => {
    expect(decodePredicate(Uint8Array.from([0xa1, 0x69, ...Buffer.from('predicate'), 0xa1, 0x61, 0x61, 0x01]))).toEqual({ a: 1 });
    expect(decodePredicate(Uint8Array.from([0xa2, 0x69, ...Buffer.from('predicate'), 0xa0, 0x69, ...Buffer.from('predicate'), 0xa0]))).toBeNull();
  });
});
