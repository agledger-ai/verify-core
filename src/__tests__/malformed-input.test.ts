import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import { underAdmittedKey } from './export-fixtures.js';
import type { RecordAuditExportInput } from '../audit-export.js';
import { buildKeyRegistry, verifyChain, type NormalizedEntry } from '../chain.js';
import { buildPredicateForRow } from '../primitives.js';
import {
  computeKeyTrust,
  keyStatementFromDumpRow,
  trustKeyFromDumpRow,
  type DumpKeyStatementRow,
  type DumpSigningKeyRow,
} from '../key-statements.js';

/**
 * Row data no engine writes: a nulled, dropped or retyped column. Each one is
 * a failure code on the entry it sits in, or a statement finding, never a
 * throw out of the walk and never a pass read off a check that was skipped.
 * Every case is a mutation of a real corpus vector.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_DIR = join(HERE, '..', '..', 'testdata', 'conformance');

function load<T = RecordAuditExportInput>(rel: string): T {
  return JSON.parse(readFileSync(join(CONFORMANCE_DIR, rel), 'utf8')) as T;
}

function ndjson<T>(rel: string): T[] {
  return readFileSync(join(CONFORMANCE_DIR, rel), 'utf8').split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as T);
}

/** The vault key valid.json is signed and anchored by. */
const ANCHOR = load('export/valid.json').exportMetadata.anchoredFrom!;
const KEY_ID = ANCHOR.slice('sha256:'.length, 'sha256:'.length + 16);

describe('an entry with no readable createdAt fails closed (CHAIN_MALFORMED_ENTRY)', () => {
  it('a distrusted key cannot be slipped past its cutoff by nulling the entry times', () => {
    // valid.json under a key its pinned root admitted, distrusted from the middle entry's write time.
    const build = () => {
      const { exp, pin, key } = underAdmittedKey();
      return { exp, options: { trustAnchors: [pin], distrustedKeys: [`sha256:${key.digest}@${exp.entries[1]!.createdAt!}`] }, keyId: key.kid };
    };
    const plain = build();
    const p = verifyAuditExport(plain.exp, plain.options);
    expect(p.valid).toBe(false);
    expect(p.entries.map((e) => e.code)).toContain('CHAIN_KEY_EXPIRED');

    for (const blank of [undefined, null, 'garbage', 7]) {
      const { exp, options, keyId } = build();
      for (const e of exp.entries) {
        if (blank === undefined) delete e.createdAt;
        else (e as { createdAt?: unknown }).createdAt = blank;
      }
      const r = verifyAuditExport(exp, options);
      expect(r.valid).toBe(false);
      expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_MALFORMED_ENTRY' });
      expect(r.brokenAt?.detail).toBe(`Entry has no parseable createdAt, so it cannot be placed inside key ${keyId}'s window.`);
      expect(r.optionalChecks.key_temporal).toBe('applied');
    }
  });

  it('a createdAt that is not strict RFC 3339 is no readable time, however the host would parse it', () => {
    // No offset (read in the host's zone), a space, a bare number, an impossible day.
    for (const odd of ['2026-09-01T00:00:00', '2026-09-01 00:00:00.000000Z', '1', '2026-02-30T00:00:00.000000Z', '2026-09-01T24:00:00Z']) {
      const exp = load('export/valid.json');
      exp.entries[1]!.createdAt = odd;
      const r = verifyAuditExport(exp);
      expect(r.brokenAt, odd).toMatchObject({ position: 2, code: 'CHAIN_MALFORMED_ENTRY' });
    }
    // An offset other than Z is RFC 3339, and places the entry where it says.
    const exp = load('export/valid.json');
    const at = new Date(Date.parse(exp.entries[1]!.createdAt!) + 2 * 3_600_000).toISOString().slice(0, 23);
    exp.entries[1]!.createdAt = `${at}+02:00`;
    expect(verifyAuditExport(exp).valid).toBe(true);
  });

  it('fails the same way unpinned, wherever the key carries a window', () => {
    const exp = load('export/valid.json');
    exp.entries[2]!.createdAt = null;
    const r = verifyAuditExport(exp);
    expect(r.valid).toBe(false);
    expect(r.brokenAt).toMatchObject({ position: 3, code: 'CHAIN_MALFORMED_ENTRY' });
  });

  it('a key with no window needs no entry time', () => {
    const exp = load('export/valid.json');
    delete exp.exportMetadata.signingKeyWindows;
    for (const e of exp.entries) delete e.createdAt;
    expect(verifyAuditExport(exp).valid).toBe(true);
  });

  it('a single unsigned entry with its time nulled is not early history under a pin', () => {
    const exp = load('export/unsigned-history-then-signed.json');
    exp.entries = exp.entries.slice(0, 1);
    exp.entries[0]!.createdAt = null;
    const r = verifyAuditExport(exp, { trustAnchors: [ANCHOR] });
    expect(r.valid).toBe(false);
    expect(r.brokenAt?.code).toBe('CHAIN_MALFORMED_ENTRY');
    expect(r.signatureCoverage.skipped).toBe(0);
  });
});

describe('malformed export rows are failure codes, not throws', () => {
  it('a null or retyped payload fails CHAIN_PAYLOAD_BINDING_MISMATCH', () => {
    for (const payload of [null, 'x', 7, []]) {
      const exp = load('export/valid.json');
      (exp.entries[0] as { payload?: unknown }).payload = payload;
      const r = verifyAuditExport(exp);
      expect(r.valid).toBe(false);
      expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_PAYLOAD_BINDING_MISMATCH' });
    }
  });

  it('an entry or integrity block that is not an object, or a non-string envelope, is CHAIN_MALFORMED_ENTRY', () => {
    const mutations: Array<(e: Record<string, unknown>) => void> = [
      (e) => { e['integrity'] = null; },
      (e) => { delete e['integrity']; },
      (e) => { (e['integrity'] as Record<string, unknown>)['coseSign1'] = 7; },
      (e) => { (e['integrity'] as Record<string, unknown>)['payloadHash'] = 7; },
    ];
    for (const mutate of mutations) {
      const exp = load('export/valid.json');
      mutate(exp.entries[0] as unknown as Record<string, unknown>);
      const r = verifyAuditExport(exp);
      expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_MALFORMED_ENTRY' });
      expect(r.brokenAt?.detail).toBe('Entry is missing coseSign1 or payloadHash, or carries one that is not a string.');
    }
    // An entry that is not an object has no position either, so it fails there.
    const exp = load('export/valid.json');
    (exp.entries as unknown[])[0] = null;
    expect(verifyAuditExport(exp).brokenAt?.code).toBe('CHAIN_POSITION_GAP');
  });

  it('an embedded key with no key material is no key: its entries fail CHAIN_SIGNATURE_MISSING_KEY', () => {
    for (const spki of [null, 7, '']) {
      const exp = load('export/valid.json');
      (exp.exportMetadata.signingPublicKeys as Record<string, unknown>)[KEY_ID] = spki;
      for (const opts of [{}, { trustAnchors: [ANCHOR] }]) {
        const r = verifyAuditExport(exp, opts);
        expect(r.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_SIGNATURE_MISSING_KEY' });
      }
    }
  });

  it('a null signing-key window or a retyped anchoredFrom is ignored, not thrown on', () => {
    const exp = load('export/valid.json');
    (exp.exportMetadata.signingKeyWindows as Record<string, unknown>)[KEY_ID] = null;
    (exp.exportMetadata as Record<string, unknown>)['anchoredFrom'] = 7;
    const r = verifyAuditExport(exp, { trustAnchors: [ANCHOR] });
    expect(r.valid).toBe(true);
    expect(r.keyTrust.anchoredFrom).toBeNull();
  });

  it('a document that is not an export throws TypeError naming the shape', () => {
    const message = 'Expected an /audit-export document: { exportMetadata: { recordId, ... }, entries: [...] }.';
    const valid = load('export/valid.json');
    for (const doc of [null, 'x', { ...valid, exportMetadata: null }, { ...valid, entries: 'x' }]) {
      expect(() => verifyAuditExport(doc as unknown as RecordAuditExportInput)).toThrow(new TypeError(message));
    }
  });

  it('buildPredicateForRow reads a payload that is not an object as no projection', () => {
    for (const payload of [null, undefined, 'x', 7, []]) {
      expect(buildPredicateForRow('00000000-0000-7000-8000-000000000000', 'RECORD_CREATED', payload as unknown as Record<string, unknown>)).toBeNull();
    }
  });
});

describe('verifyChain on dump-shaped rows', () => {
  function entries(): NormalizedEntry[] {
    const exp = load('export/valid.json');
    return exp.entries.map((e) => ({
      scopeId: exp.exportMetadata.recordId,
      chainPosition: e.chainPosition!,
      payloadHash: e.integrity.payloadHash,
      previousHash: e.integrity.previousHash,
      coseSign1: e.integrity.coseSign1,
      signingKeyId: e.integrity.signingKeyId,
      createdAt: e.createdAt!,
      binding: { recordId: e.recordId ?? null, entryType: e.entryType!, payload: e.payload! },
    }));
  }
  function registry() {
    const exp = load('export/valid.json');
    const window = exp.exportMetadata.signingKeyWindows![KEY_ID]!;
    return buildKeyRegistry([{
      keyId: KEY_ID, spkiBase64: exp.exportMetadata.signingPublicKeys![KEY_ID]!, source: 'embedded',
      algorithm: 'Ed25519', activatedAt: window.activatedAt, retiredAt: window.retiredAt,
    }]);
  }

  it('a nulled payload column is a binding mismatch, not a throw', () => {
    const rows = entries();
    rows[0]!.binding!.payload = null as unknown as Record<string, unknown>;
    expect(verifyChain(rows, registry()).brokenAt?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });

  it('a nulled write time is CHAIN_MALFORMED_ENTRY', () => {
    const rows = entries();
    for (const e of rows) e.createdAt = null;
    expect(verifyChain(rows, registry()).brokenAt?.code).toBe('CHAIN_MALFORMED_ENTRY');
  });

  it('a nulled or retyped algorithm column declares nothing, and is not thrown on', () => {
    for (const algorithm of [null, 7]) {
      const keys = registry();
      const key = keys.get(KEY_ID)!;
      const reg = buildKeyRegistry([{ ...key, algorithm: algorithm as unknown as string }]);
      expect(verifyChain(entries(), reg).valid).toBe(true);
    }
  });

  it('a registry row with no public key is no key', () => {
    const key = registry().get(KEY_ID)!;
    const reg = buildKeyRegistry([{ ...key, spkiBase64: null as unknown as string }]);
    expect(reg.size).toBe(0);
    expect(verifyChain(entries(), reg).brokenAt?.code).toBe('CHAIN_SIGNATURE_MISSING_KEY');
  });

  it('a position that is not an integer sorts last and fails CHAIN_POSITION_GAP', () => {
    for (const position of [null, '1', 1.5]) {
      const rows = entries();
      rows[0]!.chainPosition = position as unknown as number;
      const r = verifyChain(rows, registry());
      expect(r.valid).toBe(false);
      expect(r.entries.map((e) => e.failure?.code)).toContain('CHAIN_POSITION_GAP');
    }
  });
});

describe('dump key rows the walk cannot read', () => {
  const statements = ndjson<DumpKeyStatementRow>('dump/valid/vault_key_statements.ndjson');
  const keys = ndjson<DumpSigningKeyRow>('dump/valid/vault_signing_keys.ndjson');

  it('a statement row with no created_at is KEY_STATEMENT_INVALID, not a throw', () => {
    for (const blank of [undefined, null, 7, 'garbage']) {
      const rows = statements.map((r) => ({ ...r }));
      const row = rows[rows.length - 1] as unknown as Record<string, unknown>;
      if (blank === undefined) delete row['created_at'];
      else row['created_at'] = blank;
      const trust = computeKeyTrust({
        keys: keys.map(trustKeyFromDumpRow),
        statements: rows.map(keyStatementFromDumpRow),
        trustAnchors: [ANCHOR],
      });
      expect(trust.order).toBe('written');
      expect(trust.findings).toContainEqual(expect.objectContaining({
        code: 'KEY_STATEMENT_INVALID', statementId: row['id'], detail: 'the row has no parseable created_at to order it by',
      }));
    }
  });

  it('a statement row with no subject_key_id binds to nothing, and is KEY_STATEMENT_INVALID', () => {
    for (const blank of [undefined, null, 7]) {
      const rows = statements.map((r) => ({ ...r }));
      const row = rows[0] as unknown as Record<string, unknown>;
      if (blank === undefined) delete row['subject_key_id'];
      else row['subject_key_id'] = blank;
      const trust = computeKeyTrust({ keys: keys.map(trustKeyFromDumpRow), statements: rows.map(keyStatementFromDumpRow), trustAnchors: [ANCHOR] });
      expect(trust.findings.map((f) => f.code)).toContain('KEY_STATEMENT_INVALID');
    }
  });

  it('a key row with no public key or a retyped algorithm is not thrown on', () => {
    const rows = keys.map((k) => ({ ...k, public_key: null as unknown as string, algorithm: 7 as unknown as string }));
    expect(trustKeyFromDumpRow(rows[0]!).algorithm).toBeNull();
    expect(() => computeKeyTrust({ keys: rows.map(trustKeyFromDumpRow), statements: statements.map(keyStatementFromDumpRow), trustAnchors: [ANCHOR] })).not.toThrow();
  });
});

describe('distrustedKeys need trustAnchors', () => {
  it('verifyAuditExport refuses distrustedKeys without trustAnchors, as the dump verifier does', () => {
    const message = 'distrustedKeys act only inside the key-statement walk, which runs from trustAnchors; pass trustAnchors as well.';
    for (const trustAnchors of [undefined, []]) {
      expect(() => verifyAuditExport(load('export/valid.json'), { trustAnchors, distrustedKeys: [ANCHOR] })).toThrow(new TypeError(message));
    }
    expect(verifyAuditExport(load('export/valid.json'), { distrustedKeys: [] }).valid).toBe(true);
  });
});
