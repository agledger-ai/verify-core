import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput, SigningKeyWindow } from '../audit-export.js';
import {
  buildKeyRegistry,
  earliestKeyActivation,
  verifyChain,
  writtenWhileSigning,
  type NormalizedEntry,
} from '../chain.js';
import type { FailureCode } from '../failures.js';

/**
 * When an entry with no signing key id is a break (CHAIN_ENTRY_UNSIGNED) and
 * when it is only reduced coverage, graded as the engine grades
 * `signature_missing`:
 *   1. after a signed entry in the same chain, or
 *   2. written at or after the earliest activatedAt in the key set, retired
 *      keys included;
 * anything else stays a `skipped` signature. CHECKPOINT_UNSIGNED applies the
 * same instant to a checkpoint through `writtenWhileSigning`.
 *
 * Every case is derived by mutation from real corpus exports: `valid.json`
 * (signed with a key activated before its entries were written) and
 * `unsigned.json` (written before any key was registered).
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_DIR = join(HERE, '..', '..', 'testdata', 'conformance');

function load<T = RecordAuditExportInput>(rel: string): T {
  return JSON.parse(readFileSync(join(CONFORMANCE_DIR, rel), 'utf8')) as T;
}

/** The single real key window valid.json carries, and its key id. */
function realWindow(): { keyId: string; window: SigningKeyWindow } {
  const windows = load('export/valid.json').exportMetadata.signingKeyWindows ?? {};
  const [first] = Object.entries(windows);
  if (!first) throw new Error('valid.json must carry a signing key window');
  return { keyId: first[0], window: first[1] };
}

/** valid.json with every entry's signingKeyId nulled: a chain written after activation with no key. */
function validAllNulled(): RecordAuditExportInput {
  const exp = load('export/valid.json');
  for (const e of exp.entries) e.integrity = { ...e.integrity, signingKeyId: null };
  return exp;
}

function shiftMs(iso: string, ms: number): string {
  return new Date(Date.parse(iso) + ms).toISOString();
}

describe('rule 1: an unsigned entry after a signed one', () => {
  it('fails CHAIN_ENTRY_UNSIGNED at the unsigned position, with no key window anywhere', () => {
    const exp = load('export/valid.json');
    // Strip every activation time so only the signed-before half can fire.
    delete exp.exportMetadata.signingKeyWindows;
    exp.entries[1]!.integrity = { ...exp.entries[1]!.integrity, signingKeyId: null };
    const result = verifyAuditExport(exp, { publicKeys: load<Record<string, string>>('export/keys-oob.json') });
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toMatchObject({ position: 2, code: 'CHAIN_ENTRY_UNSIGNED' });
    expect(result.entries[0]).toMatchObject({ position: 1, valid: true, signature: 'ok' });
    expect(result.entries[1]).toMatchObject({ position: 2, valid: false, signature: 'not-checked' });
    expect(result.optionalChecks.key_temporal).toBe('skipped_no_input');
  });

  it('fires on the tip entry too, the shape a keyless writer leaves', () => {
    const exp = load('export/valid.json');
    delete exp.exportMetadata.signingKeyWindows;
    const last = exp.entries.length - 1;
    exp.entries[last]!.integrity = { ...exp.entries[last]!.integrity, signingKeyId: null };
    const result = verifyAuditExport(exp);
    expect(result.brokenAt).toMatchObject({ position: exp.entries.length, code: 'CHAIN_ENTRY_UNSIGNED' });
    expect(result.verifiedEntries).toBe(exp.entries.length - 1);
  });
});

describe('rule 2: an unsigned entry written once the install signs', () => {
  it('an all-unsigned chain with no keys is reduced coverage, not a break', () => {
    const exp = load('export/unsigned.json');
    expect(exp.exportMetadata.signingKeyWindows).toEqual({});
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(true);
    expect(result.signatureCoverage).toMatchObject({ signed: 0, unsigned: 0, skipped: 3 });
  });

  it('stays reduced coverage with caller keys that carry no activatedAt', () => {
    const result = verifyAuditExport(validAllNulled(), {
      publicKeys: load<Record<string, string>>('export/keys-oob.json'),
    });
    // valid.json's own export window still applies: the caller keys inherit it.
    expect(result.brokenAt?.code).toBe('CHAIN_ENTRY_UNSIGNED');

    const noWindows = validAllNulled();
    delete noWindows.exportMetadata.signingKeyWindows;
    const bare = verifyAuditExport(noWindows, {
      publicKeys: load<Record<string, string>>('export/keys-oob.json'),
    });
    expect(bare.valid).toBe(true);
    expect(bare.signatureCoverage.skipped).toBe(noWindows.entries.length);
  });

  it('an unsigned entry written before the earliest activatedAt is not a break', () => {
    const exp = load('export/unsigned.json');
    const { keyId, window } = realWindow();
    // The generator writes this chain before registering the key valid.json
    // was signed with, so the real window postdates every entry here.
    for (const e of exp.entries) expect(Date.parse(e.createdAt!)).toBeLessThan(Date.parse(window.activatedAt));
    exp.exportMetadata.signingKeyWindows = { [keyId]: window };
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(true);
    expect(result.signatureCoverage.skipped).toBe(3);
  });

  it('an unsigned entry written after activation of a key that is already retired is a break', () => {
    const exp = validAllNulled();
    const { keyId, window } = realWindow();
    // The only key in the set was retired before the first entry was written.
    const retiredAt = shiftMs(window.activatedAt, 1);
    expect(Date.parse(exp.entries[0]!.createdAt!)).toBeGreaterThan(Date.parse(retiredAt));
    exp.exportMetadata.signingKeyWindows = { [keyId]: { activatedAt: window.activatedAt, retiredAt } };
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_ENTRY_UNSIGNED' });
    expect(result.brokenAt?.detail).toContain(window.activatedAt);
  });

  it('counts a window the export lists for a key it carries no public key for', () => {
    const exp = validAllNulled();
    const { keyId, window } = realWindow();
    exp.exportMetadata.signingPublicKeys = {};
    exp.exportMetadata.signingKeyWindows = {
      [keyId]: { activatedAt: window.activatedAt, retiredAt: shiftMs(window.activatedAt, 1) },
    };
    const result = verifyAuditExport(exp);
    expect(result.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_ENTRY_UNSIGNED' });
  });

  it('takes the earliest activation across several keys', () => {
    const exp = validAllNulled();
    const created = exp.entries[0]!.createdAt!;
    exp.exportMetadata.signingKeyWindows = {
      later: { activatedAt: shiftMs(created, 60_000), retiredAt: null },
      earlier: { activatedAt: shiftMs(created, -60_000), retiredAt: shiftMs(created, -30_000) },
    };
    expect(verifyAuditExport(exp).brokenAt).toMatchObject({ position: 1, code: 'CHAIN_ENTRY_UNSIGNED' });
  });

  it('is inclusive at the activation instant and silent one millisecond before it', () => {
    const created = validAllNulled().entries[0]!.createdAt!;

    const at = validAllNulled();
    delete at.exportMetadata.signingKeyWindows;
    at.entries.splice(1);
    at.exportMetadata.signingKeyWindows = { k: { activatedAt: created, retiredAt: null } };
    expect(verifyAuditExport(at).brokenAt).toMatchObject({ position: 1, code: 'CHAIN_ENTRY_UNSIGNED' });

    const before = validAllNulled();
    before.entries.splice(1);
    before.exportMetadata.signingKeyWindows = { k: { activatedAt: shiftMs(created, 1), retiredAt: null } };
    expect(verifyAuditExport(before).valid).toBe(true);
  });

  it('reads caller-supplied activatedAt when the export carries no windows', () => {
    const exp = validAllNulled();
    delete exp.exportMetadata.signingKeyWindows;
    const { keyId, window } = realWindow();
    const spki = load<Record<string, string>>('export/keys-oob.json')[keyId]!;
    const result = verifyAuditExport(exp, {
      publicKeys: [{ keyId, publicKey: spki, activatedAt: window.activatedAt, retiredAt: shiftMs(window.activatedAt, 1) }],
    });
    expect(result.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_ENTRY_UNSIGNED' });
  });

  it("prefers the caller's window for a key over the export's, as the key-window check does", () => {
    const exp = validAllNulled();
    const { keyId } = realWindow();
    const lastCreated = exp.entries[exp.entries.length - 1]!.createdAt!;
    const spki = load<Record<string, string>>('export/keys-oob.json')[keyId]!;
    const result = verifyAuditExport(exp, {
      publicKeys: [{ keyId, publicKey: spki, activatedAt: shiftMs(lastCreated, 1), retiredAt: null }],
    });
    expect(result.valid).toBe(true);
  });

  it('does not apply to an entry that carries no createdAt', () => {
    const exp = validAllNulled();
    for (const e of exp.entries) delete e.createdAt;
    expect(verifyAuditExport(exp).valid).toBe(true);
  });
});

describe('a tamper finding on an unsigned entry keeps its own code', () => {
  // Every structural check runs before the unsigned grading, so nulling the
  // key id on a tampered entry must not turn its finding into
  // CHAIN_ENTRY_UNSIGNED.
  const STRUCTURAL: ReadonlySet<FailureCode> = new Set<FailureCode>([
    'CHAIN_POSITION_GAP',
    'CHAIN_GENESIS_INVALID',
    'CHAIN_LINK_BROKEN',
    'CHAIN_HASH_MISMATCH',
    'CHAIN_MALFORMED_ENTRY',
    'CHAIN_COSE_DECODE_FAILED',
    'CHAIN_COSE_HEADER_MISMATCH',
    'CHAIN_PAYLOAD_BINDING_MISMATCH',
    'CHAIN_ACTOR_ATTRIBUTION_MISMATCH',
    'CHAIN_OIDC_ACTOR_MISMATCH',
  ]);
  interface Vector { file: string; expect: string; failureCode?: FailureCode; brokenAt?: number }
  const vectors = load<{ vectors: Vector[] }>('manifest-export.json').vectors.filter(
    (v) => v.expect === 'fail' && v.failureCode !== undefined && STRUCTURAL.has(v.failureCode),
  );

  it('covers the corpus structural vectors', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(8);
  });

  for (const v of vectors) {
    it(`${v.file} still fails ${v.failureCode} with the broken entry's key id nulled`, () => {
      const exp = load(v.file);
      const at = v.brokenAt ?? 1;
      // Signed entries precede it, so both halves of the rule would fire here
      // if the grading ran ahead of the structural checks.
      let nulled = 0;
      for (const e of exp.entries) {
        if ((e.chainPosition ?? e.position) === at && e.integrity) {
          e.integrity = { ...e.integrity, signingKeyId: null };
          nulled++;
        }
      }
      expect(nulled).toBeGreaterThan(0);
      const result = verifyAuditExport(exp);
      expect(result.brokenAt?.code).toBe(v.failureCode);
      if (v.brokenAt !== undefined) expect(result.brokenAt?.position).toBe(v.brokenAt);
    });
  }
});

describe('verifyChain derives the instant from its keys (the dump path)', () => {
  function nulledEntries(): NormalizedEntry[] {
    const exp = load('export/valid.json');
    return exp.entries.map((e) => ({
      scopeId: exp.exportMetadata.recordId,
      chainPosition: e.chainPosition!,
      payloadHash: e.integrity.payloadHash,
      previousHash: e.integrity.previousHash,
      coseSign1: e.integrity.coseSign1,
      signingKeyId: null,
      createdAt: e.createdAt!,
    }));
  }

  function registryWithWindow() {
    const { keyId, window } = realWindow();
    const spki = load<Record<string, string>>('export/keys-oob.json')[keyId]!;
    return buildKeyRegistry([
      { keyId, spkiBase64: spki, source: 'embedded', activatedAt: window.activatedAt, retiredAt: shiftMs(window.activatedAt, 1) },
    ]);
  }

  it('breaks with the key set only', () => {
    const result = verifyChain(nulledEntries(), registryWithWindow());
    expect(result.brokenAt).toMatchObject({ position: 1, code: 'CHAIN_ENTRY_UNSIGNED' });
  });

  it('signingSince: null switches off only the time half', () => {
    expect(verifyChain(nulledEntries(), registryWithWindow(), { signingSince: null }).valid).toBe(true);
  });

  it('an unparseable signingSince throws rather than switching the check off', () => {
    expect(() => verifyChain(nulledEntries(), registryWithWindow(), { signingSince: 'soon' })).toThrow(TypeError);
  });
});

describe('the checkpoint rule and its helpers', () => {
  const { window } = realWindow();

  it('earliestKeyActivation takes the minimum, retired keys included, and ignores keys without a usable time', () => {
    expect(earliestKeyActivation([])).toBeNull();
    expect(earliestKeyActivation([{}, { activatedAt: null }, { activatedAt: 'not a time' }])).toBeNull();
    const retired = shiftMs(window.activatedAt, -5_000);
    expect(earliestKeyActivation([{ activatedAt: window.activatedAt }, { activatedAt: retired }, {}])).toBe(retired);
  });

  it('an unsigned checkpoint at or after the instant is CHECKPOINT_UNSIGNED territory; before it is not', () => {
    expect(writtenWhileSigning(window.activatedAt, window.activatedAt)).toBe(true);
    expect(writtenWhileSigning(shiftMs(window.activatedAt, 1), window.activatedAt)).toBe(true);
    expect(writtenWhileSigning(shiftMs(window.activatedAt, -1), window.activatedAt)).toBe(false);
  });

  it('cannot place a row without both times', () => {
    expect(writtenWhileSigning(window.activatedAt, null)).toBe(false);
    expect(writtenWhileSigning(undefined, window.activatedAt)).toBe(false);
    expect(writtenWhileSigning('garbage', window.activatedAt)).toBe(false);
  });
});
