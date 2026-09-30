import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildKeyRegistry, earliestKeyActivation, verifyChain, type NormalizedEntry } from '../chain.js';
import {
  applyKeyTrust,
  computeKeyTrust,
  keyStatementFromDumpRow,
  spkiSha256,
  trustKeyFromDumpRow,
  type DumpKeyStatementRow,
  type DumpSigningKeyRow,
} from '../key-statements.js';
import type { FailureCode } from '../failures.js';

/**
 * The key-statement walk against the engine's own dump vectors: real
 * statements, signed by the engine and stored by its database. The full dump
 * verdict is @agledger/verify's to give; this runs the part verify-core owns,
 * the walk and the per-entry anchoring and window checks it drives, and holds
 * every vector that pins `trustAnchors` to its expected verdict.
 */

const CORPUS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'testdata', 'conformance');

interface DumpVector {
  file: string;
  expect: 'pass' | 'fail';
  failureCode?: FailureCode;
  options?: { trustAnchors?: string[] };
  requiresAlgorithms?: string[];
}

interface VaultRow {
  record_id: string | null;
  chain_key?: string;
  chain_position: number;
  payload_hash: string;
  previous_hash: string | null;
  cose_sign1: string;
  signing_key_id: string | null;
  created_at: string;
}

function ndjson<T>(dir: string, file: string): T[] {
  return readFileSync(join(CORPUS, dir, file), 'utf8').split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as T);
}

/** Every code the walk and the chains it grades report for one dump. */
function gradeDump(dir: string, anchors: string[]): { codes: FailureCode[]; chains: number } {
  const keys = ndjson<DumpSigningKeyRow>(dir, 'vault_signing_keys.ndjson');
  const statements = ndjson<DumpKeyStatementRow>(dir, 'vault_key_statements.ndjson');
  const trust = computeKeyTrust({
    keys: keys.map(trustKeyFromDumpRow),
    statements: statements.map(keyStatementFromDumpRow),
    trustAnchors: anchors,
  });
  expect(trust.order).toBe('written');
  const registry = applyKeyTrust(
    buildKeyRegistry(keys.map((k) => ({
      keyId: k.key_id,
      spkiBase64: k.public_key,
      source: 'embedded' as const,
      ...(k.algorithm ? { algorithm: k.algorithm } : {}),
      ...(k.activated_at ? { activatedAt: k.activated_at } : {}),
      retiredAt: k.retired_at ?? null,
    }))),
    trust,
  );
  const signingSince = earliestKeyActivation(keys.map((k) => ({ activatedAt: k.activated_at ?? null })));
  const byChain = new Map<string, NormalizedEntry[]>();
  for (const e of ndjson<VaultRow>(dir, 'audit_vault.ndjson')) {
    const scope = e.chain_key ?? e.record_id ?? 'schema';
    const list = byChain.get(scope) ?? [];
    list.push({
      scopeId: scope,
      chainPosition: e.chain_position,
      payloadHash: e.payload_hash,
      previousHash: e.previous_hash,
      coseSign1: e.cose_sign1,
      signingKeyId: e.signing_key_id,
      createdAt: e.created_at,
    });
    byChain.set(scope, list);
  }
  const codes: FailureCode[] = trust.findings.map((f) => f.code);
  for (const chain of byChain.values()) {
    const result = verifyChain(chain, registry, { signingSince });
    for (const entry of result.entries) if (entry.failure) codes.push(entry.failure.code);
  }
  return { codes, chains: byChain.size };
}

/**
 * The pin an operator hands an auditor: the Server's current key, the most
 * recently activated key some statement admits (a planted row has none).
 */
function currentPin(dir: string): string {
  const admitted = new Set(ndjson<DumpKeyStatementRow>(dir, 'vault_key_statements.ndjson')
    .filter((s) => s.kind !== 'closure').map((s) => s.subject_key_id));
  const key = ndjson<DumpSigningKeyRow>(dir, 'vault_signing_keys.ndjson')
    .filter((k) => admitted.has(k.key_id))
    .sort((a, b) => Date.parse(b.activated_at ?? '') - Date.parse(a.activated_at ?? ''))[0];
  if (!key) throw new Error(`${dir}: no admitted key`);
  return `sha256:${spkiSha256(key.public_key)}`;
}

const manifest = JSON.parse(readFileSync(join(CORPUS, 'manifest-dump.json'), 'utf8')) as { vectors: DumpVector[] };

describe('key-statement walk over the dump corpus: vectors that pin trustAnchors', () => {
  const pinned = manifest.vectors.filter((v) => v.options?.trustAnchors !== undefined);

  it('the corpus carries them', () => {
    expect(pinned.length).toBeGreaterThanOrEqual(4);
  });

  for (const v of pinned) {
    it(`${v.file} pinned on ${v.options!.trustAnchors!.map((a) => a.slice(7, 23)).join(',')} -> ${v.expect}${v.failureCode ? ` (${v.failureCode})` : ''}`, () => {
      const { codes } = gradeDump(v.file, v.options!.trustAnchors!);
      if (v.expect === 'pass') expect(codes).toEqual([]);
      else expect(codes).toContain(v.failureCode);
    });
  }
});

describe('key-statement walk over the dump corpus: pass vectors pinned on the Server\'s current key', () => {
  // Every pass vector whose registry columns are the engine's own. The
  // column-edit vector valid-rotation-boundary is left out: its activated_at
  // column was moved off the signed value, which the walk reports as
  // CHAIN_KEY_WINDOW_DRIFT (see the test below).
  const vectors = ['dump/valid', 'dump/valid-es256', 'dump/valid-identity', 'dump/valid-unsigned-history-then-signed'];

  it.each(vectors)('%s verifies clean with every signed entry anchored', (dir) => {
    const { codes, chains } = gradeDump(dir, [currentPin(dir)]);
    expect(chains).toBeGreaterThan(0);
    expect(codes).toEqual([]);
  });

  it('dump/valid-es256 walks three keys across the algorithm change, and the forced closure cuts the first key off from its successors', () => {
    const dir = 'dump/valid-es256';
    const trust = computeKeyTrust({
      keys: ndjson<DumpSigningKeyRow>(dir, 'vault_signing_keys.ndjson').map(trustKeyFromDumpRow),
      statements: ndjson<DumpKeyStatementRow>(dir, 'vault_key_statements.ndjson').map(keyStatementFromDumpRow),
      trustAnchors: [currentPin(dir)],
    });
    expect(trust.trusted.size).toBe(3);
    expect(trust.statements).toEqual({ total: 4, valid: 4, invalid: 0, unverifiable: 0 });
    const genesis = ndjson<DumpKeyStatementRow>(dir, 'vault_key_statements.ndjson').find((s) => s.kind === 'genesis')!;
    const first = ndjson<DumpSigningKeyRow>(dir, 'vault_signing_keys.ndjson').find((k) => k.key_id === genesis.subject_key_id)!;
    expect(gradeDump(dir, [`sha256:${spkiSha256(first.public_key)}`]).codes).toContain('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('dump/chain-signing-key-unanchored pinned on the vault key fails the planted entry', () => {
    const { codes } = gradeDump('dump/chain-signing-key-unanchored', [currentPin('dump/chain-signing-key-unanchored')]);
    expect(codes).toContain('CHAIN_SIGNING_KEY_UNANCHORED');
  });

  it('the registry column edits read as drift from the signed window, not as the key-window codes their manifest names', () => {
    // These vectors move a vault_signing_keys column and leave the statements
    // alone. Entries are graded against the signed window, so the column is
    // drift; the manifest still expects the pre-statement verdicts.
    expect(gradeDump('dump/valid-rotation-boundary', [currentPin('dump/valid-rotation-boundary')]).codes).toEqual(['CHAIN_KEY_WINDOW_DRIFT']);
    expect(gradeDump('dump/chain-key-not-yet-active', [currentPin('dump/chain-key-not-yet-active')]).codes).toEqual(['CHAIN_KEY_WINDOW_DRIFT']);
    // A retired row no closure signs is the engine's key_closure_invalid.
    expect(gradeDump('dump/chain-key-expired', [currentPin('dump/chain-key-expired')]).codes).toEqual(['KEY_CLOSURE_INVALID']);
  });
});
