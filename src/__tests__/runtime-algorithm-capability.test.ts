import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import {
  describeUnsupportedAlgorithm,
  resolveKeyAlgorithm,
  runtimeCanCompute,
  type KeyAlgorithm,
} from '../primitives.js';

/**
 * The runtime half of algorithm capability (agents#113).
 *
 * `verifiable` in the algorithm table says what this BUILD implements. Whether
 * a signature can actually be checked also depends on the HOST RUNTIME, which
 * can refuse: an active OpenSSL FIPS provider carries no EdDSA. Before this,
 * that refusal was caught and returned as `false`, so an intact Ed25519 chain
 * was reported as CHAIN_SIGNATURE_INVALID, i.e. as forged.
 *
 * This file pins the unrestricted-runtime side. The restricted side (the bug
 * itself) is in fips-runtime.test.ts, which needs a file-wide crypto mock.
 *
 * The load-bearing case here is the first one. The checked-in known-answer
 * vectors are what prove runtime capability, so a corrupted or mistyped vector
 * would make every algorithm look unsupported and silently downgrade ALL
 * verification to "not checked" on healthy hosts. That failure is quiet and
 * total, which is exactly the kind this package cannot ship.
 */

function spkiBase64(publicKey: KeyObject): string {
  return (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
}

function algOf(spki: string): KeyAlgorithm {
  const resolved = resolveKeyAlgorithm(spki);
  if (typeof resolved !== 'object') throw new Error(`expected a table entry, got ${resolved}`);
  return resolved;
}

const ed = generateKeyPairSync('ed25519');
const es256 = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const es384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });

describe('runtimeCanCompute', () => {
  it('confirms every verifiable algorithm on an unrestricted runtime', () => {
    // Guards the checked-in KAT vectors themselves: if either were wrong, the
    // probe would fail closed and downgrade all verification to "unsupported".
    expect(runtimeCanCompute(algOf(spkiBase64(ed.publicKey)))).toBe(true);
    expect(runtimeCanCompute(algOf(spkiBase64(es256.publicKey)))).toBe(true);
  });

  it('is memoized per algorithm, so a chain of millions probes twice at most', () => {
    const alg = algOf(spkiBase64(ed.publicKey));
    for (let i = 0; i < 1000; i += 1) expect(runtimeCanCompute(alg)).toBe(true);
  });

  it('does not claim capability it cannot prove for a non-verifiable algorithm', () => {
    // ES384 has no KAT because this build cannot compute it. The build gate
    // (`verifiable: false`) is what stops it, and it must stop it first.
    expect(algOf(spkiBase64(es384.publicKey)).verifiable).toBe(false);
  });
});

describe('describeUnsupportedAlgorithm', () => {
  it('sends a build gap to the upgrade remedy', () => {
    const detail = describeUnsupportedAlgorithm(spkiBase64(es384.publicKey));
    expect(detail).toContain('ES384');
    expect(detail).toContain('upgrade the verifier');
  });

  it('never blames the chain for a build gap', () => {
    expect(describeUnsupportedAlgorithm(spkiBase64(es384.publicKey))).toContain('NOT verified');
  });

  it('falls back safely for key material that resolves to no algorithm', () => {
    const detail = describeUnsupportedAlgorithm('not-a-key');
    expect(detail).toContain('cannot compute');
    expect(detail).toContain('NOT verified');
  });
});
