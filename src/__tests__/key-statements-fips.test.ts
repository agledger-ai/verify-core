import { describe, it, expect, vi } from 'vitest';

/**
 * The walk on a host that cannot compute Ed25519 (an active OpenSSL FIPS
 * provider), ported from the engine's "a host that cannot compute a key's
 * algorithm" cases. Simulated the way fips-runtime.test.ts does it: EdDSA
 * verify() throws, everything else is real. Opaque keys are Ed25519 keys as
 * such a host sees them, bytes that do not parse, with signatures nothing can
 * check.
 */
vi.mock('node:crypto', async () => {
  const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto');
  const isEd25519 = (key: unknown): boolean => {
    const candidate = key !== null && typeof key === 'object' && 'key' in key ? (key as { key: unknown }).key : key;
    return candidate !== null && typeof candidate === 'object'
      && (candidate as { asymmetricKeyType?: string }).asymmetricKeyType === 'ed25519';
  };
  return {
    ...actual,
    default: actual,
    getFips: () => 1,
    verify: (algorithm: unknown, data: unknown, key: unknown, signature: unknown) => {
      if (isEd25519(key)) {
        const err: Error & { code?: string } = new Error('operation not supported for this keytype');
        err.code = 'ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE';
        throw err;
      }
      return (actual.verify as (...a: unknown[]) => boolean)(algorithm, data, key, signature);
    },
  };
});

const { computeKeyTrust, applyKeyTrust } = await import('../key-statements.js');
const { buildKeyRegistry } = await import('../chain.js');
const { T0, T1, T2, T3, makeKey, makeOpaqueKey, row, statement } = await import('./key-statements-helpers.js');

function fipsHistory() {
  const k0 = makeOpaqueKey();
  const k1 = makeOpaqueKey();
  const a = makeKey('ES256');
  const g0 = statement('genesis', k0, { signers: [k0], createdAt: T0 });
  const s01 = statement('succession', k1, { endorser: k0, signers: [k0, k1], activatedAt: T0, createdAt: T0 });
  const c0 = statement('closure', k0, { endorser: k1, signers: [k1], retiredAt: T1, createdAt: T1 });
  const s1a = statement('succession', a, { endorser: k1, signers: [k1, a], activatedAt: T1, createdAt: T1 });
  const c1 = statement('closure', k1, { endorser: a, signers: [a], retiredAt: T2, createdAt: T2 });
  return { k0, k1, a, history: [g0, s01, c0, s1a, c1] };
}

describe('a host that cannot compute a key\'s algorithm', () => {
  it('leaves the opaque history undecided, never trusted, and a forged statement under an opaque key decides nothing', () => {
    const { k0, k1, a, history } = fipsHistory();
    const x = makeOpaqueKey();
    const y = makeOpaqueKey();
    const intoK1 = statement('succession', k1, { endorser: x, signers: [x, k1], activatedAt: T0, createdAt: T3 });
    const fromK0 = statement('succession', y, { endorser: k0, signers: [k0, y], activatedAt: T3, createdAt: T3 });
    const trust = computeKeyTrust({
      keys: [row(k0, T0, T1), row(k1, T0, T2), row(a, T1), row(x, T0), row(y, T3)],
      statements: [...history, intoK1, fromK0],
      trustAnchors: [`sha256:${a.digest}`],
    });
    expect([...trust.trusted]).toEqual([a.digest]);
    expect(trust.undecided.has(k1.digest)).toBe(true);
    expect(trust.undecided.has(x.digest)).toBe(false);

    // An entry key's grade follows: the anchor anchored, the opaque key it
    // reaches undecided (CHAIN_UNSUPPORTED_ALGORITHM), anything else unanchored.
    const registry = applyKeyTrust(buildKeyRegistry([a, k1, x].map((k) => ({ keyId: k.kid, spkiBase64: k.publicKey, source: 'embedded' as const }))), trust);
    expect(registry.get(a.kid)?.trust).toBe('anchored');
    expect(registry.get(k1.kid)?.trust).toBe('undecided');
    expect(registry.get(x.kid)?.trust).toBe('unanchored');
  });

  it('does not leave a key it can compute undecided because an opaque half on its path cannot be checked', () => {
    const { k0, a, history } = fipsHistory();
    // An ES256 key admitted by bytes under K0 that nothing here can check.
    const y = makeKey('ES256');
    const fromK0 = statement('succession', y, { endorser: k0, signers: [k0, y], activatedAt: T3, createdAt: T3 });
    const trust = computeKeyTrust({ keys: [], statements: [...history, fromK0], trustAnchors: [`sha256:${a.digest}`] });
    expect(trust.undecided.has(k0.digest)).toBe(true);
    expect(trust.undecided.has(y.digest)).toBe(false);
    expect([...trust.trusted]).toEqual([a.digest]);
  });
});
