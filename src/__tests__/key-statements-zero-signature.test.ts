import { describe, it, expect, vi } from 'vitest';

/**
 * An all-zero statement signature is refused before it reaches the signature
 * primitive. OpenSSL rejects one on its own, but a verifier that accepts
 * small-order Ed25519 points would not, so the walk does not lean on the
 * backend for it. Simulated here with a verify() that accepts any all-zero
 * signature; everything else is real.
 */
vi.mock('node:crypto', async () => {
  const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto');
  return {
    ...actual,
    default: actual,
    verify: (algorithm: unknown, data: unknown, key: unknown, signature: unknown) => {
      if (signature instanceof Uint8Array && signature.length > 0 && signature.every((b) => b === 0)) return true;
      return (actual.verify as (...a: unknown[]) => boolean)(algorithm, data, key, signature);
    },
  };
});

const { computeKeyTrust } = await import('../key-statements.js');
const { decode, encode, rfc8949EncodeOptions } = await import('cborg');
const { makeKey, statement } = await import('./key-statements-helpers.js');

/** The same COSE_Sign1 with its signature bytes zeroed. */
function zeroed(sign1: Uint8Array): Buffer {
  const [p, u, payload, sig] = decode(sign1.subarray(1), { useMaps: true }) as [Uint8Array, Map<number, unknown>, Uint8Array, Uint8Array];
  const inner = encode([p, u, payload, new Uint8Array(sig.length)], rfc8949EncodeOptions);
  return Buffer.concat([Buffer.from([0xd2]), Buffer.from(inner)]);
}

describe('an all-zero key statement signature', () => {
  it('is refused even where the backend would accept it', () => {
    for (const alg of ['Ed25519', 'ES256'] as const) {
      const c = makeKey(alg);
      const g = statement('genesis', c, { signers: [c] });
      const walk = (cose: Buffer[]) => computeKeyTrust({ keys: [], statements: [{ ...g, cose }], trustAnchors: [`sha256:${c.digest}`] });
      expect(walk(g.cose as Buffer[]).findings).toEqual([]);
      const forged = walk([zeroed(g.cose[0] as Buffer)]);
      expect(forged.findings.map((f) => [f.code, f.statementId])).toEqual([['KEY_STATEMENT_INVALID', g.id]]);
      expect(forged.statements).toMatchObject({ valid: 0, invalid: 1 });
    }
  });
});
