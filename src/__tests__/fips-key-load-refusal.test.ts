import { describe, it, expect, vi } from 'vitest';
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { encode as cborEncode, rfc8949EncodeOptions } from 'cborg';

/**
 * The FIPS refusal measured on a real host happens at KEY LOAD, one step before
 * the verify() call `fips-runtime.test.ts` simulates (agents#113, second
 * report). `createPublicKey` throws "Failed to read asymmetric key" for a
 * perfectly good Ed25519 SPKI, so `resolveKeyAlgorithm` returns 'unparseable'
 * and `verifyCoseSign1` short-circuited to 'invalid' BEFORE reaching the
 * runtime-capability gate. The entire capability mechanism was unreachable on
 * the one path it was written for, and a FIPS-locked auditor still got
 * CHAIN_SIGNATURE_INVALID on an intact chain: tamper evidence, about a chain
 * that is fine.
 *
 * Simulated with a module mock, for the same reason as the sibling test:
 * crypto.setFips(true) without a provider loaded also breaks SHA-256, which a
 * real FIPS provider permits, so the chain walk would die before reaching a
 * key. The mock reproduces exactly one thing, an EdDSA-only refusal at key
 * load, and leaves everything else real.
 */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

vi.mock('node:crypto', async () => {
  const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto');
  const refusesEd25519 = (input: unknown): boolean => {
    const key = input !== null && typeof input === 'object' && 'key' in input
      ? (input as { key: unknown }).key
      : input;
    if (key instanceof Uint8Array) {
      return key.length === 44 && Buffer.from(key).subarray(0, 12).equals(ED25519_SPKI_PREFIX);
    }
    // JWK form, used by the SDK's raw-32-byte key path.
    return (
      key !== null &&
      typeof key === 'object' &&
      (key as { crv?: string }).crv === 'Ed25519'
    );
  };
  return {
    ...actual,
    default: actual,
    getFips: () => 1,
    createPublicKey: (input: unknown) => {
      if (refusesEd25519(input)) {
        const err: Error & { code?: string } = new Error(
          'error:1E08010C:DECODER routines::unsupported: Failed to read asymmetric key',
        );
        err.code = 'ERR_OSSL_UNSUPPORTED';
        throw err;
      }
      return (actual.createPublicKey as (...a: unknown[]) => unknown)(input);
    },
  };
});

const { verifyCoseSign1, sha256Hex, looksLikeEd25519Key, describeUnsupportedAlgorithm } =
  await import('../primitives.js');
const { buildKeyRegistry, verifyChain } = await import('../chain.js');
type NormalizedEntry = import('../chain.js').NormalizedEntry;
type VerificationKey = import('../chain.js').VerificationKey;

const COSE_TAG_PREFIX = 0xd2;
const LABEL_ALG = 1;
const LABEL_KID = 4;
const LABEL_CHAIN = -65537;

const ED_KEY_ID = 'aabbccddeeff0011';
const ES_KEY_ID = '2211ffeeddccbbaa';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function spkiBase64(publicKey: KeyObject): string {
  return (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');
}

/** Signing is unaffected by the mock: only key LOAD is refused. */
function buildEnvelope(opts: {
  alg: number;
  kidHex: string;
  signer: (toBeSigned: Uint8Array) => Uint8Array;
}): Uint8Array {
  const protectedMap = new Map<number, unknown>();
  protectedMap.set(LABEL_ALG, opts.alg);
  protectedMap.set(LABEL_KID, hexToBytes(opts.kidHex));
  const chainClaim = new Map<number, unknown>();
  chainClaim.set(1, 1);
  chainClaim.set(2, null);
  protectedMap.set(LABEL_CHAIN, chainClaim);
  const protectedBstr = cborEncode(protectedMap, rfc8949EncodeOptions);

  const payloadBstr = cborEncode({ predicate: {} }, rfc8949EncodeOptions);
  const toBeSigned = cborEncode(
    ['Signature1', protectedBstr, new Uint8Array(0), payloadBstr],
    rfc8949EncodeOptions,
  );
  const body = cborEncode(
    [protectedBstr, new Map(), payloadBstr, opts.signer(toBeSigned)],
    rfc8949EncodeOptions,
  );
  const out = new Uint8Array(1 + body.length);
  out[0] = COSE_TAG_PREFIX;
  out.set(body, 1);
  return out;
}

const ed = generateKeyPairSync('ed25519');
const es = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

const edEnvelope = buildEnvelope({
  alg: -8,
  kidHex: ED_KEY_ID,
  signer: (tbs) => new Uint8Array(cryptoSign(null, tbs, ed.privateKey)),
});

const esEnvelope = buildEnvelope({
  alg: -7,
  kidHex: ES_KEY_ID,
  signer: (tbs) =>
    new Uint8Array(cryptoSign('sha256', tbs, { key: es.privateKey, dsaEncoding: 'ieee-p1363' })),
});

const edKey: VerificationKey = {
  keyId: ED_KEY_ID,
  spkiBase64: spkiBase64(ed.publicKey),
  source: 'out-of-band',
};

function toEntry(envelope: Uint8Array, signingKeyId: string): NormalizedEntry {
  return {
    scopeId: 'fips-load-test',
    chainPosition: 1,
    payloadHash: sha256Hex(envelope),
    previousHash: null,
    coseSign1: Buffer.from(envelope).toString('base64'),
    signingKeyId,
  };
}

describe('a runtime that refuses to LOAD an Ed25519 key', () => {
  it('reports a valid Ed25519 envelope as unsupported, not invalid', () => {
    // The exact cell testbed re-measured against the 1.4.0 candidate and found
    // unchanged from the published build.
    expect(verifyCoseSign1(edEnvelope, spkiBase64(ed.publicKey))).toBe(
      'unsupported-key-algorithm',
    );
  });

  it('still verifies ES256, which a FIPS provider does carry', () => {
    expect(verifyCoseSign1(esEnvelope, spkiBase64(es.publicKey))).toBe('ok');
  });

  it('fails the chain closed, and never as tamper', () => {
    const result = verifyChain([toEntry(edEnvelope, ED_KEY_ID)], buildKeyRegistry([edKey]), {});
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_UNSUPPORTED_ALGORITHM');
    expect(result.entries.map((e) => e.signature)).toEqual(['unsupported']);
  });

  it('names the host, the cause, and the remedy rather than telling the auditor to upgrade', () => {
    const result = verifyChain([toEntry(edEnvelope, ED_KEY_ID)], buildKeyRegistry([edKey]), {});
    const detail = result.brokenAt?.detail ?? '';
    expect(detail).toContain('Ed25519');
    expect(detail).toContain('HOST RUNTIME');
    expect(detail).toContain('FIPS');
    expect(detail).toContain('NOT tamper evidence');
    // The key loaded nowhere, so the pre-fix path fell through to the generic
    // build-capability sentence, which sends an auditor to upgrade a verifier
    // that is not the problem.
    expect(detail).not.toContain('upgrade the verifier');
  });

  it('keeps garbage key material reading as tamper on the same host', () => {
    // The anti-downgrade property: promoting a signature failure to "not
    // checked" is security-relevant, so only bytes that structurally DECLARE
    // Ed25519 get the benefit. These do not.
    const garbage = Buffer.from('not a key at all, just bytes', 'utf8').toString('base64');
    expect(looksLikeEd25519Key(Buffer.from(garbage, 'base64'))).toBe(false);
    expect(verifyCoseSign1(edEnvelope, garbage)).toBe('invalid');
  });

  it('describes the refusal from the OID when no key object can exist', () => {
    expect(describeUnsupportedAlgorithm(spkiBase64(ed.publicKey))).toContain('HOST RUNTIME');
  });
});
