import { describe, it, expect, vi } from 'vitest';
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { encode as cborEncode, rfc8949EncodeOptions } from 'cborg';

/**
 * A FIPS-locked host must not report an intact Ed25519 chain as forged
 * (agents#113).
 *
 * The measured behaviour: with the OpenSSL FIPS provider active, node's
 * verify() throws ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE for a
 * perfectly good Ed25519 key, because the provider carries no EdDSA. The
 * verifier caught that and returned false, which is indistinguishable from a
 * signature that genuinely did not verify, so a healthy chain came back
 * "0/7 verified, CHAIN_SIGNATURE_INVALID". An auditor reads that as tamper and
 * opens an investigation into a chain that is fine.
 *
 * Simulated with a module mock rather than a real FIPS provider so the test
 * runs anywhere. node's own crypto.setFips(true) is NOT a faithful stand-in:
 * without the provider actually loaded it also breaks SHA-256, which a real
 * FIPS provider permits, so the chain walk would die before ever reaching the
 * signature. The mock reproduces the one thing that matters, an EdDSA-only
 * refusal at the verify() call, and leaves everything else real.
 */
vi.mock('node:crypto', async () => {
  const actual = await vi.importActual<typeof import('node:crypto')>('node:crypto');
  const isEd25519 = (key: unknown): boolean => {
    const candidate =
      key !== null && typeof key === 'object' && 'key' in key
        ? (key as { key: unknown }).key
        : key;
    return (
      candidate !== null &&
      typeof candidate === 'object' &&
      (candidate as { asymmetricKeyType?: string }).asymmetricKeyType === 'ed25519'
    );
  };
  return {
    ...actual,
    default: actual,
    // The FIPS provider is active, so getFips() reports 1 and EdDSA is absent.
    getFips: () => 1,
    verify: (algorithm: unknown, data: unknown, key: unknown, signature: unknown) => {
      if (isEd25519(key)) {
        const err: Error & { code?: string } = new Error(
          'error:03000096:digital envelope routines::operation not supported for this keytype',
        );
        err.code = 'ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE';
        throw err;
      }
      return (actual.verify as (...a: unknown[]) => boolean)(algorithm, data, key, signature);
    },
  };
});

const { sha256Hex, verifyCoseSign1 } = await import('../primitives.js');
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

const ed = generateKeyPairSync('ed25519');
const es = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

/** Signing is unaffected by the mock: only verify() is refused. */
function buildEnvelope(opts: {
  alg: number;
  kidHex: string;
  position: number;
  previousHash: string | null;
  signer: (toBeSigned: Uint8Array) => Uint8Array;
}): Uint8Array {
  const protectedMap = new Map<number, unknown>();
  protectedMap.set(LABEL_ALG, opts.alg);
  protectedMap.set(LABEL_KID, hexToBytes(opts.kidHex));
  const chainClaim = new Map<number, unknown>();
  chainClaim.set(1, opts.position);
  chainClaim.set(2, opts.previousHash === null ? null : hexToBytes(opts.previousHash));
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

const edEnvelope = buildEnvelope({
  alg: -8,
  kidHex: ED_KEY_ID,
  position: 1,
  previousHash: null,
  signer: (tbs) => new Uint8Array(cryptoSign(null, tbs, ed.privateKey)),
});

const esEnvelope = buildEnvelope({
  alg: -7,
  kidHex: ES_KEY_ID,
  position: 1,
  previousHash: null,
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
    scopeId: 'fips-test',
    chainPosition: 1,
    payloadHash: sha256Hex(envelope),
    previousHash: null,
    coseSign1: Buffer.from(envelope).toString('base64'),
    signingKeyId,
  };
}

describe('a runtime that cannot compute EdDSA', () => {
  it('reports a valid Ed25519 envelope as unsupported, not invalid', () => {
    expect(verifyCoseSign1(edEnvelope, spkiBase64(ed.publicKey))).toBe(
      'unsupported-key-algorithm',
    );
  });

  it('still verifies ES256, which the FIPS provider does carry', () => {
    // The single-variable control from the report: same host, same build, and
    // the ES256 chain passes while the Ed25519 chain cannot be computed.
    expect(verifyCoseSign1(esEnvelope, spkiBase64(es.publicKey))).toBe('ok');
  });

  it('fails the chain closed, and never as tamper', () => {
    const result = verifyChain([toEntry(edEnvelope, ED_KEY_ID)], buildKeyRegistry([edKey]), {});
    // Fail closed: an uncheckable chain is not a verified chain.
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_UNSUPPORTED_ALGORITHM');
    expect(result.brokenAt?.code).not.toBe('CHAIN_SIGNATURE_INVALID');
  });

  it('names the runtime, the real cause, and the remedy', () => {
    const result = verifyChain([toEntry(edEnvelope, ED_KEY_ID)], buildKeyRegistry([edKey]), {});
    const detail = result.brokenAt?.detail ?? '';
    expect(detail).toContain('Ed25519');
    expect(detail).toContain('HOST RUNTIME');
    expect(detail).toContain('FIPS');
    expect(detail).toContain('NOT tamper evidence');
    expect(detail).toContain('Re-run the verification on a host without that restriction');
    // The sentence that sent an auditor after a healthy chain.
    expect(detail).not.toContain('forged');
  });

  it('marks the entry unsupported rather than invalid', () => {
    const result = verifyChain([toEntry(edEnvelope, ED_KEY_ID)], buildKeyRegistry([edKey]), {});
    expect(result.entries.map((e) => e.signature)).toEqual(['unsupported']);
  });
});
