import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import {
  decodeCoseSign1,
  resolveKeyAlgorithm,
  sha256Hex,
  verifyCoseSign1,
  verifyEd25519Bytes,
} from '../primitives.js';
import { buildKeyRegistry, verifyChain } from '../chain.js';
import type { NormalizedEntry, VerificationKey } from '../chain.js';

/**
 * The verifier forward-compatibility floor (signing-agility Phase 0).
 *
 * Exit criteria pinned here:
 *   - a hand-built, conformant ES256 envelope that no engine produces yields
 *     CHAIN_UNSUPPORTED_ALGORITHM with valid:false (an upgrade signal, but
 *     never a pass);
 *   - a tampered-alg Ed25519 envelope yields a tamper-class failure, never an
 *     upgrade notice (one flipped header byte must not downgrade a forgery
 *     alarm);
 *   - dispatch binds to the trusted key, so the attacker-controlled header can
 *     select nothing; the header alg is only asserted equal;
 *   - the all-zero unsigned sentinel is evaluated at the key's expected
 *     signature length, after algorithm resolution;
 *   - the signature-covered kid (label 4) is cross-checked against the row's
 *     signingKeyId column (engine mirror: signing_key_drift, #893);
 *   - untagged COSE_Sign1 is rejected, matching the engine's decoder.
 */

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

const edSigner = (toBeSigned: Uint8Array): Uint8Array =>
  new Uint8Array(cryptoSign(null, toBeSigned, ed.privateKey));
/** Conformant ES256: SHA-256 digest, raw R||S (ieee-p1363), 64 bytes. */
const esSigner = (toBeSigned: Uint8Array): Uint8Array =>
  new Uint8Array(cryptoSign('sha256', toBeSigned, { key: es.privateKey, dsaEncoding: 'ieee-p1363' }));

interface EnvelopeOpts {
  alg?: number | null;
  kidHex?: string;
  position: number;
  previousHash: string | null;
  signer: (toBeSigned: Uint8Array) => Uint8Array;
  /** Override the signature bytes entirely (sentinel tests). */
  signatureOverride?: Uint8Array;
  untagged?: boolean;
}

function buildEnvelope(opts: EnvelopeOpts): Uint8Array {
  const protectedMap = new Map<number, unknown>();
  if (opts.alg !== null) protectedMap.set(LABEL_ALG, opts.alg ?? -8);
  protectedMap.set(LABEL_KID, hexToBytes(opts.kidHex ?? ED_KEY_ID));
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
  const signature = opts.signatureOverride ?? opts.signer(toBeSigned);

  const body = cborEncode([protectedBstr, new Map(), payloadBstr, signature], rfc8949EncodeOptions);
  if (opts.untagged) return body;
  const out = new Uint8Array(1 + body.length);
  out[0] = COSE_TAG_PREFIX;
  out.set(body, 1);
  return out;
}

function toEntry(
  envelope: Uint8Array,
  position: number,
  previousHash: string | null,
  signingKeyId: string | null,
): NormalizedEntry {
  return {
    scopeId: 'floor-test',
    chainPosition: position,
    payloadHash: sha256Hex(envelope),
    previousHash,
    coseSign1: Buffer.from(envelope).toString('base64'),
    signingKeyId,
  };
}

function registry(...keys: VerificationKey[]) {
  return buildKeyRegistry(keys);
}

const edKey: VerificationKey = { keyId: ED_KEY_ID, spkiBase64: spkiBase64(ed.publicKey), source: 'out-of-band' };
const esKey: VerificationKey = { keyId: ES_KEY_ID, spkiBase64: spkiBase64(es.publicKey), source: 'out-of-band' };

describe('resolveKeyAlgorithm', () => {
  it('classifies Ed25519 and P-256 keys from the SPKI, not any header', () => {
    const edAlg = resolveKeyAlgorithm(edKey.spkiBase64);
    const esAlg = resolveKeyAlgorithm(esKey.spkiBase64);
    expect(edAlg).toMatchObject({ name: 'Ed25519', verifiable: true, signatureLength: 64 });
    expect(esAlg).toMatchObject({ name: 'ES256', verifiable: false, signatureLength: 64 });
  });

  it('reports unrecognized key types without claiming forgery', () => {
    const x = generateKeyPairSync('x25519');
    expect(resolveKeyAlgorithm(spkiBase64(x.publicKey))).toBe('unrecognized');
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(resolveKeyAlgorithm(spkiBase64(rsa.publicKey))).toBe('unrecognized');
    expect(resolveKeyAlgorithm('bm90IGEga2V5')).toBe('unparseable');
  });
});

describe('verifyEd25519Bytes refuses non-Ed25519 keys (api#1089 mirror)', () => {
  it('returns false for a P-256 key even when the ECDSA fallback would verify', () => {
    const input = new Uint8Array([1, 2, 3]);
    // DER ECDSA signature, exactly what Node's verify(null, ...) fallback accepts.
    const derSig = new Uint8Array(cryptoSign('sha256', input, es.privateKey));
    expect(verifyEd25519Bytes(esKey.spkiBase64, input, derSig)).toBe(false);
  });
});

describe('exit criterion: conformant ES256 envelope', () => {
  const envelope = buildEnvelope({ alg: -7, kidHex: ES_KEY_ID, position: 1, previousHash: null, signer: esSigner });

  it('verifyCoseSign1 reports unsupported-key-algorithm, never invalid or ok', () => {
    expect(verifyCoseSign1(envelope, esKey.spkiBase64)).toBe('unsupported-key-algorithm');
  });

  it('the chain walk fails CHAIN_UNSUPPORTED_ALGORITHM with valid:false', () => {
    const result = verifyChain([toEntry(envelope, 1, null, ES_KEY_ID)], registry(esKey));
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_UNSUPPORTED_ALGORITHM');
    expect(result.entries[0]?.signature).toBe('unsupported');
  });

  it('fully-specified ESP256 (-9) is equally recognized as unsupported, not tamper', () => {
    const esp = buildEnvelope({ alg: -9, kidHex: ES_KEY_ID, position: 1, previousHash: null, signer: esSigner });
    expect(verifyCoseSign1(esp, esKey.spkiBase64)).toBe('unsupported-key-algorithm');
  });
});

describe('exit criterion: tampered alg is a tamper-class failure', () => {
  it('an unassigned alg on an Ed25519 key reads as forgery, not upgrade', () => {
    const envelope = buildEnvelope({ alg: -999, position: 1, previousHash: null, signer: edSigner });
    expect(verifyCoseSign1(envelope, edKey.spkiBase64)).toBe('alg-mismatch');
    const result = verifyChain([toEntry(envelope, 1, null, ED_KEY_ID)], registry(edKey));
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_ALG_MISMATCH');
  });

  it('a MAC alg (label 5, HMAC-256/256) can never bind the public key as a MAC key', () => {
    const envelope = buildEnvelope({ alg: 5, position: 1, previousHash: null, signer: edSigner });
    expect(verifyCoseSign1(envelope, edKey.spkiBase64)).toBe('alg-mismatch');
  });

  it('a missing alg is a mismatch, not a pass-through', () => {
    const envelope = buildEnvelope({ alg: null, position: 1, previousHash: null, signer: edSigner });
    expect(verifyCoseSign1(envelope, edKey.spkiBase64)).toBe('alg-mismatch');
  });

  it('the pre-guard corruption shape (P-256 key under an EdDSA header) is tamper-class', () => {
    const envelope = buildEnvelope({ alg: -8, kidHex: ES_KEY_ID, position: 1, previousHash: null, signer: esSigner });
    expect(verifyCoseSign1(envelope, esKey.spkiBase64)).toBe('alg-mismatch');
    const result = verifyChain([toEntry(envelope, 1, null, ES_KEY_ID)], registry(esKey));
    expect(result.brokenAt?.code).toBe('CHAIN_ALG_MISMATCH');
  });
});

describe('forward compatibility inside the Ed25519 family', () => {
  it('accepts the RFC 9864 fully-specified Ed25519 code point (-19)', () => {
    const envelope = buildEnvelope({ alg: -19, position: 1, previousHash: null, signer: edSigner });
    expect(verifyCoseSign1(envelope, edKey.spkiBase64)).toBe('ok');
    const result = verifyChain([toEntry(envelope, 1, null, ED_KEY_ID)], registry(edKey));
    expect(result.valid).toBe(true);
    expect(result.entries[0]?.signature).toBe('ok');
  });
});

describe('unsigned sentinel is key-length-derived and policy-gated', () => {
  const zeroSig = buildEnvelope({
    alg: -8,
    position: 1,
    previousHash: null,
    signer: edSigner,
    signatureOverride: new Uint8Array(64),
  });

  it('64 zero bytes under an Ed25519 key reads unsigned without a policy', () => {
    expect(verifyCoseSign1(zeroSig, edKey.spkiBase64)).toBe('unsigned');
    const result = verifyChain([toEntry(zeroSig, 1, null, ED_KEY_ID)], registry(edKey));
    expect(result.valid).toBe(true);
    expect(result.signatureCoverage.unsigned).toBe(1);
  });

  it('an all-zero signature on an entry claiming a key fails under requireOutOfBandKeys', () => {
    const result = verifyChain([toEntry(zeroSig, 1, null, ED_KEY_ID)], registry(edKey), {
      requireOutOfBandKeys: true,
    });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_POLICY_VIOLATION');
  });

  it('an all-zero signature fails under requireKeyId even when the id matches', () => {
    const result = verifyChain([toEntry(zeroSig, 1, null, ED_KEY_ID)], registry(edKey), {
      requireKeyId: ED_KEY_ID,
    });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_POLICY_VIOLATION');
  });

  it('a zero fill of a DIFFERENT length is not the sentinel (ML-DSA-length regression)', () => {
    const wrongLengthZeros = buildEnvelope({
      alg: -8,
      position: 1,
      previousHash: null,
      signer: edSigner,
      signatureOverride: new Uint8Array(2420),
    });
    expect(verifyCoseSign1(wrongLengthZeros, edKey.spkiBase64)).toBe('invalid');
  });
});

describe('signed-kid binding (engine signing_key_drift mirror)', () => {
  it('fails CHAIN_SIGNING_KEY_DRIFT when the row column names a different key than the signed kid', () => {
    // Envelope signed with (and naming) the Ed25519 key; the row column claims
    // the ES key id, which also resolves in the registry. Without the kid
    // binding this would fall through to a plain signature failure and hide
    // the column rewrite.
    const envelope = buildEnvelope({ alg: -8, kidHex: ED_KEY_ID, position: 1, previousHash: null, signer: edSigner });
    const result = verifyChain([toEntry(envelope, 1, null, ES_KEY_ID)], registry(edKey, esKey));
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_SIGNING_KEY_DRIFT');
  });
});

describe('registry algorithm declaration cross-check', () => {
  it('fails CHAIN_ALG_MISMATCH when the declared algorithm contradicts the key material', () => {
    const lyingKey: VerificationKey = { ...esKey, algorithm: 'Ed25519' };
    const envelope = buildEnvelope({ alg: -7, kidHex: ES_KEY_ID, position: 1, previousHash: null, signer: esSigner });
    const result = verifyChain([toEntry(envelope, 1, null, ES_KEY_ID)], registry(lyingKey));
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_ALG_MISMATCH');
    expect(result.brokenAt?.detail).toContain('registry');
  });

  it('a truthful declaration passes through to normal verification', () => {
    const truthful: VerificationKey = { ...edKey, algorithm: 'Ed25519' };
    const envelope = buildEnvelope({ alg: -8, position: 1, previousHash: null, signer: edSigner });
    const result = verifyChain([toEntry(envelope, 1, null, ED_KEY_ID)], registry(truthful));
    expect(result.valid).toBe(true);
  });
});

describe('empty-string signingKeyId is not the unsigned marker', () => {
  it('fails CHAIN_SIGNATURE_MISSING_KEY instead of skipping the signature check', () => {
    // Only null is the engine's unsigned-mode marker. A tampered row carrying
    // signingKeyId:"" must not ride the null-key skip branch to a green chain.
    const envelope = buildEnvelope({ alg: -8, position: 1, previousHash: null, signer: edSigner });
    const result = verifyChain([toEntry(envelope, 1, null, '')], registry(edKey));
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_SIGNATURE_MISSING_KEY');
    expect(result.signatureCoverage.skipped).toBe(0);
  });
});

describe('untagged COSE_Sign1 rejection (engine decoder parity)', () => {
  it('decodeCoseSign1 returns null for an untagged envelope', () => {
    const untagged = buildEnvelope({ alg: -8, position: 1, previousHash: null, signer: edSigner, untagged: true });
    expect(decodeCoseSign1(untagged)).toBeNull();
    expect(verifyCoseSign1(untagged, edKey.spkiBase64)).toBe('decode-fail');
  });

  it('the chain walk surfaces it as CHAIN_COSE_DECODE_FAILED', () => {
    const untagged = buildEnvelope({ alg: -8, position: 1, previousHash: null, signer: edSigner, untagged: true });
    const result = verifyChain([toEntry(untagged, 1, null, ED_KEY_ID)], registry(edKey));
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_COSE_DECODE_FAILED');
  });
});
