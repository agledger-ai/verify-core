import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';
import { buildAgentKeyRegistry, buildKeyRegistry, verifyChain } from '../chain.js';
import type { NormalizedEntry } from '../chain.js';
import { AGENT_SIGNATURE_CONTEXT, ed25519JwkThumbprint, sha256Hex } from '../primitives.js';
import type { AgentPublicKeyJwk } from '../primitives.js';

/**
 * Offline agent-signature re-check, and the 1.8.0 chain content it runs on.
 *
 * The fixtures under fixtures/live-1.8.0/ are unmodified `/audit-export`
 * responses from a live API 1.8.0 instance: a record walked through its whole
 * lifecycle on an API key (entries carry the internal `state` /
 * `previousState` / `newState` beside the display status), the same walk on an
 * ephemeral cert with every write agent-signed, and a bound and an unbound
 * delegated create. `agent-cert-key.json` is the Ed25519 JWK the agent sent at
 * cert exchange. The synthetic cases below cover what a live engine will not
 * produce: a sealed agent signature that does not verify.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const LIVE = join(HERE, 'fixtures', 'live-1.8.0');

function loadExport(name: string): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(LIVE, name), 'utf8')) as RecordAuditExportInput;
}

const agentCert = JSON.parse(readFileSync(join(LIVE, 'agent-cert-key.json'), 'utf8')) as {
  certId: string;
  publicKeyThumbprint: string;
  publicKeyJwk: AgentPublicKeyJwk;
};

function jwkOf(key: KeyObject): AgentPublicKeyJwk {
  const { x } = key.export({ format: 'jwk' }) as { x: string };
  return { kty: 'OKP', crv: 'Ed25519', x };
}

describe('1.8.0 chain content verifies', () => {
  it('a lifecycle signed in both state vocabularies verifies, with the binding check applied', () => {
    const doc = loadExport('export-lifecycle.json');
    // The fixture must actually carry the new keys, or this proves nothing.
    const registerHop = doc.entries[1]!.payload as Record<string, unknown>;
    expect(registerHop['previousState']).toBe('DRAFT');
    expect(registerHop['newState']).toBe('REGISTERED');
    expect(registerHop['previousStatus']).toBe('CREATED');
    expect(registerHop['newStatus']).toBe('CREATED');
    expect((doc.entries[0]!.payload as Record<string, unknown>)['state']).toBe('DRAFT');

    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(true);
    expect(result.verifiedEntries).toBe(9);
    expect(result.optionalChecks.payload_binding).toBe('applied');
    expect(result.agentSignatures).toEqual({ present: 0, verified: 0 });
    expect(result.optionalChecks.agent_signature).toBe('skipped_no_input');
  });

  it('a rewritten internal state on the registration hop is a binding mismatch', () => {
    const doc = loadExport('export-lifecycle.json');
    (doc.entries[1]!.payload as Record<string, unknown>)['previousState'] = 'REGISTERED';
    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toMatchObject({ position: 2, code: 'CHAIN_PAYLOAD_BINDING_MISMATCH' });
  });
});

describe('agent signature re-check on live exports', () => {
  it('the RFC 7638 thumbprint matches the one the engine recorded for the cert', () => {
    expect(ed25519JwkThumbprint(agentCert.publicKeyJwk)).toBe(agentCert.publicKeyThumbprint);
  });

  it('without agentKeys, sealed agent signatures are counted and reported unchecked', () => {
    const result = verifyAuditExport(loadExport('export-cert-lifecycle.json'));
    expect(result.valid).toBe(true);
    expect(result.agentSignatures.present).toBeGreaterThan(0);
    expect(result.agentSignatures.verified).toBe(0);
    expect(result.optionalChecks.agent_signature).toBe('skipped_no_input');
  });

  it('with the cert key, every sealed agent signature on a cert-signed lifecycle verifies', () => {
    const result = verifyAuditExport(loadExport('export-cert-lifecycle.json'), {
      agentKeys: [agentCert.publicKeyJwk],
    });
    expect(result.valid).toBe(true);
    expect(result.optionalChecks.agent_signature).toBe('applied');
    // Every entry written by a signed request carries it: the create and its
    // two autoActivate hops, the completion, and the verdict's outcome and
    // settlement. The three gate entries are written by the worker.
    expect(result.agentSignatures.present).toBe(6);
    expect(result.agentSignatures.verified).toBe(result.agentSignatures.present);
  });

  it('a bound delegated create carries the caller cert agent signature, and it verifies', () => {
    const result = verifyAuditExport(loadExport('export-delegated-bound.json'), {
      agentKeys: [agentCert.publicKeyJwk],
    });
    expect(result.valid).toBe(true);
    expect(result.agentSignatures).toEqual({ present: 1, verified: 1 });
  });

  it('an unbound delegated create on an API key carries no agent signature', () => {
    const result = verifyAuditExport(loadExport('export-delegated-unbound.json'), {
      agentKeys: [agentCert.publicKeyJwk],
    });
    expect(result.valid).toBe(true);
    expect(result.agentSignatures).toEqual({ present: 0, verified: 0 });
    expect(result.optionalChecks.agent_signature).toBe('skipped_no_input');
  });

  it('a key for a different cert matches nothing and is never checked against the entry', () => {
    const other = generateKeyPairSync('ed25519');
    const result = verifyAuditExport(loadExport('export-cert-lifecycle.json'), {
      agentKeys: [jwkOf(other.publicKey)],
    });
    expect(result.valid).toBe(true);
    expect(result.agentSignatures.verified).toBe(0);
    expect(result.optionalChecks.agent_signature).toBe('skipped_no_input');
  });

  it('refuses anything that is not an Ed25519 public-key JWK at the boundary', () => {
    const doc = loadExport('export-cert-lifecycle.json');
    const bad = [
      { kty: 'RSA', n: 'x', e: 'AQAB' },
      { kty: 'OKP', crv: 'X25519', x: agentCert.publicKeyJwk.x },
      { kty: 'OKP', crv: 'Ed25519', x: 'dG9vLXNob3J0' },
      null,
    ];
    for (const jwk of bad) {
      expect(() =>
        verifyAuditExport(doc, { agentKeys: [jwk as unknown as AgentPublicKeyJwk] }),
      ).toThrow(TypeError);
    }
    expect(() => buildAgentKeyRegistry('nope' as unknown as AgentPublicKeyJwk[])).toThrow(TypeError);
  });
});

// --- Synthetic envelopes: a sealed agent signature that does not verify ---

const COSE_TAG_PREFIX = 0xd2;
const KEY_ID = 'aabbccddeeff0011';
const vault = generateKeyPairSync('ed25519');
const agent = generateKeyPairSync('ed25519');
const impostor = generateKeyPairSync('ed25519');
const agentJwk = jwkOf(agent.publicKey);
const agentThumbprint = ed25519JwkThumbprint(agentJwk)!;

function agentSign(key: KeyObject, contentHex: string): string {
  return cryptoSign(null, Buffer.from(`${AGENT_SIGNATURE_CONTEXT}${contentHex}`, 'utf8'), key).toString('base64');
}

function envelopeWith(onBehalfOf: Record<string, unknown>): NormalizedEntry {
  const protectedMap = new Map<number, unknown>([
    [1, -8],
    [4, Buffer.from(KEY_ID, 'hex')],
    [-65537, new Map<number, unknown>([[1, 1], [2, null]])],
  ]);
  const protectedBstr = cborEncode(protectedMap, rfc8949EncodeOptions);
  const payloadBstr = cborEncode(
    { predicate: { record_id: 'r', entry_type: 'RECORD_CREATED', on_behalf_of: onBehalfOf } },
    rfc8949EncodeOptions,
  );
  const toBeSigned = cborEncode(['Signature1', protectedBstr, new Uint8Array(0), payloadBstr], rfc8949EncodeOptions);
  const signature = cryptoSign(null, toBeSigned, vault.privateKey);
  const body = cborEncode([protectedBstr, new Map(), payloadBstr, signature], rfc8949EncodeOptions);
  const envelope = new Uint8Array(1 + body.length);
  envelope[0] = COSE_TAG_PREFIX;
  envelope.set(body, 1);
  return {
    scopeId: 'agent-sig-test',
    chainPosition: 1,
    payloadHash: sha256Hex(envelope),
    previousHash: null,
    coseSign1: Buffer.from(envelope).toString('base64'),
    signingKeyId: KEY_ID,
  };
}

const vaultKeys = buildKeyRegistry([
  {
    keyId: KEY_ID,
    spkiBase64: (vault.publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64'),
    source: 'out-of-band',
  },
]);
const agentKeys = buildAgentKeyRegistry([agentJwk]);
const contentHex = createHash('sha256').update('{"type":"t","criteria":{}}').digest('hex');

function sealed(overrides: { validated?: boolean; signature?: Record<string, unknown> } = {}) {
  return envelopeWith({
    validated: overrides.validated ?? true,
    cert: { id: '00000000-0000-4000-8000-000000000001', thumbprint: agentThumbprint, expires_at: 1 },
    agent_signature: overrides.signature ?? {
      alg: 'EdDSA',
      content_hash: `sha256:${contentHex}`,
      signature: agentSign(agent.privateKey, contentHex),
    },
  });
}

describe('agent signature re-check on synthetic entries', () => {
  it('verifies a good sealed signature', () => {
    const result = verifyChain([sealed()], vaultKeys, { agentKeys });
    expect(result.valid).toBe(true);
    expect(result.agentSignatures).toEqual({ present: 1, verified: 1 });
    expect(result.optionalChecks.agent_signature).toBe('applied');
  });

  it('fails a sealed signature made by a key other than the one the cert names', () => {
    const entry = sealed({
      signature: { alg: 'EdDSA', content_hash: `sha256:${contentHex}`, signature: agentSign(impostor.privateKey, contentHex) },
    });
    const result = verifyChain([entry], vaultKeys, { agentKeys });
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_AGENT_SIGNATURE_INVALID');
    // The envelope itself verified: the finding is about the sealed claim.
    expect(result.entries[0]!.signature).toBe('ok');
    expect(result.agentSignatures).toEqual({ present: 1, verified: 0 });
  });

  it('fails a signature over a different content hash', () => {
    const otherHex = createHash('sha256').update('something else').digest('hex');
    const entry = sealed({
      signature: { alg: 'EdDSA', content_hash: `sha256:${contentHex}`, signature: agentSign(agent.privateKey, otherHex) },
    });
    expect(verifyChain([entry], vaultKeys, { agentKeys }).brokenAt?.code).toBe('CHAIN_AGENT_SIGNATURE_INVALID');
  });

  it('fails shapes nothing can verify', () => {
    const good = agentSign(agent.privateKey, contentHex);
    const shapes = [
      { alg: 'ES256', content_hash: `sha256:${contentHex}`, signature: good },
      { alg: 'EdDSA', content_hash: contentHex, signature: good },
      { alg: 'EdDSA', content_hash: `sha256:${contentHex}`, signature: Buffer.from(good, 'base64').toString('base64url') },
      { alg: 'EdDSA', content_hash: `sha256:${contentHex}`, signature: 42 },
    ];
    for (const signature of shapes) {
      const result = verifyChain([sealed({ signature })], vaultKeys, { agentKeys });
      expect(result.brokenAt?.code, JSON.stringify(signature)).toBe('CHAIN_AGENT_SIGNATURE_INVALID');
    }
  });

  it('leaves a caller-asserted identity unchecked, whatever its sealed signature says', () => {
    const entry = sealed({
      validated: false,
      signature: { alg: 'EdDSA', content_hash: `sha256:${contentHex}`, signature: agentSign(impostor.privateKey, contentHex) },
    });
    const result = verifyChain([entry], vaultKeys, { agentKeys });
    expect(result.valid).toBe(true);
    expect(result.agentSignatures).toEqual({ present: 1, verified: 0 });
    expect(result.optionalChecks.agent_signature).toBe('skipped_no_input');
  });

  it('never runs without agentKeys', () => {
    const entry = sealed({
      signature: { alg: 'EdDSA', content_hash: `sha256:${contentHex}`, signature: agentSign(impostor.privateKey, contentHex) },
    });
    const result = verifyChain([entry], vaultKeys);
    expect(result.valid).toBe(true);
    expect(result.optionalChecks.agent_signature).toBe('skipped_no_input');
  });
});
