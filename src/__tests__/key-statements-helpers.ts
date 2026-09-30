/**
 * Test-only signer for vault key statements, written from the statement
 * format (the engine's encodeKeyStatementPayload / signKeyStatement), so the
 * walk under test never checks bytes it produced itself.
 */
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { encode, rfc8949EncodeOptions } from 'cborg';
import type { KeyStatementInput, TrustKeyInput } from '../key-statements.js';

export type Alg = 'Ed25519' | 'ES256';

export interface TestKey {
  privateKey: string;
  publicKey: string;
  digest: string;
  kid: string;
  alg: Alg;
  /** Key material nothing on this host parses, whose signatures are random bytes. */
  opaque?: boolean;
}

export const CTY = 'application/vnd.agledger.key-statement+cbor';

export function makeKey(alg: Alg = 'Ed25519'): TestKey {
  const pair = alg === 'Ed25519'
    ? generateKeyPairSync('ed25519')
    : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const digest = createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest('hex');
  return { privateKey, publicKey, digest, kid: digest.slice(0, 16), alg };
}

/** An Ed25519 key as a host without EdDSA sees it: bytes that do not parse. */
export function makeOpaqueKey(): TestKey {
  const publicKey = randomBytes(44).toString('base64');
  const digest = createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest('hex');
  return { privateKey: '', publicKey, digest, kid: digest.slice(0, 16), alg: 'Ed25519', opaque: true };
}

export interface Payload {
  typ: string;
  iss: string;
  subject: { kid: string; spkiSha256: string; alg: string; spki: string; activatedAt: string; retiredAt?: string };
  endorser?: { kid: string; spkiSha256: string };
  iat: number;
  forced?: boolean;
}

export function encodePayload(p: Payload): Uint8Array {
  const subject: Record<string, unknown> = {
    kid: p.subject.kid,
    spkiSha256: p.subject.spkiSha256,
    alg: p.subject.alg,
    spki: Uint8Array.from(Buffer.from(p.subject.spki, 'base64')),
    activatedAt: p.subject.activatedAt,
  };
  if (p.subject.retiredAt !== undefined) subject['retiredAt'] = p.subject.retiredAt;
  const out: Record<string, unknown> = { typ: p.typ, iss: p.iss, subject, iat: p.iat };
  if (p.endorser) out['endorser'] = { kid: p.endorser.kid, spkiSha256: p.endorser.spkiSha256 };
  if (p.forced !== undefined) out['forced'] = p.forced;
  return encode(out, rfc8949EncodeOptions);
}

export function signStatement(payload: Uint8Array, k: TestKey): Buffer {
  const header = new Map<number, unknown>([
    [1, k.alg === 'Ed25519' ? -8 : -7],
    [3, CTY],
    [4, Uint8Array.from(Buffer.from(k.kid, 'hex'))],
  ]);
  const protectedBstr = encode(header, rfc8949EncodeOptions);
  const toBeSigned = encode(['Signature1', protectedBstr, new Uint8Array(0), payload], rfc8949EncodeOptions);
  let signature: Uint8Array;
  if (k.opaque) {
    signature = randomBytes(64);
  } else {
    const key = { key: Buffer.from(k.privateKey, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
    signature = k.alg === 'Ed25519'
      ? sign(null, toBeSigned, key)
      : sign('sha256', toBeSigned, { ...key, dsaEncoding: 'ieee-p1363' });
  }
  const inner = encode([protectedBstr, new Map(), payload, signature], rfc8949EncodeOptions);
  return Buffer.concat([Buffer.from([0xd2]), Buffer.from(inner)]);
}

export const T0 = '2026-09-01T00:00:00.000000Z';
export const T1 = '2026-09-02T00:00:00.000000Z';
export const T2 = '2026-09-03T00:00:00.000000Z';
export const T3 = '2026-09-04T00:00:00.000000Z';

let seq = 0;
export function nextId(): string {
  seq++;
  return `00000000-0000-7000-8000-${String(seq).padStart(12, '0')}`;
}

/** A dump key row, with the window columns at millisecond precision as the dump writes them. */
export function row(k: TestKey, activated: string, retired: string | null = null): TrustKeyInput {
  return {
    keyId: k.kid,
    publicKey: k.publicKey,
    algorithm: k.alg,
    status: retired ? 'retired' : 'active',
    activatedAt: ms(activated),
    retiredAt: retired ? ms(retired) : null,
  };
}

/** A microsecond instant as a millisecond ISO string, the way the dump writes a column. */
export function ms(instant: string): string {
  return `${instant.slice(0, 23)}Z`;
}

export type Stored = KeyStatementInput & { id: string; createdAt: string; digest: string; payload: Payload };

export function statement(
  typ: string,
  subject: TestKey,
  opts: {
    endorser?: TestKey;
    signers: TestKey[];
    activatedAt?: string;
    retiredAt?: string;
    forced?: boolean;
    iat?: number;
    createdAt?: string;
  },
): Stored {
  const payload: Payload = {
    typ,
    iss: 'https://ledger.example',
    subject: {
      kid: subject.kid,
      spkiSha256: subject.digest,
      alg: subject.alg,
      spki: subject.publicKey,
      activatedAt: opts.activatedAt ?? T0,
      ...(opts.retiredAt ? { retiredAt: opts.retiredAt } : {}),
    },
    ...(opts.endorser ? { endorser: { kid: opts.endorser.kid, spkiSha256: opts.endorser.digest } } : {}),
    iat: opts.iat ?? Math.floor(Date.parse(T3) / 1000),
    ...(typ === 'closure' ? { forced: opts.forced ?? false } : {}),
  };
  const bytes = encodePayload(payload);
  return {
    id: nextId(),
    kind: typ,
    subjectKeyId: subject.kid,
    endorserKeyId: opts.endorser?.kid ?? null,
    cose: opts.signers.map((k) => signStatement(bytes, k)),
    createdAt: ms(opts.createdAt ?? T1),
    digest: createHash('sha256').update(bytes).digest('hex'),
    payload,
  };
}

/** The same statements as a key document carries them: no write time, no endorser column. */
export function asDocument(statements: readonly Stored[]): KeyStatementInput[] {
  return statements.map(({ id, kind, subjectKeyId, cose }) => ({ id, kind, subjectKeyId, cose }));
}
