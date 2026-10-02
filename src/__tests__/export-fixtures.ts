import { readFileSync } from 'node:fs';
import { createHash, sign } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decode as cborDecode, encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import type { RecordAuditExportInput } from '../audit-export.js';
import { T0, T1, makeKey, ms, statement, type Stored, type TestKey } from './key-statements-helpers.js';

/** Corpus exports, and what the holder of a vault key can build from one. */

const EXPORT_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'testdata', 'conformance', 'export');
export const load = (name: string): RecordAuditExportInput =>
  JSON.parse(readFileSync(join(EXPORT_DIR, name), 'utf8')) as RecordAuditExportInput;

/**
 * valid.json with every entry re-signed under `key` and the chain relinked:
 * what the holder of a leaked key that admitted `key` can produce.
 */
export function resignedUnder(key: TestKey): RecordAuditExportInput {
  const exp = load('valid.json');
  const priv = { key: Buffer.from(key.privateKey, 'base64'), format: 'der' as const, type: 'pkcs8' as const };
  let prev: Buffer | null = null;
  for (const e of exp.entries) {
    const [prot0, , payload] = cborDecode(Buffer.from(e.integrity.coseSign1, 'base64').subarray(1), { useMaps: true }) as [Uint8Array, unknown, Uint8Array];
    const header = cborDecode(prot0, { useMaps: true }) as Map<number, unknown>;
    header.set(4, Uint8Array.from(Buffer.from(key.kid, 'hex')));
    (header.get(-65537) as Map<number, unknown>).set(2, prev === null ? null : Uint8Array.from(prev));
    const prot = cborEncode(header, rfc8949EncodeOptions);
    const sig = sign(null, cborEncode(['Signature1', prot, new Uint8Array(0), payload], rfc8949EncodeOptions), priv);
    const envelope = Buffer.concat([Buffer.from([0xd2]), Buffer.from(cborEncode([prot, new Map(), payload, Uint8Array.from(sig)], rfc8949EncodeOptions))]);
    const hash = createHash('sha256').update(envelope).digest();
    e.integrity.coseSign1 = envelope.toString('base64');
    e.integrity.payloadHash = hash.toString('hex');
    e.integrity.previousHash = prev === null ? null : prev.toString('hex');
    e.integrity.signingKeyId = key.kid;
    prev = hash;
  }
  return exp;
}

export const published = (st: Stored, createdAt?: string) => ({
  ...(createdAt !== undefined ? { id: st.id, createdAt } : {}),
  kind: st.kind,
  cose: st.cose.map((b) => Buffer.from(b as Uint8Array).toString('base64')),
});

/**
 * valid.json re-signed under a key K that a genesis root G admitted, with
 * both statements and windows in the export: pin `pin` (G) and distrust K,
 * the shape a leak takes, since a key is never both pinned and distrusted.
 */
export function underAdmittedKey(): { exp: RecordAuditExportInput; pin: string; key: TestKey } {
  const g = makeKey();
  const k = makeKey();
  const genesis = statement('genesis', g, { signers: [g], activatedAt: T0 });
  const succ = statement('succession', k, { endorser: g, signers: [g, k], activatedAt: T1 });
  const exp = resignedUnder(k);
  const m = exp.exportMetadata;
  m.signingPublicKeys = { [g.kid]: g.publicKey, [k.kid]: k.publicKey };
  m.signingKeyWindows = { [g.kid]: { activatedAt: ms(T0), retiredAt: null }, [k.kid]: { activatedAt: ms(T1), retiredAt: null } };
  m.anchoredFrom = `sha256:${g.digest}`;
  m.signingKeyStatements = {
    [g.kid]: [published(genesis, '2026-09-01T00:00:00.000100Z')],
    [k.kid]: [published(succ, '2026-09-02T00:00:00.000100Z')],
  };
  return { exp, pin: `sha256:${g.digest}`, key: k };
}
