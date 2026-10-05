/**
 * Seeded random key registries for the engine differential
 * (key-trust-engine.test.ts). Everything that decides a verdict is a function
 * of the seed: the key pool is derived from fixed seeds, and statement ids and
 * times come from the seed's PRNG. ES256 signatures are randomized, which moves
 * no verdict. scripts/record-key-trust-engine.mts runs the same scenarios
 * through the engine's computeKeyTrust and records what it concluded.
 */
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { encodePayload, signStatement, type Payload, type TestKey } from './key-statements-helpers.js';
import type { ComputeKeyTrustInput, KeyTrust, VerificationKeysDocument } from '../key-statements.js';

export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function fixedKey(i: number): TestKey {
  const seed = createHash('sha256').update(`agledger-key-trust-fuzz-${i}`).digest();
  const alg = i % 3 === 2 ? 'ES256' : 'Ed25519';
  // PKCS#8 around a raw Ed25519 seed, or a P-256 scalar with no public key (OpenSSL derives it).
  const der = alg === 'Ed25519'
    ? Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
    : Buffer.concat([Buffer.from('3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420', 'hex'), seed]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64');
  const digest = createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest('hex');
  return {
    privateKey: priv.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    publicKey,
    digest,
    kid: digest.slice(0, 16),
    alg,
  };
}

export const POOL: readonly TestKey[] = Array.from({ length: 12 }, (_, i) => fixedKey(i));
const indexOfKid = new Map(POOL.map((k, i) => [k.kid, i]));
const indexOfDigest = new Map(POOL.map((k, i) => [k.digest, i]));

export interface FuzzStatement {
  /** A uuid-shaped row id whose order is unrelated to the order it was written in. */
  id: string;
  kind: string;
  subject: number;
  endorser: number | null;
  cose: Buffer[];
  createdMs: number;
  /** The write time at microseconds, as the key documents publish it. */
  createdUs: string;
}

export interface FuzzRowKey {
  key: number;
  status: 'active' | 'retired';
  /** Microsecond instants; the dump columns carry them at millisecond precision. */
  activatedAt: string;
  retiredAt: string;
}

export interface FuzzScenario {
  statements: FuzzStatement[];
  anchors: number[];
  distrusted: Array<{ key: number; cutoff: string | null }>;
  rows: FuzzRowKey[];
}

const BASE = Date.parse('2026-01-01T00:00:00.000Z');
const us = (ms: number, sub: number) => `${new Date(ms).toISOString().slice(0, 23)}${String(sub).padStart(3, '0')}Z`;
export const toMs = (instant: string) => `${instant.slice(0, 23)}Z`;

/**
 * Random statements over a few pool keys: any kind, any signer order (some
 * with a signature missing), random signed instants that tie within a
 * millisecond, write times that tie within a millisecond and within a
 * microsecond (where only the row id orders them), duplicated rows, one or
 * two anchors, later admissions of an anchor (a genesis it re-signs, or a
 * succession into it from any key), and sometimes distrusted keys with or
 * without a cutoff. Statements come back in write order, `createdUs` then
 * `id`, as the engine's loader reads them.
 */
export function scenario(seed: number): FuzzScenario {
  const r = prng(seed);
  const pick = <T,>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)] as T;
  const keys = POOL.map((_, i) => i).sort(() => r() - 0.5).slice(0, 5 + Math.floor(r() * 5));
  let now = BASE;
  let idn = 0;
  const nextId = () => {
    idn++;
    const head = Math.floor(r() * 0x100000000).toString(16).padStart(8, '0');
    return `${head}-0000-4000-8000-${String(idn).padStart(12, '0')}`;
  };
  let lastSub = 0;
  /** A write time in millisecond `ms`, sometimes the same microsecond as the last one. */
  const written = (ms: number) => {
    if (r() >= 0.25) lastSub = Math.floor(r() * 1000);
    return us(ms, lastSub);
  };
  const T = () => us(BASE + Math.floor(r() * 20) * 1000 + Math.floor(r() * 3), Math.floor(r() * 1000));
  const statements: FuzzStatement[] = [];
  const add = (typ: string, subject: number, endorser: number, activatedAt: string, signerChoice: number): void => {
    let signers: number[];
    if (typ === 'genesis') signers = [subject];
    else if (typ === 'succession') signers = signerChoice < 0.9 ? [endorser, subject] : r() < 0.5 ? [endorser] : [subject, endorser];
    else signers = [endorser];
    const retiredAt = T();
    const withRetired = typ === 'closure' || r() < 0.1;
    const forced = typ === 'closure' ? r() < 0.3 : undefined;
    const s = POOL[subject]!;
    const e = POOL[endorser]!;
    const payload: Payload = {
      typ,
      iss: 'https://x',
      subject: { kid: s.kid, spkiSha256: s.digest, alg: s.alg, spki: s.publicKey, activatedAt, ...(withRetired ? { retiredAt } : {}) },
      ...(typ !== 'genesis' ? { endorser: { kid: e.kid, spkiSha256: e.digest } } : {}),
      iat: 1,
      ...(forced !== undefined ? { forced } : {}),
    };
    const bytes = encodePayload(payload);
    const st: FuzzStatement = {
      id: nextId(),
      kind: typ,
      subject,
      endorser: typ !== 'genesis' ? endorser : null,
      cose: signers.map((k) => signStatement(bytes, POOL[k]!)),
      createdMs: now,
      createdUs: written(now),
    };
    statements.push(st);
    if (r() < 0.1) statements.push({ ...st, id: nextId(), createdMs: now + 1, createdUs: written(now + 1) });
  };
  const n = 3 + Math.floor(r() * 12);
  for (let i = 0; i < n; i++) {
    now += Math.floor(r() * 3) * 1000 + (r() < 0.2 ? 0 : 1);
    const typ = pick(['genesis', 'succession', 'succession', 'closure', 'closure']);
    const subject = pick(keys);
    const endorser = pick(keys.filter((k) => k !== subject));
    add(typ, subject, endorser, T(), r());
  }
  const anchors = [...new Set([pick(keys), ...(r() < 0.3 ? [pick(keys)] : [])])];
  // Later admissions of a key the walk is likely to trust: each dates its
  // window and cuts its edge back, and the key documents publish them.
  const later = r() < 0.5 ? 1 + Math.floor(r() * 2) : 0;
  for (let i = 0; i < later; i++) {
    now += 1000 + Math.floor(r() * 2);
    const subject = r() < 0.6 ? pick(anchors) : pick(keys);
    add(r() < 0.6 ? 'genesis' : 'succession', subject, pick(keys.filter((k) => k !== subject)), T(), r());
  }
  statements.sort((a, b) => (a.createdUs < b.createdUs ? -1 : a.createdUs > b.createdUs ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const distrusted: FuzzScenario['distrusted'] = [];
  if (r() < 0.5) {
    for (const k of keys) if (r() < 0.25) distrusted.push({ key: k, cutoff: r() < 0.5 ? null : T() });
  }
  const rows = keys.filter(() => r() < 0.8).map((key): FuzzRowKey => ({ key, status: r() < 0.3 ? 'retired' : 'active', activatedAt: T(), retiredAt: T() }));
  return { statements, anchors, distrusted, rows };
}

/** The scenario as this package's computeKeyTrust takes it: a dump, in write order. */
export function portInput(sc: FuzzScenario): ComputeKeyTrustInput {
  return {
    keys: sc.rows.map((k) => ({
      keyId: POOL[k.key]!.kid,
      publicKey: POOL[k.key]!.publicKey,
      algorithm: POOL[k.key]!.alg,
      status: k.status,
      activatedAt: toMs(k.activatedAt),
      retiredAt: k.status === 'retired' ? toMs(k.retiredAt) : null,
      source: 'dump' as const,
    })),
    statements: sc.statements.map((s) => ({
      id: s.id,
      kind: s.kind,
      subjectKeyId: POOL[s.subject]!.kid,
      endorserKeyId: s.endorser === null ? null : POOL[s.endorser]!.kid,
      source: 'dump' as const,
      cose: s.cose,
      createdAt: new Date(s.createdMs).toISOString(),
    })),
    trustAnchors: sc.anchors.map((k) => `sha256:${POOL[k]!.digest}`),
    distrustedKeys: sc.distrusted.map((d) => ({ spkiSha256: POOL[d.key]!.digest, cutoff: d.cutoff })),
  };
}

/**
 * The scenario's statements at the microsecond write times a key document
 * publishes, in `order` (input order no longer carries the write order, so
 * the walk must take it from `createdAt` and `id`).
 */
export function portInputAtMicroseconds(sc: FuzzScenario, order: (xs: FuzzStatement[]) => FuzzStatement[]): ComputeKeyTrustInput {
  const base = portInput(sc);
  const byId = new Map(base.statements.map((s) => [s.id, s]));
  return {
    ...base,
    statements: order([...sc.statements]).map((s) => ({ ...byId.get(s.id)!, createdAt: s.createdUs })),
  };
}

/** One key of the document the engine publishes for a scenario, as the recorder writes it. */
export interface PublishedFuzzKey {
  key: number;
  /** As the document publishes it, at milliseconds. */
  activatedAt: string;
  retiredAt: string | null;
  /** The ids of the statements filed under the key, in write order. */
  statements: string[];
}

/** The `/v1/verification-keys` document the engine publishes for a scenario. */
export function documentOf(sc: FuzzScenario, published: readonly PublishedFuzzKey[]): VerificationKeysDocument {
  const byId = new Map(sc.statements.map((s) => [s.id, s]));
  return {
    keyStatementFormat: 'application/vnd.agledger.key-statement+cbor',
    data: published.map((k) => ({
      keyId: POOL[k.key]!.kid,
      publicKey: POOL[k.key]!.publicKey,
      algorithm: POOL[k.key]!.alg,
      status: k.retiredAt === null ? 'active' : 'retired',
      activatedAt: k.activatedAt,
      retiredAt: k.retiredAt,
      statements: k.statements.map((id) => {
        const s = byId.get(id)!;
        return { id, kind: s.kind, createdAt: s.createdUs, cose: s.cose.map((b) => b.toString('base64')) };
      }),
    })),
  };
}

/**
 * What a walk concluded, keyed by pool index so it survives regeneration:
 * the trusted keys, each one's signed window, and every finding except
 * window drift. Drift is left out because the engine compares a column at the
 * microsecond precision its database holds and a dump carries milliseconds;
 * the unit tests pin drift at the dump's precision.
 */
export interface Verdict {
  trusted: number[];
  windows: Record<string, [string | null, string | null]>;
  findings: string[];
  /** Statements the distrust entries account for, as `statementId|key`. */
  accounted: string[];
  /** Each distrusted key's span, `[cutoff, retiredAt]`. */
  spans: Record<string, [string | null, string | null]>;
}

export function verdictOf(t: {
  trusted: Iterable<string>;
  windowOf: (digest: string) => { activatedAt: string | null; retiredAt: string | null } | undefined;
  findings: Iterable<{ code: string; statementId: string | null; keyId: string | null }>;
  accounted: Iterable<{ statementId: string | null; keyId: string | null }>;
  spans: ReadonlyMap<string, { cutoff: string | null; retiredAt: string | null }>;
}): Verdict {
  const trusted = [...t.trusted].map((d) => indexOfDigest.get(d)!).sort((a, b) => a - b);
  const windows: Verdict['windows'] = {};
  for (const i of trusted) {
    const w = t.windowOf(POOL[i]!.digest);
    windows[String(i)] = [w?.activatedAt ?? null, w?.retiredAt ?? null];
  }
  const findings = [...t.findings]
    .filter((f) => f.code !== 'CHAIN_KEY_WINDOW_DRIFT')
    .map((f) => `${f.code}|${f.statementId ?? ''}|${f.keyId === null ? '' : indexOfKid.get(f.keyId) ?? f.keyId}`)
    .sort();
  const accounted = [...t.accounted]
    .map((f) => `${f.statementId ?? ''}|${f.keyId === null ? '' : indexOfKid.get(f.keyId) ?? f.keyId}`)
    .sort();
  const spans: Verdict['spans'] = {};
  for (const [d, span] of [...t.spans].sort(([a], [b]) => indexOfDigest.get(a)! - indexOfDigest.get(b)!)) {
    spans[String(indexOfDigest.get(d))] = [span.cutoff, span.retiredAt];
  }
  return { trusted, windows, findings, accounted, spans };
}

export function portVerdict(trust: KeyTrust): Verdict {
  // The engine folds a distrust cutoff into the window's upper edge; the port
  // carries it apart from the signed retirement, so compare the edge entries
  // are graded against.
  const windowOf = (d: string) => {
    const e = trust.byDigest.get(d);
    return e && { activatedAt: e.activatedAt, retiredAt: e.distrustCutoff ?? e.retiredAt };
  };
  return verdictOf({ trusted: trust.trusted, windowOf, findings: trust.findings, accounted: trust.accounted, spans: trust.distrustSpans });
}

/**
 * Where the walk may read a registry more narrowly than the engine, and only
 * so: what a distrust entry accounts for is bounded here only by a retirement
 * a key the walk trusts signed, and a later admission of a trusted key that the
 * key itself signed is never accounted for. Returns '' when `got` is `want`
 * or narrower only in those two ways, else what differs. Everything else
 * (trusted keys, windows, cutoffs, every engine finding) must be exact.
 */
export function narrowerOnly(got: Verdict, want: Verdict): string {
  if (JSON.stringify(got) === JSON.stringify(want)) return '';
  if (JSON.stringify([got.trusted, got.windows]) !== JSON.stringify([want.trusted, want.windows])) return 'trusted keys or windows differ';
  const narrowed = new Set<string>();
  for (const k of new Set([...Object.keys(got.spans), ...Object.keys(want.spans)])) {
    const [gc, gr] = got.spans[k] ?? [undefined, undefined];
    const [wc, wr] = want.spans[k] ?? [undefined, undefined];
    if (gc !== wc) return `cutoff of ${k} differs`;
    if (gr === wr) continue;
    if (gr !== null && (wr === null || wr === undefined || gr! < wr)) return `bound of ${k} is wider`;
    narrowed.add(k);
  }
  const missing = want.findings.filter((f) => !got.findings.includes(f));
  if (missing.length > 0) return `engine findings missing: ${missing.join(' ')}`;
  const extraAccounted = got.accounted.filter((a) => !want.accounted.includes(a));
  if (extraAccounted.length > 0) return `accounted beyond the engine: ${extraAccounted.join(' ')}`;
  for (const f of got.findings.filter((x) => !want.findings.includes(x))) {
    const [code, statementId, key] = f.split('|');
    if (statementId === '' && code === 'KEY_CLOSURE_INVALID' && narrowed.has(key!)) continue;
    if (statementId !== '' && want.accounted.includes(`${statementId}|${key}`)) continue;
    return `unexplained finding ${f}`;
  }
  return '';
}
