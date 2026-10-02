import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { computeKeyTrust, keyStatementsFromVerificationKeys, type KeyTrust } from '../key-statements.js';
import {
  POOL,
  documentOf,
  portInput,
  portInputAtMicroseconds,
  portVerdict,
  prng,
  scenario,
  type FuzzScenario,
  type PublishedFuzzKey,
  type Verdict,
} from './key-trust-fuzz.js';

/**
 * The walk against the engine's own verdicts on the same random registries:
 * statements of every kind in any signer order, write times and signed
 * instants that tie, duplicated rows, later admissions of trusted keys, and
 * distrusted keys with and without a cutoff. The verdicts, and the key
 * document the engine publishes for each registry, were recorded from the
 * engine by scripts/record-key-trust-engine.mts, so this needs no API
 * checkout.
 */
const recorded = JSON.parse(readFileSync(new URL('./fixtures/key-trust-engine.json', import.meta.url), 'utf8')) as {
  engine: string;
  verdicts: Record<string, Verdict>;
  published: Record<string, PublishedFuzzKey[]>;
};
const seeds = Object.keys(recorded.verdicts);

function walkDocument(sc: FuzzScenario, published: readonly PublishedFuzzKey[]): KeyTrust {
  return computeKeyTrust({
    ...keyStatementsFromVerificationKeys(documentOf(sc, published)),
    trustAnchors: sc.anchors.map((k) => `sha256:${POOL[k]!.digest}`),
    distrustedKeys: sc.distrusted.map((d) => ({ spkiSha256: POOL[d.key]!.digest, cutoff: d.cutoff })),
  });
}

describe(`the trust walk against the engine (${recorded.engine})`, () => {
  it('trusts the same keys, signs the same windows and finds the same statements on every recorded registry', () => {
    expect(seeds.length).toBeGreaterThanOrEqual(1000);
    const diverged: string[] = [];
    for (const seed of seeds) {
      const got = portVerdict(computeKeyTrust(portInput(scenario(Number(seed)))));
      const want = recorded.verdicts[seed]!;
      if (JSON.stringify(got) !== JSON.stringify(want)) diverged.push(`seed ${seed}: engine ${JSON.stringify(want)}, walk ${JSON.stringify(got)}`);
    }
    expect(diverged.slice(0, 5)).toEqual([]);
  }, 120_000);

  it('takes the write order from createdAt and id at microseconds, whatever order the statements arrive in', () => {
    const diverged: string[] = [];
    for (const seed of seeds) {
      const r = prng(Number(seed) ^ 0x5eed);
      const shuffled = portInputAtMicroseconds(scenario(Number(seed)), (xs) => xs.map((x) => [r(), x] as const).sort((a, b) => a[0] - b[0]).map(([, x]) => x));
      const got = portVerdict(computeKeyTrust(shuffled));
      if (JSON.stringify(got) !== JSON.stringify(recorded.verdicts[seed])) diverged.push(`seed ${seed}`);
    }
    expect(diverged.slice(0, 5)).toEqual([]);
  }, 120_000);
});

describe(`a walk over the key document the engine publishes (${recorded.engine})`, () => {
  it('never trusts a key the engine does not, and any window it grades more loosely on a listed key is a finding on that key', () => {
    const wrong: string[] = [];
    for (const seed of seeds) {
      const sc = scenario(Number(seed));
      const published = recorded.published[seed]!;
      const want = recorded.verdicts[seed]!;
      const trust = walkDocument(sc, published);
      const got = portVerdict(trust);
      // Only a finding on the listed key's window excuses a looser one.
      const flagged = new Set(trust.findings
        .filter((f) => f.statementId === null && (f.code === 'CHAIN_KEY_WINDOW_DRIFT' || f.code === 'KEY_CLOSURE_INVALID'))
        .map((f) => f.keyId));
      for (const k of got.trusted) {
        if (!want.trusted.includes(k)) wrong.push(`seed ${seed}: key ${k} trusted, the engine does not`);
        else if (published.some((p) => p.key === k) && JSON.stringify(got.windows[k]) !== JSON.stringify(want.windows[k]) && !flagged.has(POOL[k]!.kid)) {
          wrong.push(`seed ${seed}: key ${k} window ${JSON.stringify(got.windows[k])}, engine ${JSON.stringify(want.windows[k])}, no finding`);
        }
      }
    }
    expect(wrong.slice(0, 5)).toEqual([]);
  }, 120_000);

  it('agrees with the engine exactly when every statement verifies, every anchor is published and no key is distrusted', () => {
    let agreed = 0;
    const wrong: string[] = [];
    for (const seed of seeds) {
      const sc = scenario(Number(seed));
      const published = recorded.published[seed]!;
      // A distrusted key's edges are void on a document walk whatever time
      // the document gives, which can be narrower than the engine.
      if (sc.distrusted.length > 0 || !sc.anchors.every((a) => published.some((p) => p.key === a))) continue;
      const trust = walkDocument(sc, published);
      if (trust.statements.invalid > 0) continue;
      const want = recorded.verdicts[seed]!;
      const got = portVerdict(trust);
      const listed = published.map((p) => p.key).sort((a, b) => a - b);
      const same = JSON.stringify(got.trusted) === JSON.stringify(listed)
        && listed.every((k) => JSON.stringify(got.windows[k]) === JSON.stringify(want.windows[k]))
        && !trust.findings.some((f) => f.statementId === null);
      if (same) agreed++;
      else wrong.push(`seed ${seed}`);
    }
    expect(wrong.slice(0, 5)).toEqual([]);
    expect(agreed).toBeGreaterThanOrEqual(200);
  }, 120_000);

  it('needs the later admissions the engine publishes: with only each key\'s first, the walk dates windows differently', () => {
    let moved = 0;
    for (const seed of seeds) {
      const sc = scenario(Number(seed));
      const kindOf = new Map(sc.statements.map((s) => [s.id, s.kind]));
      const published = recorded.published[seed]!;
      const firstOnly = published.map((k) => {
        let admitted = false;
        return {
          ...k,
          statements: k.statements.filter((id) => {
            if (kindOf.get(id) === 'closure') return true;
            if (admitted) return false;
            admitted = true;
            return true;
          }),
        };
      });
      const all = portVerdict(walkDocument(sc, published));
      const first = portVerdict(walkDocument(sc, firstOnly));
      if (JSON.stringify([all.trusted, all.windows]) !== JSON.stringify([first.trusted, first.windows])) moved++;
    }
    expect(moved).toBeGreaterThanOrEqual(50);
  }, 120_000);
});

describe('a key document whose createdAt and id the holder edited', () => {
  /** The edge an entry under the key is graded against, as [lower, upper] in ms; null is open. */
  const edges = (trust: KeyTrust, digest: string): [number | null, number | null] => {
    const e = trust.byDigest.get(digest)!;
    const upper = e.distrustCutoff ?? e.retiredAt;
    return [e.activatedAt === null ? null : Date.parse(`${e.activatedAt.slice(0, 23)}Z`), upper === null ? null : Date.parse(`${upper.slice(0, 23)}Z`)];
  };

  it('with every closed key distrusted, trusts no key and no window the signed-order walk of the same statements would not', () => {
    const wrong: string[] = [];
    let distrustedEdges = 0;
    for (const seed of seeds) {
      const sc = scenario(Number(seed));
      const r = prng(Number(seed) ^ 0xed17);
      const doc = documentOf(sc, recorded.published[seed]!);
      const all = doc.data.flatMap((k) => k.statements ?? []);
      if (all.length === 0) continue;
      const kinds = new Map(sc.statements.map((s) => [s.id, s]));
      // Any write time, early or late, any id, rows copied under new ids.
      const anyTime = () => (r() < 0.3 ? '2020-01-01T00:00:00.000000Z' : `2026-01-01T00:00:${String(Math.floor(r() * 60)).padStart(2, '0')}.${String(Math.floor(r() * 1e6)).padStart(6, '0')}Z`);
      const anyId = () => (r() < 0.2 ? all[Math.floor(r() * all.length)]!.id! : `${Math.floor(r() * 0xffffffff).toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`);
      const edited = structuredClone(doc);
      for (const k of edited.data) {
        const list = [...(k.statements ?? [])].map((st) => ({ ...st, id: r() < 0.5 ? anyId() : st.id, createdAt: r() < 0.7 ? anyTime() : st.createdAt }));
        if (list.length > 0 && r() < 0.2) list.push({ ...list[Math.floor(r() * list.length)]!, id: anyId(), createdAt: anyTime() });
        (k as { statements: unknown }).statements = list;
      }
      const stripped = structuredClone(doc);
      for (const k of stripped.data) (k as { statements: unknown }).statements = (k.statements ?? []).map(({ kind, cose }) => ({ kind, cose }));
      // Every key a closure retires, and sometimes another, distrusted from a
      // random instant or with none.
      const closed = new Set(all.filter((st) => st.kind === 'closure').map((st) => kinds.get(st.id!)!.subject));
      for (const k of sc.statements.map((s) => s.subject)) if (r() < 0.2) closed.add(k);
      const distrustedKeys = [...closed].map((k) => ({ spkiSha256: POOL[k]!.digest, cutoff: r() < 0.3 ? null : `2026-01-01T00:00:${String(Math.floor(r() * 20)).padStart(2, '0')}.000000Z` }));
      if (distrustedKeys.length > 0) distrustedEdges++;
      const walk = (d: typeof doc) => computeKeyTrust({ ...keyStatementsFromVerificationKeys(d), trustAnchors: sc.anchors.map((k) => `sha256:${POOL[k]!.digest}`), distrustedKeys });
      const written = walk(edited);
      const signed = walk(stripped);
      expect(written.order).toBe('written');
      expect(signed.order).toBe('signed');
      for (const d of written.trusted) {
        if (!signed.trusted.has(d)) {
          wrong.push(`seed ${seed}: ${d.slice(0, 16)} trusted only under the edited times`);
          continue;
        }
        const [wl, wu] = edges(written, d);
        const [sl, su] = edges(signed, d);
        if ((sl !== null && (wl === null || wl < sl)) || (su !== null && (wu === null || wu > su))) {
          wrong.push(`seed ${seed}: ${d.slice(0, 16)} window [${wl}, ${wu}] wider than signed [${sl}, ${su}]`);
        }
      }
    }
    expect(distrustedEdges).toBeGreaterThanOrEqual(500);
    expect(wrong.slice(0, 5)).toEqual([]);
  }, 120_000);
});
