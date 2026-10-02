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
      const flagged = new Set(trust.findings.filter((f) => f.statementId === null).map((f) => f.keyId));
      for (const k of got.trusted) {
        if (!want.trusted.includes(k)) wrong.push(`seed ${seed}: key ${k} trusted, the engine does not`);
        else if (published.some((p) => p.key === k) && JSON.stringify(got.windows[k]) !== JSON.stringify(want.windows[k]) && !flagged.has(POOL[k]!.kid)) {
          wrong.push(`seed ${seed}: key ${k} window ${JSON.stringify(got.windows[k])}, engine ${JSON.stringify(want.windows[k])}, no finding`);
        }
      }
    }
    expect(wrong.slice(0, 5)).toEqual([]);
  }, 120_000);

  it('agrees with the engine exactly when every statement verifies and every anchor is published', () => {
    let agreed = 0;
    const wrong: string[] = [];
    for (const seed of seeds) {
      const sc = scenario(Number(seed));
      const published = recorded.published[seed]!;
      if (!sc.anchors.every((a) => published.some((p) => p.key === a))) continue;
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
    expect(agreed).toBeGreaterThanOrEqual(300);
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
