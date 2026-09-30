import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { computeKeyTrust } from '../key-statements.js';
import { portInput, portVerdict, scenario, type Verdict } from './key-trust-fuzz.js';

/**
 * The walk against the engine's own verdicts on the same random registries:
 * statements of every kind in any signer order, write times and signed
 * instants that tie, duplicated rows, and distrusted keys with and without a
 * cutoff. The verdicts were recorded from the engine's computeKeyTrust by
 * scripts/record-key-trust-engine.mts, so this needs no API checkout.
 */
const recorded = JSON.parse(readFileSync(new URL('./fixtures/key-trust-engine.json', import.meta.url), 'utf8')) as {
  engine: string;
  verdicts: Record<string, Verdict>;
};

describe(`the trust walk against the engine (${recorded.engine})`, () => {
  it('trusts the same keys, signs the same windows and finds the same statements on every recorded registry', () => {
    const seeds = Object.keys(recorded.verdicts);
    expect(seeds.length).toBeGreaterThanOrEqual(1000);
    const diverged: string[] = [];
    for (const seed of seeds) {
      const got = portVerdict(computeKeyTrust(portInput(scenario(Number(seed)))));
      const want = recorded.verdicts[seed]!;
      if (JSON.stringify(got) !== JSON.stringify(want)) diverged.push(`seed ${seed}: engine ${JSON.stringify(want)}, walk ${JSON.stringify(got)}`);
    }
    expect(diverged.slice(0, 5)).toEqual([]);
  }, 120_000);
});
