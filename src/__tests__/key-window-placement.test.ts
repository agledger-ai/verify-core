import { describe, expect, it } from 'vitest';
import { distrustAccounts, placeInKeyWindow, type VerificationKey } from '../chain.js';
import { makeKey } from './key-statements-helpers.js';

/**
 * The window rule for signed artifacts other than chain entries (vault
 * checkpoints, read-log leaves and tree heads), and the condition under which
 * a distrustedKeys entry accounts for one. The Server applies one rule to
 * all of them, the one CHAIN_KEY_NOT_YET_ACTIVE and CHAIN_KEY_EXPIRED mirror.
 */

const k = makeKey();
const key = (over: Partial<VerificationKey> = {}): VerificationKey => ({
  keyId: k.kid,
  spkiBase64: k.publicKey,
  source: 'embedded',
  activatedAt: '2026-09-02T00:01:00.000000Z',
  retiredAt: '2026-09-02T00:05:00.000000Z',
  trust: 'anchored',
  ...over,
});

describe('placeInKeyWindow', () => {
  it('places a write time between the edges inside, both edges included', () => {
    for (const at of ['2026-09-02T00:01:00.000Z', '2026-09-02T00:03:00.000Z', '2026-09-02T00:05:00.000Z']) {
      expect(placeInKeyWindow(key(), at, 'Checkpoint')).toEqual({ placement: 'inside' });
    }
  });

  it('reports a write before activation and one after retirement, naming the artifact', () => {
    const before = placeInKeyWindow(key(), '2026-09-02T00:00:59.999Z', 'Checkpoint');
    expect(before.placement).toBe('not-yet-active');
    expect(before).toHaveProperty('detail', expect.stringMatching(/^Checkpoint written 2026-09-02T00:00:59\.999Z predates key/));
    const after = placeInKeyWindow(key(), '2026-09-02T00:05:00.001Z', 'Leaf');
    expect(after.placement).toBe('expired');
    expect(after).toHaveProperty('detail', expect.stringMatching(/^Leaf written .* postdates key .* retirement/));
  });

  it('checks only the edges the key carries', () => {
    expect(placeInKeyWindow(key({ activatedAt: undefined, retiredAt: null }), 'not a time', 'Leaf')).toEqual({ placement: 'inside' });
    expect(placeInKeyWindow(key({ retiredAt: null }), '2030-01-01T00:00:00.000Z', 'Leaf')).toEqual({ placement: 'inside' });
    expect(placeInKeyWindow(key({ activatedAt: undefined }), '2020-01-01T00:00:00.000Z', 'Leaf')).toEqual({ placement: 'inside' });
  });

  it('fails closed on a write time or an edge it cannot read', () => {
    expect(placeInKeyWindow(key(), '2026-09-02 00:03:00', 'Checkpoint').placement).toBe('unplaceable');
    expect(placeInKeyWindow(key(), undefined, 'Checkpoint').placement).toBe('unplaceable');
    expect(placeInKeyWindow(key({ retiredAt: '2026-02-30T00:00:00Z' }), '2026-09-02T00:03:00.000Z', 'Checkpoint').placement).toBe('unplaceable');
  });

  it('accounts for a write from the distrust instant up to the trusted retirement, and no further', () => {
    const distrusted = key({
      retiredAt: '2026-09-02T00:05:00.000000Z',
      distrustCutoff: '2026-09-02T00:02:00.000000Z',
      distrustSpan: { cutoff: '2026-09-02T00:02:00.000000Z', retiredAt: '2026-09-02T00:05:00.000000Z' },
    });
    expect(placeInKeyWindow(distrusted, '2026-09-02T00:01:30.000Z', 'Checkpoint').placement).toBe('inside');
    expect(placeInKeyWindow(distrusted, '2026-09-02T00:03:00.000Z', 'Checkpoint').placement).toBe('accounted');
    expect(placeInKeyWindow(distrusted, '2026-09-02T00:05:00.000Z', 'Checkpoint').placement).toBe('expired');
    expect(placeInKeyWindow(distrusted, '2026-09-02T00:06:00.000Z', 'Checkpoint').placement).toBe('expired');
  });
});

describe('distrustAccounts', () => {
  const span = { cutoff: null, retiredAt: '2026-09-02T00:05:00.000000Z' };

  it('accounts for what an unanchored distrusted key signed before a trusted key retired it', () => {
    const unanchored = key({ trust: 'unanchored', distrustSpan: span });
    expect(distrustAccounts(unanchored, '2026-09-02T00:04:59.999Z')).toBe(true);
    expect(distrustAccounts(unanchored, '2026-09-02T00:05:00.000Z')).toBe(false);
    expect(distrustAccounts(unanchored, 'not a time')).toBe(false);
  });

  it('accounts for nothing under an unanchored key no trusted key retired, or one nothing distrusts', () => {
    expect(distrustAccounts(key({ trust: 'unanchored', distrustSpan: { cutoff: null, retiredAt: null } }), '2026-09-02T00:03:00.000Z')).toBe(false);
    expect(distrustAccounts(key({ trust: 'unanchored' }), '2026-09-02T00:03:00.000Z')).toBe(false);
  });

  it('accounts for what an anchored key signed past its distrust instant, and not what it signed inside its window', () => {
    const anchored = key({
      distrustCutoff: '2026-09-02T00:02:00.000000Z',
      distrustSpan: { cutoff: '2026-09-02T00:02:00.000000Z', retiredAt: '2026-09-02T00:05:00.000000Z' },
    });
    expect(distrustAccounts(anchored, '2026-09-02T00:03:00.000Z')).toBe(true);
    expect(distrustAccounts(anchored, '2026-09-02T00:01:30.000Z')).toBe(false);
    expect(distrustAccounts(key(), '2026-09-02T00:06:00.000Z')).toBe(false);
  });

  it('accounts for nothing under a key whose registry row misstates its algorithm, or one the host cannot decide', () => {
    expect(distrustAccounts(key({ trust: 'unanchored', distrustSpan: span, algorithm: 'ES256' }), '2026-09-02T00:03:00.000Z')).toBe(false);
    expect(distrustAccounts(key({ trust: 'undecided', distrustSpan: span }), '2026-09-02T00:03:00.000Z')).toBe(false);
  });
});
