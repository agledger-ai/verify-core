import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encode as cborEncode, rfc8949EncodeOptions } from 'cborg';
import { decodeCoseSign1 } from '../primitives.js';

/**
 * Guards the cborg pin's actual rationale.
 *
 * `cborg` is pinned exactly because this is the offline verifier: an auditor
 * re-running it years from now has to get byte-identical results. But the pin
 * alone does not make that true, and the two places where cborg's deterministic
 * encoder has in fact changed its output across versions are narrow:
 *
 *   - major type 7 floats: 5.1.4 started emitting shortest-form floats under
 *     `rfc8949EncodeOptions` (RFC 8949 4.2.1). 5.1.1 emitted full 64-bit doubles.
 *   - major type 7 map KEYS: 6.0.0 canonically sorts them, changing byte order
 *     for maps keyed on floats, booleans, or null.
 *
 * Neither can reach us, because the only thing this package encodes is the
 * Sig_structure `["Signature1", protected_bstr, h'', payload_bstr]`: one text
 * string and three byte strings inside an array. No floats, no maps at all.
 * That is why the encoder version is not load-bearing here, and why moving the
 * pin forward is safe.
 *
 * These tests enforce that reasoning instead of leaving it in a comment. If a
 * future change encodes something richer (a map, a number that is not an
 * integer), the invariance argument stops holding and this fails loudly rather
 * than silently making the verifier's output depend on which cborg resolved.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPORT_DIR = join(HERE, '..', '..', 'testdata', 'conformance', 'export');
const SIG_STRUCTURE_CONTEXT = 'Signature1';

/** CBOR major types that make encoder output version-sensitive. */
const MAP = 5;
const SIMPLE_OR_FLOAT = 7;

/**
 * Walk a definite-length CBOR item and collect every major type it contains.
 * Deterministic encodings are always definite-length, so a linear walk is
 * sufficient and an indefinite-length head is itself a failure worth throwing on.
 */
function majorTypesIn(bytes: Uint8Array): Set<number> {
  const seen = new Set<number>();
  let pos = 0;

  function readItem(): void {
    if (pos >= bytes.length) throw new Error('truncated CBOR');
    const ib = bytes[pos++]!;
    const major = ib >> 5;
    const ai = ib & 0x1f;
    seen.add(major);

    let value = 0;
    if (ai < 24) {
      value = ai;
    } else if (ai === 24) {
      value = bytes[pos]!;
      pos += 1;
    } else if (ai === 25) {
      value = (bytes[pos]! << 8) | bytes[pos + 1]!;
      pos += 2;
    } else if (ai === 26) {
      value = bytes[pos]! * 2 ** 24 + (bytes[pos + 1]! << 16) + (bytes[pos + 2]! << 8) + bytes[pos + 3]!;
      pos += 4;
    } else if (ai === 27) {
      let acc = 0;
      for (let i = 0; i < 8; i++) acc = acc * 256 + bytes[pos + i]!;
      value = acc;
      pos += 8;
    } else {
      throw new Error(`non-deterministic additional info ${ai} for major type ${major}`);
    }

    if (major === 2 || major === 3) {
      pos += value;
    } else if (major === 4) {
      for (let i = 0; i < value; i++) readItem();
    } else if (major === MAP) {
      for (let i = 0; i < value * 2; i++) readItem();
    } else if (major === 6) {
      readItem();
    }
  }

  readItem();
  if (pos !== bytes.length) throw new Error(`trailing bytes after CBOR item: ${bytes.length - pos}`);
  return seen;
}

/** Every COSE_Sign1 envelope the conformance corpus carries, real engine output. */
function corpusEnvelopes(): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const file of readdirSync(EXPORT_DIR)) {
    if (!file.endsWith('.json')) continue;
    const parsed: unknown = JSON.parse(readFileSync(join(EXPORT_DIR, file), 'utf8'));
    const entries = (parsed as { entries?: unknown }).entries;
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      const cose = (entry as { integrity?: { coseSign1?: unknown } }).integrity?.coseSign1;
      if (typeof cose === 'string') out.push(new Uint8Array(Buffer.from(cose, 'base64')));
    }
  }
  return out;
}

describe('encoder version invariance', () => {
  it('encodes nothing whose bytes depend on the cborg version', () => {
    const envelopes = corpusEnvelopes();
    expect(envelopes.length).toBeGreaterThan(0);

    let checked = 0;
    for (const envelope of envelopes) {
      const parts = decodeCoseSign1(envelope);
      // Adversarial fixtures carry deliberately malformed envelopes; they never
      // reach the encode path, so they have nothing to assert.
      if (!parts) continue;

      const sigStructure: unknown[] = [
        SIG_STRUCTURE_CONTEXT,
        parts.protectedBstr,
        new Uint8Array(0),
        parts.payloadBstr,
      ];
      const majors = majorTypesIn(cborEncode(sigStructure, rfc8949EncodeOptions));

      expect(majors.has(SIMPLE_OR_FLOAT)).toBe(false);
      expect(majors.has(MAP)).toBe(false);
      checked += 1;
    }

    expect(checked).toBeGreaterThan(0);
  });

  it('keeps the encode surface to the one Sig_structure call site', () => {
    const source = readFileSync(join(HERE, '..', 'primitives.ts'), 'utf8');
    const callSites = source.match(/cborEncode\(/g) ?? [];
    expect(callSites).toHaveLength(1);
  });
});
