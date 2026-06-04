import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';

/**
 * Pass-2 wire parity (agledger-agents#76, agledger-api a7eec8e4).
 *
 * The export wire now carries `actorOidcSynthesized` per entry,
 * `signingKeyWindows` in exportMetadata, and the denormalized row `payload`.
 * verify-core flips all three formerly dump-only checks (`oidc_actor`,
 * `key_temporal`, and `payload_binding` since F-731) to `applied` on the export
 * path when those inputs are present.
 *
 * The corpus is real agledger-api output (`testdata/conformance/export/valid.json`);
 * these assertions catch backslide either if verify-core stops reading the
 * fields or if the engine stops emitting them.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const EXPORT_DIR = join(HERE, '..', '..', 'testdata', 'conformance', 'export');

function loadValid(): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'valid.json'), 'utf8')) as RecordAuditExportInput;
}

function loadOobKeys(): Record<string, string> {
  return JSON.parse(readFileSync(join(EXPORT_DIR, 'keys-oob.json'), 'utf8')) as Record<string, string>;
}

describe('export-path optional checks (Pass-2 wire parity)', () => {
  it('oidc_actor, key_temporal, and payload_binding all flip to applied on a real export', () => {
    const result = verifyAuditExport(loadValid());
    expect(result.valid).toBe(true);
    expect(result.optionalChecks.oidc_actor).toBe('applied');
    expect(result.optionalChecks.key_temporal).toBe('applied');
    expect(result.optionalChecks.payload_binding).toBe('applied');
  });

  it('still applies the checks when out-of-band keys override the embedded set', () => {
    // resolveKeys must carry the signingKeyWindows window onto the out-of-band key
    // override too, otherwise key_temporal silently degrades to skipped_no_input
    // the moment an auditor supplies their own keys.
    const result = verifyAuditExport(loadValid(), { publicKeys: loadOobKeys() });
    expect(result.valid).toBe(true);
    expect(result.optionalChecks.key_temporal).toBe('applied');
    expect(result.optionalChecks.oidc_actor).toBe('applied');
    expect(result.keyProvenance.outOfBand).toBeGreaterThan(0);
  });

  it('legacy exports without the new fields keep all three optional checks skipped', () => {
    // Strip the wire fields a pre-v0.26 export would lack. The chain still
    // verifies (always-run checks are unchanged); the optional checks must NOT
    // flip to applied — otherwise older exports would silently fail the new
    // dump-only checks they were never expected to satisfy.
    const exp = loadValid();
    delete exp.exportMetadata.signingKeyWindows;
    for (const entry of exp.entries) {
      const e = entry as Record<string, unknown>;
      delete e.createdAt;
      delete e.actorOidcIss;
      delete e.actorOidcSub;
      delete e.actorOidcSynthesized;
      // A pre-binding export carries no row payload/entryType for the verifier
      // to cross-check, so payload_binding must stay skipped (never applied to
      // an export that predates the F-731 wire fields).
      delete e.payload;
      delete e.entryType;
      delete e.recordId;
    }
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(true);
    expect(result.optionalChecks.oidc_actor).toBe('skipped_no_input');
    expect(result.optionalChecks.key_temporal).toBe('skipped_no_input');
    expect(result.optionalChecks.payload_binding).toBe('skipped_no_input');
  });

  it('catches the dump-only OIDC mismatch on the export path when the wire carries it', () => {
    // synthesized=true with iss/sub that DON'T match the signed predicate's
    // on_behalf_of.oidc → CHAIN_OIDC_ACTOR_MISMATCH. Hand-tampered (the API
    // corpus generator doesn't ship this vector yet; #595 follow-up).
    const exp = loadValid();
    const target = exp.entries[0] as Record<string, unknown>;
    target.actorOidcSynthesized = true;
    target.actorOidcIss = 'https://attacker.example.com';
    target.actorOidcSub = 'spoofed-user';
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_OIDC_ACTOR_MISMATCH');
    expect(result.optionalChecks.oidc_actor).toBe('applied');
  });

  it('catches temporal-key violations on the export path when the wire carries windows', () => {
    // Move the key's activation forward so every entry's createdAt predates
    // it → CHAIN_KEY_EXPIRED at position 1.
    const exp = loadValid();
    const [keyId] = Object.keys(exp.exportMetadata.signingKeyWindows ?? {});
    if (!keyId) throw new Error('fixture must carry signingKeyWindows');
    exp.exportMetadata.signingKeyWindows = {
      [keyId]: { activatedAt: '2099-01-01T00:00:00Z', retiredAt: null },
    };
    const result = verifyAuditExport(exp);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_KEY_EXPIRED');
    expect(result.optionalChecks.key_temporal).toBe('applied');
  });
});
