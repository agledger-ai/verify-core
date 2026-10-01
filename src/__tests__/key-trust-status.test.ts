import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';
import { reportKeyTrust, settleKeyTrust } from '../key-statements.js';

/**
 * keyTrust.status, the one field a surface reads a pass as trusted from:
 * `walked` only when a signature verified under an anchored key; `no_anchor`
 * with no pin; `no_anchored_signature` with a pin and nothing signed by a key
 * it anchors. A pass on either of the last two is not a trusted verdict, and
 * the detail says so.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_DIR = join(HERE, '..', '..', 'testdata', 'conformance');

function load(rel: string): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(CONFORMANCE_DIR, rel), 'utf8')) as RecordAuditExportInput;
}

const ANCHOR = load('export/valid.json').exportMetadata.anchoredFrom!;
const STRANGER = `sha256:${'a'.repeat(64)}`;

describe('keyTrust.status', () => {
  it('no_anchor: a pass with no pin is not a trusted verdict', () => {
    const r = verifyAuditExport(load('export/valid.json'));
    expect(r.valid).toBe(true);
    expect(r.keyTrust.status).toBe('no_anchor');
    expect(r.keyTrust.detail).toBe(
      'No trustAnchors were given, so no key was anchored and this is not a trusted verdict: every key was taken on the word of whoever embedded or supplied it, and a key written into the Server\'s database alone would verify. Pin the SPKI digest of a vault key you hold or took out of band (sha256:<hex>) as trustAnchors.',
    );
    expect(r.optionalChecks.key_anchoring).toBe('skipped_no_input');
  });

  it('no_anchored_signature: an unsigned-only chain under any pin proves nothing about the pin', () => {
    for (const anchor of [STRANGER, ANCHOR]) {
      const r = verifyAuditExport(load('export/unsigned.json'), { trustAnchors: [anchor] });
      expect(r.valid).toBe(true);
      expect(r.signatureCoverage.signed).toBe(0);
      expect(r.keyTrust.status).toBe('no_anchored_signature');
      expect(r.keyTrust.detail).toBe(
        `The key statements were walked from ${anchor}, but no signature here verified under a key they anchor, so this is not a trusted verdict: an entry written before the install began signing carries no signature, and proves nothing about who wrote it.`,
      );
      expect(r.optionalChecks.key_anchoring).toBe('not_checked');
    }
  });

  it('walked: unsigned history followed by entries signed under the anchored key is trusted', () => {
    const r = verifyAuditExport(load('export/unsigned-history-then-signed.json'), { trustAnchors: [ANCHOR] });
    expect(r.valid).toBe(true);
    expect(r.signatureCoverage).toMatchObject({ signed: 1, skipped: 2 });
    expect(r.keyTrust.status).toBe('walked');
    expect(r.optionalChecks.key_anchoring).toBe('applied');
  });

  it('a chain that breaks before any entry reaches the anchoring check reports key_anchoring not_checked', () => {
    // The genesis entry dropped: every remaining entry fails its position first.
    const exp = load('export/valid.json');
    exp.entries = exp.entries.slice(1);
    const r = verifyAuditExport(exp, { trustAnchors: [ANCHOR] });
    expect(r.entries.every((e) => e.code === 'CHAIN_POSITION_GAP')).toBe(true);
    expect(r.valid).toBe(false);
    expect(r.keyTrust.status).toBe('no_anchored_signature');
    expect(r.optionalChecks.key_anchoring).toBe('not_checked');
  });

  it('settleKeyTrust leaves any report it has nothing to say about as it is', () => {
    const noAnchor = reportKeyTrust(new Map(), null, null);
    expect(settleKeyTrust(noAnchor, 0)).toBe(noAnchor);
    const walked = { ...noAnchor, status: 'walked' as const, anchors: [ANCHOR] };
    expect(settleKeyTrust(walked, 1)).toBe(walked);
    expect(settleKeyTrust(walked, 0).status).toBe('no_anchored_signature');
  });
});
