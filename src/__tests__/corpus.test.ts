import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput, VerifyExportOptions } from '../audit-export.js';
import type { FailureCode } from '../failures.js';

/**
 * EXPORT-kind conformance corpus runner.
 *
 * Reads testdata/conformance/manifest-export.json and replays every vector
 * through verifyAuditExport — the same entrypoint the SDK /verify subpath, the
 * CLI, and the MCP server call. This is the anti-drift seam: a pass vector that
 * fails (or a fail vector that passes / returns the wrong canonical code) means
 * the engine wire format and the verifier have diverged, and the test fails
 * loudly. The fixtures are REAL `/audit-export` output produced and owned by
 * agledger-api; regenerate (on a wire-format change) via agledger-api's
 * `pnpm generate:corpus`. They must mirror real output exactly, never a
 * bilingual superset (F-682).
 */

const HERE = dirname(fileURLToPath(import.meta.url));
// packages/verify-core/src/__tests__ -> repo root is four levels up.
const CONFORMANCE_DIR = join(HERE, '..', '..', '..', '..', 'testdata', 'conformance');
const MANIFEST_PATH = join(CONFORMANCE_DIR, 'manifest-export.json');

interface SignatureCoverageAssertion {
  signed: number;
  unsigned: number;
  skipped: number;
}

interface ManifestVector {
  file: string;
  kind: 'export' | 'dump';
  expect: 'pass' | 'fail';
  failureCode?: FailureCode;
  brokenAt?: number;
  options?: {
    keysFile?: string;
    requireKeyId?: string;
    requireOutOfBandKeys?: boolean;
  };
  expectSignatureCoverage?: SignatureCoverageAssertion;
  note?: string;
}

interface Manifest {
  vectors: ManifestVector[];
}

function loadJson<T>(relPath: string): T {
  return JSON.parse(readFileSync(join(CONFORMANCE_DIR, relPath), 'utf8')) as T;
}

const manifest = loadJson<Manifest>('manifest-export.json');
const exportVectors = manifest.vectors.filter((v) => v.kind === 'export');

describe('verify-core conformance corpus (export kind)', () => {
  it('manifest exists and carries export vectors', () => {
    expect(MANIFEST_PATH).toContain('manifest-export.json');
    expect(exportVectors.length).toBeGreaterThan(0);
  });

  for (const vector of exportVectors) {
    const label = `${vector.file} -> ${vector.expect}${vector.failureCode ? ` (${vector.failureCode})` : ''}`;
    it(label, () => {
      const exportData = loadJson<RecordAuditExportInput>(vector.file);

      const options: VerifyExportOptions = {};
      if (vector.options?.keysFile) {
        options.publicKeys = loadJson<Record<string, string>>(vector.options.keysFile);
      }
      if (vector.options?.requireKeyId) options.requireKeyId = vector.options.requireKeyId;
      if (vector.options?.requireOutOfBandKeys) options.requireOutOfBandKeys = true;

      const result = verifyAuditExport(exportData, options);

      expect(result.valid).toBe(vector.expect === 'pass');

      if (vector.expect === 'fail') {
        expect(result.brokenAt).toBeDefined();
        expect(result.brokenAt?.code).toBe(vector.failureCode);
        if (vector.brokenAt !== undefined) {
          expect(result.brokenAt?.position).toBe(vector.brokenAt);
        }
      }

      if (vector.expectSignatureCoverage) {
        expect(result.signatureCoverage.signed).toBe(vector.expectSignatureCoverage.signed);
        expect(result.signatureCoverage.unsigned).toBe(vector.expectSignatureCoverage.unsigned);
        expect(result.signatureCoverage.skipped).toBe(vector.expectSignatureCoverage.skipped);
      }
    });
  }
});
