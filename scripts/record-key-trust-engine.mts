// Records the engine's verdicts on the seeded registries of
// src/__tests__/key-trust-fuzz.ts, for key-trust-engine.test.ts to hold this
// package's walk to. Run from an agledger-api checkout at the engine the
// package targets, with that checkout's tsx:
//
//   cd ~/projects/agledger-api
//   node_modules/.bin/tsx ~/projects/agledger-verify-core/scripts/record-key-trust-engine.mts [first] [count]
//
// Re-record when the engine's walk changes, and say in the commit which
// engine sha the verdicts came from.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { POOL, scenario, verdictOf, toMs, type Verdict } from '../src/__tests__/key-trust-fuzz.ts';

const engine = await import(pathToFileURL(resolve('src/modules/audit-vault/key-statements.ts')).href);
const first = Number(process.argv[2] ?? 1);
const count = Number(process.argv[3] ?? 300);
let sha = 'unknown';
try { sha = execFileSync('git', ['rev-parse', '--short=8', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { /* not a git checkout */ }

const CODE: Record<string, string> = { key_statement_invalid: 'KEY_STATEMENT_INVALID', key_closure_invalid: 'KEY_CLOSURE_INVALID', key_window_drift: 'CHAIN_KEY_WINDOW_DRIFT' };
const verdicts: Record<string, Verdict> = {};
for (let seed = first; seed < first + count; seed++) {
  const sc = scenario(seed);
  const e = engine.computeKeyTrust({
    rows: sc.rows.map((k) => ({
      key_id: POOL[k.key]!.kid,
      public_key: POOL[k.key]!.publicKey,
      algorithm: POOL[k.key]!.alg,
      status: k.status,
      activated_at: new Date(toMs(k.activatedAt)),
      retired_at: k.status === 'retired' ? new Date(toMs(k.retiredAt)) : null,
      activated_at_us: k.activatedAt,
      retired_at_us: k.status === 'retired' ? k.retiredAt : null,
    })),
    statements: sc.statements.map((s) => ({
      id: s.id,
      kind: s.kind,
      subject_key_id: POOL[s.subject]!.kid,
      endorser_key_id: s.endorser === null ? null : POOL[s.endorser]!.kid,
      statement: s.cose,
      created_at: new Date(s.createdMs),
    })),
    anchors: new Set(sc.anchors.map((k) => POOL[k]!.digest)),
    distrusted: sc.distrusted.map((d) => ({ spkiSha256: POOL[d.key]!.digest, cutoff: d.cutoff })),
  });
  verdicts[String(seed)] = verdictOf({
    trusted: e.anchored,
    windowOf: (d: string) => e.byDigest.get(d),
    findings: e.findings.map((f: { class: string; statementId: string | null; keyId: string | null }) => ({ code: CODE[f.class] ?? f.class, statementId: f.statementId, keyId: f.keyId })),
  });
}
const out = new URL('../src/__tests__/fixtures/key-trust-engine.json', import.meta.url);
writeFileSync(out, `${JSON.stringify({ engine: sha, first, count, verdicts })}\n`);
console.log(`recorded ${count} verdicts from engine ${sha}`);
