// Records the Server's verdicts on the seeded registries of
// src/__tests__/key-trust-fuzz.ts, and the key document the Server would
// publish for each (every anchored or vouched key with a row, its window and
// the statements its entry files under it), for key-trust-engine.test.ts to
// hold this package's walk to. Needs the Server's key-statements module, as a
// TypeScript source file, and a TypeScript runner (tsx):
//
//   tsx scripts/record-key-trust-engine.mts <key-statements-module> [first] [count] [label]
//
// `label` (default "server") is stored in the fixture as `engine`, to say
// which Server release the verdicts came from.
//
// Re-record when the Server's walk changes.
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { POOL, scenario, verdictOf, toMs, type PublishedFuzzKey, type Verdict } from '../src/__tests__/key-trust-fuzz.ts';

const modulePath = process.argv[2];
if (modulePath === undefined) {
  console.error('usage: tsx scripts/record-key-trust-engine.mts <key-statements-module> [first] [count] [label]');
  process.exit(2);
}
const engine = await import(pathToFileURL(resolve(modulePath)).href);
const first = Number(process.argv[3] ?? 1);
const count = Number(process.argv[4] ?? 300);
const label = process.argv[5] ?? 'server';

const CODE: Record<string, string> = { key_statement_invalid: 'KEY_STATEMENT_INVALID', key_closure_invalid: 'KEY_CLOSURE_INVALID', key_window_drift: 'CHAIN_KEY_WINDOW_DRIFT' };
const verdicts: Record<string, Verdict> = {};
const documents: Record<string, Verdict> = {};
const published: Record<string, PublishedFuzzKey[]> = {};
type EngineTrust = {
  anchored: Set<string>;
  byDigest: Map<string, { activatedAt: string | null; retiredAt: string | null; statements: Array<{ row: { id: string } }> }>;
  findings: Array<{ class: string; statementId: string | null; keyId: string | null }>;
  accounted: Array<{ class: string; statementId: string | null; keyId: string | null }>;
  distrustSpans: Map<string, { cutoff: string | null; retiredAt: string | null }>;
  undecided: Set<string>;
  vouched: Set<string>;
};
const verdictOfEngine = (t: EngineTrust, asDocument: boolean): Verdict => verdictOf({
  trusted: t.anchored,
  windowOf: (d: string) => t.byDigest.get(d),
  // Over a key document, what the Server accounts for a verifier reports as a
  // finding, since a document's write
  // times are not held against anything.
  findings: [...t.findings, ...(asDocument ? t.accounted : [])].map((f) => ({ code: CODE[f.class] ?? f.class, statementId: f.statementId, keyId: f.keyId })),
  accounted: asDocument ? [] : t.accounted,
  spans: t.distrustSpans,
});
const must = <T,>(value: T | undefined, what: string): T => {
  if (value === undefined) throw new Error(`missing ${what}`);
  return value;
};
const iso = (instant: string) => new Date(toMs(instant)).toISOString();
for (let seed = first; seed < first + count; seed++) {
  const sc = scenario(seed);
  const rows = sc.rows.map((k) => ({
    key_id: must(POOL[k.key], 'POOL entry').kid,
    public_key: must(POOL[k.key], 'POOL entry').publicKey,
    algorithm: must(POOL[k.key], 'POOL entry').alg,
    status: k.status,
    activated_at: new Date(toMs(k.activatedAt)),
    retired_at: k.status === 'retired' ? new Date(toMs(k.retiredAt)) : null,
    activated_at_us: k.activatedAt,
    retired_at_us: k.status === 'retired' ? k.retiredAt : null,
  }));
  const statementRows = sc.statements.map((s) => ({
    id: s.id,
    kind: s.kind,
    subject_key_id: must(POOL[s.subject], 'POOL entry').kid,
    endorser_key_id: s.endorser === null ? null : must(POOL[s.endorser], 'POOL entry').kid,
    statement: s.cose,
    created_at: new Date(s.createdMs),
    created_at_us: s.createdUs,
  }));
  const anchors = new Set(sc.anchors.map((k) => must(POOL[k], 'POOL entry').digest));
  const distrusted = sc.distrusted.map((d) => ({ spkiSha256: must(POOL[d.key], 'POOL entry').digest, cutoff: d.cutoff }));
  const e: EngineTrust = engine.computeKeyTrust({ rows, statements: statementRows, anchors, distrusted });
  // As listPublishedSigningKeys publishes them (no fuzz key is undecided, so
  // nothing is vouched, but the rule is kept).
  const doc: PublishedFuzzKey[] = [];
  for (const [i, k] of sc.rows.entries()) {
    const digest = must(POOL[k.key], 'POOL entry').digest;
    const signed = e.byDigest.get(digest);
    const anchored = e.anchored.has(digest);
    const vouched = !anchored && e.undecided.has(digest) && e.vouched.has(digest);
    if (!anchored && !vouched) continue;
    const row = must(rows[i], 'row');
    const retiredAt = anchored
      ? (signed?.retiredAt ? iso(signed.retiredAt) : null)
      : signed?.retiredAt ? iso(signed.retiredAt) : row.retired_at?.toISOString() ?? null;
    const distrustedFrom = e.distrustSpans.get(digest)?.cutoff ?? null;
    doc.push({
      key: k.key,
      activatedAt: anchored && signed?.activatedAt ? iso(signed.activatedAt) : row.activated_at.toISOString(),
      retiredAt,
      ...(distrustedFrom !== null ? { distrustedFrom } : {}),
      statements: (signed?.statements ?? []).map((c: { row: { id: string } }) => c.row.id),
    });
  }
  published[String(seed)] = doc;
  verdicts[String(seed)] = verdictOfEngine(e, false);
  // The same walk over that document, as vault.service's publishedWalkInputs
  // feeds it: the published keys with the windows they are published with,
  // and the statements published with them.
  const ids = new Set(doc.flatMap((k) => k.statements));
  const docRows = doc.map((k) => {
    const row = must(rows[sc.rows.findIndex((r) => r.key === k.key)], 'row');
    const signed = e.byDigest.get(must(POOL[k.key], 'POOL entry').digest);
    const anchored = e.anchored.has(must(POOL[k.key], 'POOL entry').digest);
    return {
      ...row,
      status: k.retiredAt === null ? 'active' : 'retired',
      activated_at: new Date(k.activatedAt),
      retired_at: k.retiredAt === null ? null : new Date(k.retiredAt),
      activated_at_us: (anchored ? signed?.activatedAt : null) ?? row.activated_at_us,
      retired_at_us: k.retiredAt === null ? null : signed?.retiredAt ?? row.retired_at_us,
    };
  });
  documents[String(seed)] = verdictOfEngine(engine.computeKeyTrust({
    rows: docRows, statements: statementRows.filter((s) => ids.has(s.id)), anchors, distrusted, asDocument: true,
  }), true);
}
const out = new URL('../src/__tests__/fixtures/key-trust-engine.json', import.meta.url);
writeFileSync(out, `${JSON.stringify({ engine: label, first, count, verdicts, documents, published })}\n`);
console.log(`recorded ${count} verdicts from ${label}`);
