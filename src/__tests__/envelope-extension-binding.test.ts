import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAuditExport } from '../audit-export.js';
import type { RecordAuditExportInput } from '../audit-export.js';

/**
 * A row copy of `on_behalf_of` / `traceparent` in an export entry's `payload`
 * is what a reader sees, and the predicate comparison strips both sides of it,
 * so a copy that is present is bound to the signed predicate separately. Fixtures are
 * unmodified live 1.8.0 exports (see agent-signature.test.ts).
 */

const LIVE = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'live-1.8.0');

type Entry = { payload?: Record<string, unknown> };

function load(name: string): RecordAuditExportInput {
  return JSON.parse(readFileSync(join(LIVE, name), 'utf8')) as RecordAuditExportInput;
}

function firstWithObo(doc: RecordAuditExportInput): Entry & { payload: Record<string, unknown> } {
  const entry = (doc.entries as Entry[]).find((e) => e.payload && e.payload['on_behalf_of']);
  if (!entry || !entry.payload) throw new Error('fixture carries no on_behalf_of entry');
  return entry as Entry & { payload: Record<string, unknown> };
}

describe('envelope extensions in the row payload are bound to the signed predicate', () => {
  for (const name of ['export-cert-lifecycle.json', 'export-delegated-bound.json', 'export-delegated-unbound.json']) {
    it(`${name} verifies untouched`, () => {
      expect(verifyAuditExport(load(name)).valid).toBe(true);
    });
  }

  it('a rewritten on_behalf_of subject fails the binding', () => {
    const doc = load('export-cert-lifecycle.json');
    const obo = firstWithObo(doc).payload['on_behalf_of'] as { oidc: { sub: string } };
    obo.oidc.sub = 'someone-else';
    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });

  it('a rewritten sealed cert thumbprint fails the binding', () => {
    const doc = load('export-delegated-bound.json');
    const obo = firstWithObo(doc).payload['on_behalf_of'] as Record<string, unknown>;
    obo['validated'] = !obo['validated'];
    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });

  it('a row copy that is not an object fails the binding', () => {
    const doc = load('export-cert-lifecycle.json');
    firstWithObo(doc).payload['on_behalf_of'] = 'forged';
    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });

  it('a row without the block still verifies: the engine signs an on_behalf_of from authentication that never reaches the row', () => {
    const doc = load('export-cert-lifecycle.json');
    delete firstWithObo(doc).payload['on_behalf_of'];
    expect(verifyAuditExport(doc).valid).toBe(true);
  });

  it('an on_behalf_of block added to an entry that signed none fails the binding', () => {
    const doc = load('export-lifecycle.json');
    const entry = (doc.entries as Entry[]).find((e) => e.payload && !e.payload['on_behalf_of']);
    if (!entry?.payload) throw new Error('fixture has no entry without on_behalf_of');
    entry.payload['on_behalf_of'] = { oidc: { iss: 'https://idp.example', sub: 'forged' }, validated: true };
    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });

  it('an added traceparent fails the binding', () => {
    const doc = load('export-lifecycle.json');
    const entry = (doc.entries as Entry[]).find((e) => e.payload);
    if (!entry?.payload) throw new Error('fixture has no payload');
    entry.payload['traceparent'] = '00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01';
    const result = verifyAuditExport(doc);
    expect(result.valid).toBe(false);
    expect(result.brokenAt?.code).toBe('CHAIN_PAYLOAD_BINDING_MISMATCH');
  });

  it('a malformed traceparent the engine would have dropped does not break an entry that signed none', () => {
    const doc = load('export-lifecycle.json');
    const entry = (doc.entries as Entry[]).find((e) => e.payload && !e.payload['traceparent']);
    if (!entry?.payload) throw new Error('fixture has no payload');
    entry.payload['traceparent'] = 'not-a-traceparent';
    expect(verifyAuditExport(doc).valid).toBe(true);
  });
});
