#!/usr/bin/env node
/**
 * Re-capture the live fixtures under src/__tests__/fixtures/live-<version>/
 * from a scratch AGLedger Server. Everything it writes is unmodified Server
 * output; nothing is edited after the Server signs it.
 *
 * Two steps:
 *
 *   node scripts/capture-live-fixtures/capture.mjs capture --out <dir> \
 *     --server http://localhost:3100 --platform-key agl_plt_... \
 *     --idp-a http://idp-a.example.test:3120 --idp-a-listen 172.17.0.1:3120 \
 *     --idp-b http://idp-b.example.test:3121 --idp-b-listen 172.17.0.1:3121
 *
 *   node scripts/capture-live-fixtures/capture.mjs slice-dump --out <dir> --dump <full-dump-dir>
 *
 * `capture` starts two throwaway OIDC issuers (idp.mjs), registers them with
 * the Server, and drives seven records through its HTTP API:
 *
 *   1. export-cert-lifecycle   agent A, on an ephemeral cert from issuer A,
 *                              signs every request body: a self-commitment
 *                              walked create, autoActivate, completion,
 *                              principal verdict (6 sealed agent signatures).
 *   2. (no export)             the same walk by agent B on its own cert.
 *   3. export-lifecycle        the same walk on API keys: a principal and a
 *                              distinct performer, no agent signatures.
 *   4. export-delegated-bound  agent A creates on behalf of a subject of
 *                              issuer B whose `act` is agent A (bound).
 *   5. export-delegated-unbound the API-key principal creates on behalf of a
 *                              subject of issuer B (unbound, unsigned).
 *   6. export-delegation-parent agent A opens a delegation root, bound,
 *                              naming agent B as performer.
 *   7. export-delegation-child agent B delegates a child under it, bound, on
 *                              its own cert; agent A's key does not vouch for it.
 *
 * It writes those exports, `agent-cert-key.json` (agent A's key, as the
 * Server recorded it at cert exchange; agent B's key is never written) and
 * `capture-manifest.json` (the seven record ids, for `slice-dump`).
 *
 * `slice-dump` cuts a full vault dump of the same Server (written by the
 * Server's own vault dump tool, run by its operator) down to those seven
 * whole record chains into `<out>/dump/`, keeping the signing keys and key
 * statements whole.
 *
 * The Server needs its worker running (the gate moves a completion to the
 * verdict window), plain-http issuers allowed (SSRF_ALLOW_PLAIN_HTTP=true),
 * and the issuers' listen address admitted (SSRF_ALLOW_CIDRS); loopback is
 * never admitted, so bind the issuers on another local interface and map
 * their host names to it for the run. Use reserved names (RFC 6761 `.test`)
 * so no captured issuer URL points anywhere real, and a fresh database so the
 * dump holds nothing else.
 */
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { startIssuer } from './idp.mjs';

const AUDIENCE = 'agledger';
const CERT_POP_CONTEXT = 'agledger.oidc.cert.v1\n';
const AGENT_SIG_CONTEXT = 'agledger.agent.sig.v1\n';

const { positionals, values: args } = parseArgs({
  allowPositionals: true,
  options: {
    out: { type: 'string' },
    server: { type: 'string', default: process.env.AGLEDGER_API_URL },
    'platform-key': { type: 'string', default: process.env.AGLEDGER_PLATFORM_KEY },
    'idp-a': { type: 'string' },
    'idp-a-listen': { type: 'string' },
    'idp-b': { type: 'string' },
    'idp-b-listen': { type: 'string' },
    dump: { type: 'string' },
  },
});

function need(name) {
  const v = args[name];
  if (!v) throw new Error(`--${name} is required`);
  return v;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

// --- HTTP ---

async function call(method, path, { auth, body, headers = {}, expect = [200, 201] } = {}) {
  const raw = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  const res = await fetch(new URL(path, need('server')), {
    method,
    headers: {
      ...(auth ? { authorization: `Bearer ${auth}` } : {}),
      ...(raw === undefined ? {} : { 'content-type': 'application/json' }),
      ...headers,
    },
    body: raw,
  });
  const text = await res.text();
  if (!expect.includes(res.status)) throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

/** A request whose exact body bytes the cert-bound key signs (X-Agent-Signature). */
function signedCall(agent, method, path, body, headers = {}) {
  const raw = JSON.stringify(body);
  const contentHash = createHash('sha256').update(raw, 'utf8').digest('hex');
  const signature = sign(null, Buffer.from(`${AGENT_SIG_CONTEXT}${contentHash}`, 'utf8'), agent.privateKey).toString('base64');
  return call(method, path, {
    auth: agent.certJws,
    body: raw,
    headers: { ...headers, 'x-agent-signature': signature, 'x-agent-signature-content-hash': `sha256:${contentHash}` },
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- Setup ---

async function bootstrap(platformKey) {
  const orgs = await call('GET', '/v1/admin/orgs', { auth: platformKey });
  const org = orgs.data.find((o) => o.name === 'Default') ?? orgs.data[0];
  const admin = await call('POST', '/v1/admin/api-keys', {
    auth: platformKey,
    body: { role: 'admin', ownerType: 'org', ownerId: org.id, label: 'fixture-admin' },
  });
  return { orgId: org.id, adminKey: admin.apiKey };
}

async function apiKeyAgent(ctx, platformKey, displayName) {
  const agent = await call('POST', '/v1/admin/agents', { auth: ctx.adminKey, body: { orgId: ctx.orgId, displayName } });
  const key = await call('POST', '/v1/admin/api-keys', {
    auth: platformKey,
    body: { role: 'agent', ownerType: 'agent', ownerId: agent.id, label: displayName },
  });
  return { id: agent.id, apiKey: key.apiKey };
}

async function registerIssuers(ctx, platformKey, idpA, idpB) {
  // Issuer A serves the cert exchange and provisions an agent per subject.
  await call('POST', '/v1/admin/trusted-issuers', {
    auth: platformKey,
    body: {
      orgId: ctx.orgId,
      issuerUrl: idpA.issuer,
      jwksUri: idpA.jwksUri,
      expectedAudience: AUDIENCE,
      appliesTo: 'agent',
      maxCredentialTtlSeconds: 600,
      autoProvisionAgents: true,
      autoProvisionScopeProfile: 'agent-full',
      label: 'fixture workload issuer',
    },
  });
  // Issuer B serves only delegated on-behalf-of tokens.
  await call('POST', '/v1/admin/trusted-issuers', {
    auth: platformKey,
    body: {
      orgId: ctx.orgId,
      issuerUrl: idpB.issuer,
      jwksUri: idpB.jwksUri,
      expectedAudience: AUDIENCE,
      appliesTo: 'principal',
      label: 'fixture delegation issuer',
    },
  });
}

/** Exchange a fresh issuer-A token for an ephemeral cert bound to a new Ed25519 key. */
async function certAgent(idpA, sub) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' });
  const publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x };
  const proofOfPossession = sign(null, Buffer.from(`${CERT_POP_CONTEXT}${sub}`, 'utf8'), privateKey).toString('base64');
  const cert = await call('POST', '/v1/auth/oidc/cert', {
    body: { oidcToken: idpA.mint({ sub, aud: AUDIENCE }), publicKeyJwk, proofOfPossession },
  });
  return { sub, privateKey, publicKeyJwk, cert: cert.cert, certJws: cert.certJws, id: cert.cert.agentId };
}

// --- Scenarios ---

/**
 * Render the principal verdict once the worker has held the record for it. The
 * verdict is refused until then, so retry that refusal and nothing else.
 */
async function verdictWhenHeld(send) {
  for (let i = 0; ; i++) {
    try {
      return await send();
    } catch (err) {
      if (i >= 120 || !/-> 4\d\d: .*awaiting a verdict/s.test(String(err.message))) throw err;
      await sleep(250);
    }
  }
}

const LIFECYCLE_CRITERIA = { amount: 1, summary: 'fixture lifecycle' };
const EVIDENCE = { summary: 'fixture evidence' };

/** create + autoActivate, completion, principal accept: every body signed by the cert key. */
async function certLifecycle(agent) {
  const rec = await signedCall(agent, 'POST', '/v1/records', {
    type: 'principal-gate-generic-v1',
    criteria: LIFECYCLE_CRITERIA,
    performerAgentId: agent.id,
    autoActivate: true,
  });
  const completion = await signedCall(agent, 'POST', `/v1/records/${rec.id}/completions`, { evidence: EVIDENCE });
  await verdictWhenHeld(() =>
    signedCall(agent, 'POST', `/v1/records/${rec.id}/verdict`, { completionId: completion.id, verdict: 'accept' }));
  return rec.id;
}

/** The same walk on API keys, with a distinct performer. */
async function apiKeyLifecycle(principal, performer) {
  const rec = await call('POST', '/v1/records', {
    auth: principal.apiKey,
    body: { type: 'principal-gate-generic-v1', criteria: LIFECYCLE_CRITERIA, performerAgentId: performer.id, autoActivate: true },
  });
  const completion = await call('POST', `/v1/records/${rec.id}/completions`, { auth: performer.apiKey, body: { evidence: EVIDENCE } });
  await verdictWhenHeld(() =>
    call('POST', `/v1/records/${rec.id}/verdict`, { auth: principal.apiKey, body: { completionId: completion.id, verdict: 'accept' } }));
  return rec.id;
}

function onBehalfOf(idpB, subject, act) {
  return { 'agledger-on-behalf-of': idpB.mint({ sub: subject, aud: AUDIENCE, act }) };
}

// --- Commands ---

async function capture() {
  const out = need('out');
  const platformKey = need('platform-key');
  mkdirSync(out, { recursive: true });
  const idpA = await startIssuer({ issuer: need('idp-a'), listen: need('idp-a-listen'), kid: 'idp-1' });
  const idpB = await startIssuer({ issuer: need('idp-b'), listen: need('idp-b-listen'), kid: 'deleg-1' });
  try {
    const ctx = await bootstrap(platformKey);
    await registerIssuers(ctx, platformKey, idpA, idpB);
    const principal = await apiKeyAgent(ctx, platformKey, 'qs-principal');
    const performer = await apiKeyAgent(ctx, platformKey, 'qs-performer');
    const agentA = await certAgent(idpA, 'verify-fixture-agent-a');
    const agentB = await certAgent(idpA, 'verify-fixture-agent-b');

    const records = {};
    records['cert-lifecycle'] = await certLifecycle(agentA);
    records['cert-lifecycle-second-agent'] = await certLifecycle(agentB);
    records['lifecycle'] = await apiKeyLifecycle(principal, performer);

    records['delegated-bound'] = (await signedCall(
      agentA, 'POST', '/v1/records',
      { type: 'notarize-generic-v1', criteria: { summary: 'delegated create' } },
      onBehalfOf(idpB, 'user-alice', { iss: idpA.issuer, sub: agentA.sub }),
    )).id;
    records['delegated-unbound'] = (await call('POST', '/v1/records', {
      auth: principal.apiKey,
      body: { type: 'notarize-generic-v1', criteria: { summary: 'delegated unbound' } },
      headers: onBehalfOf(idpB, 'user-bob', { sub: 'some-agent' }),
    })).id;
    records['delegation-parent'] = (await signedCall(
      agentA, 'POST', '/v1/records',
      { type: 'delegated-workflow-v1', criteria: { workflowName: 'fixture delegation', expectedChildCount: 1 }, performerAgentId: agentB.id },
      onBehalfOf(idpB, 'user-alice', { iss: idpA.issuer, sub: agentA.sub }),
    )).id;
    records['delegation-child'] = (await signedCall(
      agentB, 'POST', '/v1/records',
      { type: 'notarize-generic-v1', criteria: { summary: 'delegated step' }, parentRecordId: records['delegation-parent'] },
      onBehalfOf(idpB, 'user-alice', { iss: idpA.issuer, sub: agentB.sub }),
    )).id;

    // Each export is read by the agent that wrote the record. An org admin's
    // read is itself recorded and answered with a read receipt, which the
    // record's own agent never gets.
    const readers = {
      'cert-lifecycle': agentA.certJws,
      lifecycle: principal.apiKey,
      'delegated-bound': agentA.certJws,
      'delegated-unbound': principal.apiKey,
      'delegation-parent': agentA.certJws,
      'delegation-child': agentB.certJws,
    };
    for (const [name, auth] of Object.entries(readers)) {
      writeJson(join(out, `export-${name}.json`), await call('GET', `/v1/records/${records[name]}/audit-export`, { auth }));
    }
    writeJson(join(out, 'agent-cert-key.json'), {
      certId: agentA.cert.id,
      publicKeyThumbprint: agentA.cert.publicKeyThumbprint,
      publicKeyJwk: agentA.publicKeyJwk,
    });
    writeJson(join(out, 'capture-manifest.json'), { records });
    process.stdout.write(`captured ${Object.keys(records).length} records into ${out}\n`);
  } finally {
    await idpA.close();
    await idpB.close();
  }
}

function sliceDump() {
  const out = need('out');
  const full = need('dump');
  const { records } = JSON.parse(readFileSync(join(out, 'capture-manifest.json'), 'utf8'));
  const keep = new Set(Object.values(records));
  const dest = join(out, 'dump');
  mkdirSync(dest, { recursive: true });
  for (const name of readdirSync(full)) {
    if (!name.endsWith('.ndjson')) continue;
    if (name === 'vault_signing_keys.ndjson' || name === 'vault_key_statements.ndjson') {
      copyFileSync(join(full, name), join(dest, name));
    } else if (name === 'audit_vault.ndjson') {
      const rows = readFileSync(join(full, name), 'utf8').split('\n').filter((l) => l && keep.has(JSON.parse(l).record_id));
      writeFileSync(join(dest, name), rows.map((l) => `${l}\n`).join(''));
      process.stdout.write(`kept ${rows.length} audit_vault rows from ${keep.size} record chains\n`);
    } else {
      // Checkpoints and admin-read rows cover the whole vault, not these chains.
      writeFileSync(join(dest, name), '');
    }
  }
}

const command = positionals[0];
if (command === 'capture') await capture();
else if (command === 'slice-dump') sliceDump();
else {
  process.stderr.write('usage: capture.mjs capture|slice-dump --out <dir> [options]; see the header of this file\n');
  process.exit(2);
}
