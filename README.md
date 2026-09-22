# @agledger/verify-core

The shared offline verification core for AGLedger audit chains. Decodes
canonical **COSE_Sign1** envelopes (RFC 9052, tag 18) over in-toto v1
Statement payloads, walks the per-record hash chain, and verifies the
signature over each `Sig_structure` under the algorithm the verification key
commits to (Ed25519 or ES256), with no engine, no database, and no network.

This is the single body of logic that underpins the SDK `/verify` subpath
(`@agledger/sdk/verify`), the [`@agledger/cli`](https://github.com/agledger-ai/cli)
`verify` command, the
[`@agledger/mcp-server`](https://github.com/agledger-ai/mcp-server) `agledger_verify`
tool, and the full-vault [`@agledger/verify`](https://github.com/agledger-ai/verify)
auditor package. Each of those
consumes this core rather than carrying its own copy, so a chain that passes in
one surface passes identically in all of them.

One dependency: [`cborg`](https://www.npmjs.com/package/cborg), for COSE_Sign1
CBOR decoding.

## Install

```bash
npm install @agledger/verify-core
```

Node 24 or newer. If you want a ready-made verifier rather than a library, use
[`@agledger/verify`](https://github.com/agledger-ai/verify) for a full-vault dump
or the `verify` command in [`@agledger/cli`](https://github.com/agledger-ai/cli)
for a single record export.

## Usage

```ts
import { verifyAuditExport } from '@agledger/verify-core';

const result = verifyAuditExport(exportDocument, {
  publicKeys,             // optional out-of-band keys (see "Out-of-band keys" below)
  requireOutOfBandKeys: true, // optional: refuse the export's embedded keys
});

if (!result.valid) {
  console.error(`Broken at position ${result.brokenAt?.position}: ${result.brokenAt?.code}`);
  process.exit(1);
}
// { valid: true, verifiedEntries, totalEntries, keyProvenance: { outOfBand, embedded }, ... }
```

## What it verifies

- **`chainPosition` monotonicity**: gap-free, in order.
- **`payload_hash` = sha256(cose_sign1)**: the visible row hash binds the
  signed envelope bytes.
- **`previous_hash` linkage**: each entry chains to its predecessor.
- **Signed chain-claim cross-check**: the chain position and linkage claimed in
  the COSE protected header match the row columns.
- **Envelope signature**: over the reconstructed `Sig_structure`, against the
  matched verification key, under the algorithm its SPKI commits to (Ed25519
  or ES256; anything else fails closed as `CHAIN_UNSUPPORTED_ALGORITHM`).
- **Signed-kid binding**: the row's `signingKeyId` names the key the protected
  header signed.
- **Payload binding**: each entry's human-readable `payload` still matches the
  predicate inside the signed bytes, so a rewritten view of the record fails
  `CHAIN_PAYLOAD_BINDING_MISMATCH`.
- **OIDC actor**: the row's `actorOidcIss` / `actorOidcSub` match the identity
  signed in `predicate.on_behalf_of`.
- **Actor attribution**: the row's `actorId`, `actorRole` and `actorOwnerId`,
  the attribution an export's own guide tells an auditor to rely on, match the
  actor claim signed in the protected header, so an export re-attributed to
  another actor fails `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`.
- **Key validity windows**: each entry was written inside its signing key's
  activation window.
- **Agent signatures**, when you supply the agent's cert key (below).

The payload, OIDC, attribution and key-window checks run when the export
carries their inputs, which every current Server does. The result's `optionalChecks` says
which ran, so "not checked" never reads as "passed".

## Agent signatures

An agent that authenticates with an ephemeral cert can sign each request body
it sends. The Server checks that signature, then seals it into the chain entry
as `predicate.on_behalf_of.agent_signature`, beside the RFC 7638 thumbprint of
the cert's public key. The envelope signature proves the Server wrote that. To
prove the agent itself signed, without taking the Server's word for it,
re-verify the agent signature against the cert's public key.

The export does not carry cert public keys. Supply them as the Ed25519 JWK the
agent sent to `POST /v1/auth/oidc/cert` (the same key is the `cnf.jwk` claim
inside the `certJws` it got back):

```ts
import { verifyAuditExport } from '@agledger/verify-core';

const agentKey = { kty: 'OKP', crv: 'Ed25519', x: 'BKOgK3KibE8BZH8SXTX9dmAXcwgocTMHIv-R_eRB2lo' } as const;
const result = verifyAuditExport(exportDocument, { agentKeys: [agentKey] });

console.log(result.optionalChecks.agent_signature); // 'applied'
console.log(result.agentSignatures); // e.g. { present: 6, verified: 6 }
```

A key is matched to an entry only through the thumbprint that entry signed, so
a key for some other cert is never checked against it and where the key came
from needs no trust. `present` counts entries carrying an agent signature and
`verified` those re-checked and found good; `present > verified` on a valid
result means some were not checked, never that they failed. One that does not
verify fails `CHAIN_AGENT_SIGNATURE_INVALID`. The check runs only where
`on_behalf_of.validated` is `true`: on a caller-asserted identity the two fields
may be passthrough from an older Server, and the export cannot tell which.

The Server's own chain verification also compares each sealed cert against its
live cert record (`cert_missing`, `cert_actor_drift`, `cert_window_drift`,
`cert_expired`). That record is not exported, so those checks have no offline
counterpart; the signed bytes already fix the cert id, thumbprint and expiry an
entry sealed.

## Verifying on a FIPS-locked host

This package has no crypto of its own: it verifies through the host's Node
runtime. An active OpenSSL FIPS provider carries no EdDSA, so **an Ed25519
chain cannot be verified on a FIPS-locked host**. ES256 chains can.

That is reported as `CHAIN_UNSUPPORTED_ALGORITHM`, never as a signature
failure. The distinction is the whole point: "I could not check this" and "I
checked this and it failed" lead to opposite conclusions, and only one of them
is grounds for a tamper investigation. The result still fails closed, because
an unverified chain is not a verified one. To actually verify an Ed25519 chain,
re-run on a host without the restriction; the export and keys are portable and
the verification is entirely offline, so this costs nothing but a second host.

### Asking about an algorithm directly

`CHAIN_UNSUPPORTED_ALGORITHM` covers two causes with different remedies (this
build does not implement the algorithm, versus this host refuses to compute it),
so a consumer writing its own report can ask about either:

```ts
import { algorithmByName, runtimeCanCompute, describeUnsupportedAlgorithm } from '@agledger/verify-core';

// runtimeCanCompute takes a KeyAlgorithm from this build's table, NOT a name
// string. Look one up with algorithmByName ('Ed25519', 'ES256', 'ES384',
// 'ES512', 'ES256K'); it returns null for anything else.
const ed25519 = algorithmByName('Ed25519');
if (ed25519 && !runtimeCanCompute(ed25519)) {
  console.warn('This host cannot verify Ed25519 chains.');
}

// Or ask about a specific key, given its SPKI DER base64. Safe to call without
// having established that a gap exists: a key that verifies fine here says so
// rather than asserting a refusal that did not happen.
console.log(describeUnsupportedAlgorithm(spkiBase64));
```

`algorithmByName` exists for the case `resolveKeyAlgorithm` cannot serve: a host
that refuses to *load* a key of some algorithm produces no key object to
resolve, which is exactly when the question matters most.

## Out-of-band keys

`options.publicKeys` accepts either of two shapes:

- a **`Record<keyId, base64SpkiDer>`** map (compact, keyed by key id), or
- an **`OutOfBandKeyEntry[]`** array, the natural shape returned by
  `client.verificationKeys.list().data` and SCITT COSE_KeySet listings, where
  each entry is `{ keyId, publicKey, activatedAt?, retiredAt? }` (`publicKey`
  is SPKI DER base64).

Both are normalized at the boundary; anything else throws `TypeError`
(fail-closed: the verifier never silently falls back to embedded keys).

## Canonical failure taxonomy

Every failure is a canonical SCREAMING_SNAKE `FailureCode`. Importing the
taxonomy from one place keeps every verifier reporting the same code for the
same fault, so an auditor reads `CHAIN_LINK_BROKEN` whether the
chain was checked by the SDK, the CLI, the MCP tool, or `@agledger/verify`.

## Key provenance

The result distinguishes keys supplied **out of band** (by the caller) from keys
**embedded in the export** under inspection. High-assurance audits can require
out-of-band keys and fail closed on a self-attesting export.

## License

Proprietary. See [LICENSE](./LICENSE). © AGLedger LLC. All rights reserved.
