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
  // The SPKI digest of a vault key you took out of band (see "Anchoring keys").
  trustAnchors: ['sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e'],
});

if (result.verdict === 'failed') {
  console.error(`Broken at position ${result.brokenAt?.position}: ${result.brokenAt?.code}`);
  process.exit(1);
}
console.log(result.verdict); // 'trusted', or 'unanchored' when nothing pinned backs the pass
// { valid: true, verdict, verifiedEntries, totalEntries, keyTrust, keyProvenance: { supplied, embedded }, ... }
```

Read `verdict` rather than `valid`: a valid result with no `trustAnchors` is
`unanchored`, which is not a trusted verdict. An option the function does not
read throws `TypeError` rather than being ignored, so a misspelt option, or
`requireOutOfBandKeys` (renamed `requireSuppliedKeys` in 2.0.0), cannot turn a
check off without a word.

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
  header signed. An entry that names a key but carries an all-zero signature
  fails `CHAIN_SIGNATURE_INVALID`.
- **Unsigned entries**: an entry with no `signingKeyId` fails
  `CHAIN_ENTRY_UNSIGNED` when it follows a signed entry in its chain, or when
  it was written at or after the earliest `activatedAt` in the key set
  (export `signingKeyWindows` and your own keys, retired keys included). With
  `trustAnchors`, the activations an anchored key's statements sign count as
  well, so an export stripped of its unsigned `signingKeyWindows` is still
  held to them.
  Earlier unsigned entries, written before the install had a key, count as
  `signatureCoverage.skipped` rather than a break.
- **Payload binding**: each entry's human-readable `payload` still matches the
  predicate inside the signed bytes, so a rewritten view of the record fails
  `CHAIN_PAYLOAD_BINDING_MISMATCH`.
- **OIDC actor**: the row's `actorOidcIss` / `actorOidcSub` match the identity
  signed in `predicate.on_behalf_of`.
- **Actor attribution**: the row's `actorId`, `actorRole` and `actorOwnerId`,
  the attribution an export's own guide tells an auditor to rely on, match the
  actor claim signed in the protected header, so an export re-attributed to
  another actor fails `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`.
- **Key anchoring**, with `trustAnchors`: each entry's key is linked by signed
  key statements to a key you pinned, or the entry fails
  `CHAIN_SIGNING_KEY_UNANCHORED` (below).
- **Key validity windows**: each entry was written inside its signing key's
  activation window. With `trustAnchors`, the window is the one the key
  statements sign.
- **Agent signatures**, when you supply the agent's cert key (below).

The payload, OIDC, attribution and key-window checks run when the export
carries their inputs, which every current Server does. The result's `optionalChecks` says
which ran, so "not checked" never reads as "passed".

## Anchoring keys

A vault key the Server publishes comes from its database, and anything with
write access to that database can add a key row and entries signed with it.
What it cannot add is a **key statement**: a COSE_Sign1 signed by a key the
Server already trusted (and, for a new key, by the new key too). Pass the SPKI
digest of a vault key you hold or took out of band as `trustAnchors`, and the
verifier walks the statements from it:

- the installer prints the digest of the first vault key, and the Server's
  `signing-key-digest.js` derives one from any key you hold;
- the export's `exportMetadata.anchoredFrom` names the Server's own key, and
  the result reports whether it is one of your anchors
  (`keyTrust.anchoredFromPinned`), but it is the export's word and never
  counts as an anchor itself.

An entry signed by a key the walk does not anchor fails
`CHAIN_SIGNING_KEY_UNANCHORED`, and each anchored key is held to the window its
statements sign. `keyTrust.status` says whether a pass can be trusted:

- `walked`: at least one entry verified under a key your anchors reach. The
  only status a passing result is trusted on.
- `no_anchor`: no `trustAnchors` (an empty array is the same as none), so
  `optionalChecks.key_anchoring` is `skipped_no_input` and the verdict rests on
  keys nobody pinned: a key written into the database alone would pass.
- `no_anchored_signature`: the walk ran, but no entry verified under a key it
  anchors, so `optionalChecks.key_anchoring` is `not_checked`. An export of
  entries written before the install began signing passes under any pin, and
  proves nothing about the pin.

A pass on `no_anchor` or `no_anchored_signature` is not a trusted verdict; the
`detail` says so, and `verdict` (and every AGLedger surface) reports it as
`unanchored`. `distrustedKeys` without `trustAnchors` throws `TypeError`, since
nothing would apply them, and so does a pinned key distrusted with no instant,
which the Server refuses to start with. A pin beside a dated entry
(`sha256:<hex>@<instant>`) is how a leaked key's history stays verifiable: the
pin vouches for what the key stored before the instant, and the entry
withdraws what it stored from then on.

```ts
import { verifyAuditExport } from '@agledger/verify-core';

const result = verifyAuditExport(exportDocument, {
  trustAnchors: ['sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e'],
  // The operator's VAULT_DISTRUSTED_KEYS, when a key leaked: what it signed
  // from the instant on (or, with none, from its retirement) counts for nothing.
  distrustedKeys: [],
});

const { status, anchoredKeyIds, unanchoredKeyIds, findings } = result.keyTrust;
console.log(status, anchoredKeyIds, unanchoredKeyIds);
for (const f of findings) console.log(f.code, f.keyId, f.detail);
```

The statements the export carries (`exportMetadata.signingKeyStatements`) are
walked, together with any `statements` on keys you supply from
`GET /v1/verification-keys`. Findings about the statements themselves make the
result invalid, at position 0:

- `KEY_STATEMENT_INVALID`: a statement that does not verify, disagrees with
  what it is filed under, touches no anchored key, was signed by a key after
  its closure or after the key was already admitted, or admits a trusted key
  under an endorser the walk does not trust (the Server publishes the
  admission and not its endorser);
- `KEY_CLOSURE_INVALID`: a retired key with no closure that counts for it, or
  a closure by a key the walk does not anchor, by a key after its own
  retirement, dated before its subject was activated, dated after the time it
  was stored, or signed by a key the walk reaches but does not anchor and
  closing a published key (the Server publishes the closure and not its
  signer, so no walk over what it publishes can verify it);
- `CHAIN_KEY_WINDOW_DRIFT`: a listed window or status that differs from the
  signed value (compared at millisecond precision).

A key the Server's `VAULT_DISTRUSTED_KEYS` names is listed with
`distrustedFrom`, the instant its entry gives (in an export's
`signingKeyWindows` and on `/v1/verification-keys`), and where that instant is
earlier than the retirement the key's closures sign, the listed `retiredAt` is
that instant. A walk not given the same entry still fails on that window, but
the finding names the entry the listing says the Server applied
(`distrustedKeys sha256:<hex>@<distrustedFrom>`) rather than reading as a
rewritten column, and says so when the entry it was given carries another
instant; an entry at an earlier instant, which fails nothing on the window,
is said in `keyTrust.notes`. `distrustedFrom` is the source's unsigned word
and only changes that wording: it never ends, opens or widens a window and
never clears a finding. Confirm the instant with the Server's operator before
giving that `distrustedKeys` entry: off a dump an entry also voids every
admission the key signed, so a key it admitted that nothing else reaches is
no longer trusted and its window no longer graded.

Statements are walked in the order the Server's database stored them,
`createdAt` then the row `id`, never by an instant a statement signs. A dump
carries that order (`created_at`), and so does every key document an API 2.0
Server serves: each statement in an export's `signingKeyStatements`,
`/v1/verification-keys` and `/.well-known/agledger-vault-keys.json` carries
its row `id` and `createdAt` at microsecond precision, and `keyTrust.order`
reads `written`. A `createdAt` that is not strict RFC 3339 (a `T`, an offset
or `Z`, a real calendar date) places nothing, and its statement is
`KEY_STATEMENT_INVALID`. Such a document lists under a trusted key its
admission, every later admission it signed, and the closures that count for
it, so a walk over it dates each window and cuts each edge back as the engine
does. Where it cannot (a later succession whose endorser the document does not
carry, or a closure by a key it does not list), the walk grades the window
more loosely than the listed one, and the listed `activatedAt` or `retiredAt`
reads as `CHAIN_KEY_WINDOW_DRIFT` (a listed retirement no closure it could
verify signs is `KEY_CLOSURE_INVALID`). A statement the export and a supplied
key both carry is one row, however its `id` and `createdAt` are spelled.

A document from a Server that published neither field is still read, and
`keyTrust.order` reads `signed`: statements are ordered by the instant each
one signs, with a closure after any admission that signs the same instant. For
a document the Server served, the two orders agree. If the export and a
supplied key document disagree (one carries write times and the other does
not), a statement the older one alone carries makes the whole walk fall back
to the signed order.

`createdAt` is not signed: whoever holds an export or a key document can edit
it, as they can reorder the document, with nothing offline to tell. So a
document's write order is never held against `distrustedKeys`. On any
statement from an export or a supplied key document, in either order, an edge
out of a distrusted key never admits a key or keeps one reachable, whatever
time it carries. Such a statement still counts for everything that can only
narrow trust: it dates its subject's window, cuts the subject's edge back as a
later admission, and a closure the key signed still ends a window. Where the
document dates it before the cutoff, so the engine would count it, it is no
finding: it is listed in `keyTrust.notes`, which never fails a verdict, and an
honest rotation away from the key passes when you pin its successor. Pinned
only on the distrusted key, its successor is not anchored. This is narrower
than the engine, which holds the key to the time its statements were really
stored, and never wider. Only
a dump walk holds a distrusted key's statements to their `created_at`, as the
engine does, and that adds assurance only for a dump you took from the Server
yourself or over a channel you trust; for any other dump it assures no more
than the stored times its holder chose.

An entry's `createdAt` is not signed either, so the holder of a leaked
distrusted key can still sign entries dated before its cutoff, and no offline
verifier can tell those from the history the key wrote inside its legitimate
window.

Without `distrustedKeys`, a key retired without `force` whose private half
later leaks can still admit a key on any walk: with a statement it dates
before its retirement under the signed order, or with an edited `createdAt`
under the write order. A forced retirement voids every edge out of its key
under either order. When a retired key may have leaked, retire it with
`force` or list it in `distrustedKeys`.

### Walking a dump or a key document

`@agledger/verify` walks a full-vault dump with the same functions:

```ts
import { readFileSync } from 'node:fs';
import { applyKeyTrust, buildKeyRegistry, computeKeyTrust, keyStatementFromDumpRow, trustKeyFromDumpRow } from '@agledger/verify-core';
import type { DumpKeyStatementRow, DumpSigningKeyRow } from '@agledger/verify-core';

const rows = <T,>(file: string): T[] =>
  readFileSync(file, 'utf8').split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as T);
const keys = rows<DumpSigningKeyRow>('vault_signing_keys.ndjson');

const trust = computeKeyTrust({
  keys: keys.map(trustKeyFromDumpRow),
  statements: rows<DumpKeyStatementRow>('vault_key_statements.ndjson').map(keyStatementFromDumpRow),
  trustAnchors: ['sha256:15d63684b387235c47fe3a81e3004b928f4ea535236a2c1b47465ce5fdd7ce0e'],
});
// Marks each key anchored, unanchored or undecided and gives anchored keys
// their signed windows; verifyChain then grades entries against it.
const registry = applyKeyTrust(
  buildKeyRegistry(keys.map((k) => ({ keyId: k.key_id, spkiBase64: k.public_key, source: 'embedded' as const }))),
  trust,
);
console.log([...registry.values()].map((k) => `${k.keyId} ${k.trust}`), trust.findings);
```

A dump verifier reports the walk with `reportKeyTrust(registry, trust, null)`
and, once its chains are walked, settles it with
`settleKeyTrust(report, signedEntries)`, the count of entries whose signature
verified: with none, the status becomes `no_anchored_signature`.
`writtenWhileSigning(rowTime, signingSince)` is the unsigned-row rule for
checkpoints and read-log rows, and fails closed on a row with no readable time
once signing began.

A dump row repeating an earlier row's signed payload counts once, at its
first write: a row copied in the database under a new id and time says
nothing new, as the engine reads it. On a key document a copy stays a second
statement, since its `createdAt` is the holder's word.

On a dump, a `distrustedKeys` key that a key the walk trusts has retired is
bounded by that retirement (its `DistrustSpan` in `trust.distrustSpans`; only a
retirement by a key the walk trusts counts, as in the engine), and
what it signed before then is accounted for rather than failed, as the engine's
scan lists it: a key statement it signed that counts for nothing is listed in
`trust.accounted` (and the report's `accounted`) instead of `findings`, and a
chain entry whose signature verifies under it, outside what the key is
trusted for (the key unanchored, or the entry written at or after its cutoff),
is listed in the `verifyChain` result's `accounted` as
`CHAIN_SIGNED_BY_DISTRUSTED_KEY` (`AccountedEntry`: `code`, `chain`,
`recordId`, `orgId`, `scopeId`, `position`, `keyId`, `detail`) with signature
state `accounted`, and does not fail the chain. A verdict whose only items are
accounted ones passes, and should list them. What the key signed after that
retirement fails as before, and a distrusted key with a registry row that no
trusted key has retired is `KEY_CLOSURE_INVALID` naming the forced retire call
that bounds it. An audit export is never accounted for this way: its write
times are not the Server's word.

`keyStatementsFromVerificationKeys(document)` gives the same inputs from a
`GET /v1/verification-keys` response. A key reached only through a statement
this host cannot compute (Ed25519 history on a FIPS host) is `undecided`, and
entries under it are `CHAIN_UNSUPPORTED_ALGORITHM` rather than unanchored.

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

## Supplied keys

`options.publicKeys` accepts these shapes:

- a **`Record<keyId, base64SpkiDer>`** map (compact, keyed by key id), or
- a **`SuppliedKeyEntry[]`** array, the natural shape returned by
  `client.verificationKeys.list().data` and SCITT COSE_KeySet listings, where
  each entry is `{ keyId, publicKey, activatedAt?, retiredAt?, statements? }`
  (`publicKey` is SPKI DER base64), or the `/v1/verification-keys` body as
  served, `{ data: [...] }`, read as its `data`.

Both are normalized at the boundary; anything else throws `TypeError`
(fail-closed: the verifier never silently falls back to embedded keys).

## Org-read log

The cross-party read log (`org_admin_reads`) is an RFC 9162 §2.1 Merkle tree,
the same construction SCITT Receipts use. Its hashes are lowercase hex:

```ts
import { orgReadLeafHash, orgReadMerkleRoot, verifyOrgReadInclusion } from '@agledger/verify-core';

// leaf_hash = hex(sha256(0x00 || cose_sign1)); a checkpoint's root is the RFC 9162 root over them.
const leaf = orgReadLeafHash(Buffer.from('cose-sign1-bytes'));
const root = orgReadMerkleRoot([leaf]);
// An inclusion proof from GET /v1/audit/org-reads/checkpoints/{id}/proof; a one-leaf tree has an empty path.
console.log(root === leaf, verifyOrgReadInclusion(leaf, 0, 1, [], root!)); // true true
```

## Canonical failure taxonomy

Every failure is a canonical SCREAMING_SNAKE `FailureCode`. Importing the
taxonomy from one place keeps every verifier reporting the same code for the
same fault, so an auditor reads `CHAIN_LINK_BROKEN` whether the
chain was checked by the SDK, the CLI, the MCP tool, or `@agledger/verify`.

## Key provenance

The result distinguishes keys **supplied** by the caller from keys **embedded in
the export** under inspection (`keyProvenance`), and `requireSuppliedKeys`
refuses embedded keys. That says where a key came from, not that it is trusted:
a key fetched from the Server comes from its database too. Trust is what
`trustAnchors` establishes.

## License

Proprietary. See [LICENSE](./LICENSE). © AGLedger LLC. All rights reserved.
