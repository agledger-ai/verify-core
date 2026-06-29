# @agledger/verify-core

The shared offline verification core for AGLedger audit chains. Decodes
canonical **COSE_Sign1** envelopes (RFC 9052, tag 18, EdDSA) over in-toto v1
Statement payloads, walks the per-record hash chain, and verifies the Ed25519
signature over each `Sig_structure`, with no engine, no database, and no
network.

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
- **Ed25519 signature**: over the reconstructed `Sig_structure`, against the
  matched verification key.

## Out-of-band keys

`options.publicKeys` accepts either of two shapes:

- a **`Record<keyId, base64SpkiDer>`** map (compact, keyed by key id), or
- an **`OutOfBandKeyEntry[]`** array, the natural shape returned by
  `client.verificationKeys.list().data` and SCITT COSE_KeySet listings, where
  each entry is `{ keyId, publicKey, activatedAt?, retiredAt? }` (`publicKey`
  is SPKI DER base64).

Both are normalized at the boundary; anything else throws `TypeError`
(fail-closed — the verifier never silently falls back to embedded keys).

## Canonical failure taxonomy

Every failure is a canonical SCREAMING_SNAKE `FailureCode`. Importing the
taxonomy from one place keeps every verifier reporting the same code for the
same fault — so an auditor reads `CHAIN_LINK_BROKEN` whether the
chain was checked by the SDK, the CLI, the MCP tool, or `@agledger/verify`.

## Key provenance

The result distinguishes keys supplied **out of band** (by the caller) from keys
**embedded in the export** under inspection. High-assurance audits can require
out-of-band keys and fail closed on a self-attesting export.

## License

Proprietary. See [LICENSE](./LICENSE). © AGLedger LLC. All rights reserved.
