# Changelog

All notable changes to `@agledger/verify-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.2.0] - 2026-11-18

### Added

- **`expectedEntryCount` and `optionalChecks.entry_count` on `verifyAuditExport`.** The entry counts an export states about itself are unsigned, so deleting them used to switch the length check off silently. The check is now reported as `entry_count`: `applied` when a count was held, `skipped_no_input` when none was. `expectedEntryCount` takes the count from the caller, out of band; an export with a different number of entries fails `CHAIN_POSITION_GAP`. A value that is not a non-negative integer throws `TypeError`. `ExportOptionalCheck` is the new key type of the result's `optionalChecks`.
- **`allowAfterRetirement` on `verifyAuditExport`, `verifyChain` and `checkFederationWire`.** See Changed.
- **Key windows and the distrust rule for checkpoints and the read log (`placeInKeyWindow`, `distrustAccounts`).** An AGLedger Server later than 2.2.0 holds a vault checkpoint, a read-log leaf and a read-log tree head to the signed window of the key that signed it, and sets aside the ones that a `VAULT_DISTRUSTED_KEYS` entry and the trusted retirement account for. `placeInKeyWindow(key, writtenAt, what)` places such an artifact by the same rule `CHAIN_KEY_NOT_YET_ACTIVE` and `CHAIN_KEY_EXPIRED` apply to entries; an artifact whose time cannot be read is reported as `unplaceable`. `distrustAccounts(key, writtenAt)` is the condition that lists a chain entry as `CHAIN_SIGNED_BY_DISTRUSTED_KEY`. Eight failure codes join the taxonomy for a dump verifier to report: `CHECKPOINT_KEY_NOT_YET_ACTIVE`, `CHECKPOINT_KEY_EXPIRED`, `TENANT_READ_KEY_NOT_YET_ACTIVE`, `TENANT_READ_KEY_EXPIRED`, `TENANT_CHECKPOINT_KEY_NOT_YET_ACTIVE`, `TENANT_CHECKPOINT_KEY_EXPIRED`, `CHECKPOINT_ACCOUNTED_ONLY` and `CHECKPOINT_ACCOUNTED_RUN_EXCEEDED`.
- **An export's chain is held to the entry counts the export states (`result.entryCount`).** A chain cut from the end still links and verifies entry by entry, so its length is the only sign of the cut. An export with fewer entries than `exportMetadata.expectedEntries` fails `CHECKPOINT_ROW_MISSING`; fewer than `exportMetadata.totalEntries` fails `CHAIN_POSITION_GAP`. A count that is present but not a non-negative integer or null fails `UNSUPPORTED_FORMAT`. `result.entryCount` reports both counts (`expectedEntries`, `statedEntries`), each null when the export does not state it. An export that verified on 2.1.0 with its tail removed now fails.

### Changed

- **A federation message signed by a retired key fails unless `allowAfterRetirement` is given.** A message signed more than 300 seconds after its key was retired used to be only counted in `federationWire.afterRetirement`. It now fails `CHAIN_FEDERATION_WIRE_INVALID`. Pass `allowAfterRetirement: true` to allow the short gap while a sender restarts onto its new key; such a message verifies and is counted as before.
- **A federation message must name its record and carry the fields its entry type compares.** A `FEDERATION_STATE_SYNC`, `FEDERATION_SIGNAL_RECEIVED` or `FEDERATION_CO_SIGN_RESPONDED` message with no string `recordId`, or missing the state or recommendation the other side carries, used to skip the comparison. Each now fails `CHAIN_FEDERATION_WIRE_INVALID`, as does a field present on only one side.
- **Signed CBOR is decoded strictly.** Duplicate map keys, non-minimal integer and length encodings, indefinite lengths, `undefined` and invalid UTF-8 are refused wherever the package reads signed bytes, since deterministic CBOR (RFC 8949 section 4.2.1) never contains them.
- **A pinned export that fails only because the pin reaches none of its keys reports the verdict `unanchored`, not `failed`.** Checked against another Server's pin, an untampered export failed every entry `CHAIN_SIGNING_KEY_UNANCHORED` and read as tampered. When the walk anchors no key and the export verifies without the pin, `verdict` is now `unanchored` (`valid` stays false). An export in which the pin anchors any key still fails on an entry under a key it does not reach. `verdictOf` takes an optional second argument, a rerun without the pin, to apply the same rule to other artifacts.
- **A sealed federation message is placed in its key's window with 300 seconds allowed at each edge (`FEDERATION_KEY_WINDOW_SKEW_MS`).** The message timestamp and the window edges come from different clocks, so a message signed within 300 seconds of a key change was wrongly failed or counted as after retirement. It now verifies on the key it names; only a message further out fails or is counted.
- `cborg` is pinned at 7.0.0. Everything this package encodes is byte-identical to before. One decode differs: a signed payload string that begins with U+FEFF no longer fails `CHAIN_PAYLOAD_BINDING_MISMATCH`, because the leading character is now kept.

### Fixed

- **An export's record id is the one its entries sign.** `result.recordId` used to be copied from the unsigned `exportMetadata.recordId`, so editing it changed what a passing result was about. It is now the id the entries sign, and a metadata id or entry that disagrees fails `CHAIN_PAYLOAD_BINDING_MISMATCH`.
- **An export that does not state `exportFormatVersion` or `canonicalization` fails `UNSUPPORTED_FORMAT`.** Deleting either used to skip the format gate.
- **Deleting an entry's `payload` or `entryType` no longer turns its checks off.** Once any entry of an export carries them, or `federationKeys` are supplied, an entry without them fails `CHAIN_PAYLOAD_BINDING_MISMATCH`, and the `payload_binding` (and, with `federationKeys`, `federation_wire`) check reads `not_checked`.
- **A federation projection held under a fresh local record id verifies.** From AGLedger Server 3.0.0, a receiving Server that already holds a record id a peer names stores the peer's projection under a new local id and signs `origin` (the sending Server and the id it sent) on each entry. The verifier used to fail every such entry with `CHAIN_FEDERATION_WIRE_INVALID`. When an entry signs `origin`, the sealed message's record id is now compared with `origin.recordId`, and `origin.peerHubId` must be the sealed sender. Entries without `origin` are compared with their own record id, as before.
- **A signed `traceparent` or `on_behalf_of` deleted from an export entry's `payload` fails `CHAIN_PAYLOAD_BINDING_MISMATCH`.** The Server writes every signed `on_behalf_of` and W3C `traceparent` into the entry's export `payload`, so a missing copy means it was removed after export. A rewritten or added copy already failed; a deleted one used to verify. A vault dump row never holds either, so the dump path still compares a row copy only when present.

## [2.1.0] - 2026-11-05

### Added

- **The sealed federation message on a receiver's chain is verified (`federationKeys`).** From AGLedger Server 2.0.0, a receiving Server's `FEDERATION_STATE_SYNC`, `FEDERATION_SIGNAL_RECEIVED` and `FEDERATION_CO_SIGN_RESPONDED` entries carry `payload.wire`: the peer's message as the peer signed it. `verifyChain` and `verifyAuditExport` now hold every sealed message to its body hash (SHA-256 over the RFC 8785 form of the body) and to the entry that carries it (the peer, the record, and the state, type, recommendation or dispute it asserts). Given `federationKeys` (`{ [hubId]: key }` or `[{ hubId, publicKey }]`, the key as base64 SPKI DER or base64 of the raw 32 bytes), they also re-verify the signature under that key and refuse a sealed key that is not the one supplied. A failure is the new `CHAIN_FEDERATION_WIRE_INVALID`; `federation_wire` joins `optionalChecks` and `federationWire: { present, verified, failed }` joins every result. A key that is not Ed25519 throws `TypeError`. Exported for direct use: `extractFederationWire`, `checkFederationWire`, `federationSignInput`, `buildFederationKeyRegistry`, `normalizeFederationKey` and `canonicalizeJson`.
- **A peer's federation key history (`federationKeys[].history`).** After a peer changes its federation key, entries written before the change seal the earlier key, which a single pinned key failed. A list entry now takes the peer's `GET /.well-known/agledger-federation-keys.json` beside the pinned key. Every key linked to the pin through successions both keys signed is trusted inside the window its statements sign, and each message is placed by its sealed `wire.timestamp`. A message signed before its key's activation fails; one signed after retirement verifies and is counted in the new `federationWire.afterRetirement`. A hub may be named more than once, to pin a key no succession links (`linked: false`) or one the history does not list; such a pin is trusted on its own. An altered history, another hub's, or one that lists none of the hub's pins throws `TypeError`, naming each pin. Needs AGLedger Server 2.2 or later on the peer.
- **Inlined evidence is re-bound to the hash its entry signs (`evidence_binding`).** An `/audit-export?evidence=true` carries each completion's evidence body (and, from Server 2.2, each dispute's filed payload), which is unsigned; its authority is the hash the entry signs. `verifyAuditExport` now hashes every inlined body (SHA-256 over its RFC 8785 form) and compares it with `payload.evidenceHash` on COMPLETION_SUBMITTED or `payload.payloadHash` on DISPUTE_EVIDENCE. An edited body, a body on an entry that binds none, or one that is not a JSON object fails the new `CHAIN_EVIDENCE_BINDING_MISMATCH`; before, it passed silently. An encrypted-mode completion (`payload.verifiedBy: "client"`) signs a hash over a cleartext the export does not carry, so its ciphertext is counted rather than re-bound. `evidence_binding` joins `optionalChecks`, and `evidenceBinding: { present, verified, clientHashed, failed }` joins every result.

### Changed

- The README says the package reads exports and dumps from an AGLedger Server 2.0 or later and names the last release that reads a 1.x Server's.

### Fixed

- **`keyProvenance` counts every signed entry.** An entry whose signature verified but which a later check failed (an agent signature, a sealed federation message) counted toward `signatureCoverage.signed` but toward neither `keyProvenance.supplied` nor `keyProvenance.embedded`. The two now add up to `signed`.

## [2.0.0] - 2026-10-05

This release targets AGLedger API 2.0 and reads nothing older.

### Breaking

- **The org_admin_reads tree is RFC 9162.** API 2.0 builds the cross-party read log as an RFC 9162 section 2.1 SHA-256 tree, the construction SCITT Receipts use. `merkleRoot` and `verifyInclusion`, which built the old tree, are removed. Use `orgReadLeafHash(coseSign1)`, `orgReadMerkleRoot(leafHashesHex)` and `verifyOrgReadInclusion(leafHashHex, leafIndex, treeSize, pathHex, rootHex)`. A value that is not 64 lowercase hex characters is refused (`orgReadMerkleRoot` returns null, `verifyOrgReadInclusion` false), as is a `leafIndex` or `treeSize` that is not a safe integer.
- **Out-of-band keys are now supplied keys.** A key fetched from the Server's `/v1/verification-keys` is not independent of the Server, so the old name overpromised. `requireOutOfBandKeys` is now `requireSuppliedKeys` (on `verifyAuditExport` and `verifyChain`), `KeySource` `'out-of-band'` is `'supplied'`, `keyProvenance.outOfBand` is `keyProvenance.supplied`, and `OutOfBandKeyEntry` is `SuppliedKeyEntry`. Behaviour is unchanged. What makes a key trusted is the new `trustAnchors`.
- **`OptionalCheck` gains `key_anchoring`**, so every `optionalChecks` record carries one more member, and `verifyAuditExport` results carry `keyTrust`.
- **An option a function does not read throws `TypeError`.** `verifyAuditExport`, `verifyChain` and `computeKeyTrust` refuse an unknown options key, and name the new option for `requireOutOfBandKeys`. `assertKnownOptions(fn, options, known)` applies the same refusal in a verifier built on this package. A misspelt or 1.x option name used to be dropped silently, so a caller upgrading with `requireOutOfBandKeys: true` lost the supplied-keys check and still passed.
- **A pinned key that is also distrusted with no instant is refused.** `verifyAuditExport` throws `TypeError` when `distrustedKeys` names one of the `trustAnchors` without an `@instant`. A pin beside a dated entry is accepted: it vouches for what the key stored before the instant. `assertNotPinnedAndDistrusted(trustAnchors, distrustedKeys)` applies the same check for other verifiers.
- **The signed-kid check runs before the registry algorithm check.** An entry whose `signingKeyId` column disagrees with its signed kid, and whose key's declared algorithm contradicts its material, now reports `CHAIN_SIGNING_KEY_DRIFT` rather than `CHAIN_ALG_MISMATCH`.

### Added

- **Key anchoring (`trustAnchors`).** A vault key is trusted only when signed key statements link it to a key the verifier pinned out of band, the rule API 2.0 applies to its own key registry. `verifyAuditExport` takes `trustAnchors` (`sha256:<hex>` SPKI digests) and walks the statements the export carries (`exportMetadata.signingKeyStatements`, plus any `statements` on supplied keys). An entry signed by a key the walk does not anchor fails the new `CHAIN_SIGNING_KEY_UNANCHORED`; each anchored key is held to the window its statements sign; a key reached only through a statement this host cannot compute is `undecided` and its entries fail `CHAIN_UNSUPPORTED_ALGORITHM`. Without `trustAnchors` (an empty array is the same as none) `keyTrust.status` is `no_anchor` and `optionalChecks.key_anchoring` is `skipped_no_input`.
- **`distrustedKeys`**, the verifier-side mirror of the Server's `VAULT_DISTRUSTED_KEYS` (`sha256:<hex>`, optionally `@<RFC 3339 instant>`). What such a key stored from the instant on, or with no instant from the retirement a trusted key signed for it, counts for nothing.
- **Registry findings** in `keyTrust.findings`, which make the result invalid at position 0: `KEY_STATEMENT_INVALID`, `KEY_CLOSURE_INVALID` and `CHAIN_KEY_WINDOW_DRIFT` (a listed window or status that differs from the signed value).
- **`verdict` on every `verifyAuditExport` result**: `trusted`, `unanchored` or `failed` (`Verdict`), so a caller need not combine `valid` and `keyTrust.status` to know a pass rests on nothing pinned. `verdictOf(result)` computes it for any result carrying `valid` and a `keyTrust` report.
- `publicKeys` also takes the `/v1/verification-keys` body as served, `{ data: [...] }`, as the CLI's `--keys` and the MCP tool already did.
- **`keyTrust.status` says whether a pass is trusted** (`KeyTrustStatus`): `walked` only when at least one entry verified under an anchored key; `no_anchor` with no `trustAnchors`; `no_anchored_signature` when the walk ran but no entry verified under an anchored key. A pass on either of the last two is reported as `unanchored`. `settleKeyTrust(report, anchoredSignatures)` turns a walked report into `no_anchored_signature` for a verifier that counts its own signed entries.
- `CheckApplicability` gains `not_checked`: `optionalChecks.key_anchoring` is `not_checked` when `trustAnchors` were given but no entry reached the anchoring check, where it used to read `skipped_no_input`.
- **Walk primitives** for verifiers that read key statements: `computeKeyTrust`, `applyKeyTrust`, `reportKeyTrust`, `parseTrustAnchors`, `parseDistrustedKeys`, `spkiSha256`, `instantMs`, `KEY_STATEMENT_CTY`, `KEY_STATEMENT_KINDS` (`succession`, `closure` and `genesis`, typed `KeyStatementKind`), and the source adapters `keyStatementFromDumpRow`, `trustKeyFromDumpRow`, `keyStatementsFromExport` and `keyStatementsFromVerificationKeys`. Statements are walked in write order, never by an instant a statement signs. A key document's `createdAt` is unsigned and its holder can edit it, so it is never held against `distrustedKeys`: an edge out of a distrusted key never admits a key or keeps one reachable, though the statement still dates windows and, as a closure, ends a window. Only a dump row (`KeyStatementInput.source: 'dump'`) is held to its `created_at` against the key's cutoff. Where a document dates such a statement before the cutoff, the result is a `KeyTrustNote` in the new `keyTrust.notes`, which never fails a verdict, so an honest rotation away from a distrusted key passes pinned on its successor. A statement read twice is one row. A statement with no `createdAt`, or one that is not strict RFC 3339, is `KEY_STATEMENT_INVALID`.
- Failure codes for the other logs the dump verifier checks, so every verifier reports from one taxonomy: `CHECKPOINT_KEY_UNANCHORED`, `TENANT_READ_KEY_UNANCHORED`, `TENANT_CHECKPOINT_KEY_UNANCHORED`, `TENANT_READ_LEAF_UNSIGNED`, `TENANT_CHECKPOINT_UNSIGNED`, `CHECKPOINT_CLAIM_MISMATCH`, `TENANT_READ_CLAIM_MISMATCH`, `TENANT_CHECKPOINT_CLAIM_MISMATCH` (the claim signed inside a checkpoint, leaf or tree-head envelope does not decode or disagrees with the row) and `CHECKPOINT_UNSIGNED` (never reported by `verifyAuditExport`, which carries no checkpoint envelopes).
- `earliestKeyActivation(keys)` and `writtenWhileSigning(writtenAt, signingSince)`, the instant the install began signing and the test against it. `verifyChain` takes a `signingSince` option; omitted, it is derived from the keys it is given, and `null` switches off only the time half.
- **Accounting for a distrusted key's writes on a dump.** `computeKeyTrust` returns each distrusted key's `DistrustSpan` in `distrustSpans`. On a dump, a statement or entry that a distrusted key signed before a trusted key retired it, and whose dropping reopens no key, is listed as accounted for rather than as a finding. `verifyChain` lists such entries as an `AccountedEntry` (`code: 'CHAIN_SIGNED_BY_DISTRUSTED_KEY'`, `ACCOUNTED_ENTRY_CODE`) in the new `ChainResult.accounted`, with the signature state `accounted`; they count toward `valid` and not toward `verifiedEntries` or signed coverage. One stored after the retirement stays a finding, saying the key's private half is still in use. `chainOfScope(scopeId)` names a chain as the Server does (`record`, `admin`, `schema`). A distrusted key in a dump's registry that no trusted key has retired is `KEY_CLOSURE_INVALID`. Audit exports are unchanged: they keep failing such entries and statements.
- `KEY_STATEMENT_INVALID` on the admission of a trusted key whose endorser the walk does not trust, and on the admission of a key reached only through a signature this host cannot compute whose endorser is neither trusted nor reached that way.
- **`distrustedFrom` names the distrust entry a verifier lacks.** An API 2.0 Server lists a key its `VAULT_DISTRUSTED_KEYS` names with `distrustedFrom`, in an export's `signingKeyWindows` and on `/v1/verification-keys` (`SigningKeyWindow.distrustedFrom`, `TrustKeyInput.distrustedFrom`). A walk not given the same entry still fails on that window, but the finding now names the entry the Server applied instead of reading as a rewritten column. The field only changes wording: it never ends, opens or widens a window and never clears a finding.

### Fixed

- **A copied key-statement row is a no-op.** A dump row repeating an earlier row's signed payload counts once, at its first write, so a copied row no longer reads as a second admission or fails every dump. On a key document a copy stays a second statement.
- A retirement counts toward accounting for a distrusted key only when a trusted key signed it, so a key a forced closure cut off cannot retire a distrusted key and have that key's forgeries listed as accounted for. A later admission of a trusted key that the key itself signed is always a finding.
- The admission of a trusted key signed by a distrusted key from its cutoff on is no finding when it is that key's first admission. A later one stays a finding.
- Remedies no longer name a distrusted key as a pin. They suggest a dated `distrustedKeys` entry (`sha256:<key>@<instant>`) and say a pin on the key may stay beside it.
- **An unsigned entry where the install could not have written one is a break.** An entry with no `signingKeyId` used to pass as a `skipped` signature wherever it sat, so a writer holding no key could append an unsigned entry to a signed chain, or null a signed row's key id, and the chain still verified. It now fails the new `CHAIN_ENTRY_UNSIGNED` when an earlier entry in the same chain names a key, or when its `createdAt` is at or after the earliest `activatedAt` across the key set, retired keys included. With `trustAnchors`, activations signed by anchored keys' statements count too, so an export stripped of its windows is still held to the signed activation. Unsigned entries written before the install registered its first key (as dev and test installs run) stay a `skipped` signature with reduced coverage. Under `requireKeyId` or `requireSuppliedKeys`, such an entry reports `CHAIN_ENTRY_UNSIGNED` rather than `CHAIN_KEY_POLICY_VIOLATION`.
- **An all-zero signature on an entry that names a key fails `CHAIN_SIGNATURE_INVALID`.** It used to be graded `unsigned` and pass, or fail `CHAIN_KEY_POLICY_VIOLATION` under a key policy. `verifyChain` no longer produces the `unsigned` signature state; the member stays in the type.
- **An entry with no readable `createdAt` fails closed.** A missing, null or unparseable `createdAt` used to skip the key-window check, so nulling write times let entries signed by a distrusted key after its cutoff pass. Such an entry now fails `CHAIN_MALFORMED_ENTRY` wherever the check needs the time. A readable time is strict RFC 3339 (a `T`, an offset or `Z`, a real calendar date and time). A supplied key's `activatedAt` or `retiredAt` that is not RFC 3339 throws `TypeError` naming the key, one in an export's `signingKeyWindows` fails the entries under that key with `CHAIN_MALFORMED_ENTRY`, and `instantMs` no longer falls back to `Date.parse`. `writtenWhileSigning` returns true for a row with no readable time once `signingSince` is known.
- **Malformed rows are failure codes, not exceptions.** A null or retyped `payload` now fails `CHAIN_PAYLOAD_BINDING_MISMATCH`; an entry or `integrity` block that is not an object, or a `coseSign1` or `payloadHash` that is not a string, fails `CHAIN_MALFORMED_ENTRY`; a key with no key material is left out of the registry, so its entries fail `CHAIN_SIGNATURE_MISSING_KEY`; an entry position that is not a safe integer sorts last and fails `CHAIN_POSITION_GAP`. A dump statement row with no readable `created_at` or `subject_key_id` is `KEY_STATEMENT_INVALID`. A document with no `exportMetadata` object, or `entries` that is not an array, throws `TypeError` naming the shape.
- **A distrust cutoff is not a retirement.** A `distrustedKeys` instant earlier than a key's signed retirement used to be folded into `retiredAt`, so an entry written after it failed `CHAIN_KEY_EXPIRED` as postdating a retirement the key never had. The instant is now carried apart as `distrustCutoff`, `retiredAt` stays the signed retirement, and the entry still fails `CHAIN_KEY_EXPIRED`, worded as written after the `distrustedKeys` instant.
- `verifyAuditExport` throws `TypeError` for `distrustedKeys` without `trustAnchors`, as the dump verifier and both CLIs do, where it used to ignore them.
- The `no_anchor` detail says the result is not a trusted verdict.
- `verifyRfc9162Inclusion` returns false for a `leafIndex` or `treeSize` that is not a safe integer (NaN used to verify a proof as if it were leaf 0), and handles trees past 2^32 leaves.
- `exportMetadata.signingKeyStatements` given as an array is refused with a `TypeError` (`signingKeyStatements must be an object keyed by key id.`). It used to be read by index and filed under key ids `"0"`, `"1"`, and so on.

### Changed

- The conformance corpus is regenerated from API 2.0.0 and now includes a dump slice as well as the export slice.
- The runtime known-answer, algorithm and key-material checks apply to key statements as they do to entries. A statement signature carries exactly one COSE `alg` per algorithm (-8 for Ed25519, -7 for ES256).

## [1.5.0] - 2026-09-21

### Added

- **Offline agent-signature check.** `verifyAuditExport` takes `agentKeys`, the Ed25519 JWKs of agent ephemeral certs (the `publicKeyJwk` sent to `POST /v1/auth/oidc/cert`, also the `cnf.jwk` claim inside the `certJws`). Where an entry's signed payload carries a Server-validated `predicate.on_behalf_of.agent_signature` and its sealed cert thumbprint matches one of those keys, the signature is re-verified over the request-body hash. A signature that does not verify, or is sealed in a shape nothing can verify, fails the new `CHAIN_AGENT_SIGNATURE_INVALID`. Keys are matched only through the RFC 7638 thumbprint the entry signed. `verifyChain` takes the same input as an `agentKeys` registry (`buildAgentKeyRegistry`).
- `optionalChecks.agent_signature` reports whether that check ran, and `agentSignatures: { present, verified }` on the result counts the entries carrying an agent signature and those re-verified. Without `agentKeys` the check is `skipped_no_input` and verdicts are unchanged.
- Primitives for the same check: `extractAgentSignatureClaim`, `ed25519JwkThumbprint`, `ed25519JwkToSpki`, `verifyAgentSignature`, `AGENT_SIGNATURE_CONTEXT`.

### Fixed

- **Actor attribution is verified, not displayed on trust.** An export's `actorId`, `actorOwnerId` and `actorRole` are signature-covered in the COSE protected header, but nothing compared them against the row, so an export or dump row could be re-attributed to another actor and still verify. They are now cross-checked per entry, and a divergence fails the new `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`. An artifact with no actor columns, or an envelope from a Server that predates the claim, is reported `optionalChecks.actor_attribution: skipped_no_input`. `extractActorClaim` is exported.
- **A row copy of `on_behalf_of` or `traceparent` is bound to the signed entry.** A rewritten or added `on_behalf_of` block in an export entry's `payload` used to verify. When the row payload carries an object `on_behalf_of` or a W3C v00 `traceparent`, it must now equal what the entry signed, or the entry fails `CHAIN_PAYLOAD_BINDING_MISMATCH`. A row without them is not a mismatch.
- The conformance corpus is regenerated from API 1.8.0, with new vectors for actor attribution and agent signatures. The runner now passes the manifest's agent keys to the verifier; before, that vector ran with no keys and passed without executing the check.

### Changed

- `LICENSE` follows SDK License Template 1.9.
- The README lists every check the verifier runs, and the doc comments on `optionalChecks` no longer say the payload binding check is dump-only.

## [1.4.2] - 2026-09-10

### Changed

- **LICENSE section 6 names the ciphers this package line ships**: Ed25519 (EdDSA), ECDSA P-256 with SHA-256, HMAC-SHA-256, AES-256-GCM, HKDF-SHA-256 and SHA-256. The LICENSE file is the only shipped byte that moved.

## [1.4.1] - 2026-08-30

Documentation and packaging only. Verification behaviour is identical to 1.4.0.

### Added

- The README documents how to install the package.

### Changed

- Comments and documentation no longer point at resources outside this repository.

## [1.4.0] - 2026-08-07

### Fixed

- **A runtime that cannot compute an algorithm no longer reads as tamper.** With the OpenSSL FIPS provider active there is no EdDSA, so a FIPS-locked auditor verifying an intact Ed25519 chain got `0/N verified` and `CHAIN_SIGNATURE_INVALID` on every entry. Verification now checks a fixed known-answer signature to prove the runtime can compute the algorithm before dispatching. When it cannot, the outcome is `CHAIN_UNSUPPORTED_ALGORITHM` with `signature: 'unsupported'`; its detail names the FIPS provider and says to re-run on an unrestricted host. `valid` stays `false`, since an uncheckable chain is not a verified chain.
- **The refusal is recognised at key load as well as at verify.** With the provider active, a structurally valid Ed25519 key fails to load. A key that will not load is now classified from its SPKI AlgorithmIdentifier OID (`looksLikeEd25519Key`), so a host that refuses a key is distinguishable from bytes that are not a key. Garbage key material still reads as tamper on every host.
- The refusal is per algorithm: a FIPS provider carries ECDSA P-256, so an ES256 chain is expected to verify where an Ed25519 chain cannot. That expectation is reasoned from what the provider implements and has not been measured on a real FIPS host.

### Added

- **`looksLikeEd25519Key(spkiDer)`**, exported. Answers whether bytes declare themselves an Ed25519 key without asking `node:crypto` to load them. `@agledger/sdk` uses it for the same gate on the webhook path.
- **`runtimeCanCompute(keyAlgorithm)`** and **`describeUnsupportedAlgorithm(spkiBase64)`**, exported for consumers that build their own reports. `CHAIN_UNSUPPORTED_ALGORITHM` now covers two causes with different remedies (this build does not implement the algorithm, or this host refuses to compute it), and `describeUnsupportedAlgorithm` gives the right sentence for each.

### Changed

- `CHAIN_SIGNATURE_INVALID`'s remediation text no longer hardcodes "Ed25519".
- `CHAIN_UNSUPPORTED_ALGORITHM`'s remediation text names both causes and states that the result is not tamper evidence.

### Documentation

- The README documents `algorithmByName`, `runtimeCanCompute` and `describeUnsupportedAlgorithm`. `runtimeCanCompute` takes a `KeyAlgorithm` from this build's own table, so go through `algorithmByName('Ed25519')` first; passing the string `'ed25519'` returns `false`.

### Packaging

- Source maps are no longer published, since they pointed at sources that are not in the tarball.
- `bugs` added to package.json so npm links issues to the right repo.

## [1.3.0] - 2026-08-07

### Added

- **`CHAIN_KEY_NOT_YET_ACTIVE`**, for an entry written before its signing key's activation. Both directions of the key-window check used to report `CHAIN_KEY_EXPIRED`; it now means only the retirement side. `FailureCode` gains a member, so an exhaustive switch over it needs the new case. Verdicts are unchanged.

## [1.2.0] - 2026-08-05

Signing-algorithm agility: this build now verifies ES256 chains. Ed25519 chains verify exactly as in 1.1.1.

### Added

- **ES256 verification.** A verification key whose SPKI commits to P-256 is verified with ECDSA SHA-256 over raw `r||s` signatures (the COSE wire encoding). Both `-7` (ES256) and the RFC 9864 `-9` (ESP256) header code points are accepted; a DER-encoded signature does not verify. Dispatch binds to the trusted key material, never the header. Other algorithms (ES384, ES512, ES256K) still fail closed as `CHAIN_UNSUPPORTED_ALGORITHM`.
- **`verifySignatureBytes`.** The key-dispatched form of `verifyEd25519Bytes`; returns `false` for anything the build cannot compute.

### Changed

- The conformance corpus is regenerated from API 1.3.4 and gains ES256 vectors, including a valid ES256 signature under an EdDSA header, which reads as `CHAIN_ALG_MISMATCH`.

## [1.1.1] - 2026-08-05

### Fixed

- **An empty-string `signingKeyId` is no longer treated as unsigned.** Only `null` is; any other value must resolve in the key registry and otherwise fails `CHAIN_SIGNATURE_MISSING_KEY`. Before, a tampered `signingKeyId: ""` row skipped its signature check.

## [1.1.0] - 2026-08-05

Forward-compatibility for a future signing-algorithm change. Ed25519 chains verify as in 1.0.4; non-Ed25519 and tampered inputs are classified differently, all of it fail-closed.

### Changed

- **`CoseVerifyOutcome` gains `'alg-mismatch'` and `'unsupported-key-algorithm'`.** Algorithm dispatch binds to the trusted verification key, never the protected header, and the header `alg` must equal the key's expectation. A mismatch is `'alg-mismatch'`, a tamper-class result. A key whose algorithm this build cannot compute is `'unsupported-key-algorithm'`, which callers must fail closed on.
- **`verifyEd25519Bytes` refuses non-Ed25519 keys**, returning `false`, so a P-256 key can no longer "verify" a signature no conformant EdDSA verifier accepts.
- The all-zero unsigned sentinel is evaluated after algorithm resolution, at the key's expected signature length.
- **`decodeCoseSign1` rejects untagged COSE_Sign1** (the leading byte must be `0xd2`, CBOR tag 18).
- **`FailureCode` gains `CHAIN_ALG_MISMATCH`, `CHAIN_UNSUPPORTED_ALGORITHM` and `CHAIN_SIGNING_KEY_DRIFT`**; `SignatureOutcome['state']` gains `'unsupported'`. `CHAIN_UNSUPPORTED_ALGORITHM` is always `valid: false`.
- **`ReceiptVerifyOutcome` gains `'unsupported-algorithm'`** for a transparency-service key this build cannot compute.
- **An all-zero signature on an entry that claims a signing key now fails `CHAIN_KEY_POLICY_VIOLATION`** under `requireKeyId` or `requireOutOfBandKeys`.

### Added

- **Signed-kid binding (`CHAIN_SIGNING_KEY_DRIFT`).** The signature-covered `kid` is cross-checked against the row's `signingKeyId`, so a rewritten column that points verification at a different registry key fails.
- **Registry algorithm cross-check.** `VerificationKey` gains an optional `algorithm` field; when present it is compared against what the key material commits to, and a mismatch fails `CHAIN_ALG_MISMATCH`.
- `resolveKeyAlgorithm` and `extractKid` exported, with the `KeyAlgorithm` type. Ed25519 accepts COSE alg `-8` (EdDSA) and the RFC 9864 `-19` interchangeably.

## [1.0.4] - 2026-08-03

### Changed

- `cborg` moves from 5.1.1 to 6.1.1, still an exact pin. Verification output is byte-identical.

## [1.0.3] - 2026-07-16

No change to verification or the wire format.

## [1.0.2] - 2026-06-29

### Changed

Documentation wording.

## [1.0.1] - 2026-06-22

### Added

- **`VerifyExportResult.unsignedProjectionFields`**: surfaces the export's own `verificationGuide.unsignedFields`, the per-entry display fields (such as `actorDisplayName`, `actorOwnerType`, `humanReadableLabel`) that are not covered by the signature. Empty when the export carries no such guidance. Signed attribution remains the `actorOwnerId`/`actorId` UUID. `RecordAuditExportInput` gains the optional `verificationGuide` field. No change to chain verification or the wire format.

## [1.0.0] - 2026-06-20

### Changed

- **1.0.0 GA.** Aligns with the AGLedger API v1.0.0 GA. No code, API-surface or wire-format changes from 0.1.9. The offline verifier contract is now stable and follows SemVer.
- `LICENSE` is updated to the AGLedger SDK license template v1.5.

Releases before 1.0.0 are listed on npm (https://www.npmjs.com/package/@agledger/verify-core?activeTab=versions).
