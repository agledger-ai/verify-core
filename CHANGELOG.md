# Changelog

All notable changes to `@agledger/verify-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-09-30

This release targets AGLedger API 2.0 and reads nothing older. 1.6.0 was never published; its changes are part of this release.

### Breaking

- **The org_admin_reads tree is RFC 9162.** API 2.0 builds the cross-party read log as an RFC 9162 §2.1 SHA-256 tree, the construction SCITT Receipts use: `leaf_hash` is hex(sha256(0x00 || cose_sign1)), a node is sha256(0x01 || L || R) over the bytes each hex hash denotes, a root over n leaves splits at the largest power of two below n, and the empty tree is sha256(""). `merkleRoot` and `verifyInclusion`, which built the old hex-text tree that duplicated its last leaf, are removed. In their place `orgReadLeafHash(coseSign1)`, `orgReadMerkleRoot(leafHashesHex)` and `verifyOrgReadInclusion(leafHashHex, leafIndex, treeSize, pathHex, rootHex)`, the last the RFC 9162 §2.1.3.2 audit-path walk the proof route serves. A value that is not 64 lowercase hex characters is refused (`orgReadMerkleRoot` returns null, `verifyOrgReadInclusion` false) rather than hashed, and so is a `leafIndex` or `treeSize` that is not a safe integer.
- **Out-of-band keys are supplied keys.** A key fetched from the Server's `/v1/verification-keys` comes from the same database a key-registry attacker writes to, so "out of band" promised an independence the option never gave. `requireOutOfBandKeys` is `requireSuppliedKeys` (on `verifyAuditExport` and `verifyChain`), `KeySource` `'out-of-band'` is `'supplied'`, `keyProvenance.outOfBand` is `keyProvenance.supplied`, and `OutOfBandKeyEntry` is `SuppliedKeyEntry`. Behaviour is unchanged: they say where a key came from. What makes a key trusted is the new `trustAnchors`.
- **`OptionalCheck` gains `key_anchoring`**, so every `optionalChecks` record carries one more member, and `verifyAuditExport` results carry `keyTrust`.
- **The signed-kid check runs before the registry algorithm check.** An entry whose `signingKeyId` column disagrees with its signed kid, and whose key's declared algorithm contradicts its material, now reports `CHAIN_SIGNING_KEY_DRIFT` rather than `CHAIN_ALG_MISMATCH`, the order the engine applies.

### Added

- **Key anchoring (`trustAnchors`).** A vault key is trusted only when signed key statements link it to a key the verifier pinned out of band, the rule API 2.0 applies to its own key registry. `verifyAuditExport` takes `trustAnchors` (`sha256:<hex>` SPKI digests) and walks the statements the export carries (`exportMetadata.signingKeyStatements`, plus any `statements` on supplied keys) from them. An entry signed by a key the walk does not anchor fails the new `CHAIN_SIGNING_KEY_UNANCHORED`; each anchored key is held to the window its statements sign, compared at millisecond precision as the engine compares it; a key reached only through a statement this host cannot compute is `undecided` and its entries `CHAIN_UNSUPPORTED_ALGORITHM`. The walk is the engine's two-pass rule: successions link keys forward and, through a key's sole admission, back; closures by a reached key end windows, a forced closure voids every edge out of its key, and an edge stored after a key's first closure is void. Without `trustAnchors` (an empty array is the same as none) the result says so: `keyTrust.status` is `no_anchor` and `optionalChecks.key_anchoring` is `skipped_no_input`.
- **`distrustedKeys`**, the verifier-side mirror of the Server's `VAULT_DISTRUSTED_KEYS` (`sha256:<hex>`, optionally `@<RFC 3339 instant>`): what such a key stored from the instant on, or with none from the retirement a trusted key signed for it, counts for nothing in the walk.
- **Registry findings** from the walk, in `keyTrust.findings`, which make the result invalid at position 0: `KEY_STATEMENT_INVALID` (a statement that does not verify, disagrees with what it is filed under, touches no anchored key, or was signed after its signer's closure or its subject's admission), `KEY_CLOSURE_INVALID` (a retired key with no counting closure, or a closure that should not count), and `CHAIN_KEY_WINDOW_DRIFT` (a listed window or status that differs from the signed value).
- **`keyTrust.status` says whether a pass is trusted** (`KeyTrustStatus`): `walked` only when at least one entry verified under a key the anchors reach; `no_anchor` with no `trustAnchors`; and `no_anchored_signature` when the walk ran but no entry verified under an anchored key, as for an export of unsigned history pinned on any key at all. A pass on either of the last two is not a trusted verdict, every surface reports it as `unanchored`, and its `detail` says so. `settleKeyTrust(report, anchoredSignatures)` turns a walked report into `no_anchored_signature` for a verifier that counts its own signed entries, as a dump verifier does.
- `CheckApplicability` gains `not_checked`: `optionalChecks.key_anchoring` is `not_checked` when `trustAnchors` were given but no entry reached the anchoring check (the chain broke first, or no entry was signed), where it used to read `skipped_no_input` as if no anchors had been given.
- **Walk primitives** for every verifier that reads key statements: `computeKeyTrust`, `applyKeyTrust` (marks a `KeyRegistry` with each key's `trust`, a `KeyTrustState` of `anchored`, `unanchored` or `undecided`, and its signed window, which `verifyChain` then grades), `reportKeyTrust`, `parseTrustAnchors`, `parseDistrustedKeys`, `spkiSha256`, `instantMs`, `KEY_STATEMENT_CTY`, `KEY_STATEMENT_KINDS` (the statement kinds `succession`, `closure` and `genesis`, typed `KeyStatementKind`), and the source adapters `keyStatementFromDumpRow` and `trustKeyFromDumpRow` (a dump's `vault_key_statements.ndjson` and `vault_signing_keys.ndjson`), `keyStatementsFromExport` and `keyStatementsFromVerificationKeys`. A dump carries each statement's write time and is walked in write order; a key document does not, so its statements are ordered by the instants they sign, with a closure after any admission that signs the same instant, which agrees with write order for any document the Server served (the README says what that order cannot catch, and what a dump's write order adds only when the dump came from the Server). Because a leaked key chooses the instants it signs, a document walk voids every edge out of a distrusted key whatever it signs, and keeps its closures.
- Failure codes for the other logs the dump verifier checks, so every verifier reports from one taxonomy: `CHECKPOINT_KEY_UNANCHORED`, `TENANT_READ_KEY_UNANCHORED`, `TENANT_CHECKPOINT_KEY_UNANCHORED` (the engine's `checkpoint_key_unanchored` and `leaf_key_unanchored`), and `TENANT_READ_LEAF_UNSIGNED`, `TENANT_CHECKPOINT_UNSIGNED` (the engine's `leaf_signature_missing` and the read log's `checkpoint_unsigned`).
- `CHECKPOINT_CLAIM_MISMATCH`, `TENANT_READ_CLAIM_MISMATCH` and `TENANT_CHECKPOINT_CLAIM_MISMATCH` in the failure taxonomy, the engine's vault `checkpoint_claim_mismatch` and the read log's `leaf_claim_mismatch` and `checkpoint_claim_mismatch`: the claim signed inside a checkpoint, leaf or tree-head envelope does not decode, or says something the row's columns do not. A verifier builds the comparison from `extractChainClaim` and `decodePredicate`.
- `CHECKPOINT_UNSIGNED` in the failure taxonomy, for a verifier that checks checkpoint envelopes: an unsigned checkpoint written at or after the same instant. The per-record export carries no checkpoint envelopes, so `verifyAuditExport` never reports it.
- `earliestKeyActivation(keys)` and `writtenWhileSigning(writtenAt, signingSince)`, the instant the install began signing and the test against it, so every verifier applies the same rule. `verifyChain` takes a `signingSince` option; omitted, it is derived from the keys it is given, and `null` switches off only the time half.

### Fixed

- **An unsigned entry where the install could not have written one is a break.** An entry with no `signingKeyId` used to pass as a `skipped` signature wherever it sat, so a writer holding no key could append an unsigned entry to a signed chain, or a signed row could have its key id nulled, and the chain still verified. It now fails the new `CHAIN_ENTRY_UNSIGNED` when an earlier entry in the same chain names a key, or when its `createdAt` is at or after the earliest `activatedAt` across the key set, retired keys included. That is the rule the engine applies as `signature_missing`. On the export path the key set is every key the verifier holds plus every window in `exportMetadata.signingKeyWindows`, with a caller-supplied window taking precedence for its key as it already does for the key-window check. With `trustAnchors`, every activation an anchored key's statements sign counts as well, and the earliest of all of them stands: the windows are the export's unsigned word, so an export stripped of them, or with them moved later, is still held to the signed activation. Unsigned entries written before the install registered its first key, which is how dev and test installs run, stay a `skipped` signature and reduced coverage, as before. With no activation time anywhere (an older export, or caller keys without `activatedAt` and no export windows), only the signed-before half applies. An unsigned entry with no readable `createdAt` once signing began fails `CHAIN_MALFORMED_ENTRY` (see below). Every structural check still runs first, so a tampered unsigned entry reports its own code. Under `requireKeyId` / `requireSuppliedKeys`, such an entry now reports `CHAIN_ENTRY_UNSIGNED` rather than `CHAIN_KEY_POLICY_VIOLATION`, since it is a finding about the chain whatever the policy; an unsigned entry from before the first key still fails the policy.
- **An all-zero signature on an entry that names a key fails `CHAIN_SIGNATURE_INVALID`.** Without a key policy it was graded `unsigned` and passed, and under `requireKeyId` / `requireSuppliedKeys` it failed `CHAIN_KEY_POLICY_VIOLATION`. The engine writes a key id only beside a signature it made with that key and fails this shape as an invalid signature; the verifier now agrees, with or without a policy. `verifyChain` no longer produces the `unsigned` signature state; the member stays in the type.

- **An entry with no readable `createdAt` fails closed.** A missing, null or unparseable `createdAt` skipped the key-window check and read an unsigned entry as history from before signing began, so nulling the write times let entries signed by a distrusted key after its cutoff pass, and let an unsigned single-entry chain pass pinned with no unsigned count. The engine writes `created_at` on every row, so wherever the walk needs it (the entry's key carries a window, or the entry is unsigned once the key set dates the start of signing) such an entry now fails `CHAIN_MALFORMED_ENTRY`. `writtenWhileSigning` returns true for a row with no readable time once `signingSince` is known, so a checkpoint, read-log leaf or tree head stripped of its time fails its unsigned code rather than reading as early history.
- **Malformed rows are failure codes, not exceptions.** A null or retyped `payload` threw out of `buildPredicateForRow` and now fails `CHAIN_PAYLOAD_BINDING_MISMATCH`; an entry or `integrity` block that is not an object, or a `coseSign1` or `payloadHash` that is not a string, fails `CHAIN_MALFORMED_ENTRY`; a key with no key material (a null `public_key` or `signingPublicKeys` value) is left out of the registry, so its entries fail `CHAIN_SIGNATURE_MISSING_KEY`; a null or retyped `algorithm`, window edge, `anchoredFrom` or signing-key window is read as absent; an entry position that is not a safe integer sorts last and fails `CHAIN_POSITION_GAP`. A dump statement row with no readable `created_at` or `subject_key_id` is `KEY_STATEMENT_INVALID` rather than a `TypeError`. A document with no `exportMetadata` object, or `entries` that is not an array, throws `TypeError` naming the shape.
- **A distrust cutoff is not a retirement.** A `distrustedKeys` instant earlier than a key's signed retirement was folded into the key's `retiredAt`, so an entry written after it failed `CHAIN_KEY_EXPIRED` as postdating a retirement the key never had. The walk now carries the instant apart as `distrustCutoff` on the trust entry and on the key `applyKeyTrust` returns, `retiredAt` stays the signed retirement, and the entry still fails `CHAIN_KEY_EXPIRED`, worded as written after the instant `distrustedKeys` (`VAULT_DISTRUSTED_KEYS` on the Server) gives for the key.
- `verifyAuditExport` refuses `distrustedKeys` without `trustAnchors` with a `TypeError`, as the dump verifier and both CLIs do, where it ignored them.
- The `no_anchor` detail says the result is not a trusted verdict.
- `verifyRfc9162Inclusion` returns false for a `leafIndex` or `treeSize` that is not a safe integer (NaN used to verify a proof as if it were leaf 0), and walks a tree past 2^32 leaves rather than wrapping its index.
- `exportMetadata.signingKeyStatements` given as an array is refused with the `TypeError` any other malformed statement map gets (`signingKeyStatements must be an object keyed by key id.`). An array passed the object check, so its statements were read by index and filed under key ids `"0"`, `"1"`, and so on.

### Changed

- The conformance corpus is regenerated from agledger-api 2.0.0 (`e690979c`), and this repo now carries its dump slice as well as the export slice: the walk and the org-read tree are checked against the statements, leaves and signed tree heads the engine wrote. Every export vector passes as its manifest expects, as does every dump vector that pins `trustAnchors`.
- The runtime known-answer, algorithm and key-material checks apply to key statements as they do to entries, with one difference the engine also makes: a statement signature carries exactly one COSE `alg` per algorithm (-8 for Ed25519, -7 for ES256).

## [1.5.0] - 2026-09-21

### Fixed

- **Conformance corpus regenerated from the tagged 1.8.0 engine** (`apiGitSha 3948cc68`, the `v1.8.0` commit), replacing a corpus generated at API 1.3.4. The export slice goes from 23 to 32 vectors and the dump slice from 12 to 18, and the additions cover this release's own work: `export/actor-attribution-mismatch.json` and `dump/chain-actor-attribution-mismatch` both expect `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`, and `export/agent-signature-invalid.json` expects `CHAIN_AGENT_SIGNATURE_INVALID`. The runner now maps the manifest's `agentKeysFile` to the verifier's agent-key input; without it that vector ran with no agent keys, reported `skipped_no_input`, passed, and failed the suite on a check that never executed.

- **Actor attribution is verified, not displayed on trust.** An audit export's own verification guide names `actorDisplayName`, `actorOwnerType` and `humanReadableLabel` as unsigned display projections and tells the auditor that the attribution to rely on is the `actorId`/`actorOwnerId` UUID. Those two, and `actorRole`, are signature-covered in the COSE protected header (CWT_Claims label 15, private label -65539), and nothing compared them against it: an export or dump row could be re-attributed to another actor, changing nothing else, and still verify with out-of-band keys. They are now cross-checked per entry, and a divergence fails the new `CHAIN_ACTOR_ATTRIBUTION_MISMATCH`. An artifact that carries no actor columns, or an envelope from an engine that predates the claim, is reported `optionalChecks.actor_attribution: skipped_no_input` rather than passed. `extractActorClaim` is exported for callers that want the signed value themselves.

- **A row copy of `on_behalf_of` or `traceparent` is bound to the signed entry.** The payload binding check compares the signed predicate with the one rebuilt from the row payload, and both sides leave out these two envelope extensions, so a rewritten or added `on_behalf_of` block in an export entry's `payload` (the copy a reader sees: the delegating identity, the cert, the agent signature) still verified. When the row payload carries an object `on_behalf_of` or a W3C v00 `traceparent`, the only shapes the engine lifts into the signed entry, it must now equal what the entry signed, or the entry fails `CHAIN_PAYLOAD_BINDING_MISMATCH`. Any other shape under those keys is ignored, as the engine ignores it. A row without them is not a mismatch, because the engine also signs an `on_behalf_of` built from the request's authentication that never reaches the row; that identity stays held to the actor columns by the OIDC-actor check. Every live and corpus export still verifies.

### Added

- **Offline agent-signature check.** `verifyAuditExport` takes `agentKeys`, the Ed25519 JWKs of agent ephemeral certs (the `publicKeyJwk` sent to `POST /v1/auth/oidc/cert`, also the `cnf.jwk` claim inside the `certJws`). Where an entry's signed payload carries an engine-validated `predicate.on_behalf_of.agent_signature` and its sealed cert thumbprint matches one of those keys, the signature is re-verified over the request-body hash, so the cert holder's signature is proven without taking the Server's word for it. A signature that does not verify, or is sealed in a shape nothing can verify, fails the new `CHAIN_AGENT_SIGNATURE_INVALID`. Keys are matched only through the RFC 7638 thumbprint the entry signed, so a key for another cert is never checked against it. `verifyChain` takes the same input as an `agentKeys` registry (`buildAgentKeyRegistry`).
- `optionalChecks.agent_signature` reports whether that check ran, and `agentSignatures: { present, verified }` on the result counts the entries carrying an agent signature and those re-verified. Without `agentKeys` the check is reported `skipped_no_input` and verdicts are unchanged.
- Primitives for the same check: `extractAgentSignatureClaim`, `ed25519JwkThumbprint`, `ed25519JwkToSpki`, `verifyAgentSignature`, `AGENT_SIGNATURE_CONTEXT`.

### Changed

- `LICENSE` follows SDK License Template 1.9.
- The conformance corpus is regenerated at API 1.8.0. Same vectors and expected codes as the 1.7.0 corpus, and all pass.
- Verified against live API 1.8.0 output: record-lifecycle entries that sign the internal state (`state`, `previousState`, `newState`) beside the display status, the `AUTH_KEY_ROTATED` platform entry, and cert-signed and delegated creates all verify, and a rewritten internal state fails the payload binding check. No verification change was needed for them.
- The README lists every check the verifier runs, and the doc comments on `optionalChecks` no longer say the payload binding check is dump-only.

## [1.4.2] - 2026-09-10

### Changed

- **LICENSE section 6 names the ciphers this package line ships**: Ed25519 (EdDSA), ECDSA P-256 with SHA-256, HMAC-SHA-256, AES-256-GCM, HKDF-SHA-256 and SHA-256. X25519 is gone from the list with the federation encryption key the engine no longer has. The LICENSE file is the only shipped byte that moved.

## [1.4.1] - 2026-08-30

Documentation and packaging only. Verification behaviour is identical to 1.4.0,
and the two releases verify the same inputs to the same verdicts.

### Added

- The README documents how to install the package.

### Changed

- Comments and documentation no longer point at resources outside this repository.
- Refreshed the lockfile to clear a development-only advisory in a transitive
  dependency. Nothing in the shipped runtime changed.

## [1.4.0] - 2026-08-07

### Fixed

- **A runtime that cannot compute an algorithm no longer reads as tamper.** With the OpenSSL FIPS provider active there is no EdDSA, so Node's `verify()` throws `ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` for a perfectly good Ed25519 key. That throw was caught and returned as `false`, which is indistinguishable from a signature that genuinely did not verify, so a FIPS-locked auditor verifying an intact chain got `0/N verified` and `CHAIN_SIGNATURE_INVALID` on every entry: the most alarming thing this package can say, about a chain that is fine (agents#113).

  Verification now proves runtime capability before dispatching, by checking a fixed known-answer signature for the algorithm. When the runtime refuses, the outcome is `CHAIN_UNSUPPORTED_ALGORITHM` with `signature: 'unsupported'`, whose detail names the FIPS provider as the cause and says to re-run on an unrestricted host. Still fail-closed: an uncheckable chain is not a verified chain, and `valid` stays `false`. The known-answer vectors are fixed, self-contained bytes, so nothing in the audited export can influence whether a signature failure is reported as "not checked".

  **The refusal happens at KEY LOAD, not only at verify.** With the provider active, `createPublicKey` throws "Failed to read asymmetric key" for a structurally perfect Ed25519 SPKI, so `resolveKeyAlgorithm` returned `'unparseable'` and `verifyCoseSign1` short-circuited to `'invalid'` one branch above the capability gate: the whole mechanism was unreachable on the one path it was written for, and the first candidate build reported `CHAIN_SIGNATURE_INVALID` on an intact chain exactly as the published one did. A key that will not load is now classified from its SPKI AlgorithmIdentifier OID (`looksLikeEd25519Key`, no OpenSSL involved), so "this host will not touch this key" is distinguishable from "these bytes are not a key". The narrowness is the point: only bytes that structurally declare Ed25519, on a host that cannot compute Ed25519, get the benefit. Garbage key material still reads as tamper on every host, which is also what keeps this verifier and the Python one agreeing byte for byte.

  The refusal is per algorithm, not blanket: a FIPS provider carries ECDSA P-256, so an ES256 chain is expected to verify on a host where an Ed25519 chain cannot. That is what makes the distinction worth drawing rather than failing everything. Note this expectation is reasoned from what the provider implements and is not yet measured on a real FIPS host; `crypto.setFips(true)` without a provider loaded is a degraded state that breaks unrelated primitives and cannot establish it either way.

### Added

- **`looksLikeEd25519Key(spkiDer)`**, exported. Answers whether bytes DECLARE themselves an Ed25519 key, read from the OID without asking node:crypto to load them, which is the only question available on a host that refuses the load. `@agledger/sdk` uses it for the same gate on the webhook path, so the two packages cannot drift on what counts as an Ed25519 key.
- **`runtimeCanCompute(keyAlgorithm)`** and **`describeUnsupportedAlgorithm(spkiBase64)`**, exported for consumers that build their own reports. `CHAIN_UNSUPPORTED_ALGORITHM` now covers two causes with different remedies (this build does not implement the algorithm, versus this host refuses to compute it), and `describeUnsupportedAlgorithm` produces the right sentence for each. Both are safe to call without having established that a gap exists: `describeUnsupportedAlgorithm` says so plainly for a key that verifies fine, rather than asserting a refusal that did not happen, and `runtimeCanCompute` fails closed on a `KeyAlgorithm` that is not one of this build's own table entries without memoizing that answer.

### Changed

- **`CHAIN_SIGNATURE_INVALID`'s remediation text no longer hardcodes "Ed25519".** It has been wrong since ES256 verification landed in 1.2.0, and it compounded the bug above by naming the one algorithm that had not been computed.
- **`CHAIN_UNSUPPORTED_ALGORITHM`'s remediation text** now names both causes, and states outright that the result is not tamper evidence.

### Changed

- **Remediation text no longer uses em-dashes.** `suggestion(code)` is read by auditors through the CLI, `@agledger/verify`, and the MCP tool; the text is now punctuated with periods and colons. Thirteen codes changed wording only, no verdict or code changed. The Python verifier mirrors these strings exactly and moved with them, and a test in `sdk-python` now fails if the two ever diverge again.

### Documentation

- **The README documents `algorithmByName`, `runtimeCanCompute`, and `describeUnsupportedAlgorithm`**, which 1.4.0 exports but 1.4.0's README never mentioned. It also states the one thing about them that is not guessable: `runtimeCanCompute` takes a `KeyAlgorithm` from this build's own table, so a caller must go through `algorithmByName('Ed25519')` first. Passing the string `'ed25519'` fails closed and returns `false`, which reads exactly like "this host cannot compute Ed25519" on a host that computes it fine.

### Packaging

- **Source maps are no longer published.** `dist/**/*.map` shipped with `sources` pointing at `../src/*.ts` and no `sourcesContent`, and `src/` is not in the tarball, so they resolved to nothing. Ten dead files removed. The build no longer emits them at all, so no shipped `.js` or `.d.ts` carries a `sourceMappingURL` comment pointing at a map the tarball does not contain (agents#114).
- **`bugs` added to package.json**, so npm links issues at the right repo.

## [1.3.0] - 2026-08-07

### Added (published API: widened union)

- **`CHAIN_KEY_NOT_YET_ACTIVE`**, for an entry written BEFORE its signing key's activation. Both directions of the temporal key-window check previously reported `CHAIN_KEY_EXPIRED`, so a consumer branching on the code was told "expired" about a key that had not started yet and would go looking at rotation or retention when the real condition is a backdated entry or clock skew. Those are different investigations, and the activation direction is the security-relevant one. `CHAIN_KEY_EXPIRED` now means only the retirement side, and both explanations were rewritten to say which direction they describe (agents#112).

  `FailureCode` gains a member, so an exhaustive switch over it needs the new case. Verification verdicts are unchanged: an entry that failed before still fails, only the code on the activation side differs.

## [1.2.0] - 2026-08-05

Signing-agility wave 2: this build now verifies ES256 chains. Engines older than api R2 are unaffected; Ed25519 chains verify byte-identically to 1.1.1.

### Added

- **ES256 verification.** A verification key whose SPKI commits to P-256 now dispatches to ECDSA with SHA-256 over raw `r||s` signatures (`ieee-p1363`, the COSE wire encoding), matching what the engine emits behind its ES256 opt-in. Both the original `-7` (ES256) and the RFC 9864 fully-specified `-9` (ESP256) header code points are accepted. A DER-encoded ECDSA signature does not verify: the wire is raw `r||s` only. Dispatch still binds to the trusted key material, never the header, and every other algorithm in the table (ES384, ES512, ES256K) still fails closed as `'unsupported-key-algorithm'` / `CHAIN_UNSUPPORTED_ALGORITHM`.
- **`verifySignatureBytes`.** The key-dispatched generalization of `verifyEd25519Bytes`: resolves the algorithm from the SPKI and verifies under it, returning `false` for anything the build cannot compute.

### Changed

- **Conformance corpus regenerated from engine 1.3.4 @ `ed3369ab`** (the api R2 signing-agility build) and re-pinned via `CORPUS-LOCK.json`. The export slice gains the ES256 wave: `valid-es256` (real ES256 engine output, must pass), `es256-signature-invalid`, and `es256-header-alg-mismatch` (a valid ES256 signature under an EdDSA header must read as `CHAIN_ALG_MISMATCH`, tamper class, not an upgrade notice).

## [1.1.1] - 2026-08-05

### Fixed

- **An empty-string `signingKeyId` is no longer treated as the unsigned-mode marker.** Only a true `null` is; any other value, including the `""` no engine emits, must resolve in the key registry and fails `CHAIN_SIGNATURE_MISSING_KEY`. Previously a truthiness shortcut let a tampered `signingKeyId: ""` row skip its signature check and count as `skipped` coverage. Same defect class as the harness-side fix in the 1.1.0 review pass, swept across every verification surface.

## [1.1.0] - 2026-08-05

The verifier forward-compatibility floor: this release prepares every verification path for a future signing-algorithm change without emitting or accepting anything new itself. Legitimate Ed25519 chains verify byte-identically to 1.0.4. What changes is how non-Ed25519 and tampered inputs are classified, and all of those changes are fail-closed.

### Changed (published API: widened unions, stricter classification)

- **`CoseVerifyOutcome` gains `'alg-mismatch'` and `'unsupported-key-algorithm'`.** Algorithm dispatch now binds to the TRUSTED verification key (the SPKI AlgorithmIdentifier), never to the protected header: at dispatch time the signature has not been checked, so the header `alg` is attacker-controlled input. The header value is asserted equal to the key's expectation. A mismatch (including a missing `alg`, an unassigned value, or any MAC label) is `'alg-mismatch'`, a tamper-class result: one flipped header byte reads as forgery, never as an upgrade notice. A key whose algorithm this build cannot compute is `'unsupported-key-algorithm'`, which callers must fail closed on.
- **`verifyEd25519Bytes` refuses non-Ed25519 keys.** Node's `verify(null, ...)` silently computes ECDSA/SHA-256 for EC keys, so a P-256 key could "verify" a signature no conformant EdDSA verifier accepts (the engine-side signing guard is api#1089). It now returns `false` for any non-Ed25519 key.
- **The all-zero unsigned sentinel is evaluated after algorithm resolution, at the key's expected signature length.** A zero fill of a different algorithm's length is no longer misread as unsigned or as forged.
- **`decodeCoseSign1` rejects untagged COSE_Sign1** (leading byte must be `0xd2`, CBOR tag 18), matching the engine's decoder. Producer and offline verifier previously disagreed on what a COSE_Sign1 is.
- **`FailureCode` gains `CHAIN_ALG_MISMATCH`, `CHAIN_UNSUPPORTED_ALGORITHM`, and `CHAIN_SIGNING_KEY_DRIFT`**; `SignatureOutcome['state']` gains `'unsupported'`. `CHAIN_UNSUPPORTED_ALGORITHM` is always `valid: false` and breaks the chain.
- **`ReceiptVerifyOutcome` gains `'unsupported-algorithm'`** for a transparency-service key this build cannot compute; previously that shape would have surfaced as a false `'signature-invalid'`.
- **An all-zero signature on an entry that CLAIMS a signing key now fails `CHAIN_KEY_POLICY_VIOLATION` under `requireKeyId` / `requireOutOfBandKeys`.** An auditor who demanded signed entries no longer counts a zeroed signature as green.

### Added

- **Signed-kid binding (`CHAIN_SIGNING_KEY_DRIFT`).** The signature-covered `kid` (protected header label 4) is cross-checked against the row's `signingKeyId` column, mirroring the engine's `signing_key_drift` check (#893). A rewritten column that points verification at a different registry key now fails even when the substituted signature verifies.
- **Registry algorithm cross-check.** `VerificationKey` gains an optional `algorithm` field (the registry row's declared algorithm, e.g. `vault_signing_keys.algorithm`). When present it is compared against what the key material actually commits to; a registry row that lies about its own key fails `CHAIN_ALG_MISMATCH`. The declared string never selects the verification code path.
- **`resolveKeyAlgorithm` and `extractKid`** exported, with the `KeyAlgorithm` type. Ed25519 accepts COSE alg `-8` (EdDSA) and the RFC 9864 fully-specified `-19` interchangeably, so a future producer moving to `-19` verifies on this floor.
- Conformance corpus refreshed from engine 1.3.4 (was 0.26.5), including new `key-substitution-kid-drift` and registry-lie vectors.

## [1.0.4] - 2026-08-03

Dependency and test only. No verification, signing, or wire-format change; verification output is byte-identical.

### Changed

- **`cborg` moved from 5.1.1 to 6.1.1**, still an exact pin. 5.1.1 predated the 5.1.4 fix that emits shortest-form floats under `rfc8949EncodeOptions` (RFC 8949 4.2.1), so the old pin was frozen on non-conformant float encoding rather than on conformant output. It also left this package on a different encoder than the engine that produces the envelopes it verifies (`agledger-api` runs `cborg` 5.1.8). Neither difference could change this package's output, for the reason the new test below asserts.
- Dependabot no longer ignores `cborg` updates. The exact pin stays (a given release is byte-reproducible); the new invariance test is the gate on taking a new one.

### Added

- **`encoder-version-invariance` test.** Replays every COSE_Sign1 envelope in the conformance corpus, rebuilds the Sig_structure this package encodes, and asserts the encoded bytes contain no CBOR map and no major-type-7 item. Those are the only two constructs whose deterministic encoding has changed across cborg versions (float shortest-form in 5.1.4, major-type-7 map key ordering in 6.0.0). A second check holds the encode surface to its single call site. Together they enforce, rather than assert in a comment, why the encoder version is not load-bearing here.

## [1.0.3] - 2026-07-16

Tooling only. No verification, signing, or wire-format change; the shipped dist is behavior-identical.

### Changed

- Upgraded the TypeScript devDependency to `^7.0.2`. Build, typecheck, tests, and publint/attw all pass under 7.0.2.
- Refreshed the lockfile to in-range latest dev tooling. `cborg` stays pinned at 5.1.1 for reproducibility.

## [1.0.2] - 2026-06-29

### Changed

- Docs only: removed em-dashes from the README prose and the package.json description (cross-repo #98 writing-style sweep). Rewrote each sentence rather than swapping the glyph. No verification, signing, or wire-format change.

## [1.0.1] - 2026-06-22

### Added

- **`VerifyExportResult.unsignedProjectionFields`** (cross-repo #96 / api#769) — surfaces the export's self-described `verificationGuide.unsignedFields`: per-entry fields that are UNSIGNED display projections (e.g. `actorDisplayName`, `actorOwnerType`, `humanReadableLabel`) resolved at export time and NOT covered by the COSE_Sign1 signature. Empty when the export carries no such guidance. Signed attribution remains the `actorOwnerId`/`actorId` UUID. `RecordAuditExportInput` gains the optional `verificationGuide` field it's read from. Purely additive; no change to chain verification, signing, or the wire format.

## [1.0.0] - 2026-06-20

### Changed

- **1.0.0 GA.** Version promoted to 1.0.0 to align with the AGLedger API v1.0.0 GA and the published SDK/CLI line (`@agledger/sdk`, `@agledger/cli` at 1.0.x). No code, API-surface, or wire-format changes from 0.1.9 — the COSE_Sign1 / in-toto verification core, the canonical `FailureCode` set, and all exports are byte-for-byte the same. This is a stability signal: the offline verifier contract is now considered stable and will follow SemVer from here.

### Changed

- **License re-sync.** `LICENSE` is now a verbatim copy of the canonical AGLedger SDK license template **v1.5**: §7 trademarks trimmed to **AGLedger + Settlement Signal (pending)** (removed the retired "Agentic Ledger" / AOAP claims), §6 export language modernized to ENC §740.17(b)(1) mass-market self-classification, and §1 carries the no-inspection / no-training / no-usage-data representation.
- No code changes; republished so the distributed tarball carries the corrected license text.

## [0.1.8] - 2026-06-04

No functional change to the verifier. Documentation accuracy and test-coverage hardening.

### Changed

- **README accuracy.** Cross-repo links (`@agledger/cli`, `@agledger/mcp-server`, `@agledger/verify`) now use absolute `https://github.com/agledger-ai/<repo>` URLs instead of relative paths that 404 on npm and standalone GitHub. The failure-taxonomy example cites a real code (`CHAIN_LINK_BROKEN`) instead of the non-existent `CHAIN_PREVIOUS_HASH_MISMATCH`. Added an "Out-of-band keys" section documenting both accepted `publicKeys` shapes — the `Record<keyId, base64SpkiDer>` map and the `OutOfBandKeyEntry[]` array form returned by `client.verificationKeys.list().data`.
- **Broadened no-network test scan.** The offline-verifier network-import check (`fetch`, `node:http`/`https`/`net`/`tls`/`dgram`/`dns`) now covers the `tests/` directory in addition to `src/`, so an accidental network call in a test is caught.

## [0.1.7] - 2026-06-04

No functional change to the verifier. Release-pipeline hardening (canary-validated):

### Changed

- **`actions/attest`** replaces the deprecated `actions/attest-sbom` for the signed CycloneDX SBOM attestation (predicate-type `https://cyclonedx.org/bom`).
- **publint + attw publish gate.** `npm run lint:pkg` (`publint --strict` + `attw --pack`) now runs in the release workflow and via `prepublishOnly`, so a broken `exports`/`types` map can't publish.
- **Dependabot** added (`.github/dependabot.yml`): weekly grouped github-actions + npm bumps.

## [0.1.6] - 2026-06-04

No functional change to the verifier. Release-pipeline hardening, validated end-to-end by this release:

### Changed

- **Signed CycloneDX SBOM attestation.** The per-release SBOM is now published as a signed, verifiable attestation (`actions/attest-sbom`) rather than only an ephemeral build artifact.
- **Explicit `npm publish --provenance`** (fail-closed) instead of relying on npm's auto-attach default.
- **Concurrency guard** on the release workflow so two tags pushed in quick succession can't race into a double-publish.

## [0.1.5] - 2026-06-04

Republish with provenance (CI diagnostic — isolating an OIDC trusted-publishing issue affecting the sibling repos). No functional change.

## [0.1.4] - 2026-06-03

No functional change to the verifier. This is the first release published from CI with **build provenance**.

### Changed

- **Published via npm trusted publishing (OIDC).** Releases are now built and published by this repo's GitHub Actions `release.yml` on a version tag — no long-lived npm token. npm attaches a Sigstore provenance attestation automatically; verify with `npm audit signatures`. A CycloneDX SBOM is generated per release.
- **`@agledger/verify-core` is now its own source-of-truth repo** ([agledger-ai/verify-core](https://github.com/agledger-ai/verify-core)) with a standalone build/test gate, rather than a squashed mirror of the monorepo.

## [0.1.3] - 2026-05-29

Closes [agledger-agents#84 (F-731)](https://github.com/agledger-ai/agledger-agents/issues/84) and threads the F-732 signature-state change.

### Added

- **Binding-integrity on the export path.** `verifyAuditExport` now runs the denormalised-payload vs signed-predicate cross-check (the export's own verificationGuide step 4) whenever an entry carries `recordId`/`entryType`/`payload` (engine ≥ v0.26.x). An export whose human-readable `payload` was rewritten while `coseSign1` stayed intact now fails `CHAIN_PAYLOAD_BINDING_MISMATCH`; previously this was dump-only and the export path silently trusted the denormalised view. Validated end-to-end against a live engine v0.26.4 — `buildPredicateForRow` reconstructs the signed predicate exactly, so valid exports pass (`payload_binding: applied`). `AuditExportEntryInput` gains `recordId`/`entryType`/`payload`.

### Changed

- **New `not-checked` signature state.** A failure that short-circuits before the signature check now reports `signature: 'not-checked'` instead of overloading `'skipped'` — which also stops failed entries from polluting `signatureCoverage.skipped`. `'skipped'` keeps its meaning: a chain-intact entry with no signing key (engine booted keyless). The export result's `EntryVerificationResult.signature` now references the canonical `SignatureOutcome['state']` instead of a duplicated union.

## [0.1.2] - 2026-05-28

Closes [agledger-agents#77 (F-698)](https://github.com/agledger-ai/agledger-agents/issues/77) and tightens the audit-independence claim on the temporal axis.

### Changed

- `verifyAuditExport({ publicKeys })` now accepts the natural `OutOfBandKeyEntry[]` shape returned by `client.verificationKeys.list().data` in addition to the compact `Record<keyId, base64SpkiDer>` map. Previously, passing the array form silently fell through to the export's embedded keys (`keyProvenance.outOfBand === 0` with `valid: true`) — a false independence claim that defeated the whole point of supplying OOB keys. Now: arrays are normalized at the boundary; wrong shapes (string, missing fields, non-object entries) throw `TypeError`. Fail-closed by design.
- `signingKeyWindows` from the export's own (untrusted) `exportMetadata` no longer overrides activation/retirement windows supplied on out-of-band entries. A compromised export could otherwise hide a retirement by setting `retiredAt: null` and silently pass entries signed by a key the auditor knows to be retired — F-698 on the temporal axis. When the OOB caller carries `activatedAt`/`retiredAt` on their entry, the export's window for that key is skipped entirely; when the OOB caller did not carry a window, the export's window still feeds `key_temporal` (most auditors trust the engine's published key-rotation log even when they bring their own key catalogue).

### Added

- `OutOfBandKeyEntry` type exported — the structural shape of a single OOB key in array form. Re-exported through `@agledger/sdk/verify` and `@agledger/verify`.

## [0.1.1] - 2026-05-28

Wire-parity follow-on to the verifier consolidation: the export path now exercises two of the three input-gated checks that were previously dump-only.

### Changed

- `verifyAuditExport` now reads the new export wire fields (engine ≥ v0.26.x, agledger-api commit a7eec8e4): per-entry `createdAt`, `actorOidcIss`, `actorOidcSub`, `actorOidcSynthesized`, and `exportMetadata.signingKeyWindows`. When present, `optionalChecks.oidc_actor` and `optionalChecks.key_temporal` now flip from `skipped_no_input` to `applied` on the export path, exercising `CHAIN_OIDC_ACTOR_MISMATCH` and `CHAIN_KEY_EXPIRED` against the live wire.
- `optionalChecks.payload_binding` stays `skipped_no_input` on the export path by design — the export deliberately re-projects the row payload from the signed bytes (anti-DBA-injection), so binding-integrity remains dump-only (`@agledger/verify`).
- Older exports without the new fields still verify cleanly; the optional checks stay `skipped_no_input` as before.

### Added

- `SigningKeyWindow` type exported for consumers that construct exports synthetically.

## [0.1.0] - 2026-05-27

Initial release. Shared offline verification core for the AGLedger SDK, CLI, MCP server, and `@agledger/verify` dump verifier. COSE_Sign1 (RFC 9052) hash-chain walk with Ed25519 verification, canonical SCREAMING_SNAKE `FailureCode` taxonomy, one dependency (`cborg`), no network.
