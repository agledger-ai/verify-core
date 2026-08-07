# Changelog

All notable changes to `@agledger/verify-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.4.0] - 2026-08-07

### Fixed

- **A runtime that cannot compute an algorithm no longer reads as tamper.** With the OpenSSL FIPS provider active there is no EdDSA, so Node's `verify()` throws `ERR_OSSL_EVP_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE` for a perfectly good Ed25519 key. That throw was caught and returned as `false`, which is indistinguishable from a signature that genuinely did not verify, so a FIPS-locked auditor verifying an intact chain got `0/N verified` and `CHAIN_SIGNATURE_INVALID` on every entry: the most alarming thing this package can say, about a chain that is fine (agents#113).

  Verification now proves runtime capability before dispatching, by checking a fixed known-answer signature for the algorithm. When the runtime refuses, the outcome is `CHAIN_UNSUPPORTED_ALGORITHM` with `signature: 'unsupported'`, whose detail names the FIPS provider as the cause and says to re-run on an unrestricted host. Still fail-closed: an uncheckable chain is not a verified chain, and `valid` stays `false`. The known-answer vectors are fixed, self-contained bytes, so nothing in the audited export can influence whether a signature failure is reported as "not checked".

  The refusal is per algorithm, not blanket: a FIPS provider carries ECDSA P-256, so an ES256 chain is expected to verify on a host where an Ed25519 chain cannot. That is what makes the distinction worth drawing rather than failing everything. Note this expectation is reasoned from what the provider implements and is not yet measured on a real FIPS host; `crypto.setFips(true)` without a provider loaded is a degraded state that breaks unrelated primitives and cannot establish it either way.

### Added

- **`runtimeCanCompute(keyAlgorithm)`** and **`describeUnsupportedAlgorithm(spkiBase64)`**, exported for consumers that build their own reports. `CHAIN_UNSUPPORTED_ALGORITHM` now covers two causes with different remedies (this build does not implement the algorithm, versus this host refuses to compute it), and `describeUnsupportedAlgorithm` produces the right sentence for each. Both are safe to call without having established that a gap exists: `describeUnsupportedAlgorithm` says so plainly for a key that verifies fine, rather than asserting a refusal that did not happen, and `runtimeCanCompute` fails closed on a `KeyAlgorithm` that is not one of this build's own table entries without memoizing that answer.

### Changed

- **`CHAIN_SIGNATURE_INVALID`'s remediation text no longer hardcodes "Ed25519".** It has been wrong since ES256 verification landed in 1.2.0, and it compounded the bug above by naming the one algorithm that had not been computed.
- **`CHAIN_UNSUPPORTED_ALGORITHM`'s remediation text** now names both causes, and states outright that the result is not tamper evidence.

### Changed

- **Remediation text no longer uses em-dashes.** `suggestion(code)` is read by auditors through the CLI, `@agledger/verify`, and the MCP tool; the text is now punctuated with periods and colons. Thirteen codes changed wording only, no verdict or code changed. The Python verifier mirrors these strings exactly and moved with them, and a test in `sdk-python` now fails if the two ever diverge again.

### Documentation

- **The README documents `algorithmByName`, `runtimeCanCompute`, and `describeUnsupportedAlgorithm`**, which 1.4.0 exports but 1.4.0's README never mentioned. It also states the one thing about them that is not guessable: `runtimeCanCompute` takes a `KeyAlgorithm` from this build's own table, so a caller must go through `algorithmByName('Ed25519')` first. Passing the string `'ed25519'` fails closed and returns `false`, which reads exactly like "this host cannot compute Ed25519" on a host that computes it fine.

### Packaging

- **Source maps are no longer published.** `dist/**/*.map` shipped with `sources` pointing at `../src/*.ts` and no `sourcesContent`, and `src/` is not in the tarball, so they resolved to nothing. Ten dead files removed.
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
