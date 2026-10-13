# Changelog

All notable public changes to `@charter-agreement-protocol/signer` are
documented here.

## [Unreleased]

### Added

- Add `SECURITY.md`, `CODE_OF_CONDUCT.md` and `CONTRIBUTING.md`, following
  the Elixir signer's reporting policy, Contributor Covenant and
  contribution practices, with this package's commands and checks. Include
  all three documents in the npm package.
- Real Node crypto tests mint Ed25519 and ML-DSA-65 genesis descriptors.
  Browser bundle tests use the workshop's crypto shim to mint Ed25519. On
  that bundle an ML-DSA-65 request reaches the key and then fails the
  wrong-key guard with `signing_failed`; the shim verifier reports
  `algorithm_unsupported_on_substrate` for an ML-DSA-65 artifact.
- Snapshot regression tests keep the existing non-empty decoded-key and
  string-type checks intact. CI runs the suite on Linux with Node 24.8.0
  and the current Node 24 line.

### Breaking

- Rename the handle error from `invalid_handle` to `invalid_key_handle`.
  Migration: update error comparisons and exhaustive switches to the new
  string. The result shape is unchanged.

### Changed

- Set package and lockfile versions to 0.3.0 and update the workshop badge.
- Correct the 0.2.1 release note's unshipped capability and profile claim.
  README now describes the tests that run: this repository has no Elixir
  cross-check, and the Elixir signer, which pins this repository at a public
  commit and runs this package's suite, does not compare the two signers'
  output, so no parity is established. This package has no telemetry.
- An options argument that is not an object (`null`, a number, an array,
  a bare algorithm string) returns `invalid_input` with
  `code: "invalid_type"` before either key callback, as the Elixir signer
  treats options that are neither a map nor a keyword list. It used to fall
  back to the defaults silently.
- Copy the claims at entry too, so a key callback cannot change what is
  framed after its snapshot.
- `npm run build` removes `dist/` first, so a local pack cannot ship stale
  modules. CI also typechecks and builds the workshop site.
- Copy the caller's chain arrays and acceptance/termination issuing view
  at entry, before the first `await`. Key callbacks cannot change the
  context used by the producers or post-sign verification.
- Resolve the algorithm before calling `keyIdentity`. Absent, `undefined`
  and `null` select Ed25519; supported explicit values are `Ed25519` and
  `ML-DSA-65`. Other values, including non-strings, return `invalid_input`
  with `code: "algorithm_unsupported"` without using the handle.
- Use `@charter-agreement-protocol/verifier` `^0.6.0` (locked to 0.6.0).
  Fixtures hash real bytes, use canonical revision JSON, and count real
  Ed25519 signing calls.

### Migration from verifier 0.5 to 0.6

- Producer build failures now surface as `invalid_input` with
  `code: "signing_input_invalid"`, replacing schema-specific codes.
  Termination claims must omit `extensions` and other extra members.
- Digests must be canonical base64url SHA-256 values. Revision text must
  be canonical JSON, and each revision must name two distinct parties.
  Descriptor public keys must use canonical encodings and the correct
  byte length. Mixed party histories and unknown claims now reject.
- Chain views require all four string arrays, including explicit empty
  arrays. Malformed artifact lists return `invalid_type` through the
  verifier's producers. The signer's missing-view guard continues to
  return `signing_input_invalid`.
- Direct verifier callers must pass verified predecessor facts with
  retained signed `lineage` to `verifyDescriptor`; `{ digest, claims }`
  alone no longer works. Genesis calls must omit a predecessor.
- Direct verification can now apply limits and profiles to context as
  well as the artifact, and unavailable crypto reports
  `algorithm_unsupported_on_substrate`. This signer's options expose only
  the emission algorithm, and its custody guard maps a failed signature
  check to `signing_failed`.
- `signAcceptance` and `signTermination` verify the signed artifact against
  `view.descriptorCompacts`, which must hold only the signing party's
  descriptor history. Verifier 0.6.0 rejects a list that mixes both parties'
  histories, so such a call now fails with `verification_failed`. The
  workshop page passed both parties' descriptors and is corrected.

## [0.2.2] — October 6, 2026

### Changed

- Update the build compiler from TypeScript 5.9.3 to 7.0.2 (`^7.0.2`),
  removing the `~5.9.0` pin; update `@types/node` to 26.6.4 (`^26.6.4`).
- Reconcile README and workshop documentation with verifier 0.5.0 and signer
  0.2.2. Make the Node quickstart executable, document development and trusted
  publisher staging, and clarify the workshop's chain/receipt verification,
  artifact kinds, refusal ordering, and Node-only ML-DSA support.
- Observed on October 6, 2026: `npm ci`, `typecheck`, all 18 tests, `build`,
  `typecheck:web`, `build:site`, and `npm pack --dry-run` pass.
  `diff -ru` against the TypeScript 5.9.3 baseline reports no differences:
  all four emitted JavaScript and declaration files are byte-identical.
  `npm outdated --json` returns `{}`.

## [0.2.1] — 2026-09-24

Dependency-line release: this package now tracks the published verify
line - `@charter-agreement-protocol/verifier` `^0.5.0` (resolved 0.5.0).
No API change: verifier 0.5.0 added consumer-side surface only (the
capability probe, the signature registry identity, the descriptor
timestamp floor, the 104-case corpus); the producer surface this package
delegates to is unchanged. Typecheck strict, 18/18 tests against the
resolved 0.5.0. ~~The producer-side capability alignment (mirrored
`capabilities()` with refuse-before-mint, declared minting metadata,
profile-bound signing) is the next feature release on this line.~~
Corrected in 0.3.0: that alignment did not ship in 0.2.2, and this release
did not add signer capability metadata, profile options or telemetry.

## [0.2.0] — 2026-09-17

### Changed

- **The R1–R3 honest-signer refusals now run pre-sign** (previously
  deferred to post-sign verification with mislabeled errors; the `refused`
  error was unreachable): `signAcceptance` / `signTermination` run the
  verifier package's refusal checks after framing, before the key signs.
  Breaking within 0.x: `signTermination`'s view requires `chain`,
  `signAcceptance` enforces the guards over the `chain` it previously
  ignored, and `signReceipt` requires its issuing view (the reference
  takes a context, never none).
- Post-sign verification failures return the bare `verification_failed`
  (the reference vocabulary); malformed claims are rejected pre-sign as
  `invalid_input` through the producer claims gate — no claim-shape defect
  burns a key operation.
- **All protocol logic is delegated to the verifier package's producer
  surface (`^0.4.0`)**: framing, the claims gate, the refusal guards, and
  assembly; this package keeps custody only (atomic snapshot, sign
  callback, wrong-key guard, post-sign verification, closed errors).

## [0.1.x] — 2026-09-14

- Initial public releases: one signing function per artifact kind, the
  key-handle contract with the atomic `keyIdentity` snapshot, the
  wrong-key guard, and post-sign verification through
  `@charter-agreement-protocol/verifier`.
