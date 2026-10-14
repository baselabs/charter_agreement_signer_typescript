# Changelog

All notable public changes to `@charter-agreement-protocol/signer` are
documented here.

## [Unreleased]

### Breaking

- `signAcceptance` and `signTermination` now take `(claims, keyHandle, chain,
  opts)`. The verifier derives context from that chain; `revisionText` and
  `descriptorCompacts` are removed from the signer input. Migration:

  ```ts
  // Before
  await signAcceptance(claims, keyHandle, { revisionText, descriptorCompacts, chain }, opts);
  // Now
  await signAcceptance(claims, keyHandle, chain, opts);
  await signTermination(terminationClaims, keyHandle, chain, opts);
  ```

- The holder's own descriptor key is checked before signing. A wrong kid,
  public key, or key algorithm returns
  `{ ok: false, error: "refused", code: "signing_key_mismatch" }`.
  `signing_key_invalid` maps to `invalid_key_handle`. For otherwise valid
  descriptor claims, an absent or null successor predecessor, a valid predecessor
  supplied to a genesis, broken signed lineage, or digest aliases that disagree
  with the reverified lineage return `invalid_input`/`descriptor_chain_invalid`.
  A non-object predecessor, both digest aliases absent, or missing, null, empty,
  or non-string lineage return `invalid_input`/`invalid_type`. Throwing reads also
  return `invalid_type`. History excluded by a profile or requiring unavailable
  crypto preserves the profile or substrate code.
- Context, claims/context mismatches, profile exclusions, and compact size
  limits reject before the signing callback. Missing or malformed context
  types return `invalid_input`/`invalid_type`; malformed sets preserve the
  verifier's code, including `compact_invalid`. `verification_failed` now
  means only that `finishSigning` rejected what preparation approved.
- Unavailable crypto returns the top-level
  `{ ok: false, error: "algorithm_unsupported_on_substrate" }` before signing,
  including an ML-DSA-65 request on the browser bundle.
- Rename `invalid_handle` to `invalid_key_handle`. Update error comparisons
  and exhaustive switches; the result shape is unchanged. Add the new substrate
  error and refusal code to exhaustive handling.
- Options must be absent or a plain object containing only `algorithm`,
  `limits`, `profile`, and (for `signDescriptor`) `predecessor`. Unknown keys,
  non-plain objects, and unreadable getters return `invalid_input`/`invalid_type`.
  Malformed limits and profiles preserve `invalid_limits` and `invalid_profile`.
  Previously, a misspelled option key silently fell back to Ed25519.

### Added

- `signDescriptor` accepts the verifier's `DescriptorPredecessor` as
  `opts.predecessor`, with retained signed `lineage`, for successor descriptors.
- All four functions accept verifier `limits` and `profile` options. Limits
  include the final compact and context artifacts and also apply to the custody
  guard and completion. Profiles check the new artifact and retained context.
- `signReceipt` accepts bare revision text as well as a chain view. With a
  bare revision, the custody guard checks the snapshot key and verifier facts
  list `signature` in `not_verified`.
- Export `SigningOptions` and `DescriptorOptions`. Real-key tests cover
  Ed25519 and ML-DSA-65 successors and pre-sign refusals, with zero signing calls
  asserted on rejection. The browser bundle test runs the complete workshop flow.
- Include `SECURITY.md`, `CODE_OF_CONDUCT.md`, and `CONTRIBUTING.md` in the
  npm package with this package's reporting and contribution practices.
- Run the shared Elixir signer table from `b211f3c`, copied byte for byte with
  a SHA-256 check. All 118 rows use real seed keys and compare result shapes,
  codes, snapshot counts, and custody counts. Twelve Ed25519 successes match
  exact compacts; five ML-DSA-65 successes pass public verification. The explicit
  list of unexpressible rows is empty, and the run count is asserted. Eight
  shared requests or contexts needing ML-DSA-65 refuse before browser custody.

### Changed

- Delegate preparation and completion to verifier 0.7.0's `prepareSigning`
  and `finishSigning`; remove the signer's context derivation,
  producer calls, assembly calls, and choice of post-sign verification function.
- Use the frozen verifier 0.7.0 build at `a06673c`. Its preparation corpus uses
  the public input shapes, and signing plans can only be made through
  `prepareSigning`. The signer already uses that path.
- Accept signature bytes from any JavaScript realm, including Buffer and plain
  `Uint8Array`. Ed25519 snapshot keys with noncanonical y coordinates, no curve
  point, x = 0 with the sign bit set, or small order return `invalid_key_handle`.
  Invalid descriptor claim keys can fail earlier with `signing_input_invalid`.
  The verifier checks option values before either key callback. Sparse profile
  algorithm lists return `invalid_input`/`invalid_profile`; nonfinite or
  explicitly undefined limit values return `invalid_input`/`invalid_limits`.
- Structurally copy claims, context, limits, profile, and predecessor before
  the first `await`, including Proxy-backed plain objects and repeated objects.
  Copies contain fresh plain objects and arrays. Option scalars retain
  `undefined` and nonfinite numbers for the verifier to check. Class instances,
  other non-JSON values, cycles, and throwing getters return
  `invalid_input`/`invalid_type`.
  Array copies do not call subclass constructor hooks.
- Copy iteratively and stop at the caller's JSON byte, depth, member, item,
  and string limits with `invalid_input`/`limit_exceeded` before either callback.
  Context lists also stop at the artifact item limit. The verifier checks
  immutable context text under artifact byte limits.
- Resolve limits, then profile, then algorithm, before taking the key snapshot.
  Absent, `undefined`, and `null` algorithms select Ed25519. Explicit values are
  `Ed25519` and `ML-DSA-65`; others return `invalid_input`/`algorithm_unsupported`
  before either callback. The snapshot checks only a non-empty string kid and
  a string public key; the verifier checks key encoding and shape.
- Keep version 0.3.0 and the workshop badge. Builds remove stale library output;
  CI typechecks and builds the workshop on Linux with Node 24.8.0 and Node 24.
- SECURITY.md uses GitHub private vulnerability reporting. Evidence descriptions
  name the checks that run; this signer has no telemetry.
- For acceptance and termination, the caller's profile covers the claimed
  revision, the signing party's own descriptor history, and the new artifact.
  The rest of the set is checked under the full default profile. A receipt's
  profile covers the whole retained set; a descriptor's covers its predecessor
  history.

### Migration from CAP 0.4 to 0.5

- Revisions must name two distinct parties from different descriptor histories.
  Replace fixtures that use one descriptor for both roles with two real parties.
  Chain views supply explicit `revisions`, `acceptances`, `descriptors`, and
  `terminations` arrays, including empty lists.

### Migration from verifier 0.5 to 0.6

- Producer build failures surface as `invalid_input`/`signing_input_invalid`.
  Termination claims omit `extensions` and other extra members.
- Digests are canonical base64url SHA-256 values and revision JSON is canonical.
  Descriptor keys use canonical encodings with the selected algorithm's byte
  length. Mixed party histories and unknown claims reject.
- Direct verifier callers pass retained signed `lineage` in predecessor facts
  to `verifyDescriptor`; `{ digest, claims }` alone is insufficient. Genesis
  calls omit the predecessor. This signer exposes that predecessor in options.
- Profiles and limits can reject context as well as the new artifact.

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
resolved 0.5.0. Corrected in 0.3.0: 0.2.2 did not add signer capability metadata,
profile options, or telemetry.

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
