# @charter-agreement-protocol/signer

Holder-side companion signer for the
[Charter Agreement Protocol](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
(CAP) — the TypeScript sibling of the Elixir
[charter_agreement_signer](https://hex.pm/packages/charter_agreement_signer).

**CAP verifies; it never authorizes. This signer signs; it never takes
custody.** You keep the key (HSM, OS keychain, key server) behind a handle
with two callbacks. The signer resolves limits, profile, and algorithm, copies
claims and context at entry, and takes one atomic `keyIdentity` snapshot.
The verifier's `prepareSigning` checks framing, claims, context, profile,
limits, and the holder's own descriptor key before the callback signs.
The signer checks the signature against the snapshot public key, then calls
`finishSigning` to assemble and verify under the retained context and settings.

## Install

```console
npm install @charter-agreement-protocol/signer@^1.0.0
```


Release submissions use npm's staged publishing workflow. A staged version
becomes publicly installable only after owner approval. During release review,
maintainers can use `npm stage download <stage-id>` and install that tarball.

Version **1.0.0** requires Node >= 24.8.0 and
`@charter-agreement-protocol/verifier` `^0.7.0 || ^1.0.0`, for its pre-sign API.
Both compatibility lines are checked. The registry lock pins published 0.7.0;
`reference.json` records the verifier 1.0 commit and exact staged archive integrity.
Compatibility does not extend the verifier's security-maintenance policy. Once
1.x is approved, update existing 0.7 locks to the maintained 1.x line.

## Quickstart

This runnable Ed25519 example keeps the private key in a Node `KeyObject`.
For an HSM, OS keychain, or remote key server, replace the handle's callbacks
with your custodian's key identity and signing operations.

```js
import { signDescriptor } from "@charter-agreement-protocol/signer";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyBase64url = publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64url");

const handle = {
  // ONE atomic snapshot — the kid and public key cannot disagree.
  keyIdentity() {
    return { kid: "my-key-001", publicKey: publicKeyBase64url }; // base64url raw public key
  },
  // The holder's job: sign the exact message bytes with the held key.
  sign(message) {
    return nodeSign(null, message, privateKey); // Buffer is a Uint8Array
  },
};

const result = await signDescriptor(
  {
    protocol_revision: 2,
    descriptor_number: 1,
    verification_keys: [
      { key_id: "my-key-001", algorithm: "Ed25519", public_key: publicKeyBase64url, status: "active" },
    ],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: new Date().toISOString(),
  },
  handle,
);

if (!result.ok) throw new Error(JSON.stringify(result));
console.log(result.result.descriptor); // Post-verified compact JWS
```

For ML-DSA-65 artifacts pass `{ algorithm: "ML-DSA-65" }` as the options
argument with `protocol_revision: 3` claims (pure ML-DSA per RFC 9964, the
empty context — your handle signs the exact message bytes as with Ed25519).

An absent, `undefined` or `null` algorithm selects Ed25519. Explicit
algorithms are `Ed25519` and `ML-DSA-65`; any other value returns
`invalid_input` with `code: "algorithm_unsupported"` before either key
callback runs.

## API

| Export | What it does |
|---|---|
| `signDescriptor(claims, handle, opts?)` | Signs a genesis or successor Party Descriptor; successors require `opts.predecessor` |
| `signReceipt(claims, handle, context, opts?)` | Signs a Receipt against a chain view or bare revision text |
| `signAcceptance(claims, handle, chain, opts?)` | Signs an Acceptance using the context the verifier derives from the chain |
| `signTermination(claims, handle, chain, opts?)` | Signs a Termination using the context the verifier derives from the chain |
| `SigningOptions`, `DescriptorOptions`, `ChainView`, `KeyHandle`, `KeySnapshot`, `SignError`, `SignResult` | Public TypeScript contracts |

A `ChainView` contains four string arrays: `{ revisions, acceptances,
descriptors, terminations }`. Pass all four, including explicit empty arrays.
Acceptance and termination use this chain directly. The verifier derives the
claimed revision and the holder's own descriptor history from its verified
contents. The signer copies claims at entry, before awaiting a key callback.
Claims copies contain fresh plain JSON objects and arrays, strings, finite
numbers, booleans, and null. Repeated objects are copied separately. Non-JSON
claims, cycles, and throwing reads return `invalid_input`/`invalid_type`.
Chain context and predecessor use their defined members with ordinary property
reads, and retained artifact lists get fresh arrays. Valid members are immutable
text; invalid member values stay opaque for the verifier.

Claims copies use an iterative traversal guarded by the verifier's maximum
supported JSON bounds, rather than the caller's limits. Values beyond those
maximums return `invalid_input`/`signing_input_invalid`. Smaller claims reach
`prepareSigning`, which owns all checks under caller limits, including final
compact size. Context list copies retain enough entries to exceed every
supported artifact item limit, letting the verifier return its own result.
Predecessor lineage has no signer item limit. The verifier checks immutable
artifact text under artifact byte limits, separately from parsed claims' string
limits.

Migration from the previous issuing view:

```ts
// Before
await signAcceptance(claims, handle, { revisionText, descriptorCompacts, chain }, opts);
// Now
await signAcceptance(claims, handle, chain, opts);
await signTermination(terminationClaims, handle, chain, opts);
```

For a successor descriptor, pass the verifier's `DescriptorPredecessor` facts
with retained signed `lineage`. The signing key must match an active key in
the predecessor:

```ts
import { verifyDescriptor } from "@charter-agreement-protocol/verifier";

const previous = verifyDescriptor(genesisCompact);
if (!previous.ok) throw new Error(previous.code);
const next = await signDescriptor(successorClaims, handle, { predecessor: previous.facts });
```

For a receipt against bare revision text, the verifier checks the receipt's
claims against that revision. The revision names no signing key, so the signer
uses its snapshot for the custody guard; receipt verification reports
`signature` in `not_verified`. A chain-backed receipt checks the key against
the issuing party's descriptor keys in the holder's own view.

`opts` is absent or an object with known own keys only: `algorithm`, `limits`,
and `profile`, plus `predecessor` for `signDescriptor`. Another root shape, an
unknown own key, or a throwing getter returns `invalid_input` with
`code: "invalid_type"`. Defined members use ordinary property reads, once at
entry, including inherited and nonenumerable members. Class instances and
`Map` objects work where the verifier accepts their properties; Map entries
are not option properties.

`limits` is the verifier's `Partial<Limits>` and `profile` is its `Profile`.
The signer reads only their defined shape. Invalid values stay opaque for the
verifier's synchronous checks; they are not recursively copied by the signer.
Limits are checked before profile, algorithm, and the key snapshot. Malformed
values, including bigint, symbol, and boxed numbers, retain the verifier's
`invalid_limits` or `invalid_profile` result. Sparse algorithm lists return
`invalid_profile`; nonfinite or explicitly undefined limit values return
`invalid_limits`. A list longer than the algorithm registry cannot be a valid
unique subset, so its invalid length reaches the verifier without reading its
entries. The verifier's copy failures are also returned unchanged.
Limits bound the final compact, including signature bytes, and
every context artifact read; raised limits also apply to assembly and the
custody guard. Profiles can restrict `algorithms` and/or
`revisions: { min, max }`; an omitted axis keeps the full supported range.
An EdDSA-only profile, an ML-DSA-44/87-only profile, or revisions 1..1 excludes
every artifact this signer emits. Exclusions return `algorithm_outside_profile`
or `revision_outside_profile`.

<a id="profile-scope"></a>

For acceptance and termination, the caller's profile covers the claimed
revision, the signing party's own descriptor history, and the new artifact.
The rest of the set is checked under the full default profile. For receipts,
the profile covers the new artifact and the whole retained set. For descriptors,
it covers the new artifact and predecessor history.

Errors are closed:

| Result error | Meaning |
|---|---|
| `invalid_input`, with `code` | The verifier rejected claims, context, limits, or profile, or options were invalid |
| `invalid_key_handle` | The snapshot callback failed, its shape was malformed, or the verifier returned `signing_key_invalid` |
| `refused`, with `code: "signing_refused"` | The claims contradict the holder's own verified view (R1–R3) |
| `refused`, with `code: "signing_key_mismatch"` | The kid, public key bytes, or key algorithm does not match the holder's own descriptor key |
| `algorithm_unsupported_on_substrate` | The runtime cannot verify the selected algorithm or a context artifact |
| `signing_failed` | The callback failed, returned a malformed signature, or failed the wrong-key guard |
| `verification_failed` | `finishSigning` rejected what preparation approved |

Every failure has `ok: false`. Only `invalid_input` and `refused` carry `code`.
The signing callback can return a Buffer or any `Uint8Array`, including one
from another JavaScript realm. The verifier rejects Ed25519 public keys with
noncanonical y coordinates, no curve point, x = 0 with the sign bit set, or
small order as `invalid_key_handle` when they are snapshot keys. Descriptor
claims containing such keys can fail earlier with `signing_input_invalid`.
All pre-sign rejections leave the `sign` callback untouched; the atomic key
snapshot precedes `prepareSigning`. A malformed context type returns
`invalid_input`/`invalid_type`. For otherwise valid descriptor claims, predecessor
errors return `invalid_input` with these codes before signing:

- `invalid_type`: a non-object predecessor, a missing digest alias (both `digest`
  and `descriptor_digest` absent), or missing, null, empty, or non-string `lineage`.
  Throwing reads also return this code.
- `descriptor_chain_invalid`: an absent or null predecessor for a successor,
  a valid predecessor supplied to a genesis, a broken signed lineage, or digest
  aliases that disagree with the reverified lineage.
- `algorithm_outside_profile`, `revision_outside_profile`, or
  `algorithm_unsupported_on_substrate`: predecessor history excluded by the
  profile or requiring unavailable crypto.

## The sibling verifier

The signer and verifier are separate TypeScript packages implementing the
Charter Agreement Protocol, with no Elixir dependency at runtime. The
verifier ships a corpus certified against the Elixir protocol reference.
This signer tests its artifacts through the TypeScript verifier.
All protocol checks run in `prepareSigning` and `finishSigning`; the signer
keeps key custody callbacks, the signature guard, entry copies, option
resolution, and the closed error vocabulary.

## Evidence

- Linux CI runs the suite on Node 24.8.0 and the current Node 24 line.
  Real Node crypto mints Ed25519 and ML-DSA-65 genesis and successor descriptors.
  Pre-sign rejection tests count real signing calls and require zero calls.
  Tests cover key mismatches, predecessor checks, malformed contexts, profiles,
  final compact limits, receipt claims, entry copies, and unknown algorithms.
- The workshop's browser bundle mints Ed25519 and runs the complete workshop
  flow. It cannot verify ML-DSA-65 and refuses that request before signing with
  the top-level `algorithm_unsupported_on_substrate` error.
- The [shared table](conformance/README.md) runs all 121 rows from the Elixir
  signer, `charter_agreement_signer` 1.0.0, with its exact source bytes pinned by SHA-256. Real seed
  keys check result shapes and codes, snapshot and custody counts, 12 exact
  Ed25519 success compacts, and five ML-DSA-65 successes through verification.
  All 121 rows run in both Node and the browser bundle with no skips. Eight
  shared requests or contexts that need ML-DSA-65 also return a substrate error
  before custody in the browser bundle.
  This compares the recorded Elixir outcomes; it does not run Elixir locally.

## Verifier compatibility and telemetry

The verifier requires canonical digests and revision JSON, distinct party
histories, and all four chain arrays. Build failures surface as `invalid_input`
with `code: "signing_input_invalid"`; termination claims must omit `extensions`.
See [CHANGELOG.md](CHANGELOG.md) for migration notes.

This package has no telemetry events or hooks and no signer capability report.

## SemVer

The 1.x exports, TypeScript contracts, options and documented error shapes
follow Semantic Versioning. Removal, renaming or incompatible valid-input
behavior requires a major release. New exports and optional options or fields are minor additions. An incompatible
change to a closed TypeScript union requires a major release. Compatible bug and security fixes can tighten malformed-input handling.
Protocol `protocol_revision` is a separate wire identity.

`reference.json` pins the published Elixir signer 1.0.0 archive. The unchanged
121-row table ships in `conformance/` and is checked byte for byte against it.
`npm run check:reference` performs that comparison; the native and browser
suites execute every row. Elixir is not a runtime dependency.

## Development

Use Node 24 (at least 24.8.0) and npm. The lockfile selects TypeScript 7.0.2
and `@types/node` 26.6.6. CI runs on Linux with Node 24.8.0 and Node 24
using a frozen install; the same npm commands are used for local development on macOS and Linux.

```console
npm ci
npm run check
```

`build` emits JavaScript and declarations into `dist/`; `build:site` writes
the browser workshop to `site-dist/`. `prepack` runs the library build.
For the TypeScript 7 upgrade, the four library output files were byte-identical
to the TypeScript 5.9.3 build (observed October 6, 2026 with `diff -ru`).

## Release staging

The [Release workflow](https://github.com/baselabs/charter_agreement_signer_typescript/blob/main/.github/workflows/release.yml) is the npm trusted
publisher for this repository. Prepare a release by updating `package.json`,
`package-lock.json`, this README's release version, the CHANGELOG, and the
workshop's version badge. Run the development checks above, commit and push
main, and wait for CI to pass. Then tag that same commit `v<package-version>`
and push that specific tag.

The tag verifies both compatibility lines and the packed consumer, then
a separate job runs `npm stage publish --provenance --ignore-scripts` through
GitHub Actions OIDC. A successful staging step prints the package version and
stage ID. The package becomes public only after the owner approves the staged
release on npmjs.com with 2FA. Keep npm staging in this workflow. Staging requires npm >= 11.15.0.
The full check includes the real resource-cost suite, reference byte comparison,
installed README example, declaration compilation and wrong-key rejection.
Approve the verifier stage before the signer stage.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
