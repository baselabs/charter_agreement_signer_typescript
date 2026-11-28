# @charter-agreement-protocol/signer

Holder-side companion signer for the
[Charter Agreement Protocol](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
(CAP) — the TypeScript sibling of the Elixir
[charter_agreement_signer](https://hex.pm/packages/charter_agreement_signer).

**CAP verifies; it never authorizes. This signer signs; it never takes
custody.** You keep the key (HSM, OS keychain, key server) behind a handle
with two callbacks. The signer resolves limits, profile, and algorithm, copies
claims and context at entry, and takes one atomic `keyIdentity` snapshot.
The verifier's `retainSigningContext` captures the context and keeps the
`prepareSigning` check order for framing, claims, keys, scope, and context. These
checks finish before the signing callback runs.
The signer checks the signature against the snapshot public key, then calls
`finishSigning` to assemble and verify under the retained context and settings.

## Install

```console
npm install @charter-agreement-protocol/signer@^1.1.0
```


The maintainers' release process publishes inspected archives to npm with
provenance through GitHub Actions trusted publishing after owner approval.

Version **1.1.0** requires Node >= 24.8.0 and
`@charter-agreement-protocol/verifier` `^2.0.0`. The registry lock and
`reference.json` pin the verifier 2.0.0 archive. Qualification also rebuilds
the pinned verifier commit and compares the archive integrity.

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

Legacy artifacts, including receipts, use `Ed25519` at protocol revision 2
or `ML-DSA-65` at revision 3. Revision-8 party
descriptors, acceptances (including the assignor's marked acceptance from
`signPartyReplacement`), and termination notices can use either algorithm
with `protocol_revision: 8`. Select ML-DSA-65 with
`{ algorithm: "ML-DSA-65" }`. The handle signs the exact message bytes
with pure ML-DSA and an empty context per RFC 9964.

An absent, `undefined` or `null` algorithm selects Ed25519. Explicit
algorithms are `Ed25519` and `ML-DSA-65`. An unsupported algorithm returns
`{ ok: false, error: "invalid_input", code: "algorithm_unsupported" }` before
either key callback runs.

## Descriptor rotation

Use `signDescriptor` with `protocol_revision: 8`
for a committed descriptor or its successor. Compute the successor's complete
active key commitment with CAP's `descriptorNextKeyCommitment`
and put it in the current descriptor's `next_key_commitment` field. To sign
the successor, supply the current descriptor's verified facts in
`opts.predecessor` and use a handle for one of its active signing keys.

CAP checks the opening before the handle signs. A failed opening returns
`descriptor_commitment_mismatch` as an invalid-input code. After signing,
assemble the unsigned distribution document through CAP and pass it to
`verifyDescriptorPublication` with the complete signed history.

## Signer scopes

A revision-8 descriptor can declare `signing_scopes` by role, active key
thumbprint, and artifact kind. CAP checks the relevant pinned descriptor
before custody signs. If the key is outside scope, acceptance, assignment
acceptance, termination and receipt signing return
`{ ok: false, error: "refused", code: "signing_refused" }`.
Descriptor succession checks the predecessor for the `descriptor` kind
under a role and returns `invalid_input` with `descriptor_chain_invalid`
on a scope failure.

## Inspect a signed receipt

Retain the raw chain view used when signing. Call the verifier with the
returned receipt and an optional tagged grant digest from your own records.

```ts
import { signReceipt } from "@charter-agreement-protocol/signer";
import { inspectReceipt } from "@charter-agreement-protocol/verifier";

const signed = await signReceipt(claims, handle, chain, options);
if (signed.ok) {
  const checked = inspectReceipt(signed.result.receipt, chain, grantReference, {
    limits: options.limits,
    profile: options.profile,
  });
  if (checked.ok) {
    const { provenance, grant, agreement } = checked.inspection;
    const exported = JSON.stringify(checked.inspection);
  }
}
```

Use `null` or omit the grant reference when you hold none. Read
`provenance.scope_status` and `provenance.signer_thumbprint` for the signing key's
scope evidence. `grant` compares the digests, while `agreement` compares the
receipt claims with the revision governing at `occurred_at`. The portable
record holds the original signed segments and decoded claims. Handle the
export as receipt evidence.

## API

| Export | What it does |
|---|---|
| `signDescriptor(claims, handle, opts?)` | Signs a genesis or successor Party Descriptor; successors require `opts.predecessor` |
| `signReceipt(claims, handle, context, opts?)` | Signs a Receipt against a verified chain view or bare legacy revision text |
| `signAcceptance(claims, handle, chain, opts?)` | Signs an Acceptance using the context the verifier derives from the chain |
| `signPartyReplacement(claims, handle, chain, opts?)` | Signs the departing party's marked acceptance of a declared replacement |
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
compact size. Context list copies stop at the item limit and defer that error
until the verifier reaches the context check.
The signer finishes capturing chain lists, predecessor lineage, and options
before either async key callback runs.
Predecessor lineage uses the verifier's absolute item ceiling independent of
caller artifact-set limits. The verifier checks immutable
artifact text under artifact byte limits, separately from parsed claims' string
limits.

Migration from the previous issuing view:

```ts
// Before
await signAcceptance(claims, handle, { revisionText, descriptorCompacts, chain }, opts);
// Now
await signAcceptance(claims, handle, chain, opts);
await signPartyReplacement(replacementClaims, handle, chain, opts);
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

For a receipt against bare legacy revision text, the verifier checks the receipt's
claims against that revision. The revision names no signing key, so the signer
uses its snapshot for the custody guard; receipt verification reports
`signature` in `not_verified`. Signing against a bare revision-8 charter
returns `{ ok: false, error: "refused", code: "signing_refused" }`. A
chain-backed receipt checks the issuing party's descriptor keys in the
holder's own view.

`opts` is absent or an object with known own keys only: `algorithm`, `limits`,
`profile` and `keyIdentity`, plus `predecessor` for `signDescriptor`. Another root shape, an
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
unique subset, so it returns `invalid_profile` without reading its entries.
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
| `refused`, with `code: "signing_refused"` | The claims contradict the holder's own verified view (R1–R3), or the key is outside the descriptor scope for the role and kind |
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
Without a declared identity, the signer takes one atomic key snapshot and
passes that identity to `prepareSigning`. With a declared identity and
descriptor membership evidence, CAP can refuse an unauthorized key before
either callback. After successful declared-identity preparation, the signer
takes one atomic snapshot and compares it with the prepared identity before
calling `sign`. A receipt against a bare legacy revision checks key shape and runtime support
during preparation, then compares the snapshot before signing.

A malformed context type returns
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

- Linux CI runs the suite on the exact Node in `.tool-versions` and Node 24.8.0.
  Real Node crypto mints Ed25519 and ML-DSA-65 genesis and successor descriptors.
  Pre-sign rejection tests count real signing calls and require zero calls.
  Tests cover key mismatches, predecessor checks, malformed contexts, profiles,
  final compact limits, receipt claims, entry copies, and unknown algorithms.
- The workshop's browser bundle mints Ed25519 and runs the complete workshop
  flow. It cannot verify ML-DSA-65 and refuses that request before signing with
  the top-level `algorithm_unsupported_on_substrate` error.
- The [shared table](conformance/README.md) runs all 137 rows from the Elixir
  signer, with its source commit and exact bytes pinned by SHA-256. Real seed
  keys check result shapes and codes, snapshot and custody counts, 17 exact
  Ed25519 success compacts, and eight ML-DSA-65 successes through verification.
  All 137 rows run in both Node and the browser bundle with no skips. Eleven
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

`reference.json` pins the published Elixir signer 1.0.0 archive.
`npm run check:reference` fetches the pinned Elixir commit directly,
compares the vendored table to its Git blob byte for byte, and confirms
that the published reference rows remain in the current table. The native and browser suites execute every current row.

Pass `keyIdentity: { kid, publicKey }` to check a caller-declared identity
before either handle callback. With descriptor membership evidence, an unauthorized identity returns
`{ ok: false, error: "refused", code: "signing_key_mismatch" }`.
After successful preparation, a different snapshot returns the same
refusal before the handle signs.

## Development

Use Node 24 (at least 24.8.0) and npm. The lockfile selects TypeScript 7.0.2
and `@types/node` 26.6.6. CI runs on Linux with the exact Node in `.tool-versions`
and the Node 24.8.0 compatibility floor, checks the installed versions, and uses
a frozen install. Qualification runs these commands on GitHub-hosted runners:

```console
npm ci
npm run check
```

`build` emits JavaScript and declarations into `dist/`; `build:site` writes
the browser workshop to `site-dist/`. `prepack` runs the library build.
For the TypeScript 7 upgrade, the four library output files were byte-identical
to the TypeScript 5.9.3 build (observed October 6, 2026 with `diff -ru`).

## Releases

The maintainers' release process runs covering checks on the build box where
configured, never on a workstation. This public repository has no build-box
checkout: its qualification runs on pinned GitHub-hosted runners at landing.
Prepare the version commit with matching `package.json` and `package-lock.json`
versions, stamp the changelog, and update this README's release version and the
workshop's version badge. Land the full commit through the maintainers' landing tool;
it qualifies the commit on `kci/**` before moving the default branch. Do not push
the default branch or version tags directly.

Send the release operator one message with the repository, full commit, version, what goes out,
and the green `qualified` run. The release operator obtains owner approval and dispatches
[publish.yml](https://github.com/baselabs/charter_agreement_signer_typescript/blob/main/.github/workflows/publish.yml)
from the default branch with the full qualified SHA as `release_commit`.
The first job checks default-branch history, the successful `qualified` check and
the absence of a version tag before checkout. The build uses that commit and the
registry script comes from the workflow revision. The build refuses a package
name the registry lacks, a deprecated or unpublished version, and served bytes
that differ from the inspected archive. A first publication is the owner's
decision. The build produces the library and documentation site and inspects
the archive. The protected upload job verifies the archive checksum and stages
missing bytes with
`npm stage publish --provenance` through OIDC. No stored npm token is used.
The package becomes public only after the owner approves the staged release
on npmjs.com with 2FA.

A held release is finished by dispatching `publish.yml` again with the same
`release_commit` after approval. It stages only what is missing, skips an identical
served version, and refuses differing bytes or a retired version. npm's OIDC
credentials cannot read pending staged versions: a dispatch while approval
is still pending may attempt to stage again, which npm refuses without
replacing the staged version. Approve the pending stage before dispatching
again.

Read-back downloads the npm tarball and compares its bytes with the inspected
archive. After it verifies the signed release commit, the workflow exports
`charter-agreement-protocol-signer-<version>.tgz`, the site docs archive and `SHA256SUMS`. The docs archive
contains root `index.html` and `release.json`. The release operator compares the
tarball with npm's bytes and tags the commit named by `release.json`.
For a paired release, publish and verify the verifier first.

### Release source attestation

npm provenance identifies the default-branch workflow revision. The release
workflow also signs a predicate containing the qualified `release_commit` over
the checked tarball's digest. Read-back checks that predicate against the
tarball downloaded from npm.

To verify a release, download the archives and `SHA256SUMS` from the matching
[`v<version>` GitHub release](https://github.com/baselabs/charter_agreement_signer_typescript/releases) and run
`sha256sum --check SHA256SUMS` in their directory. Compare the tarball's SHA-512
with npm's `dist.integrity`, then verify its release source against the tag.
Download the bundle first because GitHub's attestation API does not filter on
custom predicate types.

```sh
published_commit=$(gh api "repos/baselabs/charter_agreement_signer_typescript/commits/v<version>" -q .sha)
archive="charter-agreement-protocol-signer-<version>.tgz"
digest=$(sha256sum < "$archive")
gh attestation download "$archive" --repo baselabs/charter_agreement_signer_typescript &&
gh attestation verify "$archive" \
  --repo baselabs/charter_agreement_signer_typescript \
  --bundle "sha256:${digest%% *}.jsonl" \
  --signer-workflow baselabs/charter_agreement_signer_typescript/.github/workflows/publish.yml \
  --source-ref refs/heads/main \
  --predicate-type 'https://github.com/baselabs/charter_agreement_signer_typescript/blob/main/README.md#release-source-attestation' \
  --format json |
  jq -e --arg commit "$published_commit" \
    'any(.[]; .verificationResult.statement.predicate.release_commit == $commit)'
```

Site typechecking and building are required by `qualified`. The release operator
dispatches [pages.yml](https://github.com/baselabs/charter_agreement_signer_typescript/blob/main/.github/workflows/pages.yml)
from the default branch to build and deploy the static site through GitHub's
`github-pages` environment. A default-branch push or version tag starts neither workflow.

## License

Apache-2.0, maintained by BaseLabs Holdings LLC. See LICENSE and NOTICE, and IPR.md
for contributions.
