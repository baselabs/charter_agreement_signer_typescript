# @charter-agreement-protocol/signer

Holder-side companion signer for the
[Charter Agreement Protocol](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
(CAP) — the TypeScript sibling of the Elixir
[charter_agreement_signer](https://hex.pm/packages/charter_agreement_signer).

**CAP verifies; it never authorizes. This signer signs; it never takes
custody.** You keep the key (HSM, OS keychain, key server) behind a handle
object with two callbacks; the signer resolves ONE atomic `keyIdentity`
snapshot, then delegates EVERYTHING pure to the verifier package's producer
surface — the exact RFC 7515 signing input, the producer claims gate, the
R1–R3 honest-signer refusal guards (claims-truth, no-equivocation,
ancestry/governing coverage), and assembly — **before the key signs**, with
exactly one implementation. What stays here is custody: the sign callback,
the wrong-key guard against the snapshot's public key, and the post-sign
verification of the assembled artifact through the
`@charter-agreement-protocol/verifier` package.

## Install

```console
npm install @charter-agreement-protocol/signer
```

Release **0.2.2** requires Node >= 24.8.0 (ML-DSA support in the Node builtins)
and depends on `@charter-agreement-protocol/verifier` `^0.5.0`.

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

## API

| Export | What it does |
|---|---|
| `signDescriptor(claims, handle, opts?)` | Signs one Party Descriptor; post-verified via `verifyDescriptor` |
| `signReceipt(claims, handle, chain, opts?)` | Signs one Receipt against the required issuing view; post-verified via `verifyReceipt` (the reference takes a context, never none) |
| `signAcceptance(claims, handle, view, opts?)` | Signs one Acceptance against the caller's verified view — the R1–R3 refusal guards run over `view.chain` before the key signs |
| `signTermination(claims, handle, view, opts?)` | Signs one Termination against the caller's verified view — the R1–R3 refusal guards run over `view.chain` before the key signs |

The acceptance/termination `view` is `{ revisionText, descriptorCompacts,
chain }`: the revision the claims name, the signing party's descriptor
chain, and the caller's full `ChainView` (`{ revisions, acceptances,
descriptors, terminations }`) the refusal guards verify and bind against.

Errors are closed: `{ ok: false, error: "invalid_handle" \| "signing_failed"
\| "invalid_input" \| "refused" \| "verification_failed" }` — `code` rides
only on `invalid_input` and `refused`; `verification_failed` is bare
(reference parity).
`"refused"` is the honest-signer refusal: the claims contradict the caller's
own verified view, and the handle's `sign` callback is never reached (the
atomic `keyIdentity` snapshot resolves first — the reference ordering).
`"verification_failed"` is the separate post-sign discipline: the assembled
artifact did not verify against the caller's view (for example a key that is
not in the party descriptor's `verification_keys`). Malformed claims are
rejected pre-sign as `"invalid_input"` through the verifier package's
producer claims gate — they never burn a key operation. A signing failure is
never a silent pass.

## The sibling verifier

This package is one of two independent TypeScript siblings implementing the
Charter Agreement Protocol — no Elixir code or dependency at runtime; the
Elixir reference is the certification oracle (the verifier's vendored
corpus is certified against it, and its CI cross-verifies
TypeScript-signed artifacts from raw bytes).

- **This package** — `@charter-agreement-protocol/signer`: key custody,
  the wrong-key guard, post-sign verification, and the closed error
  vocabulary — all protocol logic delegated to the verifier.
- [`@charter-agreement-protocol/verifier`](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
  — verification and the pure producer surface (signing inputs, claims
  gate, refusal guards, assembly) that this package signs through.

This signer depends on the verifier (`^0.5.0`, locked to 0.5.0). When changing
that dependency, publish the verifier version first, then lock and release
the signer against the published version. The packages have independent
SemVer versions; signer documentation and build-tool updates can release
without a verifier version change.

## Evidence

- The Elixir reference repository's gate verifies TypeScript-signed
  artifacts from raw bytes (cross-implementation agreement, enforced in CI).
- Framing, the producer claims gate, refusal guards, and assembly are the
  verifier package's producer surface (0.5.0) — the same single
  implementation the independent verifier certifies. What remains here is
  custody plus input policing: the issuing-view discipline composes the
  verifier's own `verifyChain`, never a local reimplementation.
- Post-sign verification goes through the
  [@charter-agreement-protocol/verifier](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
  package — the certified dual-implementation-verified verifier.

## The verify side

This package tracks the published verify line: it depends on
`@charter-agreement-protocol/verifier` `^0.5.0`. Verifier 0.5.0 added
consumer-side surface only; the producer surface this package uses is
unchanged. The producer-side capability alignment (mirrored
`capabilities()` with refuse-before-mint, declared minting metadata,
profile-bound signing) is the next feature release on this line.

## SemVer

Package SemVer decoupled from the protocol's `protocol_revision`. While the
package is below 1.0, breaking public-API changes land in minor versions and
are named in the commit message (0.2.0 is one: `signTermination`'s view
requires `chain`, `signAcceptance` now enforces the refusal guards over the
`chain` it previously ignored, and `signReceipt` requires its issuing view);
at or above 1.0 a package major is owed when a shipped public API is removed
or changes behavior.

## Development

Use Node 24 (at least 24.8.0) and npm. The lockfile selects TypeScript 7.0.2
and `@types/node` 26.6.4. CI runs on Linux with Node 24 and a frozen install;
the same npm commands are used for local development on macOS and Linux.

```console
npm ci
npm run typecheck
npm test
npm run build
npm run typecheck:web
npm run build:site
npm pack --dry-run
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

The tag triggers verification and `npm stage publish --provenance` through
GitHub Actions OIDC. A successful staging step prints the package version and
stage ID. The package becomes public only after the owner approves the staged
release on npmjs.com with 2FA. Keep npm staging in this workflow.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
