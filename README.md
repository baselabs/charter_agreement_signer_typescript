# @charter-agreement-protocol/signer

Holder-side companion signer for the
[Charter Agreement Protocol](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
(CAP) — the TypeScript sibling of the Elixir
[charter_agreement_signer](https://hex.pm/packages/charter_agreement_signer).

**CAP verifies; it never authorizes. This signer signs; it never takes
custody.** You keep the key (HSM, OS keychain, key server) behind a handle
object with two callbacks; the signer resolves ONE atomic `keyIdentity`
snapshot, builds the exact RFC 7515 signing input, runs the honest-signer
refusal guards before any key is touched, checks the returned signature
against the snapshot's public key (the wrong-key guard), assembles the
compact, and post-sign-verifies the assembled artifact through the
`@charter-agreement-protocol/verifier` package — exactly one verification
implementation.

## Install

```console
npm install @charter-agreement-protocol/signer
```

Requires Node >= 24.8 (ML-DSA support in the Node builtins).

## Quickstart

```js
import { signDescriptor } from "@charter-agreement-protocol/signer";

const handle = {
  // ONE atomic snapshot — the kid and public key cannot disagree.
  keyIdentity() {
    return { kid: "my-key-001", publicKey }; // base64url raw public key
  },
  // The holder's job: sign the exact message bytes with the held key.
  sign(message) {
    return myHsm.sign(message); // Uint8Array signature
  },
};

const result = await signDescriptor(
  {
    protocol_revision: 2,
    descriptor_number: 1,
    verification_keys: [
      { key_id: "my-key-001", algorithm: "Ed25519", public_key: publicKey, status: "active" },
    ],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  },
  handle,
);

// result.ok === true: { descriptor } is a CAP-verified compact JWS.
```

For ML-DSA-65 artifacts pass `{ algorithm: "ML-DSA-65" }` as the options
argument with `protocol_revision: 3` claims (pure ML-DSA per RFC 9964, the
empty context — your handle signs the exact message bytes as with Ed25519).

## API

| Export | What it does |
|---|---|
| `signDescriptor(claims, handle, opts?)` | Signs one Party Descriptor; post-verified via `verifyDescriptor` |
| `signReceipt(claims, handle, chain \| null, opts?)` | Signs one Receipt; post-verified via `verifyReceipt` when a chain view is supplied |
| `signAcceptance(claims, handle, view, opts?)` | Signs one Acceptance against the caller's verified view |
| `signTermination(claims, handle, view, opts?)` | Signs one Termination against the caller's verified view |

Errors are closed: `{ ok: false, error: "invalid_handle" \| "signing_failed"
\| "invalid_input" \| "refused", code? }`. A signing failure is never a
silent pass.

## Evidence

- The Elixir reference repository's gate verifies TypeScript-signed
  artifacts from raw bytes (cross-implementation agreement, enforced in CI).
- Post-sign verification goes through the
  [@charter-agreement-protocol/verifier](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
  package — the certified dual-implementation-verified verifier.

## SemVer

Package SemVer decoupled from the protocol's `protocol_revision`; a package
major is owed only when a shipped public API is removed or changes
behavior.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
