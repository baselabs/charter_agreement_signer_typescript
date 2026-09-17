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

## Evidence

- The Elixir reference repository's gate verifies TypeScript-signed
  artifacts from raw bytes (cross-implementation agreement, enforced in CI).
- Framing, refusal guards, and assembly are the verifier package's producer
  surface (0.4.0) — the same single implementation the independent verifier
  certifies; this package contains no protocol logic of its own.
- Post-sign verification goes through the
  [@charter-agreement-protocol/verifier](https://www.npmjs.com/package/@charter-agreement-protocol/verifier)
  package — the certified dual-implementation-verified verifier.

## SemVer

Package SemVer decoupled from the protocol's `protocol_revision`. While the
package is below 1.0, breaking public-API changes land in minor versions and
are named in the commit message (0.2.0 is one: `signTermination`'s view
requires `chain`, `signAcceptance` now enforces the refusal guards over the
`chain` it previously ignored, and `signReceipt` requires its issuing view);
at or above 1.0 a package major is owed when a shipped public API is removed
or changes behavior.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
