# Shared signer cases

`signer_cases.json` is copied byte for byte from the CAS Elixir signer. The
source commit and SHA-256 are recorded once in
[`reference.json`](../reference.json). Qualification fetches that
commit directly and compares the vendored table with its exact Git blob.
The digest covers whitespace and JSON values. These seeds are public test
material.

Run `npm run test:cases` for all 137 Node rows. The runner executes
every row in the table. The run count is asserted,
so new omissions cannot pass silently.

The outcome mapping preserves nested error codes and maps top-level error
atoms to the TypeScript error member without a code. Every row checks the full result shape, snapshot
count, and custody count. The operations are descriptor, acceptance, party
replacement, termination, and receipt signing. A replacement returns a marked
acceptance. Ed25519 successes compare the exact compact. Every success is
checked through public verification, including ML-DSA-65 successes.

Node crypto imports the Ed25519 and ML-DSA-65 seeds into private keys and signs
the prepared bytes. The mixed-order Ed25519 row uses the seed's scalar and
real nonce keys with an even challenge, matching the Elixir custody handle.
Node crypto independently checks its signature. Key entries that advertise a
different public key keep that advertised snapshot and sign with the listed
seed, including the wrong-key guard row.

Profiles translate inclusive `revisions: [min, max]` into the TS
`{ min, max }` shape. Bare revision contexts stay text. A predecessor context
is publicly verified into the last descriptor's facts. TS chain contexts use
the same four artifact arrays after public verification; Elixir retains a
verified struct. Raw set contexts pass the four arrays directly.

The browser bundle test uses `expected_limited` where present and the normal
expectation otherwise. It runs all 137 rows with no skips, compares 17 exact
Ed25519 successes, and checks eleven substrate errors with zero custody calls.
Both `ml-successor-ok` and `ml-successor-wrong` use their `expected_limited`
substrate errors with one snapshot and zero custody calls. It checks result
shapes and callback counts and verifies each success in the bundle.
The full table runs in Node 24.8.0 and the current Node 24 line. A mismatch
prints both the Elixir expectation and TS result and counts. The source table
is never adjusted to make a mismatch pass.

The [CAP companion-signer rule](https://github.com/baselabs/charter_agreement_protocol/blob/9cc6dfa4104b17d4017ae3b1a307e3ddf8460545/spec/core.md#441-pre-sign-check)
defines the order of callbacks. The declared-key successor rows check
refusal before either callback, refusal after a different snapshot, and
successful signing with the authorized identity. Both refusals use `signing_key_mismatch`.

An explicit null identity returns `invalid_input` / `invalid_type` with zero
identity and signing calls.
