# Shared signer cases

`signer_cases.json` is copied byte for byte from the CAS Elixir signer. The
source commit and SHA-256 are recorded once in
[`SHARED_SOURCE`](../signer-cases.ts). The digest covers whitespace as well as
JSON values. These seeds are public test material.

Run `npm run test:cases` for all 122 Node rows. The runner is
[`signer.cases.test.ts`](../../signer.cases.test.ts); its empty
`unexpressibleRows` map is the explicit list of Elixir-only shapes, keyed by
row id with a reason. This table has no such rows. The run count is asserted,
so new omissions cannot pass silently.

The outcome mapping table is in [`signer-cases.ts`](../signer-cases.ts).
It preserves nested error codes and maps top-level error atoms to the TS
error member without a code. Every row checks the full result shape, snapshot
count, and custody count. Ed25519 successes compare the exact compact. Every
success is checked through public verification, including ML-DSA-65 successes.

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

The browser bundle test also runs eight rows whose request or context needs
ML-DSA-65 and checks a substrate error, one snapshot, and zero custody calls.
The full table runs in Node 24.8.0 and the current Node 24 line. A mismatch
prints both the Elixir expectation and TS result and counts. The source table
is never adjusted to make a mismatch pass.
