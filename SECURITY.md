# Security policy

## Supported versions

The 1.x line is supported after staged 1.0.0 is approved. Until then, 0.3.x
remains supported. Signer 1.0 supports verifier `^0.7.0 || ^1.0.0`; both
compatibility lines run through release checks. This does not promise maintenance
of verifier 0.7 after its security-support window ends: follow the verifier's
security policy and update locks to maintained 1.x once approved. Wire compatibility follows the verifier's
protocol contract, separately from package Semantic Versioning.

## Security invariants

- The library never solicits, processes or retains private key material.
  Custody lives behind the caller's key-handle callbacks.
- Every signature is verified against the snapshot public key before
  success. A signature from another key returns `signing_failed`.
- Key identity (`kid` and public key) comes from one atomic `keyIdentity`
  snapshot per signing call. The signer supplies that snapshot's kid to
  the producer.
- Errors contain closed names and codes, with no key material, message
  bytes, claims content or callback exception text.
- The library's only runtime dependency is the public verifier package.
  It contains no transport or HTTP client/server.
- Test handles stay in test files and do not ship in the npm package.

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting for
`baselabs/charter_agreement_signer_typescript` (the repository's Security
tab, then "Report a vulnerability"). Do not open a public issue containing
an exploit, credential, private key or unreleased vulnerability detail.

A report should include:

- the affected version or commit;
- the violated property;
- a minimal reproduction with newly generated test keys and no production
  claims or credentials;
- the expected security outcome.

## Verifying a release

The [Release workflow](https://github.com/baselabs/charter_agreement_signer_typescript/blob/main/.github/workflows/release.yml)
checks the package before staging it on npm with provenance through
GitHub Actions OIDC. The owner approves the staged release on npm with 2FA.
Inspect the published package's source repository, archive integrity and
provenance metadata with:

```console
npm view @charter-agreement-protocol/signer repository.url dist.integrity dist.attestations
```

## Acknowledgment

We will acknowledge reports within 7 days and send status updates at least
weekly until resolution, coordinating disclosure through a private advisory.
This is a best-effort cadence from a small maintainer team, not a contractual
SLA. Mark urgent reports clearly.
