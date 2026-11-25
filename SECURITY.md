# Security policy

## Supported versions

The 1.x line is supported; 1.0.0 is served by npm. The 0.3.x support window
ended when 1.0.0 was approved. Signer 1.0 supports verifier `^0.7.0 || ^1.0.0`; both
compatibility lines run through release checks. This does not promise maintenance
of verifier 0.7 after its security-support window ends: follow the verifier's
security policy and update locks to maintained 1.x. Wire compatibility follows the verifier's
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

The maintainers' release process qualifies each commit before landing.
After owner approval, infra dispatches the protected
[Publish workflow](https://github.com/baselabs/charter_agreement_signer_typescript/blob/main/.github/workflows/publish.yml)
from the default branch with the full qualified SHA as `release_commit`. It
validates the input before checkout and builds and inspects that commit’s archive,
then stages missing bytes with npm provenance through GitHub Actions OIDC.
It refuses an absent package name (first publication is the owner's decision),
differing served bytes, a version tag, and deprecated or unpublished versions.
Finish a held release by approving it on npmjs.com and dispatching the workflow
again with the same `release_commit`. It stages only what is missing and skips identical
served versions. OIDC cannot read pending stages; npm refuses a duplicate
pending stage without replacing it. Read-back compares the downloaded tarball
with the inspected bytes and verifies the signed `release_commit` before
exporting the release assets.

The consumer files leave as one `release-assets` artifact. After registry
read-back, the maintainers' release process tags the published commit as
`v<version>`, compares the archive with npm's bytes, and creates that GitHub
release from those files. No workflow creates a release or runs on a tag.
Download `charter-agreement-protocol-signer-<version>.tgz`, the docs archive and `SHA256SUMS` from the matching
[GitHub release](https://github.com/baselabs/charter_agreement_signer_typescript/releases)
and run `sha256sum --check SHA256SUMS` in their directory. Compare the
archive's SHA-512 with npm's integrity and inspect source and provenance for
the exact release version (replace `<version>` below):

```console
npm view '@charter-agreement-protocol/signer@<version>' repository.url dist.integrity dist.attestations
```

## Acknowledgment

We will acknowledge reports within 7 days and send status updates at least
weekly until resolution, coordinating disclosure through a private advisory.
This is a best-effort cadence from a small maintainer team, not a contractual
SLA. Mark urgent reports clearly.
