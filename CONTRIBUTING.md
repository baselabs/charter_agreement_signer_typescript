# Contributing

Contributions must preserve the signer's boundaries: the library depends
only on the public verifier package, key identity comes from one atomic
snapshot, errors contain no caller values, and test handles do not ship.
Private keys stay behind the caller's callbacks.

## Toolchain

Use Node 24, at least 24.8.0, and npm. `package-lock.json` pins the build
tools and verifier version. CI runs on Linux with the exact Node pin in
`.tool-versions` and the Node 24.8.0 compatibility floor, refusing a different
installed version.

## Before a pull request

Qualification installs with the frozen lockfile and runs these checks:

```console
npm ci
npm run check
npm run check:verifier
```

The maintainers' release process runs covering checks on the build box where
configured, never on a workstation. This public repository has no build-box
checkout; its checks run on GitHub-hosted CI at landing through the maintainers' landing tool.
The unit and type checks can use installed dependencies offline. Reference,
package-consumer and verifier-candidate checks need network access to Hex, npm
and GitHub.
The suite builds a browser bundle with the workshop's shims and exercises
real Ed25519 and ML-DSA-65 keys. The library build writes `dist/`; the site
build writes `site-dist/`. Site typechecking and building run in a dedicated
qualification job; `qualified` requires every source and site job to succeed.

## Windows

Developer platforms are macOS and Linux. Windows developers use WSL2,
clone inside its filesystem and follow the Linux commands. CI runs on
Linux only. Native ML-DSA tests require the supported Node crypto runtime.

## Commits

Use explicit paths when staging or committing. Keep tool directories and
local process state out of commits. Work on a branch in small commits with
plain messages and land the full commit through the maintainers' landing tool.
Do not push the default branch or version tags directly. Do not use `git stash`.

## Tests and checks

- For behavior changes, write the test, observe it fail for the intended
  reason, then make it pass. Record the observed failure in the commit.
- New checks must fail under a named temporary mutation. Restore the
  original code and run the suite again before committing.
- Use real keys and real signing callbacks. Do not use mocks, fake crypto
  or handles that return invented signatures.
- Search for tests of the old contract before changing behavior.

The suite runs the [shared signer table](conformance/README.md)
against the TypeScript verifier this checkout installs. It compares recorded
Elixir outcomes and exact Ed25519 compacts with real seed keys, then checks
every success through verification. It does not execute Elixir locally.
`check:reference` verifies the rows against the published Elixir signer 1.0.0
archive. `check:verifier` fetches verifier 1.0.0 at the immutable commit in
`reference.json`, rebuilds its archive and requires the exact recorded staged
integrity. It checks the same signer archive against that candidate as well
as the frozen registry baseline. To use a downloaded copy of that same staged
archive, use `npm run check:verifier -- --archive /absolute/path/package.tgz`.
The archive must match the recorded staged integrity. No repository lock is replaced.
Keep the source table byte for byte and report disagreements with both outcomes.

## Protocol dependency changes

Move the verifier requirement and lockfile together. Read its changelog,
test against the published package and document changes to input rules
or error codes. Keep signing fixtures canonical.

## Docs

Update documentation with the behavior it describes. Keep error names,
supported options, package metadata and the workshop's version badge in
sync. Describe only checks that run and features that ship.

## Releases

The version commit stamps the changelog. After qualification and landing, send
the release operator one message containing the repository, full commit, version, what goes out,
and the green `qualified` run. The release operator obtains owner approval, dispatches
`publish.yml` from the default branch with the full qualified SHA as `release_commit`. The
workflow validates the input before checkout, builds that commit, and loads the
registry script from the workflow revision. Publication uses the protected `publish`
environment and npm OIDC trusted publishing; no maintainer-held registry token
is needed. It refuses a package name the registry lacks: first publication
is the owner's decision. It also refuses a version tag, differing served
bytes, and deprecated or unpublished versions.

Finish a held release by dispatching `publish.yml` again with the same `release_commit`
after owner approval on npmjs.com. The job stages only what is missing and
skips identical served bytes. OIDC cannot list or view pending stages, so
npm refuses a repeated pending stage without replacement; approve it before
redispatching.

The verified archive and checksum leave as one `release-assets` artifact.
After registry read-back, the maintainers' release process tags the published
commit as `v<version>`, compares the archive with npm, and creates the GitHub
release from those files. No workflow creates a release or runs on a tag.
Consumer verification uses the matching
[GitHub release's assets](https://github.com/baselabs/charter_agreement_signer_typescript/releases)
and npm provenance; follow [the README verification commands](README.md#releases).
Static-site publication is a separate release-operator dispatch of `pages.yml` from the
default branch.
