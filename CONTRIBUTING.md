# Contributing

Contributions must preserve the signer's boundaries: the library depends
only on the public verifier package, key identity comes from one atomic
snapshot, errors contain no caller values, and test handles do not ship.
Private keys stay behind the caller's callbacks.

## Toolchain

Use Node 24, at least 24.8.0, and npm. `package-lock.json` pins the build
tools and verifier version. CI runs on Linux with Node 24.8.0 and the current
Node 24 line.

## Before a pull request

Install with the frozen lockfile, then run the local checks:

```console
npm ci
npm test
npm run typecheck
npm run typecheck:web
npm run build
npm run build:site
npm pack --dry-run
```

The checks after installation run locally without a network connection.
The suite builds a browser bundle with the workshop's shims and exercises
real Ed25519 and ML-DSA-65 keys. The library build writes `dist/`; the site
build writes `site-dist/`.

## Windows

Developer platforms are macOS and Linux. Windows developers use WSL2,
clone inside its filesystem and follow the Linux commands. CI runs on
Linux only. Native ML-DSA tests require the supported Node crypto runtime.

## Commits

Use explicit paths when staging or committing. Keep tool directories and
local process state out of commits. Work on `main` in small commits with
plain messages unless the maintainer asks otherwise. Do not use `git stash`.

## Tests and checks

- For behavior changes, write the test, observe it fail for the intended
  reason, then make it pass. Record the observed failure in the commit.
- New checks must fail under a named temporary mutation. Restore the
  original code and run the suite again before committing.
- Use real keys and real signing callbacks. Do not use mocks, fake crypto
  or handles that return invented signatures.
- Search for tests of the old contract before changing behavior.

This repository does not run an Elixir cross-check. The Elixir signer pins
this repository at a public commit and runs this package's own test suite;
it does not compare what the two signers produce or refuse, so it does not
certify parity. The local suite verifies artifacts through the
published TypeScript verifier.

## Protocol dependency changes

Move the verifier requirement and lockfile together. Read its changelog,
test against the published package and document changes to input rules
or error codes. Keep signing fixtures canonical.

## Docs

Update documentation with the behavior it describes. Keep error names,
supported options, package metadata and the workshop's version badge in
sync. Describe only checks that run and features that ship.
