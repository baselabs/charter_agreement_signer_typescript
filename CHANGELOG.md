# Changelog

All notable public changes to `@charter-agreement-protocol/signer` are
documented here.

## [Unreleased]

### Documentation

- The verify side moved: `@charter-agreement-protocol/verifier` 0.5.0 is
  live — it mirrors the protocol package's 0.4.0 release-identity act
  (`capabilities()`, the signature registry identity
  `algorithmRegistryDigest()`, the descriptor timestamp floor, and the
  104-case certified corpus). Nothing breaks this package: its dependency
  stays `^0.4.0` deliberately (caret on 0.x pins the minor),
  the producer surface it delegates to is unchanged, and the wire is
  unchanged (`protocol_revision` stays 3).
- The producer-side capability alignment is recorded as a contract with
  the protocol repository (a mirrored `capabilities()` probe with
  refuse-before-mint, declared minting metadata, a profile-bound signing
  mode). When it lands here, the dependency moves to `^0.5.0`
  in the same release — a deliberate one-line bump, never a silent
  re-resolve.

## [0.2.0] — 2026-09-17

### Changed

- **The R1–R3 honest-signer refusals now run pre-sign** (previously
  deferred to post-sign verification with mislabeled errors; the `refused`
  error was unreachable): `signAcceptance` / `signTermination` run the
  verifier package's refusal checks after framing, before the key signs.
  Breaking within 0.x: `signTermination`'s view requires `chain`,
  `signAcceptance` enforces the guards over the `chain` it previously
  ignored, and `signReceipt` requires its issuing view (the reference
  takes a context, never none).
- Post-sign verification failures return the bare `verification_failed`
  (the reference vocabulary); malformed claims are rejected pre-sign as
  `invalid_input` through the producer claims gate — no claim-shape defect
  burns a key operation.
- **All protocol logic is delegated to the verifier package's producer
  surface (`^0.4.0`)**: framing, the claims gate, the refusal guards, and
  assembly; this package keeps custody only (atomic snapshot, sign
  callback, wrong-key guard, post-sign verification, closed errors).

## [0.1.x] — 2026-09-14

- Initial public releases: one signing function per artifact kind, the
  key-handle contract with the atomic `keyIdentity` snapshot, the
  wrong-key guard, and post-sign verification through
  `@charter-agreement-protocol/verifier`.
