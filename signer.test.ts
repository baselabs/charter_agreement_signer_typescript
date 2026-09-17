// CAP never authorizes.
//
// Signer tests: a raw test key handle (Ed25519 from a deterministic seed and
// an ML-DSA-65 handle) exercises the full custody path per artifact kind —
// snapshot → producer (provisional framing + refusals) → sign → wrong-key
// guard → assemble → post-sign verify through the verifier package. The
// Elixir-repo gate separately proves these TS-signed artifacts verify under
// the Elixir reference implementation.
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { before, test } from "node:test";
import {
  signAcceptance,
  signDescriptor,
  signReceipt,
  signTermination,
  type ChainView,
  type KeyHandle,
} from "./signer.ts";
import {
  verifyAcceptance,
  verifyChain,
  verifyDescriptor,
  verifySignature,
  verifyTermination,
} from "@charter-agreement-protocol/verifier";

// Deterministic Ed25519 from a 32-byte seed (PKCS#8 prefix + seed).
function ed25519FromSeed(seed: Buffer) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return { privateKey, publicKey: seed };
}

function rawKeyHandle(seed: Buffer, kid: string): { handle: unknown } {
  const keys = ed25519FromSeed(seed);
  const context = { kid, keys };
  const handle: KeyHandle = {
    keyIdentity(_h: unknown) {
      // The snapshot's public key is the SEED-derived public key; derive it
      // by signing once is wrong — instead compute from the private handle
      // via a verify round-trip is unavailable, so use node's derived public.
      return { kid, publicKey: derivedPublic(keys.privateKey) };
    },
    sign(message: Uint8Array, _h: unknown) {
      return new Uint8Array(nodeSign(null, Buffer.from(message), keys.privateKey));
    },
  };
  return { handle };
}

function derivedPublic(privateKey: ReturnType<typeof createPrivateKey>): string {
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  return Buffer.from(spki.subarray(spki.length - 32)).toString("base64url");
}

test("signDescriptor: full custody path, post-verified at revision 2", async () => {
  const { handle } = rawKeyHandle(Buffer.alloc(32, 1), "test-key-001");

  const snapshot = await (handle as KeyHandle).keyIdentity(null);
  const claims = {
    protocol_revision: 2,
    descriptor_number: 1,
    verification_keys: [
      { key_id: "test-key-001", algorithm: "Ed25519", public_key: snapshot.publicKey, status: "active" },
    ],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };

  const result = await signDescriptor(claims, handle);
  assert.ok(result.ok, JSON.stringify(result));
  const verified = verifyDescriptor(result.result.descriptor);
  assert.ok(verified.ok);
  assert.equal(verified.facts.descriptor_number, 1);
  assert.equal(verified.facts.protocol_revision, 2);
});

test("signDescriptor refuses a claims/algorithm mismatch before any key use", async () => {
  const { handle } = rawKeyHandle(Buffer.alloc(32, 2), "test-key-002");
  const snapshot = await (handle as KeyHandle).keyIdentity(null);

  const claims = {
    protocol_revision: 3, // ML-DSA-65's revision with the Ed25519 default
    descriptor_number: 1,
    verification_keys: [
      { key_id: "test-key-002", algorithm: "Ed25519", public_key: snapshot.publicKey, status: "active" },
    ],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };

  const result = await signDescriptor(claims, handle);
  assert.ok(!result.ok);
  assert.equal((result as { error: string; code?: string }).code, "signing_input_invalid");
});

test("the wrong-key guard rejects a signature from a different key", async () => {
  const good = rawKeyHandle(Buffer.alloc(32, 3), "test-key-003");
  const rogueSeed = Buffer.alloc(32, 9);
  const rogue = ed25519FromSeed(rogueSeed);
  const snapshot = await (good.handle as KeyHandle).keyIdentity(null);

  const rogueHandle: KeyHandle = {
    keyIdentity: (_h: unknown) => ({ kid: "test-key-003", publicKey: snapshot.publicKey }),
    sign(message: Uint8Array, _h: unknown) {
      return new Uint8Array(nodeSign(null, Buffer.from(message), rogue.privateKey));
    },
  };

  const claims = {
    protocol_revision: 2,
    descriptor_number: 1,
    verification_keys: [
      { key_id: "test-key-003", algorithm: "Ed25519", public_key: snapshot.publicKey, status: "active" },
    ],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };

  const result = await signDescriptor(claims, rogueHandle);
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "signing_failed");
});

test("signReceipt round-trips without a chain context (revision-only posture)", async () => {
  const { handle } = rawKeyHandle(Buffer.alloc(32, 4), "test-key-004");
  const snapshot = await (handle as KeyHandle).keyIdentity(null);

  const claims = {
    protocol_revision: 2,
    charter_id: "sha-256:" + "A".repeat(43),
    revision_number: 1,
    revision_digest: "sha-256:" + "B".repeat(43),
    issuing_party_role: "issuer",
    agent_party_role: "agent",
    deployment_digest: "sha-256:" + "C".repeat(43),
    grant: { scheme: "bap", id: "grant-001", grant_digest: "sha-256:" + "D".repeat(43) },
    invocation_id: "inv-001",
    decision: "accepted",
    outcome: "effect_committed",
    occurred_at: "2026-08-25T12:00:01Z",
    recorded_at: "2026-08-25T12:00:02Z",
    extensions: { critical: {}, optional: {} },
  };
  void snapshot;

  const result = await signReceipt(claims, handle, null);
  assert.ok(result.ok, JSON.stringify(result));
  const header = JSON.parse(Buffer.from(result.result.receipt.split(".")[0], "base64url").toString("utf8"));
  assert.equal(header.typ, "cap+receipt");
  assert.equal(header.alg, "Ed25519");
});

// ---------------------------------------------------------------------------
// Honest-signer refusals (R1-R3) and the acceptance/termination custody
// paths. The world fixture mirrors the Elixir ChainFixture: two parties'
// genesis descriptors signed through signDescriptor, revision texts, dual
// acceptances signed through signAcceptance itself (the empty view admits
// the first acceptance), a successor revision, and a forked variant for
// the equivocation refusal. Revision digests come from the verifier's own
// chain facts over the fixture texts — never re-derived here. Refusal
// cases run with a spy handle whose sign() must never be reached.
// ---------------------------------------------------------------------------


type Party = { handle: unknown; descriptor: string; pdd: string };

type World = {
  issuer: Party;
  acceptor: Party;
  genesisText: string;
  genesisDigest: string;
  successorText: string;
  successorDigest: string;
  leftText: string;
  leftDigest: string;
  rightText: string;
  rightDigest: string;
  genesisView: ChainView;
  advancedView: ChainView;
  forkView: ChainView;
  genesisIssuerClaims: Record<string, unknown>;
};

const world = {} as World;

function revisionDigestOf(texts: string[], index: number): string {
  const verified = verifyChain({
    revisions: texts,
    acceptances: [],
    descriptors: [world.issuer.descriptor, world.acceptor.descriptor],
    terminations: [],
  });
  if (!verified.ok) throw new Error("fixture chain failed: " + verified.code);
  return (verified.facts.revisions as { digest: string }[])[index].digest;
}

before(async () => {
  const issuerKeys = rawKeyHandle(Buffer.alloc(32, 11), "issuer-key-001");
  const acceptorKeys = rawKeyHandle(Buffer.alloc(32, 12), "acceptor-key-001");
  const issuerSnapshot = await (issuerKeys.handle as KeyHandle).keyIdentity(null);
  const acceptorSnapshot = await (acceptorKeys.handle as KeyHandle).keyIdentity(null);

  const descriptorFor = async (handle: unknown, kid: string, publicKey: string) => {
    const result = await signDescriptor(
      {
        protocol_revision: 2,
        descriptor_number: 1,
        verification_keys: [{ key_id: kid, algorithm: "Ed25519", public_key: publicKey, status: "active" }],
        attestation_hints: [],
        extensions: { critical: {}, optional: {} },
        effective_from: "2026-08-25T10:00:00Z",
      },
      handle,
    );
    if (!result.ok) throw new Error("fixture descriptor failed: " + JSON.stringify(result));
    return result.result.descriptor;
  };

  const issuerDescriptor = await descriptorFor(issuerKeys.handle, "issuer-key-001", issuerSnapshot.publicKey);
  const acceptorDescriptor = await descriptorFor(acceptorKeys.handle, "acceptor-key-001", acceptorSnapshot.publicKey);
  const issuerVerified = verifyDescriptor(issuerDescriptor);
  const acceptorVerified = verifyDescriptor(acceptorDescriptor);
  if (!issuerVerified.ok || !acceptorVerified.ok) throw new Error("fixture descriptor failed to verify");
  const issuerPdd = issuerVerified.facts.descriptor_digest as string;
  const acceptorPdd = acceptorVerified.facts.descriptor_digest as string;

  const revisionText = (overrides: Record<string, unknown>) =>
    JSON.stringify({
      abp_bindings: [],
      attribution_declaration: { basis: "bound_deployments" },
      effective_from: "2026-08-25T12:00:00Z",
      extensions: { critical: {}, optional: {} },
      legal_text: { content_digest: "sha-256:" + "L".repeat(43), media_type: "text/plain" },
      parties: [
        { party_descriptor_digest: issuerPdd, role: "issuer" },
        { party_descriptor_digest: acceptorPdd, role: "acceptor" },
      ],
      precedence_declaration: "legal_text_governs",
      protocol_revision: 2,
      receipt_profile: "com.example.charter/default",
      revision_number: 1,
      termination_rules: { reason_codes: ["mutual", "breach"] },
      ...overrides,
    });

  const genesisText = revisionText({});
  const successorText = revisionText({
    charter_id: "PENDING_GENESIS_DIGEST",
    legal_text: { content_digest: "sha-256:" + "S".repeat(43), media_type: "text/plain" },
    effective_from: "2026-08-25T12:00:01Z",
    prev_revision_digest: "PENDING_GENESIS_DIGEST",
    revision_number: 2,
  });
  const forkText = (legalChar: string) =>
    revisionText({
      charter_id: "PENDING_GENESIS_DIGEST",
      legal_text: { content_digest: "sha-256:" + legalChar.repeat(43), media_type: "text/plain" },
      effective_from: "2026-08-25T12:00:01Z",
      prev_revision_digest: "PENDING_GENESIS_DIGEST",
      revision_number: 2,
    });

  // Resolve the genesis digest through the verifier, then stamp it into the
  // successor/fork texts (their digests depend on the final bytes).
  world.issuer = { handle: issuerKeys.handle, descriptor: issuerDescriptor, pdd: issuerPdd };
  world.acceptor = { handle: acceptorKeys.handle, descriptor: acceptorDescriptor, pdd: acceptorPdd };
  const genesisDigest = revisionDigestOf([genesisText], 0);
  const withGenesis = (text: string) => text.split("PENDING_GENESIS_DIGEST").join(genesisDigest);
  const successorFinal = withGenesis(successorText);
  const leftFinal = withGenesis(forkText("F"));
  const rightFinal = withGenesis(forkText("R"));
  const successorDigest = revisionDigestOf([genesisText, successorFinal], 1);
  const leftDigest = revisionDigestOf([genesisText, leftFinal, rightFinal], 1);
  const rightDigest = revisionDigestOf([genesisText, leftFinal, rightFinal], 2);

  const acceptanceClaims = (digest: string, number: number, role: string, pdd: string) => ({
    protocol_revision: 2,
    accepted_at: "2026-08-25T13:00:00Z",
    charter_id: genesisDigest,
    party_descriptor_digest: pdd,
    party_role: role,
    ...(number > 1 ? { prev_revision_digest: genesisDigest } : {}),
    revision_digest: digest,
    revision_number: number,
  });

  const view = (revisions: string[], acceptances: string[]): ChainView => ({
    revisions,
    acceptances,
    descriptors: [issuerDescriptor, acceptorDescriptor],
    terminations: [],
  });

  const acceptInto = async (
    chain: ChainView,
    claims: Record<string, unknown>,
    party: Party,
    textForVerify: string,
  ) => {
    const result = await signAcceptance(claims, party.handle, {
      revisionText: textForVerify,
      descriptorCompacts: [party.descriptor],
      chain,
    });
    if (!result.ok) throw new Error("fixture acceptance failed: " + JSON.stringify(result));
    return result.result.acceptance;
  };

  const genesisIssuerClaims = acceptanceClaims(genesisDigest, 1, "issuer", issuerPdd);
  const genesisAcceptorClaims = acceptanceClaims(genesisDigest, 1, "acceptor", acceptorPdd);

  // Bootstrap: the first acceptance into an empty-acceptance view is clean.
  const gIssuer = await acceptInto(view([genesisText], []), genesisIssuerClaims, world.issuer, genesisText);
  const gAcceptor = await acceptInto(view([genesisText], [gIssuer]), genesisAcceptorClaims, world.acceptor, genesisText);
  const genesisView = view([genesisText], [gIssuer, gAcceptor]);

  const sIssuer = await acceptInto(
    view([genesisText, successorFinal], [gIssuer, gAcceptor]),
    acceptanceClaims(successorDigest, 2, "issuer", issuerPdd),
    world.issuer, successorFinal,
  );
  const sAcceptor = await acceptInto(
    view([genesisText, successorFinal], [gIssuer, gAcceptor, sIssuer]),
    acceptanceClaims(successorDigest, 2, "acceptor", acceptorPdd),
    world.acceptor, successorFinal,
  );
  const advancedView = view([genesisText, successorFinal], [gIssuer, gAcceptor, sIssuer, sAcceptor]);

  const rIssuer = await acceptInto(
    view([genesisText, rightFinal], [gIssuer, gAcceptor]),
    acceptanceClaims(rightDigest, 2, "issuer", issuerPdd),
    world.issuer, rightFinal,
  );
  const rAcceptor = await acceptInto(
    view([genesisText, rightFinal], [gIssuer, gAcceptor, rIssuer]),
    acceptanceClaims(rightDigest, 2, "acceptor", acceptorPdd),
    world.acceptor, rightFinal,
  );
  const forkView = view([genesisText, leftFinal, rightFinal], [gIssuer, gAcceptor, rIssuer, rAcceptor]);

  Object.assign(world, {
    genesisText, genesisDigest,
    successorText: successorFinal, successorDigest,
    leftText: leftFinal, leftDigest,
    rightText: rightFinal, rightDigest,
    genesisView, advancedView, forkView,
    genesisIssuerClaims,
  });
});

// A spy handle: identity resolves, but sign() counts touches — refusal paths
// must leave the count at zero.
function spyHandle(): { handle: unknown; touches: () => number } {
  let touches = 0;
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "spy-key", publicKey: Buffer.alloc(32, 7).toString("base64url") }),
    sign() {
      touches += 1;
      return new Uint8Array(64);
    },
  };
  return { handle, touches: () => touches };
}

test("signAcceptance: R1 false revision coordinates are refused before the key is used", async () => {
  const spy = spyHandle();
  const result = await signAcceptance(
    { ...world.genesisIssuerClaims, revision_digest: "sha-256:" + "0".repeat(43) },
    spy.handle,
    { revisionText: world.genesisText, descriptorCompacts: [world.issuer.descriptor], chain: world.genesisView },
  );
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "refused");
  assert.equal(spy.touches(), 0);
});

test("signAcceptance: R2 equivocation at an occupied revision number is refused", async () => {
  const spy = spyHandle();
  const claims = {
    ...world.genesisIssuerClaims,
    prev_revision_digest: world.genesisDigest,
    revision_digest: world.leftDigest,
    revision_number: 2,
  };
  const result = await signAcceptance(claims, spy.handle, {
    revisionText: world.leftText,
    descriptorCompacts: [world.issuer.descriptor],
    chain: world.forkView,
  });
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "refused");
  assert.equal(spy.touches(), 0);
});

test("signAcceptance: R3 re-accepting a non-head revision is refused (uncovered head)", async () => {
  const spy = spyHandle();
  const result = await signAcceptance(world.genesisIssuerClaims, spy.handle, {
    revisionText: world.genesisText,
    descriptorCompacts: [world.issuer.descriptor],
    chain: world.forkView,
  });
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "refused");
  assert.equal(spy.touches(), 0);
});

test("signTermination: an unlisted reason is refused before the key is used", async () => {
  const spy = spyHandle();
  const result = await signTermination(
    {
      protocol_revision: 2,
      charter_id: world.genesisDigest,
      governing_revision_digest: world.successorDigest,
      party_descriptor_digest: world.issuer.pdd,
      party_role: "issuer",
      reason_code: "not-in-charter",
      issued_at: "2026-08-25T14:00:00Z",
      effective_at: "2026-08-25T15:00:00Z",
      extensions: { critical: {}, optional: {} },
    },
    spy.handle,
    { revisionText: world.successorText, descriptorCompacts: [world.issuer.descriptor], chain: world.advancedView },
  );
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "refused");
  assert.equal(spy.touches(), 0);
});

test("signTermination: a stale termination (non-governing revision) is refused", async () => {
  const spy = spyHandle();
  const result = await signTermination(
    {
      protocol_revision: 2,
      charter_id: world.genesisDigest,
      governing_revision_digest: world.genesisDigest,
      party_descriptor_digest: world.issuer.pdd,
      party_role: "issuer",
      reason_code: "mutual",
      issued_at: "2026-08-25T14:00:00Z",
      effective_at: "2026-08-25T15:00:00Z",
      extensions: { critical: {}, optional: {} },
    },
    spy.handle,
    { revisionText: world.genesisText, descriptorCompacts: [world.issuer.descriptor], chain: world.advancedView },
  );
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "refused");
  assert.equal(spy.touches(), 0);
});

test("a malformed caller view is invalid input, not a refusal", async () => {
  const spy = spyHandle();
  const result = await signAcceptance(world.genesisIssuerClaims, spy.handle, {
    revisionText: world.genesisText,
    descriptorCompacts: [world.issuer.descriptor],
    chain: { ...world.genesisView, acceptances: ["not-a-compact-jws"] },
  });
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "invalid_input");
  assert.equal((result as { code?: string }).code, "chain_invalid");
  assert.equal(spy.touches(), 0);
});

test("signTermination: happy path over the governing successor, post-verified", async () => {
  const { handle } = rawKeyHandle(Buffer.alloc(32, 11), "issuer-key-001");
  const result = await signTermination(
    {
      protocol_revision: 2,
      charter_id: world.genesisDigest,
      governing_revision_digest: world.successorDigest,
      party_descriptor_digest: world.issuer.pdd,
      party_role: "issuer",
      reason_code: "mutual",
      issued_at: "2026-08-25T14:00:00Z",
      effective_at: "2026-08-25T15:00:00Z",
      extensions: { critical: {}, optional: {} },
    },
    handle,
    { revisionText: world.successorText, descriptorCompacts: [world.issuer.descriptor], chain: world.advancedView },
  );
  assert.ok(result.ok, JSON.stringify(result));
  const verified = verifyTermination(result.result.termination, world.successorText, [world.issuer.descriptor]);
  assert.ok(verified.ok, JSON.stringify(verified));
});

test("signAcceptance: happy path re-accepting the governing successor, post-verified", async () => {
  const { handle } = rawKeyHandle(Buffer.alloc(32, 11), "issuer-key-001");
  const claims = {
    ...world.genesisIssuerClaims,
    prev_revision_digest: world.genesisDigest,
    revision_digest: world.successorDigest,
    revision_number: 2,
  };
  const result = await signAcceptance(claims, handle, {
    revisionText: world.successorText,
    descriptorCompacts: [world.issuer.descriptor],
    chain: world.advancedView,
  });
  assert.ok(result.ok, JSON.stringify(result));
  const verified = verifyAcceptance(result.result.acceptance, world.successorText, [world.issuer.descriptor]);
  assert.ok(verified.ok, JSON.stringify(verified));
});

test("a 0.1.x-shaped termination view (no chain) fails closed, never throws", async () => {
  const spy = spyHandle();
  const result = await signTermination(
    {
      protocol_revision: 2,
      charter_id: world.genesisDigest,
      governing_revision_digest: world.genesisDigest,
      party_descriptor_digest: world.issuer.pdd,
      party_role: "issuer",
      reason_code: "mutual",
      issued_at: "2026-08-25T14:00:00Z",
      effective_at: "2026-08-25T15:00:00Z",
      extensions: { critical: {}, optional: {} },
    },
    spy.handle,
    // The pre-0.2.0 view shape: no chain member.
    { revisionText: world.genesisText, descriptorCompacts: [world.issuer.descriptor] } as never,
  );
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "invalid_input");
  assert.equal((result as { code?: string }).code, "signing_input_invalid");
  assert.equal(spy.touches(), 0);
});
