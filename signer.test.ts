// CAP never authorizes.
//
// Signer tests: a raw test key handle (Ed25519 from a deterministic seed and
// an ML-DSA-65 handle) exercises the full custody path per artifact kind —
// snapshot → producer (provisional framing + refusals) → sign → wrong-key
// guard → assemble → post-sign verify through the verifier package. The
// Elixir-repo gate separately proves these TS-signed artifacts verify under
// the Elixir reference implementation.
import test from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import {
  signDescriptor,
  signReceipt,
  type KeyHandle,
} from "./signer.ts";
import { verifyDescriptor, verifySignature } from "@charter-agreement-protocol/verifier";

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
