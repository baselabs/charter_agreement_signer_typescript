// CAP never authorizes.
//
// Real key handles exercise preparation, signing, the wrong-key guard,
// and completion through the verifier package.
import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { before, test } from "node:test";
import { runInNewContext } from "node:vm";
import {
  signAcceptance,
  signDescriptor,
  signReceipt,
  signTermination,
  type ChainView,
  type KeyHandle,
} from "./signer.ts";
import {
  canonical,
  prepareSigning,
  MAXIMUM_LIMITS,
  type SigningKind,
  decodeCharterRevision,
  decodeJsonText,
  descriptorSigningInput,
  acceptanceSigningInput,
  terminationSigningInput,
  receiptSigningInput,
  assembleCompact,
  revisionDigest,
  verifyAcceptance,
  verifyChain,
  verifyDescriptor,
  verifyReceipt,
  verifySignature,
  verifyTermination,
} from "@charter-agreement-protocol/verifier";

// Deterministic Ed25519 from a 32-byte seed (PKCS#8 prefix + seed).
function ed25519FromSeed(seed: Buffer) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return { privateKey };
}

function rawKeyHandle(seed: Buffer, kid: string): { handle: unknown } {
  const keys = ed25519FromSeed(seed);
  const handle: KeyHandle = {
    keyIdentity(_h: unknown) {
      // Derive the public key from the held private KeyObject.
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

function digestOf(text: string): string {
  return "sha-256:" + createHash("sha256").update(text).digest("base64url");
}

function receiptClaims(): Record<string, unknown> {
  return {
    protocol_revision: 2,
    charter_id: world.genesisDigest,
    revision_number: 1,
    revision_digest: world.genesisDigest,
    issuing_party_role: "issuer",
    agent_party_role: "acceptor",
    deployment_digest: world.deploymentDigest,
    grant: { scheme: "bap", id: "grant-001", grant_digest: digestOf("example receipt reference bytes") },
    invocation_id: "inv-001",
    decision: "accepted",
    outcome: "effect_committed",
    occurred_at: "2026-08-25T13:30:00Z",
    recorded_at: "2026-08-25T13:30:01Z",
    extensions: { critical: {}, optional: {} },
  };
}

function signingCalls(handle: unknown) {
  const view = world.genesisView;
  const publicKey = derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey);
  const descriptorClaims = {
    protocol_revision: 2,
    descriptor_number: 1,
    verification_keys: [{ key_id: "issuer-key-001", algorithm: "Ed25519", public_key: publicKey, status: "active" }],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };
  const terminationClaims = {
    protocol_revision: 2,
    charter_id: world.genesisDigest,
    governing_revision_digest: world.genesisDigest,
    party_descriptor_digest: world.issuer.pdd,
    party_role: "issuer",
    reason_code: "mutual",
    issued_at: "2026-08-25T14:00:00Z",
    effective_at: "2026-08-25T15:00:00Z",
  };
  type Options = Parameters<typeof signDescriptor>[2];
  return [
    { kind: "descriptor", claims: descriptorClaims, call: (opts: Options) => signDescriptor(descriptorClaims, handle, opts) },
    { kind: "receipt", claims: receiptClaims(), call: (opts: Options) => signReceipt(receiptClaims(), handle, world.genesisView, opts) },
    { kind: "acceptance", claims: world.genesisIssuerClaims, call: (opts: Options) => signAcceptance(world.genesisIssuerClaims, handle, view, opts) },
    { kind: "termination", claims: terminationClaims, call: (opts: Options) => signTermination(terminationClaims, handle, view, opts) },
  ];
}

function copyChain(chain: ChainView): ChainView {
  return {
    revisions: [...chain.revisions],
    acceptances: [...chain.acceptances],
    descriptors: [...chain.descriptors],
    terminations: [...chain.terminations],
  };
}

test("signReceipt keeps entry acceptances when sign empties the caller's array", async () => {
  const chain = copyChain(world.genesisView);
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "issuer-key-001", publicKey: derivedPublic(keys.privateKey) }),
    sign(message) {
      signs += 1;
      chain.acceptances.length = 0;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  const result = await signReceipt(receiptClaims(), handle, chain);
  assert.equal(signs, 1);
  assert.equal(chain.acceptances.length, 0);
  assert.ok(result.ok, JSON.stringify(result));
  assert.ok(verifyReceipt(result.result.receipt, world.genesisView).ok);
  assert.equal(verifyReceipt(result.result.receipt, chain).ok, false);
});

test("signReceipt copies all four arrays before keyIdentity can mutate them", async () => {
  for (const field of ["revisions", "acceptances", "descriptors", "terminations"] as const) {
    const chain = copyChain(world.genesisView);
    const keys = ed25519FromSeed(Buffer.alloc(32, 11));
    const handle: KeyHandle = {
      async keyIdentity() {
        chain[field].splice(0, chain[field].length, "invalid artifact text");
        return { kid: "issuer-key-001", publicKey: derivedPublic(keys.privateKey) };
      },
      sign: (message) => nodeSign(null, message, keys.privateKey),
    };
    const result = await signReceipt(receiptClaims(), handle, chain);
    assert.ok(result.ok, `${field}: ${JSON.stringify(result)}`);
    assert.ok(verifyReceipt(result.result.receipt, world.genesisView).ok);
  }
});

test("acceptance and termination retain entry views across both key callbacks", async () => {
  for (const kind of ["acceptance", "termination"] as const) {
    for (const mutateAt of ["identity", "sign"] as const) {
      const chain = copyChain(world.genesisView);
      const view = chain;
      const keys = ed25519FromSeed(Buffer.alloc(32, 11));
      const mutate = () => {
        chain.acceptances.length = 0;
        chain.revisions.length = 0;
        chain.descriptors.length = 0;
        chain.terminations.push("invalid artifact text");
      };
      const handle: KeyHandle = {
        keyIdentity() {
          if (mutateAt === "identity") mutate();
          return { kid: "issuer-key-001", publicKey: derivedPublic(keys.privateKey) };
        },
        sign(message) {
          if (mutateAt === "sign") mutate();
          return nodeSign(null, message, keys.privateKey);
        },
      };
      if (kind === "acceptance") {
        const result = await signAcceptance(world.genesisIssuerClaims, handle, view);
        assert.ok(result.ok, `${kind}/${mutateAt}: ${JSON.stringify(result)}`);
        assert.ok(verifyAcceptance(result.result.acceptance, world.genesisText, [world.issuer.descriptor]).ok);
      } else {
        const result = await signTermination({
          protocol_revision: 2,
          charter_id: world.genesisDigest,
          governing_revision_digest: world.genesisDigest,
          party_descriptor_digest: world.issuer.pdd,
          party_role: "issuer",
          reason_code: "mutual",
          issued_at: "2026-08-25T14:00:00Z",
          effective_at: "2026-08-25T15:00:00Z",
        }, handle, view);
        assert.ok(result.ok, `${kind}/${mutateAt}: ${JSON.stringify(result)}`);
        assert.ok(verifyTermination(result.result.termination, world.genesisText, [world.issuer.descriptor]).ok);
      }
    }
  }
});

test("unsupported algorithm values return algorithm_unsupported before either key callback", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  let identities = 0;
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity() {
      identities += 1;
      return { kid: "issuer-key-001", publicKey: derivedPublic(keys.privateKey) };
    },
    sign(message) {
      signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  const invalidValues = ["", "EdDSA", "ML-DSA-44", "ML-DSA-87", "unknown", "constructor", "__proto__", 0, 42, false, true, [], {}, Symbol("algorithm")];
  for (const algorithm of invalidValues) {
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call({ algorithm } as never),
        { ok: false, error: "invalid_input", code: "algorithm_unsupported" }, kind);
      assert.equal(identities, 0, kind);
      assert.equal(signs, 0, kind);
    }
  }
  for (const { kind, call } of signingCalls(null)) {
    assert.deepEqual(await call({ algorithm: "unknown" }),
      { ok: false, error: "invalid_input", code: "algorithm_unsupported" }, kind);
  }
});

test("absent, undefined and null algorithms select Ed25519 on every signing entry point", async () => {
  const { handle } = rawKeyHandle(Buffer.alloc(32, 11), "issuer-key-001");
  for (const opts of [undefined, {}, { algorithm: undefined }, { algorithm: null }, { algorithm: "Ed25519" }]) {
    for (const { kind, call } of signingCalls(handle)) {
      const result = await call(opts as never);
      assert.ok(result.ok, `${kind}: ${JSON.stringify(result)}`);
      const compact = Object.values(result.result)[0];
      const header = JSON.parse(Buffer.from(compact.split(".")[0], "base64url").toString("utf8"));
      assert.equal(header.alg, "Ed25519", kind);
    }
  }
});

test("malformed key snapshots return invalid_key_handle on every signing entry point", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 17));
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "", publicKey: derivedPublic(keys.privateKey) }),
    sign(message) {
      signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  const expected = { ok: false, error: "invalid_key_handle" };
  assert.deepEqual(await signDescriptor({}, handle), expected);
  assert.deepEqual(await signReceipt({}, handle, world.genesisView), expected);
  const view = world.genesisView;
  assert.deepEqual(await signAcceptance({}, handle, view), expected);
  assert.deepEqual(await signTermination({}, handle, view), expected);
  assert.equal(signs, 0);
});

test("empty or non-string snapshot public keys remain invalid before signing", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 17));
  let signs = 0;
  for (const publicKey of ["", " ", null, undefined, 42, new Uint8Array(32)]) {
    const handle: KeyHandle = {
      keyIdentity: () => ({ kid: "snapshot-key", publicKey } as never),
      sign(message) {
        signs += 1;
        return nodeSign(null, message, keys.privateKey);
      },
    };
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call(undefined), { ok: false, error: "invalid_key_handle" }, kind);
    }
  }
  assert.equal(signs, 0);
});

test("Node mints Ed25519 and ML-DSA-65 genesis descriptors with real keys", async () => {
  for (const algorithm of ["Ed25519", "ML-DSA-65"] as const) {
    const keys = algorithm === "Ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ml-dsa-65");
    const keyBytes = algorithm === "Ed25519" ? 32 : 1952;
    const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).subarray(-keyBytes).toString("base64url");
    const protocolRevision = algorithm === "Ed25519" ? 2 : 3;
    let signs = 0;
    const handle: KeyHandle = {
      keyIdentity: () => ({ kid: "genesis-key", publicKey }),
      sign(message) {
        signs += 1;
        return nodeSign(null, message, keys.privateKey);
      },
    };
    const result = await signDescriptor({
      protocol_revision: protocolRevision,
      descriptor_number: 1,
      verification_keys: [{ key_id: "genesis-key", algorithm, public_key: publicKey, status: "active" }],
      attestation_hints: [],
      extensions: { critical: {}, optional: {} },
      effective_from: "2026-08-25T10:00:00Z",
    }, handle, { algorithm });
    assert.equal(signs, 1, algorithm);
    assert.ok(result.ok, `${algorithm}: ${JSON.stringify(result)}`);
    const verified = verifyDescriptor(result.result.descriptor);
    assert.ok(verified.ok, `${algorithm}: ${JSON.stringify(verified)}`);
    assert.equal(verified.facts.descriptor_number, 1);
    assert.equal(verified.facts.protocol_revision, protocolRevision);
    assert.equal(verified.facts.alg, algorithm);
  }
});

function callbackCounts(seed: number, kid: string) {
  const keys = ed25519FromSeed(Buffer.alloc(32, seed));
  const counts = { identities: 0, signs: 0 };
  const handle: KeyHandle = {
    keyIdentity() {
      counts.identities += 1;
      return { kid, publicKey: derivedPublic(keys.privateKey) };
    },
    sign(message) {
      counts.signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  return { handle, counts };
}

test("options outside the record shape return invalid_type before either key callback", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const opts of [null, 42, [], "ML-DSA-65", true, 1n, Symbol("options"), new Number(1)]) {
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call(opts as never),
        { ok: false, error: "invalid_input", code: "invalid_type" }, kind);
    }
  }
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});

test("option records follow the verifier's accepted shapes", async () => {
  class Options { algorithm = "Ed25519"; }
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const opts of [new Map([["algorithm", "ML-DSA-65"]]), new Options()]) {
    for (const { kind, call } of signingCalls(handle)) {
      const result = await call(opts as never);
      assert.ok(result.ok, `${kind}: ${JSON.stringify(result)}`);
    }
  }
  assert.deepEqual(counts, { identities: 8, signs: 8 });
});

test("unknown option keys and throwing getters return invalid_type before either key callback", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const opts = Object.defineProperty({}, "algorithm", { enumerable: true, get() { throw new Error("getter"); } });
  for (const value of [opts, { algoritm: "ML-DSA-65" }, { algorithm: "Ed25519", extra: true }]) {
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call(value), { ok: false, error: "invalid_input", code: "invalid_type" }, kind);
    }
  }
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});

test("a handle that is not an object, or whose keyIdentity throws, is invalid_key_handle before signing", async () => {
  let signs = 0;
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const throwing = {
    keyIdentity() {
      throw new Error("custody unavailable");
    },
    sign(message: Uint8Array) {
      signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  for (const handle of [undefined, null, 7, "handle", throwing]) {
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call({}), { ok: false, error: "invalid_key_handle" }, `${kind} ${String(handle)}`);
    }
  }
  assert.equal(signs, 0);
});

test("claims changed by a key callback after entry do not change what is signed, for every kind and for Proxy claims", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const publicKey = derivedPublic(keys.privateKey);
  const view = world.genesisView;
  const kinds: Array<{ kind: string; claims: () => Record<string, any>; field: string; changed: unknown; call: (claims: Record<string, unknown>, handle: KeyHandle) => Promise<any> }> = [
    {
      kind: "descriptor",
      claims: () => ({
        protocol_revision: 2,
        descriptor_number: 1,
        verification_keys: [{ key_id: "issuer-key-001", algorithm: "Ed25519", public_key: publicKey, status: "active" }],
        attestation_hints: [],
        extensions: { critical: {}, optional: {} },
        effective_from: "2026-08-25T10:00:00Z",
      }),
      field: "effective_from",
      changed: "2026-08-25T11:00:00Z",
      call: (claims, handle) => signDescriptor(claims, handle),
    },
    { kind: "receipt", claims: () => structuredClone(receiptClaims()) as Record<string, any>, field: "outcome", changed: "effect_failed", call: (claims, handle) => signReceipt(claims, handle, world.genesisView) },
    { kind: "acceptance", claims: () => structuredClone(world.genesisIssuerClaims), field: "accepted_at", changed: "2026-08-25T13:00:01Z", call: (claims, handle) => signAcceptance(claims, handle, view) },
    {
      kind: "termination",
      claims: () => ({
        protocol_revision: 2,
        charter_id: world.genesisDigest,
        governing_revision_digest: world.genesisDigest,
        party_descriptor_digest: world.issuer.pdd,
        party_role: "issuer",
        reason_code: "mutual",
        issued_at: "2026-08-25T14:00:00Z",
        effective_at: "2026-08-25T15:00:00Z",
      }),
      field: "reason_code",
      changed: "breach",
      call: (claims, handle) => signTermination(claims, handle, view),
    },
  ];
  const wrappers: Array<[string, (claims: Record<string, any>) => Record<string, any>]> = [
    ["plain", (claims) => claims],
    ["proxy", (claims) => new Proxy(claims, {})],
    ["nested proxy", (claims) => {
      const key = Object.keys(claims).find((name) => typeof claims[name] === "object" && claims[name] !== null);
      if (key) claims[key] = new Proxy(claims[key], {});
      return new Proxy(claims, {});
    }],
  ];
  for (const { kind, claims: make, field, changed, call } of kinds) {
    for (const [label, wrap] of wrappers) {
      const target = make();
      const original = target[field];
      const claims = wrap(target);
      const handle: KeyHandle = {
        keyIdentity() {
          target[field] = changed;
          return { kid: "issuer-key-001", publicKey };
        },
        sign: (message) => nodeSign(null, message, keys.privateKey),
      };
      const result = await call(claims, handle);
      assert.ok(result.ok, `${kind} ${label}: ${JSON.stringify(result)}`);
      const compact = Object.values(result.result)[0] as string;
      const payload = JSON.parse(Buffer.from(compact.split(".")[1], "base64url").toString("utf8"));
      assert.equal(payload[field], original, `${kind} ${label}`);
    }
  }
});

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

  let signs = 0;
  const counted: KeyHandle = {
    keyIdentity: (h) => (handle as KeyHandle).keyIdentity(h),
    sign(message, h) {
      signs += 1;
      return (handle as KeyHandle).sign(message, h);
    },
  };
  const result = await signDescriptor(claims, counted);
  assert.ok(!result.ok);
  assert.equal((result as { error: string; code?: string }).code, "signing_input_invalid");
  assert.equal(signs, 0);
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

test("signReceipt rejects a missing or chain-invalid issuing view before the key is used", async () => {
  // Well-formed claims: the ONLY rejection path is the view gate, so this
  // goes red if the gate is removed (empty claims would be rejected by
  // framing regardless, proving nothing about the gate).
  const counted = countingHandle();
  const claims = {
    protocol_revision: 2,
    charter_id: world.genesisDigest,
    revision_number: 1,
    revision_digest: world.genesisDigest,
    issuing_party_role: "issuer",
    agent_party_role: "acceptor",
    deployment_digest: world.deploymentDigest,
    grant: { scheme: "bap", id: "grant-001", grant_digest: digestOf("example receipt reference bytes") },
    invocation_id: "inv-001",
    decision: "accepted",
    outcome: "effect_committed",
    occurred_at: "2026-08-25T13:30:00Z",
    recorded_at: "2026-08-25T13:30:01Z",
    extensions: { critical: {}, optional: {} },
  };
  const missing = await signReceipt(claims, counted.handle, null as never);
  assert.ok(!missing.ok);
  assert.equal((missing as { error: string }).error, "invalid_input");
  assert.equal((missing as { code?: string }).code, "invalid_type");
  assert.equal(counted.touches(), 0);

  const broken: ChainView = { ...world.genesisView, acceptances: ["not-a-compact-jws"] };
  const invalid = await signReceipt(claims, counted.handle, broken);
  assert.ok(!invalid.ok);
  assert.equal((invalid as { error: string }).error, "invalid_input");
  assert.equal((invalid as { code?: string }).code, "compact_invalid");
  assert.equal(counted.touches(), 0);
});

test("a missing view object is the closed invalid_input, never a throw", async () => {
  const counted = countingHandle();
  const acceptance = await signAcceptance(world.genesisIssuerClaims, counted.handle, undefined as never);
  assert.ok(!acceptance.ok);
  assert.equal((acceptance as { error: string }).error, "invalid_input");
  assert.equal(counted.touches(), 0);
});

// ---------------------------------------------------------------------------
// Honest-signer refusals (R1-R3) and the acceptance/termination custody
// paths. The world fixture mirrors the Elixir ChainFixture: two parties'
// genesis descriptors signed through signDescriptor, revision texts, dual
// acceptances signed through signAcceptance itself (the empty view admits
// the first acceptance), a successor revision, and a forked variant for
// the equivocation refusal. Revision digests come from the verifier's own
// chain facts over the fixture texts — never re-derived here. Refusal
// cases count real signing calls, which must remain at zero.
// ---------------------------------------------------------------------------


type Party = { handle: unknown; descriptor: string; pdd: string };

type World = {
  issuer: Party;
  acceptor: Party;
  deploymentDigest: string;
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

  const deploymentDigest = digestOf("example deployment bytes");
  const revisionText = (overrides: Record<string, unknown>) =>
    canonical({
      abp_bindings: [
        {
          blueprint_id: "example.demo/echo",
          content_digest: digestOf("example blueprint bytes"),
          deployment_digest: deploymentDigest,
          party_role: "acceptor",
          release_number: 1,
        },
      ],
      attribution_declaration: { basis: "bound_deployments" },
      effective_from: "2026-08-25T12:00:00Z",
      extensions: { critical: {}, optional: {} },
      legal_text: { content_digest: digestOf("genesis legal text"), media_type: "text/plain" },
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
    legal_text: { content_digest: digestOf("successor legal text"), media_type: "text/plain" },
    effective_from: "2026-08-25T12:00:01Z",
    prev_revision_digest: "PENDING_GENESIS_DIGEST",
    revision_number: 2,
  });
  const forkText = (legalText: string) =>
    revisionText({
      charter_id: "PENDING_GENESIS_DIGEST",
      legal_text: { content_digest: digestOf(legalText), media_type: "text/plain" },
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
  ) => {
    const result = await signAcceptance(claims, party.handle, chain);
    if (!result.ok) throw new Error("fixture acceptance failed: " + JSON.stringify(result));
    return result.result.acceptance;
  };

  const genesisIssuerClaims = acceptanceClaims(genesisDigest, 1, "issuer", issuerPdd);
  const genesisAcceptorClaims = acceptanceClaims(genesisDigest, 1, "acceptor", acceptorPdd);

  // Bootstrap: the first acceptance into an empty-acceptance view is clean.
  const gIssuer = await acceptInto(view([genesisText], []), genesisIssuerClaims, world.issuer);
  const gAcceptor = await acceptInto(view([genesisText], [gIssuer]), genesisAcceptorClaims, world.acceptor);
  const genesisView = view([genesisText], [gIssuer, gAcceptor]);

  const sIssuer = await acceptInto(
    view([genesisText, successorFinal], [gIssuer, gAcceptor]),
    acceptanceClaims(successorDigest, 2, "issuer", issuerPdd),
    world.issuer,
  );
  const sAcceptor = await acceptInto(
    view([genesisText, successorFinal], [gIssuer, gAcceptor, sIssuer]),
    acceptanceClaims(successorDigest, 2, "acceptor", acceptorPdd),
    world.acceptor,
  );
  const advancedView = view([genesisText, successorFinal], [gIssuer, gAcceptor, sIssuer, sAcceptor]);

  const rIssuer = await acceptInto(
    view([genesisText, rightFinal], [gIssuer, gAcceptor]),
    acceptanceClaims(rightDigest, 2, "issuer", issuerPdd),
    world.issuer,
  );
  const rAcceptor = await acceptInto(
    view([genesisText, rightFinal], [gIssuer, gAcceptor, rIssuer]),
    acceptanceClaims(rightDigest, 2, "acceptor", acceptorPdd),
    world.acceptor,
  );
  const forkView = view([genesisText, leftFinal, rightFinal], [gIssuer, gAcceptor, rIssuer, rAcceptor]);

  Object.assign(world, {
    deploymentDigest,
    genesisText, genesisDigest,
    successorText: successorFinal, successorDigest,
    leftText: leftFinal, leftDigest,
    rightText: rightFinal, rightDigest,
    genesisView, advancedView, forkView,
    genesisIssuerClaims,
  });
});

// Count real Ed25519 signing calls; refusal paths must leave the count at zero.
function countingHandle(): { handle: unknown; touches: () => number } {
  let touches = 0;
  const keys = ed25519FromSeed(Buffer.alloc(32, 7));
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "counted-key", publicKey: derivedPublic(keys.privateKey) }),
    sign(message) {
      touches += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  return { handle, touches: () => touches };
}

test("signAcceptance: R1 false revision coordinates are refused before the key is used", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const result = await signAcceptance(
    { ...world.genesisIssuerClaims, revision_digest: digestOf("different revision bytes") },
    handle,
    world.genesisView,
  );
  assert.deepEqual(result, { ok: false, error: "refused", code: "signing_refused" });
  assert.equal(counts.signs, 0);
});

test("signAcceptance: R2 equivocation at an occupied revision number is refused", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const claims = {
    ...world.genesisIssuerClaims,
    prev_revision_digest: world.genesisDigest,
    revision_digest: world.leftDigest,
    revision_number: 2,
  };
  const result = await signAcceptance(claims, handle, world.forkView);
  assert.deepEqual(result, { ok: false, error: "refused", code: "signing_refused" });
  assert.equal(counts.signs, 0);
});

test("signAcceptance: R3 re-accepting a non-head revision is refused (uncovered head)", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const result = await signAcceptance(world.genesisIssuerClaims, handle, world.forkView);
  assert.deepEqual(result, { ok: false, error: "refused", code: "signing_refused" });
  assert.equal(counts.signs, 0);
});

test("signTermination: an unlisted reason is refused before the key is used", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
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
    },
    handle,
    world.advancedView,
  );
  assert.deepEqual(result, { ok: false, error: "refused", code: "signing_refused" });
  assert.equal(counts.signs, 0);
});

test("signTermination: a stale termination (non-governing revision) is refused", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
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
    },
    handle,
    world.advancedView,
  );
  assert.deepEqual(result, { ok: false, error: "refused", code: "signing_refused" });
  assert.equal(counts.signs, 0);
});

test("a malformed caller view is invalid input, not a refusal", async () => {
  const counted = countingHandle();
  const result = await signAcceptance(world.genesisIssuerClaims, counted.handle, { ...world.genesisView, acceptances: ["not-a-compact-jws"],
  });
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "invalid_input");
  assert.equal((result as { code?: string }).code, "compact_invalid");
  assert.equal(counted.touches(), 0);
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
    },
    handle,
    world.advancedView,
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
  const result = await signAcceptance(claims, handle, world.advancedView);
  assert.ok(result.ok, JSON.stringify(result));
  const verified = verifyAcceptance(result.result.acceptance, world.successorText, [world.issuer.descriptor]);
  assert.ok(verified.ok, JSON.stringify(verified));
});

test("a 0.1.x-shaped termination view (no chain) fails closed, never throws", async () => {
  const counted = countingHandle();
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
    },
    counted.handle,
    // The pre-0.2.0 view shape: no chain member.
    { revisionText: world.genesisText, descriptorCompacts: [world.issuer.descriptor] } as never,
  );
  assert.ok(!result.ok);
  assert.equal((result as { error: string }).error, "invalid_input");
  assert.equal((result as { code?: string }).code, "invalid_type");
  assert.equal(counted.touches(), 0);
});

test("signReceipt: bound context happy path, post-verified", async () => {
  const { handle } = rawKeyHandle(Buffer.alloc(32, 11), "issuer-key-001");
  const claims = {
    protocol_revision: 2,
    charter_id: world.genesisDigest,
    revision_number: 1,
    revision_digest: world.genesisDigest,
    issuing_party_role: "issuer",
    agent_party_role: "acceptor",
    deployment_digest: world.deploymentDigest,
    grant: { scheme: "bap", id: "grant-001", grant_digest: digestOf("example receipt reference bytes") },
    invocation_id: "inv-001",
    decision: "accepted",
    outcome: "effect_committed",
    occurred_at: "2026-08-25T13:30:00Z",
    recorded_at: "2026-08-25T13:30:01Z",
    extensions: { critical: {}, optional: {} },
  };
  const result = await signReceipt(claims, handle, world.genesisView);
  assert.ok(result.ok, JSON.stringify(result));
  const header = JSON.parse(Buffer.from(result.result.receipt.split(".")[0], "base64url").toString("utf8"));
  assert.equal(header.typ, "cap+receipt");
  assert.equal(header.alg, "Ed25519");
  const verified = verifyReceipt(result.result.receipt, world.genesisView);
  assert.ok(verified.ok, JSON.stringify(verified));
});

test("malformed claims are rejected before the key is used (the producer claims gate)", async () => {
  const counted = countingHandle();
  // Acceptance n>1 without a predecessor digest: a codec schema red.
  const acceptance = await signAcceptance(
    { ...world.genesisIssuerClaims, revision_number: 2 } as Record<string, unknown>,
    counted.handle,
    world.genesisView,
  );
  assert.ok(!acceptance.ok);
  assert.equal((acceptance as { error: string }).error, "invalid_input");
  assert.equal((acceptance as { code?: string }).code, "signing_input_invalid");
  assert.equal(counted.touches(), 0);

  // Rejected receipts require no_effect.
  const receipt = await signReceipt(
    {
      protocol_revision: 2,
      charter_id: world.genesisDigest,
      revision_number: 1,
      revision_digest: world.genesisDigest,
      issuing_party_role: "issuer",
      agent_party_role: "acceptor",
      deployment_digest: world.deploymentDigest,
      grant: { scheme: "bap", id: "grant-001", grant_digest: digestOf("example receipt reference bytes") },
      invocation_id: "inv-001",
      decision: "rejected",
      outcome: "effect_committed",
      occurred_at: "2026-08-25T13:30:00Z",
      recorded_at: "2026-08-25T13:30:01Z",
      extensions: { critical: {}, optional: {} },
    },
    counted.handle,
    world.genesisView,
  );
  assert.ok(!receipt.ok);
  assert.equal((receipt as { error: string }).error, "invalid_input");
  assert.equal((receipt as { code?: string }).code, "signing_input_invalid");
  assert.equal(counted.touches(), 0);
});

test("a key absent from the holder's descriptor is refused before signing", async () => {
  const { handle, counts } = callbackCounts(99, "not-in-descriptor");
  const result = await signAcceptance(world.genesisIssuerClaims, handle, world.genesisView);
  assert.ok(!result.ok);
  assert.deepEqual(result, { ok: false, error: "refused", code: "signing_key_mismatch" });
  assert.equal(counts.signs, 0);
});

test("context type checks precede claims checks", async () => {
  const counted = countingHandle();
  const claimsBadAndViewMissing = await signAcceptance(
    { ...world.genesisIssuerClaims, revision_number: 2 } as Record<string, unknown>,
    counted.handle,
    undefined as never,
  );
  assert.ok(!claimsBadAndViewMissing.ok);
  assert.equal((claimsBadAndViewMissing as { code?: string }).code, "invalid_type");
  assert.equal(counted.touches(), 0);
});

test("limits and profiles use verifier errors before algorithms and key callbacks", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const invalidLimits = [null, 4, [], { extra: 1 }, { max_bytes: -1 }, { max_bytes: 1.5 }, { max_bytes: 16_777_217 }];
  const invalidProfiles = [null, 4, [], { extra: true }, { algorithms: [] }, { algorithms: ["unknown"] }, { algorithms: ["Ed25519", "Ed25519"] }, { revisions: { min: 3, max: 2 } }];
  for (const { kind, call } of signingCalls(handle)) {
    for (const limits of invalidLimits) {
      assert.deepEqual(await call({ limits, profile: null, algorithm: "unknown" } as never),
        { ok: false, error: "invalid_input", code: "invalid_limits" }, kind);
    }
    for (const profile of invalidProfiles) {
      assert.deepEqual(await call({ limits: {}, profile, algorithm: "unknown" } as never),
        { ok: false, error: "invalid_input", code: "invalid_profile" }, kind);
    }
    assert.equal(counts.identities, 0, kind);
    assert.equal(counts.signs, 0, kind);
  }
});

test("valid limits and profiles are accepted and predecessor is descriptor-only", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const { kind, call } of signingCalls(handle)) {
    const result = await call({ limits: {}, profile: { algorithms: ["Ed25519"], revisions: { min: 2, max: 2 } } } as never);
    assert.ok(result.ok, `${kind}: ${JSON.stringify(result)}`);
    const before = { ...counts };
    const withPrevious = await call({ predecessor: null } as never);
    if (kind === "descriptor") {
      assert.ok(withPrevious.ok, JSON.stringify(withPrevious));
    } else {
      assert.deepEqual(withPrevious, { ok: false, error: "invalid_input", code: "invalid_type" }, kind);
      assert.deepEqual(counts, before, kind);
    }
  }
});

test("the holder's own descriptor key must match the kid and bytes before signing", async () => {
  for (const [seed, kid] of [[11, "wrong-kid"], [99, "not-in-descriptor"], [99, "issuer-key-001"], [12, "acceptor-key-001"]] as const) {
    const { handle, counts } = callbackCounts(seed, kid);
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call({}), { ok: false, error: "refused", code: "signing_key_mismatch" }, `${kind}/${kid}/${seed}`);
      assert.equal(counts.signs, 0, kind);
    }
  }
});

test("receipt claims must match their context before signing", async () => {
  for (const patch of [
    { deployment_digest: digestOf("other deployment") },
    { revision_number: 2 },
    { charter_id: digestOf("other charter") },
  ]) {
    const { handle, counts } = callbackCounts(11, "issuer-key-001");
    assert.deepEqual(await signReceipt({ ...receiptClaims(), ...patch }, handle, world.genesisView),
      { ok: false, error: "invalid_input", code: "receipt_claims_mismatch" });
    assert.equal(counts.signs, 0);
  }
});

test("profiles exclude the artifact before signing for every kind", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const profile of [{ algorithms: ["ML-DSA-65"] }, { algorithms: ["EdDSA"] }, { algorithms: ["ML-DSA-44", "ML-DSA-87"] }, { revisions: { min: 1, max: 1 } }]) {
    for (const { kind, call } of signingCalls(handle)) {
      const result = await call({ profile });
      assert.deepEqual(result, { ok: false, error: "invalid_input", code: "algorithms" in profile ? "algorithm_outside_profile" : "revision_outside_profile" }, kind);
      assert.equal(counts.signs, 0, kind);
    }
  }
});

function generatedHandle(algorithm: "Ed25519" | "ML-DSA-65", kid: string) {
  const keys = algorithm === "Ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ml-dsa-65");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).subarray(algorithm === "Ed25519" ? -32 : -1952).toString("base64url");
  const counts = { signs: 0 };
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid, publicKey }),
    sign(message) {
      counts.signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  return { handle, publicKey, counts };
}

function genesisClaims(algorithm: "Ed25519" | "ML-DSA-65", kid: string, publicKey: string) {
  return {
    protocol_revision: algorithm === "Ed25519" ? 2 : 3,
    descriptor_number: 1,
    verification_keys: [{ key_id: kid, algorithm, public_key: publicKey, status: "active" }],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };
}

test("profiles excluding the signing party history or revision reject before signing", async () => {
  for (const profile of [{ algorithms: ["ML-DSA-65"] }, { revisions: { min: 3, max: 3 } }]) {
    const fixture = generatedHandle("ML-DSA-65", "issuer-key-001");
    const opts = { algorithm: "ML-DSA-65", profile };
    const expected = { ok: false, error: "invalid_input", code: "algorithms" in profile ? "algorithm_outside_profile" : "revision_outside_profile" };
    assert.deepEqual(await signAcceptance({ ...world.genesisIssuerClaims, protocol_revision: 3 }, fixture.handle, world.genesisView, opts), expected);
    assert.equal(fixture.counts.signs, 0);
    assert.deepEqual(await signTermination({
      protocol_revision: 3, charter_id: world.genesisDigest, governing_revision_digest: world.genesisDigest,
      party_descriptor_digest: world.issuer.pdd, party_role: "issuer", reason_code: "mutual",
      issued_at: "2026-08-25T14:00:00Z", effective_at: "2026-08-25T15:00:00Z",
    }, fixture.handle, world.genesisView, opts), expected);
    assert.equal(fixture.counts.signs, 0);
    assert.deepEqual(await signReceipt({ ...receiptClaims(), protocol_revision: 3 }, fixture.handle, world.genesisView, opts), expected);
    assert.equal(fixture.counts.signs, 0);
  }
});

test("limits include the final signature bytes and allow exactly the compact size", async () => {
  for (const algorithm of ["Ed25519", "ML-DSA-65"] as const) {
    const fixture = generatedHandle(algorithm, "size-key");
    const claims = genesisClaims(algorithm, "size-key", fixture.publicKey);
    const original = await signDescriptor(claims, fixture.handle, { algorithm });
    assert.ok(original.ok, JSON.stringify(original));
    const size = Buffer.byteLength(original.result.descriptor);
    const before = fixture.counts.signs;
    assert.deepEqual(await signDescriptor(claims, fixture.handle, { algorithm, limits: { max_bytes: size - 1 } }),
      { ok: false, error: "invalid_input", code: "signing_input_invalid" });
    assert.equal(fixture.counts.signs, before);
    const exact = await signDescriptor(claims, fixture.handle, { algorithm, limits: { max_bytes: size } });
    assert.ok(exact.ok, JSON.stringify(exact));
    assert.equal(Buffer.byteLength(exact.result.descriptor), size);
    if (algorithm === "Ed25519") assert.equal(exact.result.descriptor, original.result.descriptor);
  }
});

test("receipts can use a bare revision text with a real unnamed key", async () => {
  const { handle, counts } = callbackCounts(99, "receipt-key");
  const result = await signReceipt(receiptClaims(), handle, world.genesisText);
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(counts.signs, 1);
  assert.ok(verifyReceipt(result.result.receipt, world.genesisText).ok);
});

test("successor descriptors use the retained predecessor for both algorithms", async () => {
  for (const algorithm of ["Ed25519", "ML-DSA-65"] as const) {
    const previousKey = generatedHandle(algorithm, "previous-key");
    const nextKey = generatedHandle(algorithm, "next-key");
    const root = await signDescriptor(genesisClaims(algorithm, "previous-key", previousKey.publicKey), previousKey.handle, { algorithm });
    assert.ok(root.ok, JSON.stringify(root));
    const verified = verifyDescriptor(root.result.descriptor);
    assert.ok(verified.ok, JSON.stringify(verified));
    const successor = {
      ...genesisClaims(algorithm, "next-key", nextKey.publicKey),
      descriptor_number: 2,
      party_id: verified.facts.party_id,
      prev_descriptor_digest: verified.facts.descriptor_digest,
      effective_from: "2026-08-25T11:00:00Z",
    };
    const before = previousKey.counts.signs;
    for (const [predecessor, code] of [
      [undefined, "descriptor_chain_invalid"],
      [{ ...verified.facts, descriptor_digest: digestOf("other descriptor") }, "descriptor_chain_invalid"],
      [{ lineage: [42] }, "invalid_type"],
      ...[undefined, null, [], [42]].map((lineage) => [{ ...verified.facts, lineage }, "invalid_type"]),
      [{ lineage: verified.facts.lineage }, "invalid_type"],
      [{ ...verified.facts, lineage: ["bad compact"] }, "descriptor_chain_invalid"],
    ] as const) {
      assert.deepEqual(await signDescriptor(successor, previousKey.handle, { algorithm, predecessor } as never),
        { ok: false, error: "invalid_input", code });
      assert.equal(previousKey.counts.signs, before);
    }
    assert.deepEqual(await signDescriptor(successor, nextKey.handle, { algorithm, predecessor: verified.facts }),
      { ok: false, error: "refused", code: "signing_key_mismatch" });
    assert.equal(nextKey.counts.signs, 0);
    const result = await signDescriptor(successor, previousKey.handle, { algorithm, predecessor: verified.facts });
    assert.ok(result.ok, JSON.stringify(result));
    assert.ok(verifyDescriptor(result.result.descriptor, verified.facts).ok);
  }
});

test("key encoding checks follow context type and claims checks", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "issuer-key-001", publicKey: "" }),
    sign(message) { signs += 1; return nodeSign(null, message, keys.privateKey); },
  };
  assert.deepEqual(await signDescriptor({}, handle), { ok: false, error: "invalid_input", code: "signing_input_invalid" });
  assert.deepEqual(await signReceipt({}, handle, null as never), { ok: false, error: "invalid_input", code: "invalid_type" });
  assert.equal(signs, 0);
});

test("invalid limits precede a throwing profile getter", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const opts = {
    limits: { max_bytes: -1 },
    get profile(): never { throw new Error("profile unreadable"); },
  };
  for (const { kind, call } of signingCalls(handle)) {
    assert.deepEqual(await call(opts), { ok: false, error: "invalid_input", code: "invalid_limits" }, kind);
    assert.equal(counts.identities, 0, kind);
    assert.equal(counts.signs, 0, kind);
  }
});

test("malformed contexts return verifier codes without signing", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const termination = {
    protocol_revision: 2, charter_id: world.genesisDigest,
    governing_revision_digest: world.genesisDigest, party_descriptor_digest: world.issuer.pdd,
    party_role: "issuer", reason_code: "mutual", issued_at: "2026-08-25T14:00:00Z", effective_at: "2026-08-25T15:00:00Z",
  };
  for (const context of [null, undefined, 42, [], ["x"], {},
    ...(["revisions", "acceptances", "descriptors", "terminations"] as const).flatMap((field) =>
      [null, "x", [42]].map((value) => ({ ...world.genesisView, [field]: value })))]) {
    const calls = [
      () => signAcceptance(world.genesisIssuerClaims, handle, context as never),
      () => signTermination(termination, handle, context as never),
      () => signReceipt(receiptClaims(), handle, context as never),
    ];
    for (const call of calls) {
      assert.deepEqual(await call(), { ok: false, error: "invalid_input", code: "invalid_type" });
      assert.equal(counts.signs, 0);
    }
  }
  for (const predecessor of [42, [], {}, { lineage: null }, { lineage: [] }, { lineage: [42] }]) {
    const snapshot = await handle.keyIdentity(handle);
    const result = await signDescriptor(genesisClaims("Ed25519", snapshot.kid, snapshot.publicKey), handle, { predecessor } as never);
    assert.deepEqual(result, { ok: false, error: "invalid_input", code: "invalid_type" });
    assert.equal(counts.signs, 0);
  }
});

test("an unheld successor descriptor returns claims mismatch before signing", async () => {
  const root = verifyDescriptor(world.issuer.descriptor);
  assert.ok(root.ok);
  const snapshot = await (world.issuer.handle as KeyHandle).keyIdentity(world.issuer.handle);
  const successor = await signDescriptor({
    ...genesisClaims("Ed25519", snapshot.kid, snapshot.publicKey),
    descriptor_number: 2, party_id: root.facts.party_id,
    prev_descriptor_digest: root.facts.descriptor_digest, effective_from: "2026-08-25T11:00:00Z",
  }, world.issuer.handle, { predecessor: root.facts });
  assert.ok(successor.ok, JSON.stringify(successor));
  const next = verifyDescriptor(successor.result.descriptor, root.facts);
  assert.ok(next.ok);
  const revision = canonical({
    ...JSON.parse(world.genesisText),
    charter_id: world.genesisDigest, prev_revision_digest: world.genesisDigest, revision_number: 2,
    effective_from: "2026-08-25T12:00:01Z",
    parties: [{ party_descriptor_digest: next.facts.descriptor_digest, role: "issuer" }, { party_descriptor_digest: world.acceptor.pdd, role: "acceptor" }],
  });
  const chain = { ...copyChain(world.genesisView), revisions: [world.genesisText, revision] };
  assert.ok(verifyChain(chain).ok);
  const digested = revisionDigest(revision);
  assert.ok(digested.ok);
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  assert.deepEqual(await signAcceptance({
    ...world.genesisIssuerClaims, revision_number: 2, prev_revision_digest: world.genesisDigest,
    revision_digest: digested.digest, party_descriptor_digest: next.facts.descriptor_digest,
  }, handle, chain), { ok: false, error: "invalid_input", code: "acceptance_claims_mismatch" });
  assert.equal(counts.signs, 0);

});

test("entry copies retain limits, profiles and predecessor lineage across callbacks", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const publicKey = derivedPublic(keys.privateKey);
  const root = verifyDescriptor(world.issuer.descriptor);
  assert.ok(root.ok);
  const successor = {
    ...genesisClaims("Ed25519", "issuer-key-001", publicKey),
    descriptor_number: 2, party_id: root.facts.party_id, prev_descriptor_digest: root.facts.descriptor_digest,
    effective_from: "2026-08-25T11:00:00Z",
  };
  for (const mutateAt of ["identity", "sign"] as const) {
    const opts = { predecessor: structuredClone(root.facts), limits: { max_bytes: 4096 }, profile: { algorithms: ["Ed25519"], revisions: { min: 2, max: 2 } } };
    const mutate = () => {
      (opts.predecessor.lineage as string[]).length = 0;
      opts.limits.max_bytes = 0;
      opts.profile.algorithms[0] = "ML-DSA-65";
      opts.profile.revisions.min = opts.profile.revisions.max = 3;
    };
    const handle: KeyHandle = {
      async keyIdentity() {
        if (mutateAt === "identity") mutate();
        return { kid: "issuer-key-001", publicKey };
      },
      sign(message) {
        if (mutateAt === "sign") mutate();
        return nodeSign(null, message, keys.privateKey);
      },
    };
    const result = await signDescriptor(successor, handle, opts);
    assert.ok(result.ok, `${mutateAt}: ${JSON.stringify(result)}`);
    assert.ok(verifyDescriptor(result.result.descriptor, root.facts).ok);
  }
});

test("raised limits prepare and finish a receipt larger than the default compact limit", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const claims = { ...receiptClaims(), extensions: { critical: {}, optional: { "com.example/text": "x".repeat(800_000) } } };
  assert.deepEqual(await signReceipt(claims, handle, world.genesisView), { ok: false, error: "invalid_input", code: "signing_input_invalid" });
  assert.equal(counts.signs, 0);
  const opts = { limits: { max_bytes: 2_097_152, max_string_bytes: 1_048_576 } };
  const result = await signReceipt(claims, handle, world.genesisView, opts);
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(counts.signs, 1);
  assert.ok(Buffer.byteLength(result.result.receipt) > 1_048_576);
  assert.ok(verifyReceipt(result.result.receipt, world.genesisView, opts).ok);
  const before = counts.signs;
  assert.deepEqual(await signReceipt(claims, handle, world.genesisView, { limits: { ...opts.limits, max_bytes: Buffer.byteLength(result.result.receipt) - 1 } }),
    { ok: false, error: "invalid_input", code: "signing_input_invalid" });
  assert.equal(counts.signs, before);
});

test("throwing claim and context getters return input errors before signing", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const claims = Object.defineProperty({}, "protocol_revision", { enumerable: true, get() { throw new Error("claims unreadable"); } });
  assert.deepEqual(await signDescriptor(claims, handle), { ok: false, error: "invalid_input", code: "invalid_type" });
  assert.equal(counts.signs, 0);
  const chain = Object.defineProperty(copyChain(world.genesisView), "revisions", { enumerable: true, get() { throw new Error("context unreadable"); } });
  assert.deepEqual(await signReceipt(receiptClaims(), handle, chain), { ok: false, error: "invalid_input", code: "invalid_type" });
  assert.equal(counts.signs, 0);
});

test("the verifier checks canonical key encodings and lengths before signing", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const good = derivedPublic(keys.privateKey);
  let signs = 0;
  for (const publicKey of [good + "=", Buffer.alloc(31).toString("base64url"), Buffer.alloc(33).toString("base64url"), Buffer.alloc(32).toString("base64url"), "not base64url"]) {
    const handle: KeyHandle = {
      keyIdentity: () => ({ kid: "issuer-key-001", publicKey }),
      sign(message) { signs += 1; return nodeSign(null, message, keys.privateKey); },
    };
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call({}), { ok: false, error: "invalid_key_handle" }, kind);
      assert.equal(signs, 0, kind);
    }
  }
});

test("Ed25519 point admission rejects invalid snapshot keys on every entry point", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const encoded = (y: bigint, signBit = false) => Buffer.from(
    (y | (signBit ? 1n << 255n : 0n)).toString(16).padStart(64, "0"), "hex",
  ).reverse().toString("base64url");
  const prime = (1n << 255n) - 19n;
  const rejected = [
    encoded(prime), encoded(prime + 1n), encoded(2n),
    encoded(1n, true), encoded(prime - 1n, true),
    encoded(0n), encoded(1n), encoded(prime - 1n),
  ];
  for (const publicKey of rejected) {
    const counts = { identities: 0, signs: 0 };
    const handle: KeyHandle = {
      keyIdentity() { counts.identities += 1; return { kid: "issuer-key-001", publicKey }; },
      sign(message) { counts.signs += 1; return nodeSign(null, message, keys.privateKey); },
    };
    for (const { kind, call } of signingCalls(handle)) {
      const before = counts.identities;
      assert.deepEqual(await call({}), { ok: false, error: "invalid_key_handle" }, kind);
      assert.equal(counts.identities, before + 1, kind);
      assert.equal(counts.signs, 0, kind);
    }
  }
});

test("signature faults and truncated real signatures remain signing_failed", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const publicKey = derivedPublic(keys.privateKey);
  for (const failure of ["crypto", "length"] as const) {
    let signs = 0;
    const handle: KeyHandle = {
      keyIdentity: () => ({ kid: "issuer-key-001", publicKey }),
      sign(message) {
        signs += 1;
        if (failure === "crypto") return nodeSign("unsupported-digest", message, keys.privateKey);
        return nodeSign(null, message, keys.privateKey).subarray(0, 63);
      },
    };
    for (const { kind, call } of signingCalls(handle)) {
      const before = signs;
      assert.deepEqual(await call({}), { ok: false, error: "signing_failed" }, kind);
      assert.equal(signs, before + 1, kind);
    }
  }
});

test("the wrong-key guard rejects bytes changed in place by the signing callback", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const publicKey = derivedPublic(keys.privateKey);
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "issuer-key-001", publicKey }),
    sign(message) {
      signs += 1;
      // A real signature over changed bytes must fail the custody guard.
      message[0] ^= 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  for (const { kind, call } of signingCalls(handle)) {
    const before = signs;
    assert.deepEqual(await call({}), { ok: false, error: "signing_failed" }, kind);
    assert.equal(signs, before + 1, kind);
  }
});

test("completion uses the signature bytes copied for the guard", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  let signs = 0;
  let reads = 0;
  let copyReads = 0;
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "issuer-key-001", publicKey: derivedPublic(keys.privateKey) }),
    sign(message) {
      signs += 1;
      const signature = new Uint8Array(nodeSign(null, message, keys.privateKey));
      const length = signature.length;
      reads = 0;
      copyReads = Infinity;
      Object.defineProperty(signature, "length", { get() {
        reads += 1;
        if (reads > copyReads) signature[0] ^= 1;
        return length;
      } });
      // Count this runtime's reads for one copy of the real signature.
      Buffer.from(signature);
      copyReads = reads;
      reads = 0;
      return signature;
    },
  };
  for (const { kind, call } of signingCalls(handle)) {
    const result = await call({});
    assert.ok(result.ok, `${kind}: ${JSON.stringify(result)}`);
    assert.equal(reads, copyReads, kind);
  }
  assert.equal(signs, 4);
});

test("Ed25519 compacts retain byte identity with the build-only producer surface", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const { handle } = rawKeyHandle(Buffer.alloc(32, 11), "issuer-key-001");
  for (const { kind, claims, call } of signingCalls(handle)) {
    const built = kind === "descriptor" ? descriptorSigningInput("issuer-key-001", claims) :
      kind === "receipt" ? receiptSigningInput("issuer-key-001", claims) :
      kind === "acceptance" ? acceptanceSigningInput("issuer-key-001", claims, world.genesisView) :
      terminationSigningInput("issuer-key-001", claims, world.genesisView);
    assert.ok(built.ok, JSON.stringify(built));
    const expected = assembleCompact(built.input, nodeSign(null, built.input.message, keys.privateKey));
    assert.ok(expected.ok, JSON.stringify(expected));
    const result = await call({});
    assert.ok(result.ok, JSON.stringify(result));
    assert.equal(Object.values(result.result)[0], expected.compact, kind);
  }
});


test("mixed sets use the signing party profile for acceptance and termination", async () => {
  const ml = generatedHandle("ML-DSA-65", "acceptor-key-ml");
  const descriptor = await signDescriptor(genesisClaims("ML-DSA-65", "acceptor-key-ml", ml.publicKey), ml.handle, { algorithm: "ML-DSA-65" });
  assert.ok(descriptor.ok, JSON.stringify(descriptor));
  const verified = verifyDescriptor(descriptor.result.descriptor);
  assert.ok(verified.ok);
  const revisionClaims = JSON.parse(world.genesisText);
  revisionClaims.parties[1].party_descriptor_digest = verified.facts.descriptor_digest;
  const revisionText = canonical(revisionClaims);
  const digested = revisionDigest(revisionText);
  assert.ok(digested.ok);
  const chain: ChainView = {
    revisions: [revisionText], acceptances: [],
    descriptors: [world.issuer.descriptor, descriptor.result.descriptor], terminations: [],
  };
  const issuerClaims = { ...world.genesisIssuerClaims, charter_id: digested.digest, revision_digest: digested.digest };
  const issuer = callbackCounts(11, "issuer-key-001");
  const initial = await signAcceptance(issuerClaims, issuer.handle, chain);
  assert.ok(initial.ok, JSON.stringify(initial));
  chain.acceptances.push(initial.result.acceptance);
  const counterparty = await signAcceptance({
    ...issuerClaims, protocol_revision: 3, party_role: "acceptor", party_descriptor_digest: verified.facts.descriptor_digest,
  }, ml.handle, chain, { algorithm: "ML-DSA-65" });
  assert.ok(counterparty.ok, JSON.stringify(counterparty));
  chain.acceptances.push(counterparty.result.acceptance);
  assert.ok(verifyChain(chain).ok);
  const profile = { algorithms: ["Ed25519"] };
  assert.deepEqual(verifyChain(chain, { profile }), { ok: false, code: "algorithm_outside_profile" });
  const terminationClaims = {
    protocol_revision: 2, charter_id: digested.digest, governing_revision_digest: digested.digest,
    party_descriptor_digest: world.issuer.pdd, party_role: "issuer", reason_code: "mutual",
    issued_at: "2026-08-25T14:00:00Z", effective_at: "2026-08-25T15:00:00Z",
  };
  for (const kind of ["acceptance", "termination"] as const) {
    const before = issuer.counts.signs;
    const result = kind === "acceptance" ? await signAcceptance(issuerClaims, issuer.handle, chain, { profile }) :
      await signTermination(terminationClaims, issuer.handle, chain, { profile });
    assert.ok(result.ok, `${kind}: ${JSON.stringify(result)}`);
    assert.equal(issuer.counts.signs, before + 1, kind);
    const compact = Object.values(result.result)[0];
    const checked = kind === "acceptance" ? verifyAcceptance(compact, revisionText, [world.issuer.descriptor], { profile }) :
      verifyTermination(compact, revisionText, [world.issuer.descriptor], { profile });
    assert.ok(checked.ok, `${kind}: ${JSON.stringify(checked)}`);
  }
  const before = issuer.counts.signs;
  assert.deepEqual(await signReceipt({ ...receiptClaims(), charter_id: digested.digest, revision_digest: digested.digest }, issuer.handle, chain, { profile }),
    { ok: false, error: "invalid_input", code: "algorithm_outside_profile" });
  assert.equal(issuer.counts.signs, before);
});


test("entry copies retain shared and nested claims before keyIdentity", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  const shared = { nested: { value: "entry" } };
  const row = { value: "entry" };
  const claims = {
    ...genesisClaims("Ed25519", "issuer-key-001", derivedPublic(keys.privateKey)),
    extensions: { critical: {}, optional: {
      "com.example/first": shared, "com.example/second": shared, "com.example/rows": [row],
    } },
  };
  const expected = structuredClone(claims);
  let identities = 0;
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity() {
      identities += 1;
      shared.nested.value = "changed";
      row.value = "changed";
      return { kid: "issuer-key-001", publicKey: derivedPublic(keys.privateKey) };
    },
    sign(message) {
      signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  const result = await signDescriptor(claims, handle);
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(identities, 1);
  assert.equal(signs, 1);
  const checked = verifyDescriptor(result.result.descriptor);
  assert.ok(checked.ok);
  const payload = JSON.parse(Buffer.from(result.result.descriptor.split(".")[1], "base64url").toString("utf8"));
  assert.deepEqual(payload, expected);
});

test("non-JSON claims values return invalid_type before either key callback", async (t) => {
  class NestedValue { value = "entry"; }
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  const values: Array<[string, unknown]> = [
    ["class instance", new NestedValue()], ["date", new Date("2026-08-25T10:00:00Z")],
    ["map", new Map()], ["set", new Set()], ["typed array", new Uint8Array(1)],
    ["boxed number", new Number(1)], ["function", () => "entry"], ["bigint", 1n],
    ["symbol", Symbol("value")], ["undefined", undefined], ["non-finite number", NaN],
    ["infinity", Infinity], ["cycle", cycle],
  ];
  for (const [label, value] of values) await t.test(label, async () => {
    const { handle, counts } = callbackCounts(11, "issuer-key-001");
    for (const { kind, claims } of signingCalls(handle)) {
      const copiedClaims = { ...claims, ...(kind === "termination" ? { extra: value } : {
        extensions: { critical: {}, optional: { "com.example/value": value } },
      }) };
      const result = kind === "descriptor" ? await signDescriptor(copiedClaims, handle) :
        kind === "receipt" ? await signReceipt(copiedClaims, handle, world.genesisView) :
        kind === "acceptance" ? await signAcceptance(copiedClaims, handle, world.genesisView) :
        await signTermination(copiedClaims, handle, world.genesisView);
      assert.deepEqual(result, { ok: false, error: "invalid_input", code: "invalid_type" }, kind);
    }
    assert.deepEqual(counts, { identities: 0, signs: 0 });
  });
});

test("array subclasses are copied into plain arrays without constructor hooks", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const rows = ["entry"];
  class Rows extends Array<string> {}
  Object.setPrototypeOf(rows, Rows.prototype);
  let hooks = 0;
  Object.defineProperty(rows, "constructor", { get() { hooks += 1; throw new Error("array constructor"); } });
  const result = await signDescriptor({
    ...genesisClaims("Ed25519", "issuer-key-001", derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey)),
    extensions: { critical: {}, optional: { "com.example/rows": rows } },
  }, handle);
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(hooks, 0);
  assert.deepEqual(counts, { identities: 1, signs: 1 });
  const payload = JSON.parse(Buffer.from(result.result.descriptor.split(".")[1], "base64url").toString("utf8"));
  assert.deepEqual(payload.extensions.optional["com.example/rows"], ["entry"]);
});

test("class instances and throwing nested getters are invalid_type in entry options", async (t) => {
  class LimitsValue {
    constructor() {
      Object.defineProperty(this, "max_bytes", { enumerable: true, get() { throw new Error("limits unreadable"); } });
    }
  }
  class ProfileValue { get algorithms(): string[] { throw new Error("profile unreadable"); } }
  class PreviousValue { get lineage(): string[] { throw new Error("predecessor unreadable"); } }
  class BoundsValue { get min(): number { throw new Error("bounds unreadable"); } max = 2; }
  const throwingLimits = Object.defineProperty({}, "max_bytes", { enumerable: true, get() { throw new Error("limits unreadable"); } });
  const throwingProfile = Object.defineProperty({}, "algorithms", { enumerable: true, get() { throw new Error("profile unreadable"); } });
  const throwingPrevious = Object.defineProperty({}, "lineage", { enumerable: true, get() { throw new Error("predecessor unreadable"); } });
  const values = [
    { limits: new LimitsValue() }, { profile: new ProfileValue() }, { predecessor: new PreviousValue() },
    { profile: { revisions: new BoundsValue() } },
    { limits: throwingLimits }, { profile: throwingProfile }, { predecessor: throwingPrevious },
  ];
  for (const [index, opts] of values.entries()) await t.test(String(index), async () => {
    const { handle, counts } = callbackCounts(11, "issuer-key-001");
    assert.deepEqual(await signDescriptor(genesisClaims("Ed25519", "issuer-key-001", derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey)), handle, opts as never),
      { ok: false, error: "invalid_input", code: "invalid_type" });
    assert.deepEqual(counts, { identities: 0, signs: 0 });
  });
});

test("a throwing claims getter with a wrong-type context returns invalid_type", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const claims = Object.defineProperty({}, "protocol_revision", { enumerable: true, get() { throw new Error("claims unreadable"); } });
  for (const context of [null, 42, [], "revision text"] as const) {
    assert.deepEqual(await signAcceptance(claims, handle, context as never),
      { ok: false, error: "invalid_input", code: "invalid_type" });
  }
  assert.equal(counts.signs, 0);
});


test("the key snapshot precedes context type errors in prepareSigning", async () => {
  const keys = ed25519FromSeed(Buffer.alloc(32, 11));
  let identities = 0;
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity() {
      identities += 1;
      return { kid: "", publicKey: derivedPublic(keys.privateKey) };
    },
    sign(message) {
      signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  for (const context of [null, [], 42, "revision text"] as const) {
    assert.deepEqual(await signAcceptance(world.genesisIssuerClaims, handle, context as never), { ok: false, error: "invalid_key_handle" });
    assert.deepEqual(await signTermination({}, handle, context as never), { ok: false, error: "invalid_key_handle" });
    if (typeof context !== "string") {
      assert.deepEqual(await signReceipt(receiptClaims(), handle, context as never), { ok: false, error: "invalid_key_handle" });
    }
  }
  assert.equal(identities, 11);
  assert.equal(signs, 0);
});

test("successful signing reads exactly one key snapshot on every entry point", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const { kind, call } of signingCalls(handle)) {
    const before = { ...counts };
    const result = await call({});
    assert.ok(result.ok, `${kind}: ${JSON.stringify(result)}`);
    assert.equal(counts.identities, before.identities + 1, kind);
    assert.equal(counts.signs, before.signs + 1, kind);
  }
});

test("a wrong key algorithm returns signing_key_mismatch before signing", async () => {
  const fixture = generatedHandle("ML-DSA-65", "issuer-key-001");
  for (const { kind, claims } of signingCalls(fixture.handle)) {
    const mlClaims = { ...claims, protocol_revision: 3 };
    const opts = { algorithm: "ML-DSA-65" };
    const result = kind === "descriptor" ? await signDescriptor(mlClaims, fixture.handle, opts) :
      kind === "receipt" ? await signReceipt(mlClaims, fixture.handle, world.genesisView, opts) :
      kind === "acceptance" ? await signAcceptance(mlClaims, fixture.handle, world.genesisView, opts) :
      await signTermination(mlClaims, fixture.handle, world.genesisView, opts);
    assert.deepEqual(result, { ok: false, error: "refused", code: "signing_key_mismatch" }, kind);
    assert.equal(fixture.counts.signs, 0, kind);
  }
});


test("the signature guard rejects short and long real signatures for both algorithms", async () => {
  for (const algorithm of ["Ed25519", "ML-DSA-65"] as const) {
    const keys = algorithm === "Ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ml-dsa-65");
    const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).subarray(algorithm === "Ed25519" ? -32 : -1952).toString("base64url");
    for (const length of ["short", "long"] as const) {
      let signs = 0;
      const handle: KeyHandle = {
        keyIdentity: () => ({ kid: "length-key", publicKey }),
        sign(message) {
          signs += 1;
          const signature = nodeSign(null, message, keys.privateKey);
          const resized = length === "short" ? signature.subarray(0, signature.length - 1) : Buffer.concat([signature, Buffer.from([0])]);
          assert.equal(verifySignature(Buffer.from(message), resized, publicKey, algorithm), false, `${algorithm}/${length}`);
          return resized;
        },
      };
      assert.deepEqual(await signDescriptor(genesisClaims(algorithm, "length-key", publicKey), handle, { algorithm }),
        { ok: false, error: "signing_failed" }, `${algorithm}/${length}`);
      assert.equal(signs, 1);
    }
  }
});

test("real signature bytes work as Buffer, plain and cross-realm Uint8Array", async () => {
  for (const algorithm of ["Ed25519", "ML-DSA-65"] as const) {
    const keys = algorithm === "Ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ml-dsa-65");
    const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).subarray(algorithm === "Ed25519" ? -32 : -1952).toString("base64url");
    for (const format of ["buffer", "plain", "cross-realm"] as const) {
      const counts = { identities: 0, signs: 0 };
      const handle: KeyHandle = {
        keyIdentity() { counts.identities += 1; return { kid: "bytes-key", publicKey }; },
        sign(message) {
          counts.signs += 1;
          const bytes = nodeSign(null, message, keys.privateKey);
          if (format === "buffer") return bytes;
          if (format === "plain") return new Uint8Array(bytes);
          const foreign = runInNewContext("new Uint8Array(bytes)", { bytes: Array.from(bytes) }) as Uint8Array;
          assert.equal(foreign instanceof Uint8Array, false);
          return foreign;
        },
      };
      const result = await signDescriptor(genesisClaims(algorithm, "bytes-key", publicKey), handle, { algorithm });
      assert.ok(result.ok, `${algorithm}/${format}: ${JSON.stringify(result)}`);
      assert.ok(verifyDescriptor(result.result.descriptor).ok);
      assert.deepEqual(counts, { identities: 1, signs: 1 });
    }
  }
});

test("sparse profile algorithm lists reject before either key callback", async () => {
  const algorithms = Array<string>(2);
  algorithms[0] = "Ed25519";
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const { kind, call } of signingCalls(handle)) {
    assert.deepEqual(await call({ profile: { algorithms } }),
      { ok: false, error: "invalid_input", code: "invalid_profile" }, kind);
    assert.deepEqual(counts, { identities: 0, signs: 0 });
  }
});

test("option copies preserve the verifier's invalid limits and profile codes", async (t) => {
  const values = [
    ...[1n, Symbol("value"), new Number(1)].flatMap((value) => [
      { limits: value }, { limits: { max_bytes: value } }, { profile: value },
      { profile: { algorithms: [value] } }, { profile: { revisions: { min: value, max: 3 } } },
    ]),
    { limits: { max_bytes: NaN } },
    { limits: { max_bytes: Infinity } },
    { limits: { max_bytes: undefined } },
    { profile: { revisions: { min: 2, max: undefined } } },
    { profile: { algorithms: ["Ed25519", undefined] } },
    { profile: { algorithms: ["Ed25519", null] } },
  ];
  for (const [index, opts] of values.entries()) await t.test(String(index), async () => {
    const checked = decodeCharterRevision(undefined, opts as never);
    assert.ok(!checked.ok);
    assert.ok(checked.code === "invalid_limits" || checked.code === "invalid_profile");
    const { handle, counts } = callbackCounts(11, "issuer-key-001");
    for (const { kind, call } of signingCalls(handle)) {
      assert.deepEqual(await call(opts as never),
        { ok: false, error: "invalid_input", code: checked.code }, kind);
    }
    assert.deepEqual(counts, { identities: 0, signs: 0 });
  });
});

test("undefined option axes retain the verifier's defaults", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const { kind, call } of signingCalls(handle)) {
    const result = await call({ limits: undefined, profile: { algorithms: undefined, revisions: undefined } });
    assert.ok(result.ok, `${kind}: ${JSON.stringify(result)}`);
  }
  assert.deepEqual(counts, { identities: 4, signs: 4 });
});

test("claims copies stop repeated trees beyond the largest verifier limits", async () => {
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  let reads = 0;
  let tree: unknown = Object.defineProperty({}, "value", { enumerable: true, get() {
    reads += 1;
    return "entry";
  } });
  for (let depth = 0; depth < 24; depth += 1) tree = { left: tree, right: tree };
  const claims = {
    ...genesisClaims("Ed25519", "issuer-key-001", derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey)),
    extensions: { critical: {}, optional: { "com.example/tree": tree } },
  };
  const started = performance.now();
  const result = await signDescriptor(claims, handle, { limits: { max_bytes: 1_024 } });
  process.stdout.write(`Repeated claims copy: ${(performance.now() - started).toFixed(1)} ms, ${reads} leaf reads, ${JSON.stringify(result)}.\n`);
  assert.deepEqual(result, { ok: false, error: "invalid_input", code: "signing_input_invalid" });
  assert.ok(reads < MAXIMUM_LIMITS.max_bytes / 16, String(reads));
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});

test("claims copies bound 200000 levels without overflowing the stack", async () => {
  let tree: unknown = "entry";
  for (let depth = 0; depth < 200_000; depth += 1) tree = { child: tree };
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const claims = {
    ...genesisClaims("Ed25519", "issuer-key-001", derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey)),
    extensions: { critical: {}, optional: { "com.example/tree": tree } },
  };
  for (const max_depth of [64, 128]) {
    assert.deepEqual(await signDescriptor(claims, handle, { limits: { max_depth } }),
      { ok: false, error: "invalid_input", code: "signing_input_invalid" });
  }
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});

test("claims copy bounds match JSON depth, members, items and UTF-8 strings", async (t) => {
  const cases = [
    { label: "depth", value: { child: { child: "entry" } }, limits: { max_depth: 5 }, lower: { max_depth: 4 } },
    { label: "members", value: Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`key${i}`, i])), limits: { max_object_members: 8 }, lower: { max_object_members: 7 } },
    { label: "items", value: Array.from({ length: 8 }, (_, i) => i), limits: { max_array_items: 8 }, lower: { max_array_items: 7 } },
    { label: "string", value: "é".repeat(32), limits: { max_string_bytes: 64 }, lower: { max_string_bytes: 63 } },
    { label: "escaped string", value: "\u0000".repeat(64), limits: { max_string_bytes: 64 }, lower: { max_string_bytes: 63 } },
    { label: "member name", value: { ["é".repeat(32)]: "entry" }, limits: { max_string_bytes: 64 }, lower: { max_string_bytes: 63 } },
  ];
  for (const { label, value, limits, lower } of cases) await t.test(label, async () => {
    const { handle, counts } = callbackCounts(11, "issuer-key-001");
    const claims = {
      ...genesisClaims("Ed25519", "issuer-key-001", derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey)),
      extensions: { critical: {}, optional: { "com.example/value": value } },
    };
    const text = canonical(claims as never);
    assert.ok(decodeJsonText(text, limits).ok, label);
    assert.deepEqual(decodeJsonText(text, lower), { ok: false, code: "limit_exceeded" }, label);
    const result = await signDescriptor(claims, handle, { limits });
    assert.ok(result.ok, `${label}: ${JSON.stringify(result)}`);
    assert.deepEqual(await signDescriptor(claims, handle, { limits: lower }),
      { ok: false, error: "invalid_input", code: "signing_input_invalid" }, label);
    assert.deepEqual(counts, { identities: 2, signs: 1 });
  });
});

test("claims below the entry guard read later members before preparation", async () => {
  let reads = 0;
  const value = Object.defineProperty({ first: "\u0000".repeat(128) }, "later", { enumerable: true, get() {
    reads += 1;
    throw new Error("later member");
  } });
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const { kind, claims } of signingCalls(handle)) {
    const input = { ...claims, extensions: { critical: {}, optional: { "com.example/value": value } } };
    const options = { limits: { max_bytes: 512 } };
    const result = kind === "descriptor" ? await signDescriptor(input, handle, options) :
      kind === "receipt" ? await signReceipt(input, handle, world.genesisView, options) :
      kind === "acceptance" ? await signAcceptance(input, handle, world.genesisView, options) :
      await signTermination(input, handle, world.genesisView, options);
    assert.deepEqual(result, { ok: false, error: "invalid_input", code: "invalid_type" }, kind);
  }
  assert.equal(reads, 4);
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});

test("context entry copies read lists below the verifier maximum", async () => {
  let reads = 0;
  const acceptances = Object.defineProperty(Array<string>(2), "0", { get() {
    reads += 1;
    throw new Error("artifact entry");
  } });
  const chain = { ...world.genesisView, acceptances };
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const options = { limits: { max_artifact_set_items: 1 } };
  for (const result of [
    await signReceipt(receiptClaims(), handle, chain, options),
    await signAcceptance(world.genesisIssuerClaims, handle, chain, options),
    await signTermination({}, handle, chain, options),
  ]) assert.deepEqual(result, { ok: false, error: "invalid_input", code: "invalid_type" });
  assert.equal(reads, 3);
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});

test("deep JSON option values reach the verifier without a recursive copy", async () => {
  let value: unknown = "invalid";
  for (let depth = 0; depth < 200_000; depth += 1) value = { child: value };
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const claims = genesisClaims("Ed25519", "issuer-key-001", derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey));
  for (const opts of [{ limits: { max_bytes: value } }, { profile: { algorithms: [value] } }]) {
    const checked = decodeCharterRevision(undefined, opts as never);
    assert.ok(!checked.ok);
    assert.deepEqual(await signDescriptor(claims, handle, opts as never),
      { ok: false, error: "invalid_input", code: checked.code });
  }
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});


test("small final compact limits return the verifier code after one snapshot", async () => {
  const publicKey = derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey);
  const claims = genesisClaims("Ed25519", "issuer-key-001", publicKey);
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const max_bytes of [200, 100, 50]) {
    const options = { limits: { max_bytes } };
    const checked = prepareSigning("descriptor", "issuer-key-001", claims, publicKey, null, options);
    assert.deepEqual(checked, { ok: false, code: "signing_input_invalid" });
    assert.deepEqual(await signDescriptor(claims, handle, options),
      { ok: false, error: "invalid_input", code: checked.code });
  }
  assert.deepEqual(counts, { identities: 3, signs: 0 });
});


test("defined option members are read once through ordinary property access", async () => {
  const counts = new Map<string, number>();
  const read = (name: string, value: unknown) => ({ get() {
    counts.set(name, (counts.get(name) ?? 0) + 1);
    return value;
  } });
  const range = Object.create(null, { min: read("min", 2), max: read("max", 2) });
  const profile = Object.create(null, { algorithms: read("algorithms", ["Ed25519"]), revisions: read("revisions", range) });
  const limits = Object.create(null, { max_bytes: read("max_bytes", 4096) });
  const options = Object.create({ }, {
    limits: read("limits", limits), profile: read("profile", profile), algorithm: read("algorithm", "Ed25519"),
  });
  const { handle } = callbackCounts(11, "issuer-key-001");
  const claims = genesisClaims("Ed25519", "issuer-key-001", derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey));
  const result = await signDescriptor(claims, handle, options);
  assert.ok(result.ok, JSON.stringify(result));
  assert.deepEqual(Object.fromEntries(counts), {
    limits: 1, max_bytes: 1, profile: 1, algorithms: 1, revisions: 1, min: 1, max: 1, algorithm: 1,
  });
});

test("inherited options and nested option records match their plain values", async () => {
  class Bounds { min = 2; max = 2; }
  class LimitsValue { max_bytes = 4096; }
  class ProfileValue { algorithms = ["Ed25519"]; revisions = new Bounds(); }
  const publicKey = derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey);
  const claims = genesisClaims("Ed25519", "issuer-key-001", publicKey);
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const options of [
    Object.create({ limits: { max_bytes: 4096 }, profile: { algorithms: ["Ed25519"], revisions: { min: 2, max: 2 } } }),
    { limits: new LimitsValue(), profile: new ProfileValue() },
    { limits: Object.create({ max_bytes: 4096 }), profile: Object.create({ algorithms: ["Ed25519"], revisions: Object.create({ min: 2, max: 2 }) }) },
    { limits: new Map(), profile: new Map() },
  ]) {
    const result = await signDescriptor(claims, handle, options);
    assert.ok(result.ok, JSON.stringify(result));
    assert.ok(verifyDescriptor(result.result.descriptor).ok);
  }
  const options = Object.create({ profile: Object.create({ algorithms: ["ML-DSA-65"] }) });
  const checked = prepareSigning("descriptor", "issuer-key-001", claims, publicKey, null, { profile: { algorithms: ["ML-DSA-65"] } });
  assert.deepEqual(checked, { ok: false, code: "algorithm_outside_profile" });
  assert.deepEqual(await signDescriptor(claims, handle, options), { ok: false, error: "invalid_input", code: checked.code });
  assert.deepEqual(counts, { identities: 5, signs: 4 });
});


test("predecessor lineage is independent of the caller's artifact item limit", async () => {
  const publicKey = derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey);
  const claims = genesisClaims("Ed25519", "issuer-key-001", publicKey);
  const { handle } = callbackCounts(11, "issuer-key-001");
  const root = await signDescriptor(claims, handle);
  assert.ok(root.ok);
  const first = verifyDescriptor(root.result.descriptor);
  assert.ok(first.ok);
  const next = await signDescriptor({ ...claims, descriptor_number: 2, party_id: first.facts.party_id,
    prev_descriptor_digest: first.facts.descriptor_digest }, handle, { predecessor: first.facts });
  assert.ok(next.ok, JSON.stringify(next));
  const previous = verifyDescriptor(next.result.descriptor, first.facts);
  assert.ok(previous.ok);
  assert.equal(previous.facts.lineage.length, 2);
  const successor = { ...claims, descriptor_number: 3, party_id: previous.facts.party_id,
    prev_descriptor_digest: previous.facts.descriptor_digest };
  for (const max_artifact_set_items of [0, 1]) {
    const options = { limits: { max_artifact_set_items, max_array_items: 1 } };
    const prepared = prepareSigning("descriptor", "issuer-key-001", successor, publicKey, previous.facts, options);
    assert.ok(prepared.ok, JSON.stringify(prepared));
    const signed = await signDescriptor(successor, handle, { ...options, predecessor: previous.facts });
    assert.ok(signed.ok, JSON.stringify(signed));
    assert.ok(verifyDescriptor(signed.result.descriptor, previous.facts).ok);
  }
});

test("the verifier checks claims before the caller's context item limit", async () => {
  const publicKey = derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey);
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const options = { limits: { max_artifact_set_items: 1 } };
  for (const { kind, claims, call } of signingCalls(handle)) {
    if (kind === "descriptor") continue;
    const input = kind === "termination" ? {} : claims;
    const checked = prepareSigning(kind as SigningKind, "issuer-key-001", input, publicKey, world.genesisView, options);
    assert.ok(!checked.ok);
    const result = kind === "termination" ? await signTermination(input, handle, world.genesisView, options) : await call(options);
    assert.deepEqual(result, { ok: false, error: "invalid_input", code: checked.code }, kind);
  }
  assert.deepEqual(counts, { identities: 3, signs: 0 });
});


test("invalid algorithm list contents remain opaque for the verifier", async () => {
  let value: unknown = "invalid";
  for (let depth = 0; depth < 200; depth += 1) value = { child: value };
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  const publicKey = derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey);
  const claims = genesisClaims("Ed25519", "issuer-key-001", publicKey);
  const options = { profile: { algorithms: ["Ed25519", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", value] } };
  const checked = decodeCharterRevision("", options as never);
  assert.ok(!checked.ok);
  assert.deepEqual(await signDescriptor(claims, handle, options as never),
    { ok: false, error: "invalid_input", code: checked.code });
  assert.deepEqual(counts, { identities: 0, signs: 0 });
});


test("predecessor option records match the verifier's plain predecessor", async () => {
  const previous = verifyDescriptor(world.issuer.descriptor);
  assert.ok(previous.ok);
  class Previous { constructor() { Object.assign(this, previous.ok && previous.facts); } }
  const publicKey = derivedPublic(ed25519FromSeed(Buffer.alloc(32, 11)).privateKey);
  const claims = { ...genesisClaims("Ed25519", "issuer-key-001", publicKey), descriptor_number: 2,
    party_id: previous.facts.party_id, prev_descriptor_digest: previous.facts.descriptor_digest };
  const { handle, counts } = callbackCounts(11, "issuer-key-001");
  for (const predecessor of [new Previous(), Object.assign(new Map(), previous.facts), Object.create(previous.facts)]) {
    const signed = await signDescriptor(claims, handle, { predecessor } as never);
    assert.ok(signed.ok, JSON.stringify(signed));
    assert.ok(verifyDescriptor(signed.result.descriptor, previous.facts).ok);
  }
  assert.deepEqual(counts, { identities: 3, signs: 3 });
});
