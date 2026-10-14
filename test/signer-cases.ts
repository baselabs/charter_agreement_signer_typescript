import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { Point } from "@noble/ed25519";
import {
  decodeCharterRevision,
  verifyChain,
  verifyDescriptor,
  verifyReceipt,
  type DescriptorPredecessor,
} from "@charter-agreement-protocol/verifier";
import {
  signAcceptance, signDescriptor, signReceipt, signTermination,
  type ChainView, type DescriptorOptions, type KeyHandle, type SignResult,
} from "../signer.ts";

// The digest is from the exact file in the source commit, including whitespace.
export const SHARED_SOURCE = {
  commit: "dab4d86230551a95185e5057d98cd20b85285734",
  file: "test/fixtures/signer_cases.json",
  sha256: "3db6f031d6edec92c59e15481fdba884992f95837ea0aefd5bda6b9375c27bb2",
} as const;

type Key = {
  algorithm: "Ed25519" | "ML-DSA-65";
  kid: string;
  seed: string;
  public_key: string;
  mixed_order?: boolean;
};
type Expected = {
  shape: keyof typeof OUTCOME_MAPPING;
  code: string | null;
  snapshot_called: boolean;
  custody_called: boolean;
  compact?: string;
};
export type Case = {
  id: string;
  kind: "descriptor" | "acceptance" | "termination" | "receipt";
  key: string;
  claims: Record<string, unknown>;
  context: unknown;
  options: Record<string, unknown>;
  expected: Expected;
  expected_limited?: Expected;
};
type Context = Partial<ChainView> & { type: "set" | "chain" | "revision" | "predecessor"; text?: string };
type Table = { format_version: number; keys: Record<string, Key>; contexts: Record<string, Context>; cases: Case[] };

export const fixtureBytes = readFileSync(new URL("./fixtures/signer_cases.json", import.meta.url));
export const sharedTable: Table = JSON.parse(fixtureBytes.toString("utf8"));

// Elixir outcome                        TypeScript outcome
// {:ok, result}                         {ok:true, result}
// {:error, {:refused, code}}            {ok:false, error:"refused", code}
// {:error, {:invalid_input, code}}      {ok:false, error:"invalid_input", code}
// {:error, top_level_atom}              {ok:false, error:top_level_atom}
const OUTCOME_MAPPING = {
  ok: { ok: true, coded: false },
  refused: { ok: false, coded: true },
  invalid_input: { ok: false, coded: true },
  invalid_key_handle: { ok: false, coded: false },
  signing_failed: { ok: false, coded: false },
  verification_failed: { ok: false, coded: false },
  algorithm_unsupported_on_substrate: { ok: false, coded: false },
} as const;

export function expectedFailure(expected: Expected) {
  const entry = OUTCOME_MAPPING[expected.shape];
  assert.equal(entry.ok, false);
  if (entry.coded) return { ok: false, error: expected.shape, code: expected.code };
  assert.equal(expected.code, expected.shape);
  return { ok: false, error: expected.shape };
}

function privateKey(key: Key) {
  const seed = Buffer.from(key.seed, "base64url");
  assert.equal(seed.length, 32);
  assert.equal(seed.toString("base64url"), key.seed);
  // PKCS#8 holds an Ed25519 seed or the ML-DSA-65 seed CHOICE [0].
  const prefix = key.algorithm === "Ed25519"
    ? "302e020100300506032b657004220420"
    : "3034020100300b060960864801650304031204228020";
  return createPrivateKey({ key: Buffer.concat([Buffer.from(prefix, "hex"), seed]), type: "pkcs8", format: "der" });
}

function littleInteger(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
}

function privateScalar(seed: Uint8Array): bigint {
  const bytes = createHash("sha512").update(seed).digest().subarray(0, 32);
  bytes[0] &= 248;
  bytes[31] = (bytes[31] & 63) | 64;
  return littleInteger(bytes);
}

function mixedSignature(message: Uint8Array, key: Key): Buffer {
  const seed = Buffer.from(key.seed, "base64url");
  const publicKey = Buffer.from(key.public_key, "base64url");
  const prefix = createHash("sha512").update(seed).digest().subarray(32);
  const scalar = privateScalar(seed);
  const order = Point.CURVE().n;
  // A real mixed-order key is aB + T. An even challenge cancels order-two T.
  for (let attempt = 0; ; attempt += 1) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(attempt);
    const nonceSeed = createHash("sha256").update(prefix).update(message).update(counter).digest();
    const nonceKey = privateKey({ ...key, seed: nonceSeed.toString("base64url") });
    const point = createPublicKey(nonceKey).export({ format: "der", type: "spki" }).subarray(-32);
    const challenge = littleInteger(createHash("sha512").update(point).update(publicKey).update(message).digest()) % order;
    if (challenge % 2n !== 0n) continue;
    const response = (privateScalar(nonceSeed) + challenge * scalar) % order;
    const signature = Buffer.concat([point, Buffer.from(response.toString(16).padStart(64, "0"), "hex").reverse()]);
    const verifyingKey = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]), format: "der", type: "spki",
    });
    assert.ok(nodeVerify(null, message, verifyingKey, signature));
    return signature;
  }
}

export function realKey(row: Case) {
  const key = sharedTable.keys[row.key];
  assert.ok(key, `missing key for ${row.id}`);
  const heldKey = privateKey(key);
  const heldPublic = createPublicKey(heldKey).export({ format: "der", type: "spki" }).subarray(key.algorithm === "Ed25519" ? -32 : -1952);
  if (key.algorithm === "ML-DSA-65") assert.equal(heldPublic.toString("base64url"), key.public_key);
  if (key.mixed_order) {
    const torsion = Point.fromAffine({ x: 0n, y: Point.CURVE().p - 1n });
    assert.equal(Buffer.from(Point.fromBytes(heldPublic).add(torsion).toBytes()).toString("base64url"), key.public_key);
  }
  const counts = { snapshots: 0, custody: 0 };
  const handle: KeyHandle = {
    keyIdentity() {
      counts.snapshots += 1;
      return { kid: key.kid, publicKey: key.public_key };
    },
    sign(message) {
      counts.custody += 1;
      return key.mixed_order ? mixedSignature(message, key) : nodeSign(null, message, heldKey);
    },
  };
  return { handle, counts, algorithm: key.algorithm };
}

export function caseContext(row: Case): unknown {
  if (typeof row.context !== "string") return row.context;
  const input = sharedTable.contexts[row.context];
  assert.ok(input, `missing context for ${row.id}`);
  if (input.type === "revision") {
    assert.ok(decodeCharterRevision(input.text).ok, row.id);
    return input.text;
  }
  if (input.type === "predecessor") {
    let previous: DescriptorPredecessor | null = null;
    assert.ok(input.descriptors?.length);
    for (const compact of input.descriptors) {
      const verified = verifyDescriptor(compact, previous);
      assert.ok(verified.ok, `${row.id}: ${JSON.stringify(verified)}`);
      previous = verified.facts;
    }
    return previous;
  }
  assert.ok(input.type === "set" || input.type === "chain");
  const chain: ChainView = {
    revisions: input.revisions!, acceptances: input.acceptances!,
    descriptors: input.descriptors!, terminations: input.terminations!,
  };
  // TS retains chain arrays; Elixir retains verified chain structs for this type.
  if (input.type === "chain") {
    const verified = verifyChain(chain);
    assert.ok(verified.ok, `${row.id}: ${JSON.stringify(verified)}`);
  }
  return chain;
}

export function caseOptions(row: Case, context: unknown): DescriptorOptions {
  const options = structuredClone(row.options);
  const profile = options.profile;
  if (profile && typeof profile === "object" && !Array.isArray(profile)) {
    const value = profile as Record<string, unknown>;
    if (Array.isArray(value.revisions) && value.revisions.length === 2) {
      value.revisions = { min: value.revisions[0], max: value.revisions[1] };
    }
  }
  if (row.kind === "descriptor" && context !== null) options.predecessor = context;
  return options as DescriptorOptions;
}

type Signer = Pick<typeof import("../signer.ts"), "signDescriptor" | "signAcceptance" | "signTermination" | "signReceipt">;
const nativeSigner: Signer = { signDescriptor, signAcceptance, signTermination, signReceipt };

export async function runCase(row: Case, signer: Signer = nativeSigner) {
  const { handle, counts, algorithm } = realKey(row);
  const context = caseContext(row);
  const options = caseOptions(row, context);
  let result: SignResult<Record<string, string>>;
  switch (row.kind) {
    case "descriptor": result = await signer.signDescriptor(row.claims, handle, options); break;
    case "acceptance": result = await signer.signAcceptance(row.claims, handle, context as ChainView, options); break;
    case "termination": result = await signer.signTermination(row.claims, handle, context as ChainView, options); break;
    case "receipt": result = await signer.signReceipt(row.claims, handle, context as ChainView | string, options); break;
  }
  return { result, counts, context, algorithm };
}

export function verifySuccess(row: Case, compact: string, context: unknown,
  verifier = { verifyDescriptor, verifyReceipt, verifyChain }) {
  if (row.kind === "descriptor") return verifier.verifyDescriptor(compact, context as DescriptorPredecessor | null);
  if (row.kind === "receipt") return verifier.verifyReceipt(compact, context as ChainView | string);
  const chain = context as ChainView;
  return verifier.verifyChain({
    ...chain,
    acceptances: row.kind === "acceptance" && !chain.acceptances.includes(compact) ? [...chain.acceptances, compact] : chain.acceptances,
    terminations: row.kind === "termination" ? [...chain.terminations, compact] : chain.terminations,
  });
}
