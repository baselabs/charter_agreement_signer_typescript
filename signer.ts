// CAP never authorizes.
//
// The holder-side companion signer for the Charter Agreement Protocol,
// ported from the Elixir reference (charter_agreement_signer). The caller
// owns key custody through a handle object with two callbacks:
//
//   keyIdentity(handle) -> { kid, publicKey }   // ONE atomic snapshot
//   sign(message, handle) -> signature bytes    // the holder's job
//
// Framing, the producer claims gate, the honest-signer refusal guards
// (R1–R3), and assembly are ALL the verifier package's producer surface —
// exactly one implementation, exactly the reference signer's delegation.
// This package adds the custody half: the atomic key snapshot, the sign
// callback, the wrong-key guard against the snapshot's public key, and the
// post-sign verification of the assembled artifact. It never verifies
// third-party artifacts, never transports, never persists, and never sees
// a private key.

import {
  acceptanceSigningInput,
  algorithmRegistry,
  assembleCompact,
  defaultEmissionName,
  decodeCharterRevision,
  descriptorSigningInput,
  emissions,
  receiptSigningInput,
  terminationSigningInput,
  verifyAcceptance,
  verifyChain,
  verifyDescriptor,
  verifyReceipt,
  verifySignature,
  verifyTermination,
  type ProducerResult,
  type SigningInput,
  type DescriptorPredecessor,
  type Limits,
  type Profile,
} from "@charter-agreement-protocol/verifier";

export type KeySnapshot = { kid: string; publicKey: string };
export type KeyHandle = {
  keyIdentity(handle: unknown): KeySnapshot | Promise<KeySnapshot>;
  sign(message: Uint8Array, handle: unknown): Uint8Array | Promise<Uint8Array>;
};

export type SignError =
  | { error: "invalid_key_handle" }
  | { error: "signing_failed" }
  | { error: "invalid_input"; code: string }
  | { error: "refused"; code: string }
  | { error: "verification_failed" };

export type SignOk<T> = { ok: true; result: T };
export type SignResult<T> = SignOk<T> | ({ ok: false } & SignError);

export type ChainView = {
  revisions: string[];
  acceptances: string[];
  descriptors: string[];
  terminations: string[];
};

export type SigningOptions = {
  algorithm?: string | null;
  limits?: Partial<Limits>;
  profile?: Profile;
};

export type DescriptorOptions = SigningOptions & { predecessor?: DescriptorPredecessor | null };

function copyArray(values: string[]): string[] {
  return Array.isArray(values) ? [...values] : values;
}

function copyChainView(chain: ChainView): ChainView {
  if (!chain || typeof chain !== "object" || Array.isArray(chain)) return chain;
  return {
    ...chain,
    revisions: copyArray(chain.revisions),
    acceptances: copyArray(chain.acceptances),
    descriptors: copyArray(chain.descriptors),
    terminations: copyArray(chain.terminations),
  };
}

// Claims are copied at entry too, so a key callback cannot change the
// claims that get framed after its snapshot. The copy walks plain objects
// and arrays through ordinary property reads, so a Proxy (Vue, MobX, Immer
// state) is copied like the object it presents. Any other value (a class
// instance, a function, a bigint) is kept as is for the producer to judge,
// as before; a cycle is kept by reference and the producer rejects it.
function copyClaims(claims: Record<string, unknown>): Record<string, unknown> {
  const seen = new WeakSet<object>();
  const copy = (value: unknown): unknown => {
    if (value === null || typeof value !== "object") return value;
    if (seen.has(value)) return value;
    if (Array.isArray(value)) {
      seen.add(value);
      return value.map(copy);
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return value;
    seen.add(value);
    return Object.fromEntries(Object.keys(value).map((key) => [key, copy((value as Record<string, unknown>)[key])]));
  };
  return copy(claims) as Record<string, unknown>;
}

function copyIssuingView(view: { revisionText: string; descriptorCompacts: string[]; chain: ChainView }): typeof view {
  if (!view || typeof view !== "object") return view;
  return {
    ...view,
    descriptorCompacts: copyArray(view.descriptorCompacts),
    chain: copyChainView(view.chain),
  };
}

function registryRow(algorithm: string) {
  return algorithmRegistry().find((row) => row.name === algorithm) ?? null;
}

async function resolveKeyIdentity(
  handle: unknown,
): Promise<{ kid: string; publicKey: string } | SignError> {
  if (handle === null || typeof handle !== "object" || !("keyIdentity" in handle)) {
    return { error: "invalid_key_handle" };
  }
  try {
    const snapshot = await (handle as KeyHandle).keyIdentity(handle);
    if (
      snapshot &&
      typeof snapshot.kid === "string" &&
      snapshot.kid.length > 0 &&
      typeof snapshot.publicKey === "string" &&
      Buffer.from(snapshot.publicKey, "base64url").length > 0
    ) {
      return snapshot;
    }
    return { error: "invalid_key_handle" };
  } catch (_fault) {
    return { error: "invalid_key_handle" };
  }
}

// Options are a plain object with known keys only: a misspelled key must not
// fall back to the default silently, and a Map, a class instance or a
// throwing getter is caller input error, never a thrown exception.
const OPTION_KEYS = new Set(["algorithm", "limits", "profile"]);

function signingOptions(opts: unknown, descriptor: boolean): DescriptorOptions | SignError {
  try {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) return { error: "invalid_input", code: "invalid_type" };
    const prototype = Object.getPrototypeOf(opts);
    if (prototype !== Object.prototype && prototype !== null ||
        !Reflect.ownKeys(opts).every((key) => typeof key === "string" && (OPTION_KEYS.has(key) || descriptor && key === "predecessor"))) {
      return { error: "invalid_input", code: "invalid_type" };
    }
    const supplied = opts as DescriptorOptions;
    const settings = copyClaims({ limits: supplied.limits, profile: supplied.profile }) as SigningOptions;
    // The verifier resolves limits, then profile, before decoding any text.
    const checked = decodeCharterRevision(undefined, settings);
    if (!checked.ok && (checked.code === "invalid_limits" || checked.code === "invalid_profile")) {
      return { error: "invalid_input", code: checked.code };
    }
    const algorithm = supplied.algorithm ?? defaultEmissionName();
    if (typeof algorithm !== "string" || !Object.hasOwn(emissions(), algorithm)) {
      return { error: "invalid_input", code: "algorithm_unsupported" };
    }
    return { ...settings, algorithm, ...(descriptor ? { predecessor: supplied.predecessor } : {}) };
  } catch (_getter) {
    return { error: "invalid_input", code: "invalid_type" };
  }
}

// The shared custody tail (the reference signer's): identity snapshot ->
// producer (framing, claims schema, R1-R3 refusals - one implementation,
// in the verifier package) -> sign via the handle -> wrong-key guard.
// A refusal or producer rejection never touches the key.
async function signProduced(
  keyHandle: unknown,
  produce: (kid: string, algorithm?: string) => ProducerResult,
  opts: SigningOptions,
  descriptor = false,
): Promise<{ input: SigningInput; signature: Buffer } | SignError> {
  // Options are an object or absent, as the Elixir signer takes a map or a
  // keyword list: null, a number, an array or a bare string is caller input
  // error, never a silent default.
  const options = signingOptions(opts, descriptor);
  if ("error" in options) return options;
  const algorithm = options.algorithm as string;
  const snapshot = await resolveKeyIdentity(keyHandle);
  if ("error" in snapshot) return snapshot;

  const produced = produce(snapshot.kid, algorithm);
  if (!produced.ok) {
    // signing_refused is the honest-signer refusal; every other producer
    // code stays caller input.
    return produced.code === "signing_refused"
      ? { error: "refused", code: produced.code }
      : { error: "invalid_input", code: produced.code };
  }

  // The holder signs the exact message; a fault or a wrong-length result is
  // a signing failure, never a silent pass.
  let signature: Uint8Array;
  try {
    signature = await (keyHandle as KeyHandle).sign(produced.input.message, keyHandle);
  } catch (_fault) {
    return { error: "signing_failed" };
  }
  if (!(signature instanceof Uint8Array) || signature.length === 0) {
    return { error: "signing_failed" };
  }
  const row = registryRow(produced.input.alg);
  if (!row || signature.length !== row.signatureBytes) {
    return { error: "signing_failed" };
  }

  // The wrong-key guard: the signature MUST verify against the snapshot's
  // public key under the minted algorithm.
  if (
    !verifySignature(
      produced.input.message,
      Buffer.from(signature),
      snapshot.publicKey,
      produced.input.alg,
    )
  ) {
    return { error: "signing_failed" };
  }

  return { input: produced.input, signature: Buffer.from(signature) };
}

// Assembly goes through the verifier's assembleCompact: registry-row
// length, framing re-decode, size gate - never a local string join.
function compactOrInvalid(signed: { input: SigningInput; signature: Buffer }): { compact: string } | SignError {
  const assembled = assembleCompact(signed.input, signed.signature);
  if (!assembled.ok) return { error: "invalid_input", code: assembled.code };
  return { compact: assembled.compact };
}

// The view's chain is THIS package's public contract (the producer surface
// validates its depth); the shallow shape is policed here so the closed
// error vocabulary holds regardless of which verifier revision resolves.
// A verifier crash past this gate stays loud - never a misleading error.
function chainViewOrInvalid(chain: unknown): ChainView | { error: "invalid_input"; code: string } {
  if (!chain || typeof chain !== "object" || Array.isArray(chain)) {
    return { error: "invalid_input", code: "signing_input_invalid" };
  }
  return chain as ChainView;
}

// A missing view object is caller input like a missing chain: the closed
// error, never a dereference throw.
function viewChainOrInvalid(view: { chain: ChainView }): ChainView | { error: "invalid_input"; code: string } {
  if (!view || typeof view !== "object") return { error: "invalid_input", code: "signing_input_invalid" };
  return chainViewOrInvalid(view.chain);
}

// ---------------------------------------------------------------------------
// Public signing surface
// ---------------------------------------------------------------------------

export async function signDescriptor(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  opts: DescriptorOptions = {},
): Promise<SignResult<{ descriptor: string }>> {
  claims = copyClaims(claims);
  const signed = await signProduced(keyHandle, (kid, algorithm) => descriptorSigningInput(kid, claims, algorithm), opts, true);
  if ("error" in signed) return { ok: false, ...signed };
  const assembled = compactOrInvalid(signed);
  if ("error" in assembled) return { ok: false, ...assembled };
  const verified = verifyDescriptor(assembled.compact);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { descriptor: assembled.compact } };
}

export async function signReceipt(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  chain: ChainView,
  opts: SigningOptions = {},
): Promise<SignResult<{ receipt: string }>> {
  claims = copyClaims(claims);
  chain = copyChainView(chain);
  // The issuing view is REQUIRED (the reference takes ChainFacts or a
  // CharterRevision, never none) and its discipline runs after the build,
  // before the key - the reference's context is a verified ChainFacts by
  // construction, so a TS view that fails the chain discipline is caller
  // input, never a burned key operation.
  const signed = await signProduced(keyHandle, (kid, algorithm) => {
    const built = receiptSigningInput(kid, claims, algorithm);
    if (!built.ok) return built;
    const resolved = chainViewOrInvalid(chain);
    if ("error" in resolved) return { ok: false, code: resolved.code };
    if (!verifyChain(resolved).ok) return { ok: false, code: "chain_invalid" };
    return built;
  }, opts);
  if ("error" in signed) return { ok: false, ...signed };
  const assembled = compactOrInvalid(signed);
  if ("error" in assembled) return { ok: false, ...assembled };
  const verified = verifyReceipt(assembled.compact, chain);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { receipt: assembled.compact } };
}

export async function signAcceptance(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  view: { revisionText: string; descriptorCompacts: string[]; chain: ChainView },
  opts: SigningOptions = {},
): Promise<SignResult<{ acceptance: string }>> {
  claims = copyClaims(claims);
  view = copyIssuingView(view);
  const viewChain = viewChainOrInvalid(view);
  const signed = await signProduced(keyHandle, (kid, algorithm) => {
    if ("error" in viewChain) return { ok: false, code: viewChain.code };
    return acceptanceSigningInput(kid, claims, viewChain, algorithm);
  }, opts);
  if ("error" in signed) return { ok: false, ...signed };
  const assembled = compactOrInvalid(signed);
  if ("error" in assembled) return { ok: false, ...assembled };
  const verified = verifyAcceptance(assembled.compact, view.revisionText, view.descriptorCompacts);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { acceptance: assembled.compact } };
}

export async function signTermination(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  view: { revisionText: string; descriptorCompacts: string[]; chain: ChainView },
  opts: SigningOptions = {},
): Promise<SignResult<{ termination: string }>> {
  claims = copyClaims(claims);
  view = copyIssuingView(view);
  const viewChain = viewChainOrInvalid(view);
  const signed = await signProduced(keyHandle, (kid, algorithm) => {
    if ("error" in viewChain) return { ok: false, code: viewChain.code };
    return terminationSigningInput(kid, claims, viewChain, algorithm);
  }, opts);
  if ("error" in signed) return { ok: false, ...signed };
  const assembled = compactOrInvalid(signed);
  if ("error" in assembled) return { ok: false, ...assembled };
  const verified = verifyTermination(assembled.compact, view.revisionText, view.descriptorCompacts);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { termination: assembled.compact } };
}
