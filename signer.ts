// CAP never authorizes.
// The holder supplies one key snapshot and signs the verifier's prepared
// message. The verifier owns framing, claims, context, limits, profile,
// key matching, assembly, and completion. This package keeps custody and
// the wrong-key guard.

import {
  algorithmRegistry,
  defaultEmissionName,
  decodeCharterRevision,
  emissions,
  finishSigning,
  prepareSigning,
  verifySignature,
  type DescriptorPredecessor,
  type Limits,
  type Profile,
  type SigningKind,
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
  | { error: "refused"; code: "signing_refused" | "signing_key_mismatch" }
  | { error: "algorithm_unsupported_on_substrate" }
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

async function resolveKeyIdentity(handle: unknown): Promise<KeySnapshot | SignError> {
  try {
    if (handle === null || typeof handle !== "object") return { error: "invalid_key_handle" };
    const snapshot = await (handle as KeyHandle).keyIdentity(handle);
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) return { error: "invalid_key_handle" };
    const { kid, publicKey } = snapshot;
    if (typeof kid !== "string" || kid.length === 0 || typeof publicKey !== "string") {
      return { error: "invalid_key_handle" };
    }
    return { kid, publicKey };
  } catch (_fault) {
    return { error: "invalid_key_handle" };
  }
}

// Options are a plain object with known keys only: a misspelled key must not
// fall back to the default silently, and a Map, a class instance or a
// throwing getter is caller input error, never a thrown exception.
const OPTION_KEYS = new Set(["algorithm", "limits", "profile"]);

type ResolvedOptions = Omit<DescriptorOptions, "algorithm"> & { algorithm: string };

function readOption(opts: Record<string, unknown>, key: string): { value: unknown } | SignError {
  try {
    return { value: copyClaims(opts[key] as Record<string, unknown>) };
  } catch (_getter) {
    return { error: "invalid_input", code: "invalid_type" };
  }
}

function signingOptions(opts: unknown, descriptor: boolean): ResolvedOptions | SignError {
  try {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) return { error: "invalid_input", code: "invalid_type" };
    const prototype = Object.getPrototypeOf(opts);
    if ((prototype !== Object.prototype && prototype !== null) ||
        !Reflect.ownKeys(opts).every((key) => typeof key === "string" && (OPTION_KEYS.has(key) || descriptor && key === "predecessor"))) {
      return { error: "invalid_input", code: "invalid_type" };
    }
  } catch (_shape) {
    return { error: "invalid_input", code: "invalid_type" };
  }
  const supplied = opts as Record<string, unknown>;
  const limits = readOption(supplied, "limits");
  if ("error" in limits) return limits;
  // The verifier resolves settings before decoding any text.
  const settings: SigningOptions = { limits: limits.value as Partial<Limits> | undefined };
  const checkedLimits = decodeCharterRevision(undefined, settings);
  if (!checkedLimits.ok && checkedLimits.code === "invalid_limits") {
    return { error: "invalid_input", code: checkedLimits.code };
  }
  const profile = readOption(supplied, "profile");
  if ("error" in profile) return profile;
  settings.profile = profile.value as Profile | undefined;
  const checkedProfile = decodeCharterRevision(undefined, settings);
  if (!checkedProfile.ok && checkedProfile.code === "invalid_profile") {
    return { error: "invalid_input", code: checkedProfile.code };
  }
  const selected = readOption(supplied, "algorithm");
  if ("error" in selected) return selected;
  const algorithm = selected.value ?? defaultEmissionName();
  if (typeof algorithm !== "string" || !Object.hasOwn(emissions(), algorithm)) {
    return { error: "invalid_input", code: "algorithm_unsupported" };
  }
  if (!descriptor) return { ...settings, algorithm };
  const predecessor = readOption(supplied, "predecessor");
  if ("error" in predecessor) return predecessor;
  return { ...settings, algorithm, predecessor: predecessor.value as DescriptorPredecessor | undefined };
}

function prepareError(code: string): SignError {
  switch (code) {
    case "signing_refused":
    case "signing_key_mismatch":
      return { error: "refused", code };
    case "signing_key_invalid":
      return { error: "invalid_key_handle" };
    case "algorithm_unsupported_on_substrate":
      return { error: "algorithm_unsupported_on_substrate" };
    default:
      return { error: "invalid_input", code };
  }
}

async function signPrepared(
  kind: SigningKind,
  claims: Record<string, unknown>,
  keyHandle: unknown,
  context: ChainView | string | null,
  opts: DescriptorOptions,
): Promise<{ compact: string } | SignError> {
  const options = signingOptions(opts, kind === "descriptor");
  if ("error" in options) return options;
  claims = copyClaims(claims);
  const retained = kind === "descriptor" ? options.predecessor ?? null :
    typeof context === "string" ? context : copyChainView(context as ChainView);
  const snapshot = await resolveKeyIdentity(keyHandle);
  if ("error" in snapshot) return snapshot;

  const prepared = prepareSigning(kind, snapshot.kid, claims, snapshot.publicKey, retained, {
    algorithm: options.algorithm,
    limits: options.limits,
    profile: options.profile,
  });
  if (!prepared.ok) return prepareError(prepared.code);
  const input = prepared.plan.input;

  let signature: Uint8Array;
  try {
    signature = await (keyHandle as KeyHandle).sign(input.message, keyHandle);
  } catch (_fault) {
    return { error: "signing_failed" };
  }
  const row = algorithmRegistry().find((one) => one.name === input.alg);
  if (!(signature instanceof Uint8Array) || !row || signature.length !== row.signatureBytes) {
    return { error: "signing_failed" };
  }
  if (!verifySignature(input.message, Buffer.from(signature), snapshot.publicKey, input.alg)) {
    return { error: "signing_failed" };
  }
  const finished = finishSigning(prepared.plan, signature);
  if (!finished.ok) return { error: "verification_failed" };
  return { compact: finished.compact };
}

export async function signDescriptor(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  opts: DescriptorOptions = {},
): Promise<SignResult<{ descriptor: string }>> {
  const signed = await signPrepared("descriptor", claims, keyHandle, null, opts);
  return "error" in signed ? { ok: false, ...signed } : { ok: true, result: { descriptor: signed.compact } };
}

export async function signReceipt(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  context: ChainView | string,
  opts: SigningOptions = {},
): Promise<SignResult<{ receipt: string }>> {
  const signed = await signPrepared("receipt", claims, keyHandle, context, opts);
  return "error" in signed ? { ok: false, ...signed } : { ok: true, result: { receipt: signed.compact } };
}

export async function signAcceptance(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  chain: ChainView,
  opts: SigningOptions = {},
): Promise<SignResult<{ acceptance: string }>> {
  const signed = await signPrepared("acceptance", claims, keyHandle, chain, opts);
  return "error" in signed ? { ok: false, ...signed } : { ok: true, result: { acceptance: signed.compact } };
}

export async function signTermination(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  chain: ChainView,
  opts: SigningOptions = {},
): Promise<SignResult<{ termination: string }>> {
  const signed = await signPrepared("termination", claims, keyHandle, chain, opts);
  return "error" in signed ? { ok: false, ...signed } : { ok: true, result: { termination: signed.compact } };
}
