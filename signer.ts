// CAP never authorizes.
// The holder supplies one key snapshot and signs the verifier's prepared
// message. The verifier owns framing, claims, context, limits, profile,
// key matching, assembly, and completion. This package keeps custody and
// the wrong-key guard.

import {
  DEFAULT_LIMITS,
  MAXIMUM_LIMITS,
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

const COPY_LIMIT = Symbol("copy limit");
const ARTIFACT_LISTS = new Set(["revisions", "acceptances", "descriptors", "terminations", "lineage"]);
type CopySettings = { optionValues?: boolean; limits?: Limits; context?: boolean };
type CopyFrame = {
  source: object;
  target: Record<string, unknown> | unknown[];
  keys: string[] | null;
  size: number;
  index: number;
  depth: number;
  artifacts: boolean;
};

// Read one child at a time without recursion or array constructor hooks.
// Only ancestors are retained, so repeated objects get separate copies.
function copyClaims<T>(value: T, { optionValues = false, limits, context = false }: CopySettings = {}): T {
  const ancestors = new WeakSet<object>();
  const frames: CopyFrame[] = [];
  let bytes = 0;
  const addBytes = (size: number) => {
    bytes += size;
    if (limits && bytes > limits.max_bytes) throw COPY_LIMIT;
  };
  const stringBytes = (text: string) => {
    if (limits && Buffer.byteLength(text) > limits.max_string_bytes) throw COPY_LIMIT;
    return Buffer.byteLength(JSON.stringify(text));
  };
  const copy = (item: unknown, depth: number, artifacts = false, artifact = false): unknown => {
    if (item === null || typeof item === "boolean") {
      addBytes(item === null || item === true ? 4 : 5);
      return item;
    }
    if (typeof item === "string") {
      // Context artifact text is immutable. The verifier checks its bytes
      // per artifact and per set; JSON string limits apply to parsed claims.
      addBytes(artifact ? 2 : stringBytes(item));
      return item;
    }
    // Option scalars, including undefined and nonfinite numbers, stay intact
    // so the verifier can apply its own validity checks and defaults.
    if (optionValues && item === undefined) return item;
    if (typeof item === "number" && (optionValues || Number.isFinite(item))) {
      addBytes(JSON.stringify(item).length);
      return item;
    }
    if (typeof item !== "object" || ancestors.has(item)) throw new TypeError("invalid_type");
    if (limits && depth + 1 > limits.max_depth) throw COPY_LIMIT;
    const array = Array.isArray(item);
    let keys: string[] | null = null;
    if (!array) {
      const prototype = Object.getPrototypeOf(item);
      if ((prototype !== Object.prototype && prototype !== null) || Object.getOwnPropertySymbols(item).length > 0) {
        throw new TypeError("invalid_type");
      }
      keys = Object.keys(item);
    }
    const size = array ? item.length : keys!.length;
    if (!Number.isSafeInteger(size) || size < 0) throw new TypeError("invalid_type");
    if (limits && size > (array ? artifacts ? limits.max_artifact_set_items : limits.max_array_items : limits.max_object_members)) {
      throw COPY_LIMIT;
    }
    addBytes(2 + Math.max(0, size - 1));
    const target: Record<string, unknown> | unknown[] = array ? [] : Object.create(null);
    ancestors.add(item);
    frames.push({ source: item, target, keys, size, index: 0, depth: depth + 1, artifacts });
    return target;
  };
  const result = copy(value, 0);
  while (frames.length > 0) {
    const frame = frames[frames.length - 1];
    if (frame.index === frame.size) {
      ancestors.delete(frame.source);
      frames.pop();
      continue;
    }
    const index = frame.index++;
    const key = frame.keys ? frame.keys[index] : String(index);
    if (frame.keys) addBytes(stringBytes(key) + 1);
    const child = (frame.source as Record<string, unknown>)[key];
    const artifacts = context && frame.depth === 1 && frame.keys !== null && ARTIFACT_LISTS.has(key);
    const copied = copy(child, frame.depth, artifacts, frame.artifacts);
    if (Array.isArray(frame.target)) frame.target.push(copied);
    else frame.target[key] = copied;
  }
  return result as T;
}

function copyChainView(chain: ChainView, limits: Limits): ChainView {
  // An omitted context still reaches the verifier after the key snapshot.
  return chain === undefined ? chain : copyClaims(chain, { limits, context: true });
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
const byteArrayTag = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag)!.get!;

type ResolvedOptions = Omit<DescriptorOptions, "algorithm"> & { algorithm: string };

function readOption(opts: Record<string, unknown>, key: string, limits?: Limits): { value: unknown } | SignError {
  try {
    const value = opts[key];
    return { value: value === undefined || key === "algorithm" ? value : copyClaims(value, {
      optionValues: key !== "predecessor", limits, context: key === "predecessor",
    }) };
  } catch (fault) {
    return { error: "invalid_input", code: fault === COPY_LIMIT ? "limit_exceeded" : "invalid_type" };
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
  // The verifier exports no option validator. Its decoder resolves limits
  // and profile before reading text, so use it to preserve that order.
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
  const predecessor = readOption(supplied, "predecessor", { ...DEFAULT_LIMITS, ...settings.limits });
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
  const copyLimits = { ...DEFAULT_LIMITS, ...options.limits };
  let retained: DescriptorPredecessor | ChainView | string | null;
  try {
    retained = kind === "descriptor" ? options.predecessor ?? null :
      typeof context === "string" ? context : copyChainView(context as ChainView, copyLimits);
  } catch (fault) {
    return { error: "invalid_input", code: fault === COPY_LIMIT ? "limit_exceeded" : "invalid_type" };
  }
  try {
    // Caller limits belong to preparation. The entry guard only stops values
    // beyond every JSON limit the verifier can accept.
    claims = copyClaims(claims, { limits: MAXIMUM_LIMITS });
  } catch (fault) {
    return { error: "invalid_input", code: fault === COPY_LIMIT ? "signing_input_invalid" : "invalid_type" };
  }
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
    signature = await (keyHandle as KeyHandle).sign(Buffer.from(input.message), keyHandle);
  } catch (_fault) {
    return { error: "signing_failed" };
  }
  if (!ArrayBuffer.isView(signature) || byteArrayTag.call(signature) !== "Uint8Array") {
    return { error: "signing_failed" };
  }
  let checkedSignature: Buffer;
  try {
    checkedSignature = Buffer.from(signature);
  } catch (_signature) {
    return { error: "signing_failed" };
  }
  // The verifier's signature guard owns signature length checks.
  if (!verifySignature(prepared.plan.input.message, checkedSignature, snapshot.publicKey, input.alg, {
    limits: options.limits,
    profile: options.profile,
  })) {
    return { error: "signing_failed" };
  }
  const finished = finishSigning(prepared.plan, checkedSignature);
  // No real-crypto path reaches this mapping after preparation and the
  // custody guard succeed; keep it for a verifier completion error.
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
