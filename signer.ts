// CAP never authorizes.
// The holder supplies one key snapshot and signs the verifier's prepared
// message. The verifier owns framing, claims, context, limits, profile,
// key matching, assembly, and completion. This package keeps custody and
// the wrong-key guard.

import {
  DEFAULT_LIMITS,
  algorithmRegistry,
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
type CopySettings = { limits?: Limits; context?: boolean; predecessor?: boolean };
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
function copyClaims<T>(value: T, { limits, context = false, predecessor = false }: CopySettings = {}): T {
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
    if (typeof item === "number" && Number.isFinite(item)) {
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
    if (limits && !(array && artifacts && predecessor) &&
        size > (array ? artifacts ? limits.max_artifact_set_items : limits.max_array_items : limits.max_object_members)) {
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

const OPTION_KEYS = new Set(["algorithm", "limits", "profile"]);
const byteArrayTag = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag)!.get!;

type ResolvedOptions = Omit<DescriptorOptions, "algorithm"> & { algorithm: string };

// Read the defined shape once, including inherited and nonenumerable members.
// Invalid member values stay opaque for the verifier to check synchronously.
function optionMembers(value: unknown, names: string[], nested: Record<string, (value: unknown) => unknown> = {}): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Number) return value;
  const source = value as Record<string, unknown>;
  const result: Record<string, unknown> = Object.create(null);
  const unknown = Object.keys(source).find((name) => !names.includes(name));
  if (unknown !== undefined) result[unknown] = null;
  for (const name of names) {
    const member = source[name];
    if (member !== undefined || name in source) result[name] = nested[name] ? nested[name](member) : member;
  }
  return result;
}

function optionAlgorithms(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  const length = value.length;
  if (!Number.isSafeInteger(length) || length < 0) throw new TypeError("invalid_type");
  // A unique registry subset cannot be longer than the registry. Retain an
  // invalid length for the verifier without reading an unbounded caller list.
  if (length > MAXIMUM_LIMITS.max_artifact_set_items) return Array(MAXIMUM_LIMITS.max_artifact_set_items + 1);
  if (length > algorithmRegistry().length) return value;
  const result: unknown[] = [];
  for (let i = 0; i < length; i += 1) result.push(value[i]);
  return result;
}

function checkOptions(settings: SigningOptions): SignError | null {
  // Empty text always gives invalid_syntax after successful option checks.
  // Every earlier code comes from the verifier, including copy failures.
  const checked = decodeCharterRevision("", settings);
  return !checked.ok && checked.code !== "invalid_syntax" ? { error: "invalid_input", code: checked.code } : null;
}

function signingOptions(opts: unknown, descriptor: boolean): ResolvedOptions | SignError {
  try {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts) || opts instanceof Number) {
      return { error: "invalid_input", code: "invalid_type" };
    }
    if (!Reflect.ownKeys(opts).every((key) => typeof key === "string" &&
        (OPTION_KEYS.has(key) || descriptor && key === "predecessor"))) {
      return { error: "invalid_input", code: "invalid_type" };
    }
    const supplied = opts as Record<string, unknown>;
    const settings: SigningOptions = {
      limits: optionMembers(supplied.limits, Object.keys(DEFAULT_LIMITS)) as Partial<Limits> | undefined,
    };
    const limitsError = checkOptions(settings);
    if (limitsError) return limitsError;
    settings.profile = optionMembers(supplied.profile, ["algorithms", "revisions"], {
      algorithms: optionAlgorithms,
      revisions: (range) => optionMembers(range, ["min", "max"]),
    }) as Profile | undefined;
    const profileError = checkOptions(settings);
    if (profileError) return profileError;
    const algorithm = supplied.algorithm ?? defaultEmissionName();
    if (typeof algorithm !== "string" || !Object.hasOwn(emissions(), algorithm)) {
      return { error: "invalid_input", code: "algorithm_unsupported" };
    }
    if (!descriptor) return { ...settings, algorithm };
    const previous = supplied.predecessor;
    const predecessor = previous === undefined ? previous : copyClaims(
      optionMembers(previous, ["digest", "descriptor_digest", "lineage"]), {
        limits: MAXIMUM_LIMITS, context: true, predecessor: true,
      });
    return { ...settings, algorithm, predecessor: predecessor as DescriptorPredecessor | undefined };
  } catch (fault) {
    return { error: "invalid_input", code: fault === COPY_LIMIT ? "limit_exceeded" : "invalid_type" };
  }
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
  const copyLimits = MAXIMUM_LIMITS;
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
