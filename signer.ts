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
  retainSigningContext,
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
  /** Public key identity to verify before invoking the handle. */
  keyIdentity?: KeySnapshot;
};

export type DescriptorOptions = SigningOptions & { predecessor?: DescriptorPredecessor | null };

const COPY_LIMIT = Symbol("copy limit");

type CopyFrame = {
  source: object;
  target: Record<string, unknown> | unknown[];
  keys: string[] | null;
  size: number;
  index: number;
  depth: number;
};

function arrayLength(list: unknown[]): number {
  const length = list.length;
  if (!Number.isInteger(length) || length < 0 || length > 0xffff_ffff) throw new TypeError("invalid_type");
  return length;
}

// Read one child at a time without recursion or array constructor hooks.
// Only ancestors are retained, so repeated objects get separate copies.
function copyClaims<T>(value: T): T {
  const limits = MAXIMUM_LIMITS;
  const ancestors = new WeakSet<object>();
  const frames: CopyFrame[] = [];
  let bytes = 0;
  const addBytes = (size: number) => {
    bytes += size;
    if (bytes > limits.max_bytes) throw COPY_LIMIT;
  };
  const stringBytes = (text: string) => {
    if (Buffer.byteLength(text) > limits.max_string_bytes) throw COPY_LIMIT;
    return Buffer.byteLength(JSON.stringify(text));
  };
  const copy = (item: unknown, depth: number): unknown => {
    if (item === null || typeof item === "boolean") {
      addBytes(item === null || item === true ? 4 : 5);
      return item;
    }
    if (typeof item === "string") {
      addBytes(stringBytes(item));
      return item;
    }
    if (typeof item === "number" && Number.isFinite(item)) {
      addBytes(JSON.stringify(item).length);
      return item;
    }
    if (typeof item !== "object" || ancestors.has(item)) throw new TypeError("invalid_type");
    if (depth + 1 > limits.max_depth) throw COPY_LIMIT;
    const array = Array.isArray(item);
    let keys: string[] | null = null;
    if (!array) {
      const prototype = Object.getPrototypeOf(item);
      if ((prototype !== Object.prototype && prototype !== null) || Object.getOwnPropertySymbols(item).length > 0) {
        throw new TypeError("invalid_type");
      }
      keys = Object.keys(item);
    }
    const size = array ? arrayLength(item) : keys!.length;
    if (size > (array ? limits.max_array_items : limits.max_object_members)) {
      throw COPY_LIMIT;
    }
    addBytes(2 + Math.max(0, size - 1));
    const target: Record<string, unknown> | unknown[] = array ? [] : Object.create(null);
    ancestors.add(item);
    frames.push({ source: item, target, keys, size, index: 0, depth: depth + 1 });
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
    const copied = copy(child, frame.depth);
    if (Array.isArray(frame.target)) frame.target.push(copied);
    else frame.target[key] = copied;
  }
  return result as T;
}

async function resolveKeyIdentity(handle: unknown): Promise<KeySnapshot | SignError> {
  try {
    if (handle === null || typeof handle !== "object") return { error: "invalid_key_handle" };
    const snapshot = await (handle as KeyHandle).keyIdentity(handle);
    return copyKeyIdentity(snapshot) ?? { error: "invalid_key_handle" };
  } catch (_fault) {
    return { error: "invalid_key_handle" };
  }
}

function copyKeyIdentity(value: unknown): KeySnapshot | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const { kid, publicKey } = value as Partial<KeySnapshot>;
  return typeof kid === "string" && kid.length > 0 && typeof publicKey === "string" ? { kid, publicKey } : null;
}

const OPTION_KEYS = new Set(["algorithm", "limits", "profile", "keyIdentity"]);
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteArrayTag = Object.getOwnPropertyDescriptor(typedArrayPrototype, Symbol.toStringTag)!.get!;
const byteArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;

type ResolvedOptions = Omit<SigningOptions, "algorithm"> & { algorithm: string };

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
  const registry = algorithmRegistry().map((row) => row.name);
  // A unique registry subset cannot be longer than the registry. Retain an
  // invalid profile without reading an unbounded caller list.
  if (!Number.isInteger(length) || length < 1 || length > registry.length) return [];
  const result: string[] = [];
  for (let i = 0; i < length; i += 1) {
    const name = value[i];
    if (typeof name !== "string" || !registry.includes(name) || result.includes(name)) return [];
    result.push(name);
  }
  return result;
}

function optionProfile(value: unknown): Profile | undefined {
  const names = ["algorithms", "revisions"];
  const projected = optionMembers(value, names, {
    revisions: (range) => optionMembers(range, ["min", "max"]),
  });
  if (projected !== value) {
    const profile = projected as Record<string, unknown>;
    if (profile.algorithms !== undefined && Object.keys(profile).every((name) => names.includes(name))) {
      profile.algorithms = optionAlgorithms(profile.algorithms);
    }
  }
  return projected as Profile | undefined;
}

// The verifier reads just these members during its bounded context capture.
// Preserve ordinary access for inherited and nonenumerable signer inputs.
function signingContext<T>(value: T, names: readonly string[]): T {
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Number) return value;
  const source = value as Record<string, unknown>;
  const projected = Object.create(null);
  for (const name of names) {
    if (name in source) Object.defineProperty(projected, name, { enumerable: true, get: () => source[name] });
  }
  return projected;
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
    settings.profile = optionProfile(supplied.profile);
    const profileError = checkOptions(settings);
    if (profileError) return profileError;
    const algorithm = supplied.algorithm ?? defaultEmissionName();
    if (typeof algorithm !== "string" || !Object.hasOwn(emissions(), algorithm)) {
      return { error: "invalid_input", code: "algorithm_unsupported" };
    }
    const suppliedIdentity = supplied.keyIdentity;
    const keyIdentity = copyKeyIdentity(suppliedIdentity);
    if (suppliedIdentity !== undefined && !keyIdentity) return { error: "invalid_input", code: "invalid_type" };
    return { ...settings, algorithm, keyIdentity: keyIdentity ?? undefined };
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

type CapturedSigning = {
  claims: Record<string, unknown>;
  options: ResolvedOptions;
  retained: ReturnType<typeof retainSigningContext>;
};

function captureSigning(
  kind: SigningKind,
  claims: Record<string, unknown>,
  context: ChainView | string | null,
  opts: DescriptorOptions,
): CapturedSigning | SignError {
  const options = signingOptions(opts, kind === "descriptor");
  if ("error" in options) return options;
  let predecessor: DescriptorPredecessor | null = null;
  try {
    if (kind === "descriptor") predecessor = opts.predecessor ?? null;
  } catch (_fault) {
    return { error: "invalid_input", code: "invalid_type" };
  }
  let retained: ReturnType<typeof retainSigningContext>;
  try {
    const input = kind === "descriptor" ? signingContext(predecessor, ["digest", "descriptor_digest", "lineage"]) :
      signingContext(context, ["revisions", "acceptances", "descriptors", "terminations"]);
    retained = retainSigningContext(kind, input, {
      algorithm: options.algorithm,
      limits: options.limits,
      profile: options.profile,
    });
  } catch (_fault) {
    retained = { ok: false, code: "invalid_type" };
  }
  try {
    // Caller limits belong to preparation. The entry guard only stops values
    // beyond every JSON limit the verifier can accept.
    claims = copyClaims(claims);
  } catch (fault) {
    if (!retained.ok) return prepareError(retained.code);
    return { error: "invalid_input", code: fault === COPY_LIMIT ? "signing_input_invalid" : "invalid_type" };
  }
  return { claims, options, retained };
}

async function signCaptured(
  { claims, options, retained }: CapturedSigning,
  keyHandle: unknown,
): Promise<{ compact: string } | SignError> {
  const prepare = ({ kid, publicKey }: KeySnapshot) => retained.ok ? retained.value(kid, claims, publicKey) : retained;
  const declared = options.keyIdentity;
  const preflight = declared && prepare(declared);
  if (preflight && !preflight.ok) return prepareError(preflight.code);

  const snapshot = await resolveKeyIdentity(keyHandle);
  if ("error" in snapshot) return snapshot;
  if (declared && (snapshot.kid !== declared.kid || snapshot.publicKey !== declared.publicKey)) {
    return { error: "refused", code: "signing_key_mismatch" };
  }

  const prepared = preflight ?? prepare(snapshot);
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
    const length = byteArrayLength.call(signature);
    if (length > MAXIMUM_LIMITS.max_bytes) return { error: "signing_failed" };
    const bytes = new Uint8Array(length);
    bytes.set(signature);
    checkedSignature = Buffer.from(bytes);
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

function signArtifact<T>(
  kind: SigningKind, claims: Record<string, unknown>, keyHandle: unknown, context: ChainView | string | null,
  opts: DescriptorOptions, result: (compact: string) => T,
): Promise<SignResult<T>> {
  const captured = captureSigning(kind, claims, context, opts);
  return "error" in captured ? Promise.resolve<SignResult<T>>({ ok: false, ...captured }) :
    artifactResult(signCaptured(captured, keyHandle), result);
}

async function artifactResult<T>(
  signing: Promise<{ compact: string } | SignError>, result: (compact: string) => T,
): Promise<SignResult<T>> {
  const signed = await signing;
  return "error" in signed ? { ok: false, ...signed } : { ok: true, result: result(signed.compact) };
}

export function signDescriptor(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  opts: DescriptorOptions = {},
): Promise<SignResult<{ descriptor: string }>> {
  return signArtifact("descriptor", claims, keyHandle, null, opts, (descriptor) => ({ descriptor }));
}

export function signReceipt(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  context: ChainView | string,
  opts: SigningOptions = {},
): Promise<SignResult<{ receipt: string }>> {
  return signArtifact("receipt", claims, keyHandle, context, opts, (receipt) => ({ receipt }));
}

export function signAcceptance(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  chain: ChainView,
  opts: SigningOptions = {},
): Promise<SignResult<{ acceptance: string }>> {
  return signArtifact("acceptance", claims, keyHandle, chain, opts, (acceptance) => ({ acceptance }));
}

/** Sign the departing party's acceptance. Other parties sign separately. */
export function signPartyReplacement(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  chain: ChainView,
  opts: SigningOptions = {},
): Promise<SignResult<{ acceptance: string }>> {
  return signArtifact("party_replacement", claims, keyHandle, chain, opts, (acceptance) => ({ acceptance }));
}

export function signTermination(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  chain: ChainView,
  opts: SigningOptions = {},
): Promise<SignResult<{ termination: string }>> {
  return signArtifact("termination", claims, keyHandle, chain, opts, (termination) => ({ termination }));
}
