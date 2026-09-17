// CAP never authorizes.
//
// The holder-side companion signer for the Charter Agreement Protocol,
// ported from the Elixir reference (charter_agreement_signer). The caller
// owns key custody through a handle object with two callbacks:
//
//   keyIdentity(handle) -> { kid, publicKey }   // ONE atomic snapshot
//   sign(message, handle) -> signature bytes    // the holder's job
//
// The signer builds the exact RFC 7515 signing input through the verifier
// package's producers surface, runs the honest-signer refusal guards
// (R1–R3, through the verifier package's refusal surface) before the key
// signs, checks the returned signature against the
// snapshot's public key (the wrong-key guard), assembles the compact, and
// post-sign-verifies the assembled artifact through the verifier package.
// It never verifies third-party artifacts, never transports, never
// persists, and never sees a private key.

import {
  acceptanceRefusal,
  algorithmRegistry,
  checkSigningClaims,
  canonical,
  decodeArtifact,
  defaultEmissionName,
  emissions,
  encodeBase64url,
  terminationRefusal,
  verifyAcceptance,
  verifyChain,
  verifyDescriptor,
  verifyReceipt,
  verifySignature,
  verifyTermination,
  type RefusalResult,
} from "@charter-agreement-protocol/verifier";

export type KeySnapshot = { kid: string; publicKey: string };
export type KeyHandle = {
  keyIdentity(handle: unknown): KeySnapshot | Promise<KeySnapshot>;
  sign(message: Uint8Array, handle: unknown): Uint8Array | Promise<Uint8Array>;
};

export type SignError =
  | { error: "invalid_handle" }
  | { error: "signing_failed" }
  | { error: "invalid_input"; code: string }
  | { error: "refused"; code: string }
  | { error: "verification_failed" };

export type SignOk<T> = { ok: true; result: T };
export type SignResult<T> = SignOk<T> | { ok: false } & SignError;

export type ChainView = {
  revisions: string[];
  acceptances: string[];
  descriptors: string[];
  terminations: string[];
};

const KINDS = ["descriptor", "acceptance", "termination", "receipt"] as const;
type ArtifactKind = (typeof KINDS)[number];
const TYPES: Record<ArtifactKind, string> = {
  descriptor: "cap+party",
  acceptance: "cap+acceptance",
  termination: "cap+termination",
  receipt: "cap+receipt",
};

const MAX_INPUT_BYTES = 1_048_576;

function registryRow(algorithm: string) {
  return algorithmRegistry().find((row) => row.name === algorithm) ?? null;
}

async function resolveKeyIdentity(
  handle: unknown,
): Promise<{ kid: string; publicKey: string } | SignError> {
  if (handle === null || typeof handle !== "object" || !("keyIdentity" in handle)) {
    return { error: "invalid_handle" };
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
    return { error: "invalid_handle" };
  } catch (_fault) {
    return { error: "invalid_handle" };
  }
}

function resolveAlgorithm(selection: unknown): string | SignError {
  if (selection === undefined || selection === null) return defaultEmissionName();
  if (typeof selection === "string" && selection in emissions()) return selection;
  return { error: "invalid_input", code: "algorithm_unsupported" };
}

function claimsRevision(claims: Record<string, unknown>): number | null {
  const value = claims.protocol_revision;
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

// The producer core: canonical claims, the closed protected header with the
// selected emission name and the SNAPSHOT kid, the size guard, and the
// provisional framing check over a zero signature — CAP's producer contract.
function frameSigningInput(
  kind: keyof typeof TYPES,
  claims: Record<string, unknown>,
  kid: string,
  algorithm: string,
): { protectedSegment: string; payloadSegment: string; message: Buffer } | SignError {
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    return { error: "invalid_input", code: "invalid_type" };
  }
  if (claimsRevision(claims) !== emissions()[algorithm]) {
    return { error: "invalid_input", code: "signing_input_invalid" };
  }
  if (typeof kid !== "string" || kid.length === 0 || kid.length > 128 || !/^[A-Za-z0-9._~-]+$/.test(kid)) {
    return { error: "invalid_input", code: "signing_input_invalid" };
  }
  const row = registryRow(algorithm);
  if (!row) return { error: "invalid_input", code: "algorithm_unsupported" };

  const payloadBytes = Buffer.from(canonical(claims as never), "utf8");
  const protectedBytes = Buffer.from(
    canonical({ alg: algorithm, kid, typ: TYPES[kind] } as never),
    "utf8",
  );
  const protectedSegment = encodeBase64url(protectedBytes);
  const payloadSegment = encodeBase64url(payloadBytes);
  const message = Buffer.from(`${protectedSegment}.${payloadSegment}`, "utf8");

  const signatureSegmentLength = Math.ceil((row.signatureBytes * 4) / 3);
  if (message.length + 1 + signatureSegmentLength > MAX_INPUT_BYTES) {
    return { error: "invalid_input", code: "signing_input_invalid" };
  }

  // The provisional check: a zero signature of the row's exact length must
  // frame and bind (canonical bytes, registry binding, per-row length).
  const zeroSignature = Buffer.alloc(row.signatureBytes);
  const provisional = `${protectedSegment}.${payloadSegment}.${encodeBase64url(zeroSignature)}`;
  const decoded = decodeArtifact(provisional);
  if (!decoded.ok) return { error: "invalid_input", code: "signing_input_invalid" };

  return { protectedSegment, payloadSegment, message };
}

async function signCommon(
  kind: keyof typeof TYPES,
  claims: Record<string, unknown>,
  keyHandle: KeyHandle | unknown,
  opts: { algorithm?: string },
  refusal?: () => SignError | null,
): Promise<{ message: Buffer; signature: Buffer } | SignError> {
  const snapshot = await resolveKeyIdentity(keyHandle);
  if ("error" in snapshot) return snapshot;

  const algorithm = resolveAlgorithm(opts?.algorithm);
  if (typeof algorithm !== "string" && "error" in algorithm) return algorithm;

  const framed = frameSigningInput(kind, claims, snapshot.kid, algorithm);
  if ("error" in framed) return framed;

  // The producer build gate's claims half (the reference decode_for_signing):
  // schema checks over the claims alone, BEFORE any key is used - malformed
  // claims are a typed producer rejection, never a burned key operation.
  const claimsGate = checkSigningClaims(kind, claims);
  if (!claimsGate.ok) return { error: "invalid_input", code: claimsGate.code };

  // The honest-signer refusal boundary (R1-R3 from the Elixir reference):
  // the set-aware guards run here — after framing, BEFORE the key signs —
  // against the caller's own verified view, exactly the reference producer
  // ordering. A refusal never touches the key.
  if (refusal) {
    const refusalError = refusal();
    if (refusalError) return refusalError;
  }

  // The holder signs the exact message; a fault or a wrong-length result is
  // a signing failure, never a silent pass.
  let signature: Uint8Array;
  try {
    signature = await (keyHandle as KeyHandle).sign(framed.message, keyHandle);
  } catch (_fault) {
    return { error: "signing_failed" };
  }
  if (!(signature instanceof Uint8Array) || signature.length === 0) {
    return { error: "signing_failed" };
  }
  const row = registryRow(algorithm);
  if (!row || signature.length !== row.signatureBytes) {
    return { error: "signing_failed" };
  }

  // The wrong-key guard: the signature MUST verify against the snapshot's
  // public key under the selected algorithm.
  if (
    !verifySignature(
      framed.message,
      Buffer.from(signature),
      snapshot.publicKey,
      algorithm,
    )
  ) {
    return { error: "signing_failed" };
  }

  return { message: framed.message, signature: Buffer.from(signature) };
}

function assemble(message: Buffer, signature: Buffer): string {
  return `${message.toString("utf8")}.${encodeBase64url(signature)}`;
}

// The refusal surface's closed mapping: signing_refused is the honest-signer
// refusal; the view/claims-shape codes stay caller-input errors.
function mapRefusal(result: RefusalResult): SignError | null {
  if (result.ok) return null;
  if (result.code === "signing_refused") return { error: "refused", code: result.code };
  return { error: "invalid_input", code: result.code };
}

// The view's chain is THIS package's public contract (the refusal surface
// validates its depth); the shallow shape is policed here so the closed
// error vocabulary holds regardless of which verifier revision resolves.
// A verifier crash past this gate stays loud - never a misleading error.
function chainViewOrInvalid(chain: unknown): ChainView | SignError {
  if (!chain || typeof chain !== "object" || Array.isArray(chain)) {
    return { error: "invalid_input", code: "signing_input_invalid" };
  }
  return chain as ChainView;
}

// A missing view object is caller input like a missing chain: the closed
// error, never a dereference throw.
function viewChainOrInvalid(view: { chain: ChainView }): ChainView | SignError {
  if (!view || typeof view !== "object") return { error: "invalid_input", code: "signing_input_invalid" };
  return chainViewOrInvalid(view.chain);
}

// ---------------------------------------------------------------------------
// Public signing surface
// ---------------------------------------------------------------------------

export async function signDescriptor(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  opts: { algorithm?: string } = {},
): Promise<SignResult<{ descriptor: string }>> {
  const signed = await signCommon("descriptor", claims, keyHandle, opts);
  if ("error" in signed) return { ok: false, ...signed };
  const compact = assemble(signed.message, signed.signature);
  const verified = verifyDescriptor(compact);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { descriptor: compact } };
}

export async function signReceipt(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  chain: ChainView,
  opts: { algorithm?: string } = {},
): Promise<SignResult<{ receipt: string }>> {
  // The issuing view is REQUIRED (the reference takes ChainFacts or a
  // CharterRevision, never none). Its discipline runs pre-sign through the
  // same closure position as the refusal pass - the reference's context is
  // a verified ChainFacts by construction, so a TS view that fails the
  // chain discipline is caller input, never a burned key operation.
  const signed = await signCommon("receipt", claims, keyHandle, opts, () => {
    const resolved = chainViewOrInvalid(chain);
    if ("error" in resolved) return resolved;
    if (!verifyChain(resolved).ok) return { error: "invalid_input", code: "chain_invalid" };
    return null;
  });
  if ("error" in signed) return { ok: false, ...signed };
  const compact = assemble(signed.message, signed.signature);
  const verified = verifyReceipt(compact, chain);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { receipt: compact } };
}

export async function signAcceptance(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  view: { revisionText: string; descriptorCompacts: string[]; chain: ChainView },
  opts: { algorithm?: string } = {},
): Promise<SignResult<{ acceptance: string }>> {
  const chain = viewChainOrInvalid(view);
  const signed = await signCommon("acceptance", claims, keyHandle, opts, () =>
    "error" in chain ? chain : mapRefusal(acceptanceRefusal(claims, chain)),
  );
  if ("error" in signed) return { ok: false, ...signed };
  const compact = assemble(signed.message, signed.signature);
  const verified = verifyAcceptance(compact, view.revisionText, view.descriptorCompacts);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { acceptance: compact } };
}

export async function signTermination(
  claims: Record<string, unknown>,
  keyHandle: unknown,
  view: { revisionText: string; descriptorCompacts: string[]; chain: ChainView },
  opts: { algorithm?: string } = {},
): Promise<SignResult<{ termination: string }>> {
  const chain = viewChainOrInvalid(view);
  const signed = await signCommon("termination", claims, keyHandle, opts, () =>
    "error" in chain ? chain : mapRefusal(terminationRefusal(claims, chain)),
  );
  if ("error" in signed) return { ok: false, ...signed };
  const compact = assemble(signed.message, signed.signature);
  const verified = verifyTermination(compact, view.revisionText, view.descriptorCompacts);
  if (!verified.ok) return { ok: false, error: "verification_failed" };
  return { ok: true, result: { termination: compact } };
}
