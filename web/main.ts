// The charter workshop — the CAP signer package's live page. Everything runs
// the REAL published code: @charter-agreement-protocol/signer for signing (via
// this repository's source) and the verifier package it delegates to, bundled
// with node:crypto/fs/path shims. Two parties' keys are generated in your
// browser; the private keys never enter either library.
import { keygen, sign as nobleSign } from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  signAcceptance,
  signDescriptor,
  signReceipt,
  type ChainView,
} from "../signer.js";
import {
  verifyChain,
  verifyDescriptor,
} from "@charter-agreement-protocol/verifier";

interface CustodyKey {
  publicKeyB64: string;
  sign: (m: Uint8Array) => Promise<Uint8Array>;
  mode: "WebCrypto non-extractable" | "in-page (noble)";
}

async function makeKey(): Promise<CustodyKey> {
  try {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" } as Algorithm, false, ["sign"])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return {
      publicKeyB64: Buffer.from(raw).toString("base64url"),
      sign: async (m) => new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, m as BufferSource)),
      mode: "WebCrypto non-extractable",
    };
  } catch {
    const kp = keygen();
    return {
      publicKeyB64: Buffer.from(kp.publicKey).toString("base64url"),
      sign: async (m) => nobleSign(m, kp.secretKey),
      mode: "in-page (noble)",
    };
  }
}

// ---------- the demo world (mirrors the package's own test fixture) ----------

interface Party { key: CustodyKey; kid: string; descriptor?: string; pdd?: string; role: "issuer" | "acceptor" }
let issuer: Party, acceptor: Party;
let genesisText = "", genesisDigest = "";
let acceptanceIssuer = "", acceptanceAcceptor = "";
let receipt = "";
// Deterministic fixture digests: hash the seed so every demo digest READS like
// a digest (43 base64url chars of real SHA-256 output) instead of a repeated
// letter — the shape the protocol's digest fields validate either way.
const dg = (seed: string): string =>
  "sha-256:" + Buffer.from(sha256(new TextEncoder().encode("demo:" + seed))).toString("base64url");

function revisionText(overrides: Record<string, unknown>): string {
  // Mirrors the package's own test fixture exactly: the genesis revision
  // carries NO charter_id (successors stamp it); key order is the fixture's.
  return JSON.stringify({
    abp_bindings: [{
      blueprint_id: "example.demo/echo",
      content_digest: dg("P"),
      deployment_digest: dg("Q"),
      party_role: "acceptor",
      release_number: 1,
    }],
    attribution_declaration: { basis: "bound_deployments" },
    effective_from: "2026-08-25T12:00:00Z",
    extensions: { critical: {}, optional: {} },
    legal_text: { content_digest: dg("L"), media_type: "text/plain" },
    parties: [
      { party_descriptor_digest: issuer.pdd as string, role: "issuer" },
      { party_descriptor_digest: acceptor.pdd as string, role: "acceptor" },
    ],
    precedence_declaration: "legal_text_governs",
    protocol_revision: 2,
    receipt_profile: "com.example.charter/default",
    revision_number: 1,
    termination_rules: { reason_codes: ["mutual", "breach"] },
    ...overrides,
  });
}

const view = (extra: Partial<ChainView> = {}): ChainView => ({
  revisions: [genesisText],
  acceptances: [acceptanceIssuer, acceptanceAcceptor],
  descriptors: [issuer.descriptor!, acceptor.descriptor!],
  terminations: [],
  ...extra,
});

function chainDigest(texts: string[], index: number): string {
  const verified = verifyChain({ revisions: texts, acceptances: [], descriptors: [issuer.descriptor!, acceptor.descriptor!], terminations: [] });
  if (!verified.ok) throw new Error("chain fixture failed: " + JSON.stringify(verified));
  return (verified.facts.revisions as { digest: string }[])[index].digest;
}

const handle = (p: Party) => ({
  keyIdentity: () => ({ kid: p.kid, publicKey: p.key.publicKeyB64 }),
  sign: (m: Uint8Array) => p.key.sign(m),
});

const acceptanceClaims = (pdd: string, role: string) => ({
  protocol_revision: 2,
  accepted_at: "2026-08-25T13:00:00Z",
  charter_id: genesisDigest,
  party_descriptor_digest: pdd,
  party_role: role,
  revision_digest: genesisDigest,
  revision_number: 1,
});

// ---------- DOM ----------

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
const bForm = $<HTMLButtonElement>("btn-form"), bAccept = $<HTMLButtonElement>("btn-accept"), bReceipt = $<HTMLButtonElement>("btn-receipt"), bVerify = $<HTMLButtonElement>("btn-verify");
const tamperBtns = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-tamper]"));
let lastTamper: string | null = null;

function flash(lane: HTMLElement): void { lane.classList.remove("flash"); void lane.offsetWidth; lane.classList.add("flash"); }

function artifactCard(kind: string, typ: string, extra: string, compact: string): HTMLButtonElement {
  const card = document.createElement("button");
  card.className = `artifact-card ${kind}`;
  card.innerHTML = `<span class="t"><svg class="ic"><use href="#i-doc"/></svg> ${kind.toUpperCase()}</span><span class="meta">typ: ${typ} · ${extra}</span>`;
  card.addEventListener("click", () => {
    document.querySelectorAll(".artifact-card.selected").forEach((c) => c.classList.remove("selected"));
    card.classList.add("selected");
    showWire(kind, compact);
  });
  return card;
}

function slot(id: string, card: HTMLElement): void { const s = $(id); s.textContent = ""; s.appendChild(card); }

// ---------- wire viewer ----------

const wireBody = $("wire-body"), segTabs = $("seg-tabs");
function showWire(label: string, compact: string): void {
  const segs = compact.split(".");
  segTabs.innerHTML = "";
  const names = ["protected (header)", "payload", "signature"];
  const render = (idx: number) => {
    Array.from(segTabs.children).forEach((c, i) => c.classList.toggle("on", i === idx));
    const raw = Buffer.from(segs[idx], "base64url");
    let body: string;
    if (idx === 2) body = Array.from(raw, (b) => b.toString(16).padStart(2, "0")).join("");
    else { const utf8 = raw.toString("utf8"); try { body = JSON.stringify(JSON.parse(utf8), null, 2); } catch { body = utf8; } }
    wireBody.innerHTML = `<span class="k">// ${label} — ${names[idx]} (${raw.length} bytes)\n</span>`;
    wireBody.append(body);
  };
  segs.forEach((_, i) => {
    const b = document.createElement("button");
    b.textContent = names[i] ?? `segment ${i}`;
    if (i === 0) b.classList.add("on");
    b.addEventListener("click", () => render(i));
    segTabs.appendChild(b);
  });
  render(0);
}

function replacer(_k: string, v: unknown): unknown {
  if (v instanceof Uint8Array) return `hex:${Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32)}…`;
  return v;
}


// ---------- fact panels (designed key/value view; raw JSON behind a toggle) ----------
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// Byte-ish values (Uint8Array, or strings carrying raw binary from the
// package's decode surface) render as compact hex — never utf-8 mojibake.
const toHex = (bytes: number[]): string => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
const isBinaryString = (s: string): boolean => /[\u0000-\u0008\u000e-\u001f\u007f-\u00ff]/.test(s);
const asBytes = (v: Uint8Array | string): number[] =>
  typeof v === "string" ? Array.from(v, (c) => c.charCodeAt(0) & 0xff) : Array.from(v);

function renderValue(v: unknown): { shown: string; title: string } | null {
  if (v instanceof Uint8Array || (typeof v === "string" && isBinaryString(v))) {
    const bytes = asBytes(v as Uint8Array | string);
    const hex = toHex(bytes);
    return { shown: `hex:${hex.slice(0, 24)}… (${bytes.length}B)`, title: hex };
  }
  return null;
}

function factRows(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    const s = String(obj);
    return `<span class="fv">${esc(s)}</span>`;
  }
  const entries: [string, unknown][] = Array.isArray(obj)
    ? obj.map((v, i) => [`#${i + 1}`, v])
    : Object.entries(obj as Record<string, unknown>);
  return entries.map(([k, v]) => {
    if (v !== null && typeof v === "object" && !(v instanceof Uint8Array)) {
      return `<div class="factrow nest"><span class="fk">${esc(k)}</span><div class="subfacts">${factRows(v)}</div></div>`;
    }
    const bin = renderValue(v);
    if (bin) {
      return `<div class="factrow"><span class="fk">${esc(k)}</span><span class="fv" title="${esc(bin.title)}">${esc(bin.shown)}</span></div>`;
    }
    const s = String(v);
    const shown = s.length > 64 ? s.slice(0, 64) + "…" : s;
    return `<div class="factrow"><span class="fk">${esc(k)}</span><span class="fv" title="${esc(s)}">${esc(shown)}</span></div>`;
  }).join("");
}

function factPanel(label: string, facts: unknown): string {
  return `<div class="factlabel">${esc(label)}</div><div class="facts">${factRows(facts)}</div>`;
}

function setVerdict(state: "idle" | "ok" | "fail", html: string): void {
  const v = $("verdict");
  v.dataset.state = state;
  const icon = state === "ok" ? "#i-check" : state === "fail" ? "#i-x" : "#i-terminal";
  v.innerHTML = `<span class="verdict-mark"><svg class="ic"><use href="${icon}"/></svg></span><span class="verdict-text">${html}</span>`;
  if (state !== "idle") flash($("lane-verify"));
}

// ---------- the four steps ----------

async function doForm(): Promise<void> {
  for (const p of [issuer, acceptor]) {
    const r = await signDescriptor({
      protocol_revision: 2, descriptor_number: 1,
      verification_keys: [{ key_id: p.kid, algorithm: "Ed25519", public_key: p.key.publicKeyB64, status: "active" }],
      attestation_hints: [], extensions: { critical: {}, optional: {} },
      effective_from: "2026-08-25T10:00:00Z",
    }, handle(p));
    if (!r.ok) { setVerdict("fail", `signDescriptor → ${r.error}${"code" in r ? " " + (r as { code?: string }).code : ""}`); return; }
    p.descriptor = r.result.descriptor;
    const v = verifyDescriptor(p.descriptor);
    if (!v.ok) { setVerdict("fail", "post-sign verify failed"); return; }
    p.pdd = v.facts.descriptor_digest as string;
  }
  genesisText = revisionText({});
  genesisDigest = chainDigest([genesisText], 0);
  slot("slot-desc-a", artifactCard("grant", "cap+party", `${issuer.kid}`, issuer.descriptor!));
  slot("slot-desc-b", artifactCard("proof", "cap+party", `${acceptor.kid}`, acceptor.descriptor!));
  slot("slot-revision", artifactCard("grant", "revision", `digest ${genesisDigest.slice(0, 14)}…`, genesisText));
  flash($("lane-form"));
  bAccept.disabled = false;
  setVerdict("idle", "two descriptors + the genesis revision — now both parties accept");
}

async function doAccept(): Promise<void> {
  for (const [p, other] of [[issuer, acceptor], [acceptor, issuer]] as const) {
    const r = await signAcceptance(acceptanceClaims(p.pdd!, p.role), handle(p), {
      revisionText: genesisText,
      descriptorCompacts: [p.descriptor!, other.descriptor!],
      chain: view({ acceptances: acceptanceIssuer ? [acceptanceIssuer] : [] }),
    });
    if (!r.ok) { setVerdict("fail", `signAcceptance (${p.role}) → ${r.error}${"code" in r ? " " + (r as { code?: string }).code : ""}`); return; }
    if (p === issuer) acceptanceIssuer = r.result.acceptance; else acceptanceAcceptor = r.result.acceptance;
  }
  slot("slot-acc-a", artifactCard("grant", "cap+acceptance", `issuer signs revision 1`, acceptanceIssuer));
  slot("slot-acc-b", artifactCard("proof", "cap+acceptance", `acceptor countersigns`, acceptanceAcceptor));
  flash($("lane-accept"));
  bReceipt.disabled = false;
  setVerdict("idle", "bilateral assent complete — the charter is in force");
}

async function doReceipt(): Promise<void> {
  const r = await signReceipt({
    protocol_revision: 2,
    charter_id: genesisDigest,
    revision_number: 1,
    revision_digest: genesisDigest,
    issuing_party_role: "issuer",
    agent_party_role: "acceptor",
    deployment_digest: dg("Q"),
    grant: { scheme: "bap", id: "grant-001", grant_digest: dg("E") },
    invocation_id: "inv-001",
    decision: "accepted",
    outcome: "effect_committed",
    occurred_at: "2026-08-25T13:30:00Z",
    recorded_at: "2026-08-25T13:30:01Z",
    extensions: { critical: {}, optional: {} },
  }, handle(issuer), view());
  if (!r.ok) { setVerdict("fail", `signReceipt → ${r.error}${"code" in r ? " " + (r as { code?: string }).code : ""}`); return; }
  receipt = r.result.receipt;
  slot("slot-receipt", artifactCard("proof", "cap+receipt", "bound to revision 1", receipt));
  flash($("lane-accept"));
  bVerify.disabled = false;
  tamperBtns.forEach((b) => (b.disabled = false));
  setVerdict("idle", "a signed action bound to exact revision coordinates — verify the set");
}

function factsSummary(facts: Record<string, unknown>): string {
  const nv = facts.not_verified as string[] | undefined;
  const lines = [`revisions verified: ${(facts.revisions as unknown[] | undefined)?.length ?? 0}`,
    `acceptances verified: ${(facts.acceptances as unknown[] | undefined)?.length ?? 0}`,
    `descriptors verified: ${(facts.descriptors as unknown[] | undefined)?.length ?? 0}`,
    `governing revision: ${typeof facts.governing_revision === "string" ? facts.governing_revision.slice(0, 18) + "…" : JSON.stringify(facts.governing_revision) ?? "—"}`];
  return lines.join("\n") + (nv ? `\n\nnot_verified floor (${nv.length} items — CAP never authorizes):\n  ` + nv.join("\n  ") : "");
}

function verifyWorld(w: { revisions: string[]; acceptances: string[]; descriptors: string[]; terminations: string[] }, label: string): void {
  const at = verifyChain(w);
  if (at.ok) {
    setVerdict("ok", "CHAIN VERIFIED — structural facts returned");
    $("facts-body").innerHTML = factPanel("chain facts", at.facts);
    $("tamper-hint").className = "hint";
    $("tamper-hint").textContent = "Now break it — every button below produces a real refusal.";
  } else {
    setVerdict("fail", `VERIFICATION FAILED — <b>${(at as { code?: string }).code ?? "invalid"}</b>`);
    $("facts-body").innerHTML = factPanel("result", at);
    $("tamper-hint").className = "hint fail";
    const why: Record<string, string> = {
      revision: "the revision bytes changed after acceptance — the digest bindings no longer match",
      receipt: "the receipt claims a different revision than the one the acceptances govern",
      descriptor: "the issuer's descriptor was re-signed by a different key — identity binding failed",
    };
    const w = lastTamper ? why[lastTamper] : undefined;
    $("tamper-hint").textContent = w ? `${w} — the verifier returns its closed refusal.` : "the verifier returned its closed refusal.";
  }
  void label;
}

function doVerify(): void {
  lastTamper = null;
  verifyWorld(view(), "full set");
  showWire("receipt (as verified)", receipt);
}

async function tamper(kind: string): Promise<void> {
  if (!receipt) return;
  lastTamper = kind;
  if (kind === "revision") {
    // The terms change AFTER both parties accepted: the acceptances bind the
    // original revision digest, so the rewritten text no longer matches.
    const rewritten = revisionText({ legal_text: { content_digest: dg("S"), media_type: "text/plain" } });
    verifyWorld({ revisions: [rewritten], acceptances: view().acceptances, descriptors: view().descriptors, terminations: [] }, "rewritten terms");
    return;
  }
  if (kind === "receipt") {
    verifyWorld({ revisions: [genesisText], acceptances: view().acceptances, descriptors: view().descriptors, terminations: [] }, "receipt mismatch");
    return;
  }
  if (kind === "descriptor") {
    // Re-form the issuer descriptor under a FRESH key (a different identity
    // claiming the same seat) and present the original acceptances.
    const impostor = await makeKey();
    const r = await signDescriptor({
      protocol_revision: 2, descriptor_number: 1,
      verification_keys: [{ key_id: issuer.kid, algorithm: "Ed25519", public_key: impostor.publicKeyB64, status: "active" }],
      attestation_hints: [], extensions: { critical: {}, optional: {} },
      effective_from: "2026-08-25T10:00:00Z",
    }, { keyIdentity: () => ({ kid: issuer.kid, publicKey: impostor.publicKeyB64 }), sign: (m: Uint8Array) => impostor.sign(m) });
    if (!r.ok) { setVerdict("fail", `impostor descriptor → ${r.error}`); return; }
    verifyWorld({ revisions: [genesisText], acceptances: view().acceptances, descriptors: [r.result.descriptor, acceptor.descriptor!], terminations: [] }, "impostor descriptor");
    return;
  }
}

// ---------- boot ----------

async function reset(): Promise<void> {
  const [ik, ak] = await Promise.all([makeKey(), makeKey()]);
  issuer = { key: ik, kid: "issuer-key-001", role: "issuer" };
  acceptor = { key: ak, kid: "acceptor-key-001", role: "acceptor" };
  genesisText = genesisDigest = acceptanceIssuer = acceptanceAcceptor = receipt = "";
  for (const id of ["slot-desc-a", "slot-desc-b", "slot-revision", "slot-acc-a", "slot-acc-b", "slot-receipt"]) $(id).textContent = "";
  bAccept.disabled = bReceipt.disabled = bVerify.disabled = true;
  tamperBtns.forEach((b) => (b.disabled = true));
  $("facts-body").textContent = "—";
  segTabs.innerHTML = ""; wireBody.textContent = "nothing selected yet";
  $("custody-mode").textContent = `key custody: ${issuer.key.mode} (both parties)`;
  setVerdict("idle", "form the charter to see the structural facts");
}

bForm.addEventListener("click", () => void doForm());
bAccept.addEventListener("click", () => void doAccept());
bReceipt.addEventListener("click", () => void doReceipt());
bVerify.addEventListener("click", doVerify);
$("reset").addEventListener("click", () => void reset());
tamperBtns.forEach((b) => b.addEventListener("click", () => void tamper(b.dataset.tamper!)));

void reset();
