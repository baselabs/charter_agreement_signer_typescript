// The charter workshop — the CAP signer package's live page. Everything runs
// the REAL published code: @charter-agreement-protocol/signer for signing (via
// this repository's source) and the verifier package it delegates to, bundled
// with node:crypto/fs/path shims. Two parties' keys are generated in your
// browser; the private keys never enter either library. The signing flow
// lives in ./flow.ts; this file renders it.
import { verifyChain } from "@charter-agreement-protocol/verifier";
import { Workshop, type World } from "./flow.js";

const ws = new Workshop();

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


// ---------- artifact accordions: designed, animated disclosure ----------
const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");


const humanize = (k: string): string =>
  k.replace(/[_-]+/g, " ").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/\b\w/g, (c) => c.toUpperCase()).trim();

const isBinaryString2 = (s: string): boolean => /[\u0000-\u0008\u000e-\u001f\u007f-\u00ff]/.test(s);
const toHex2 = (bytes: number[]): string => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");

function valueChip(v: unknown): string | null {
  if (v instanceof Uint8Array) {
    const hex = toHex2(Array.from(v));
    return `<span class="chip mono" title="${esc(hex)}">${hex.slice(0, 20)}… · ${v.length}B</span>`;
  }
  if (typeof v === "string" && isBinaryString2(v)) {
    const m = v.match(/^([a-z0-9]+-?[a-z0-9]*:)/i);
    const prefix = m ? m[1] : "";
    const hex = toHex2(Array.from(v.slice(prefix.length), (c) => c.charCodeAt(0) & 0xff));
    return `<span class="chip mono" title="${esc(prefix + hex)}">${prefix}${hex.slice(0, 20)}… · ${v.length - prefix.length}B</span>`;
  }
  return null;
}

function fieldRows(obj: unknown, depth = 0): string {
  if (obj === null || typeof obj !== "object") {
    const chip = valueChip(obj);
    return chip ?? `<span class="val">${esc(String(obj))}</span>`;
  }
  const entries: [string, unknown][] = Array.isArray(obj)
    ? obj.map((v, i) => [`Item ${i + 1}`, v])
    : Object.entries(obj as Record<string, unknown>);
  return entries.map(([k, v]) => {
    if (v !== null && typeof v === "object" && !(v instanceof Uint8Array)) {
      return `<div class="field group"><div class="fl">${esc(humanize(k))}</div><div class="group-inner">${fieldRows(v, depth + 1)}</div></div>`;
    }
    const chip = valueChip(v);
    const s = String(v);
    const shown = chip ?? `<span class="val${/sha-256:|urn:|https:/.test(s) ? " mono" : ""}" title="${esc(s)}">${esc(s.length > 72 ? s.slice(0, 72) + "…" : s)}</span>`;
    return `<div class="field"><div class="fl">${esc(humanize(k))}</div><div class="fvs">${shown}</div></div>`;
  }).join("");
}

function accordion(title: string, chip: string | undefined, facts: unknown, open = false): string {
  return `<div class="acc${open ? " open" : ""}">
    <button type="button" class="acc-head" aria-expanded="${open}">
      <svg class="ic"><use href="#i-doc"/></svg>
      <span class="acc-title">${esc(title)}</span>
      ${chip ? `<span class="acc-chip mono">${esc(chip)}</span>` : ""}
      <svg class="ic acc-chev"><use href="#i-chev"/></svg>
    </button>
    <div class="acc-body"><div class="acc-inner">${fieldRows(facts)}</div></div>
  </div>`;
}


// Raw-JSON code box for the FACTS area (owner-directed: no formatted view) —
// defensively hex any string that still carries control/lossy characters.
function sanitize(v: unknown): unknown {
  // Byte arrays render as their base64url wire form — JSON.stringify on a
  // Uint8Array explodes into {"0":123,"1":34,…} index objects otherwise.
  if (v instanceof Uint8Array) {
    return Buffer.from(v).toString("base64url");
  }
  if (typeof v === "string" && /[\u0000-\u0008\u000e-\u001f\u007f-\u00ff\ufffd]/.test(v)) {
    return "0x" + Array.from(v, (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  }
  if (Array.isArray(v)) return v.map(sanitize);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = sanitize(val);
    return o;
  }
  return v;
}
function rawJsonBox(facts: unknown): string {
  return `<pre class="codebox">${esc(JSON.stringify(sanitize(facts), null, 2))}</pre>`;
}

// One delegated listener drives every accordion on the page, including ones
// injected later (artifacts after mint).
document.addEventListener("click", (e) => {
  const head = (e.target as HTMLElement).closest?.(".acc-head");
  if (!(head instanceof HTMLElement)) return;
  const acc = head.parentElement;
  if (!acc) return;
  const open = acc.classList.toggle("open");
  head.setAttribute("aria-expanded", String(open));
});

function setVerdict(state: "idle" | "ok" | "fail", html: string): void {
  const v = $("verdict");
  v.dataset.state = state;
  const icon = state === "ok" ? "#i-check" : state === "fail" ? "#i-x" : "#i-terminal";
  v.innerHTML = `<span class="verdict-mark"><svg class="ic"><use href="${icon}"/></svg></span><span class="verdict-text">${html}</span>`;
  if (state !== "idle") flash($("lane-verify"));
}

// ---------- the four steps ----------

async function doForm(): Promise<void> {
  const r = await ws.form();
  if (!r.ok) { setVerdict("fail", r.message); return; }
  slot("slot-desc-a", artifactCard("grant", "cap+party", `${ws.issuer.kid}`, ws.issuer.descriptor!));
  slot("slot-desc-b", artifactCard("proof", "cap+party", `${ws.acceptor.kid}`, ws.acceptor.descriptor!));
  slot("slot-revision", artifactCard("grant", "revision", `digest ${ws.genesisDigest.slice(0, 14)}…`, ws.genesisText));
  flash($("lane-form"));
  bAccept.disabled = false;
  setVerdict("idle", "two descriptors + the genesis revision — now both parties accept");
}

async function doAccept(): Promise<void> {
  const r = await ws.accept();
  if (!r.ok) { setVerdict("fail", r.message); return; }
  slot("slot-acc-a", artifactCard("grant", "cap+acceptance", `issuer signs revision 1`, ws.acceptanceIssuer));
  slot("slot-acc-b", artifactCard("proof", "cap+acceptance", `acceptor countersigns`, ws.acceptanceAcceptor));
  flash($("lane-accept"));
  bReceipt.disabled = false;
  setVerdict("idle", "bilateral assent complete — the charter is in force");
}

async function doReceipt(): Promise<void> {
  const r = await ws.signActionReceipt();
  if (!r.ok) { setVerdict("fail", r.message); return; }
  slot("slot-receipt", artifactCard("proof", "cap+receipt", "bound to revision 1", ws.receipt));
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
    $("facts-body").innerHTML = rawJsonBox(at.facts);
    $("tamper-hint").className = "hint";
    $("tamper-hint").textContent = "Revision and key edits fail verification. Rechecking without the receipt verifies the charter only; verifyReceipt checks receipts separately.";
  } else {
    setVerdict("fail", `VERIFICATION FAILED — <b>${(at as { code?: string }).code ?? "invalid"}</b>`);
    $("facts-body").innerHTML = rawJsonBox(at);
    $("tamper-hint").className = "hint fail";
    const why: Record<string, string> = {
      revision: "the revision bytes changed after acceptance — the digest bindings no longer match",
      receipt: "the charter view failed verification; verifyReceipt checks receipts separately",
      descriptor: "the issuer's descriptor was re-signed by a different key — identity binding failed",
    };
    const w = lastTamper ? why[lastTamper] : undefined;
    $("tamper-hint").textContent = w ? `${w} — the verifier returns its closed refusal.` : "the verifier returned its closed refusal.";
  }
  void label;
}

function doVerify(): void {
  lastTamper = null;
  verifyWorld(ws.view(), "full set");
  showWire("receipt (post-verified when signed)", ws.receipt);
}

async function tamper(kind: string): Promise<void> {
  if (!ws.receipt) return;
  lastTamper = kind;
  const world: World | { error: string } = await ws.tampered(kind);
  if ("error" in world) { setVerdict("fail", world.error); return; }
  verifyWorld(world, kind);
}

// ---------- boot ----------

async function reset(): Promise<void> {
  await ws.reset();
  for (const id of ["slot-desc-a", "slot-desc-b", "slot-revision", "slot-acc-a", "slot-acc-b", "slot-receipt"]) $(id).textContent = "";
  bAccept.disabled = bReceipt.disabled = bVerify.disabled = true;
  tamperBtns.forEach((b) => (b.disabled = true));
  $("facts-body").textContent = "—";
  segTabs.innerHTML = ""; wireBody.textContent = "nothing selected yet";
  $("custody-mode").textContent = `key custody: ${ws.issuer.key.mode} (both parties)`;
  setVerdict("idle", "form the charter to see the structural facts");
}

bForm.addEventListener("click", () => void doForm());
bAccept.addEventListener("click", () => void doAccept());
bReceipt.addEventListener("click", () => void doReceipt());
bVerify.addEventListener("click", doVerify);
$("reset").addEventListener("click", () => void reset());
tamperBtns.forEach((b) => b.addEventListener("click", () => void tamper(b.dataset.tamper!)));

void reset();
