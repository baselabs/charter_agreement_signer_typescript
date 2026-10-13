import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";
import { signDescriptor, type KeyHandle } from "./signer.ts";

let bundleDirectory: string;
let browser: typeof import("./index.ts") & Pick<typeof import("@charter-agreement-protocol/verifier"), "verifyDescriptor">;

before(async () => {
  const root = fileURLToPath(new URL(".", import.meta.url));
  bundleDirectory = await mkdtemp(join(tmpdir(), "cas-signer-browser-"));
  const outfile = join(bundleDirectory, "signer.mjs");
  await build({
    stdin: {
      contents: 'export * from "./index.ts"; export { verifyDescriptor } from "@charter-agreement-protocol/verifier";',
      resolveDir: root,
    },
    absWorkingDir: root,
    bundle: true,
    platform: "browser",
    format: "esm",
    target: "es2022",
    outfile,
    alias: {
      "node:crypto": "./web/shim/node-crypto.ts",
      "node:fs": "./web/shim/node-fs.ts",
      "node:path": "./web/shim/node-path.ts",
    },
    inject: [join(root, "web/shim/buffer-global.ts")],
  });
  browser = await import(pathToFileURL(outfile).href);
});

after(async () => {
  if (bundleDirectory) await rm(bundleDirectory, { recursive: true, force: true });
});

function genesis(algorithm: "Ed25519" | "ML-DSA-65") {
  const keys = algorithm === "Ed25519" ? generateKeyPairSync("ed25519") : generateKeyPairSync("ml-dsa-65");
  const keyBytes = algorithm === "Ed25519" ? 32 : 1952;
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).subarray(-keyBytes).toString("base64url");
  let signs = 0;
  const handle: KeyHandle = {
    keyIdentity: () => ({ kid: "browser-key", publicKey }),
    sign(message) {
      signs += 1;
      return nodeSign(null, message, keys.privateKey);
    },
  };
  const claims = {
    protocol_revision: algorithm === "Ed25519" ? 2 : 3,
    descriptor_number: 1,
    verification_keys: [{ key_id: "browser-key", algorithm, public_key: publicKey, status: "active" }],
    attestation_hints: [],
    extensions: { critical: {}, optional: {} },
    effective_from: "2026-08-25T10:00:00Z",
  };
  return { handle, claims, signs: () => signs };
}

test("browser shim mints and verifies an Ed25519 genesis descriptor", async () => {
  const fixture = genesis("Ed25519");
  const result = await browser.signDescriptor(fixture.claims, fixture.handle);
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(fixture.signs(), 1);
  assert.ok(browser.verifyDescriptor(result.result.descriptor).ok);
});

test("browser shim refuses a real ML-DSA-65 genesis descriptor", async () => {
  const fixture = genesis("ML-DSA-65");
  const native = await signDescriptor(fixture.claims, fixture.handle, { algorithm: "ML-DSA-65" });
  assert.ok(native.ok, JSON.stringify(native));
  assert.deepEqual(browser.verifyDescriptor(native.result.descriptor),
    { ok: false, code: "algorithm_unsupported_on_substrate" });
  const result = await browser.signDescriptor(fixture.claims, fixture.handle, { algorithm: "ML-DSA-65" });
  assert.deepEqual(result, { ok: false, error: "signing_failed" });
  assert.equal(fixture.signs(), 2);
});
