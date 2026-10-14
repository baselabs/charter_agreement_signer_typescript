import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

for (const shape of ["shared limits", "proxy algorithms", "shared claims", "proxy claims", "deep claims"]) {
  test(`entry input cost stays bounded for ${shape}`, () => {
    const script = `
      import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
      import { signDescriptor } from ${JSON.stringify(new URL("./signer.ts", import.meta.url).href)};
      const keys = generateKeyPairSync("ed25519");
      const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64url");
      const counts = { identities: 0, signs: 0, lengths: 0, entries: 0 };
      const handle = {
        keyIdentity() { counts.identities += 1; return { kid: "cost-key", publicKey }; },
        sign(message) { counts.signs += 1; return nodeSign(null, message, keys.privateKey); },
      };
      const claims = {
        protocol_revision: 2, descriptor_number: 1,
        verification_keys: [{ key_id: "cost-key", algorithm: "Ed25519", public_key: publicKey, status: "active" }],
        attestation_hints: [], extensions: { critical: {}, optional: {} }, effective_from: "2026-08-25T10:00:00Z",
      };
      const options = {};
      const shape = ${JSON.stringify(shape)};
      if (shape === "proxy algorithms" || shape === "proxy claims") {
        const value = new Proxy([], { get(target, key) {
          if (key === "length") { counts.lengths += 1; return 2 ** 53 - 1; }
          counts.entries += 1;
          return "Ed25519";
        } });
        if (shape === "proxy algorithms") options.profile = { algorithms: value };
        else claims.extensions.optional["com.example/value"] = value;
      } else {
        let value = { value: "entry" };
        const depth = shape === "deep claims" ? 200000 : shape === "shared limits" ? 24 : 40;
        for (let i = 0; i < depth; i += 1) value = shape === "deep claims" ? { child: value } : { left: value, right: value };
        if (shape === "shared limits") options.limits = { max_bytes: value };
        else claims.extensions.optional["com.example/value"] = value;
      }
      const started = performance.now();
      const result = await signDescriptor(claims, handle, options);
      console.log(JSON.stringify({ result, counts, elapsed: performance.now() - started, maxRSSKiB: process.resourceUsage().maxRSS }));
    `;
    const started = performance.now();
    const child = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script], {
      encoding: "utf8", timeout: 5000,
    });
    if (child.status !== 0) process.stdout.write(`${shape}: stopped after ${(performance.now() - started).toFixed(1)} ms, ${child.error?.message ?? child.stderr}\n`);
    assert.equal(child.status, 0, child.error?.message ?? child.stderr);
    const observation = JSON.parse(child.stdout);
    assert.equal(observation.result.ok, false);
    assert.equal(observation.result.error, "invalid_input");
    assert.equal(observation.counts.identities, 0);
    assert.equal(observation.counts.signs, 0);
    if (shape.startsWith("proxy")) {
      assert.equal(observation.counts.lengths, 1);
      assert.equal(observation.counts.entries, 0);
    }
    assert.ok(observation.elapsed < 3000, JSON.stringify(observation));
    assert.ok(observation.maxRSSKiB < 512 * 1024, JSON.stringify(observation));
    process.stdout.write(`${shape}: ${JSON.stringify(observation)}\n`);
  });
}
