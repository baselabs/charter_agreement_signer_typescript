import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const candidate = JSON.parse(readFileSync(join(root, "reference.json"), "utf8")).verifier;
assert.equal(candidate?.version, "1.0.0", "record the real staged verifier identity first");
assert.match(candidate.commit, /^[0-9a-f]{40}$/);
assert.match(candidate.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
const scratch = mkdtempSync(join(tmpdir(), "signer-verifier-"));
const baseEnv = { ...process.env, PATH: dirname(process.execPath) + delimiter + process.env.PATH };
const run = (args, cwd, env = baseEnv) => execFileSync(args[0], args.slice(1), { cwd, env, stdio: "inherit" });
try {
  let archive;
  if (process.argv.length > 2) {
    assert.equal(process.argv[2], "--archive");
    assert.equal(process.argv.length, 4);
    archive = resolve(process.argv[3]);
  } else {
    const verifier = join(scratch, "verifier");
    run(["git", "init", "--quiet", verifier], scratch);
    run(["git", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "fetch", "--depth", "1", "https://github.com/baselabs/charter_agreement_protocol_typescript.git", candidate.commit], verifier);
    run(["git", "checkout", "--detach", "--quiet", "FETCH_HEAD"], verifier);
    assert.equal(execFileSync("git", ["rev-parse", "HEAD"], { cwd: verifier, encoding: "utf8" }).trim(), candidate.commit);
    assert.equal(JSON.parse(readFileSync(join(verifier, "package.json"), "utf8")).version, candidate.version);
    run(["npm", "ci"], verifier);
    run(["npm", "run", "check:package"], verifier);
    archive = join(verifier, "artifacts/package.tgz");
  }
  assert.ok(isAbsolute(archive) && existsSync(archive));
  assert.equal(`sha512-${createHash("sha512").update(readFileSync(archive)).digest("base64")}`, candidate.integrity, "verifier bytes must equal the exact staged archive");
  const signer = join(scratch, "signer");
  for (const path of ["package.json", "package-lock.json", "index.ts", "signer.ts", "signer.test.ts", "signer.browser.test.ts", "signer.cases.test.ts", "signer.cost.test.ts", "tsconfig.json", "tsconfig.build.json", "tsconfig.web.json", "test", "conformance", "web", "scripts", "reference.json", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "LICENSE", "NOTICE"]) {
    cpSync(join(root, path), join(signer, path), { recursive: true });
  }
  run(["npm", "ci"], signer);
  run(["npm", "install", "--no-save", "--package-lock=false", "--ignore-scripts", archive], signer);
  assert.equal(JSON.parse(readFileSync(join(signer, "node_modules/@charter-agreement-protocol/verifier/package.json"), "utf8")).version, "1.0.0");
  for (const script of ["typecheck", "test", "typecheck:web", "build:site", "check:reference", "check:package"]) {
    run(["npm", "run", script], signer, { ...baseEnv, CAP_VERIFIER_ARCHIVE: archive });
  }
  const digest = (path) => createHash("sha512").update(readFileSync(path)).digest("hex");
  assert.equal(digest(join(signer, "artifacts/package.tgz")), digest(join(root, "artifacts/package.tgz")), "one signer archive must pass against both verifier lines");
  console.log("Same signer package passed the complete suite and installed consumer against verifier 1.0.0");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
