import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const reference = JSON.parse(readFileSync(join(root, "reference.json"), "utf8"));
assert.ok(["charter_agreement_protocol", "charter_agreement_signer"].includes(reference.package));
assert.match(reference.version, /^\d+\.\d+\.\d+$/);
assert.match(reference.archive_sha256, /^[a-f0-9]{64}$/);
assert.ok(process.argv.slice(2).every((value) => value === "--report"), "unknown reference-check argument");
assert.ok(!process.argv.includes("--report") || reference.package === "charter_agreement_protocol");
assert.equal(reference.corpus_path, "priv/conformance");
assert.match(reference.corpus_source.commit, /^[a-f0-9]{40}$/);

function verifyCorpusSource(scratch) {
  const source = reference.corpus_source;
  const checkout = join(scratch, "source");
  execFileSync("git", ["init", "--quiet", checkout]);
  const git = (...args) => execFileSync("git", args, { cwd: checkout, maxBuffer: 32 * 1024 * 1024 });
  const remote = `https://github.com/baselabs/${reference.package}.git`;
  git("fetch", "--quiet", "--no-tags", "--depth=1", remote, source.commit);
  assert.equal(git("rev-parse", "FETCH_HEAD").toString().trim(), source.commit);

  const vendored = join(root, "conformance");
  let files;
  if (reference.package === "charter_agreement_protocol") {
    const index = readFileSync(join(vendored, "index.json"));
    assert.equal(createHash("sha256").update(index).digest("base64url"), source.index_sha256_base64url);
    files = ["index.json", ...JSON.parse(index).files.map((one) => one.path)];
    const sourceFiles = git("ls-tree", "-r", "-z", "--name-only", "FETCH_HEAD", "--", reference.corpus_path)
      .toString().split("\0").filter(Boolean);
    assert.deepEqual(sourceFiles.sort(), files.map((path) => `${reference.corpus_path}/${path}`).sort());
  } else {
    files = ["signer_cases.json"];
    const table = readFileSync(join(vendored, files[0]));
    assert.equal(createHash("sha256").update(table).digest("hex"), source.sha256);
  }
  for (const path of files) {
    const blob = git("cat-file", "blob", `FETCH_HEAD:${reference.corpus_path}/${path}`);
    assert.deepEqual(readFileSync(join(vendored, path)), blob, path);
  }
  console.log(`Canonical Elixir source ${source.commit}: ${files.length} exact Git blob(s)`);
}

const scratch = mkdtempSync(join(tmpdir(), "charter-reference-"));
try {
  verifyCorpusSource(scratch);
  const url = `https://repo.hex.pm/tarballs/${reference.package}-${reference.version}.tar`;
  const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
  assert.equal(response.status, 200, `reference download: ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  assert.equal(createHash("sha256").update(archive).digest("hex"), reference.archive_sha256);
  const outer = join(scratch, "reference.tar");
  const contents = join(scratch, "contents.tar.gz");
  writeFileSync(outer, archive);
  writeFileSync(contents, execFileSync("tar", ["-xOf", outer, "contents.tar.gz"], { maxBuffer: 16 * 1024 * 1024 }));
  const read = (path) => execFileSync("tar", ["-xzOf", contents, `${reference.corpus_path}/${path}`], { maxBuffer: 16 * 1024 * 1024 });
  if (reference.package === "charter_agreement_protocol") {
    const index = JSON.parse(read("index.json"));
    assert.equal(index.total_cases, 541);
    const files = ["index.json", ...index.files.map((entry) => entry.path)];
    for (const path of files) assert.deepEqual(readFileSync(join(root, "conformance", path)), read(path), path);
    assert.equal(readdirSync(join(root, "conformance/cases")).length, index.files.length);
    if (process.argv.includes("--report")) {
      const sdk = join(scratch, "sdk");
      mkdirSync(sdk);
      execFileSync("tar", ["-xzf", contents, "-C", sdk]);
      const result = join(scratch, "report.json");
      const runner = join(scratch, "report.exs");
      writeFileSync(runner, `
        Mix.install([{:charter_agreement_protocol, path: ${JSON.stringify(sdk)}}])
        {:ok, io} = StringIO.open("")
        previous = Process.group_leader()
        Process.group_leader(self(), io)
        status = CharterAgreementProtocol.Conformance.Cli.run(["--corpus", Application.app_dir(:charter_agreement_protocol, "priv/conformance")])
        Process.group_leader(self(), previous)
        {_, bytes} = StringIO.contents(io)
        File.write!(${JSON.stringify(result)}, bytes)
        System.halt(status)
      `);
      execFileSync("elixir", [runner], { stdio: "inherit" });
      const { reportFor } = await import("../dist/index.js");
      const actual = reportFor(join(root, "conformance"));
      assert.equal(actual.exitStatus, 0);
      assert.deepEqual(Buffer.from(actual.bytes), readFileSync(result));
      console.log("Published Elixir/TypeScript reports: byte-identical, 541 cases");
    }
    console.log("Elixir reference archive and all 17 corpus files match");
  } else {
    const released = JSON.parse(read("signer_cases.json"));
    const current = JSON.parse(readFileSync(join(root, "conformance/signer_cases.json")));
    assert.deepEqual(Object.keys(current).sort(), Object.keys(released).sort());
    assert.equal(current.format_version, released.format_version);
    for (const section of ["keys", "contexts"]) {
      for (const [name, value] of Object.entries(released[section])) {
        assert.deepEqual(current[section][name], value, `${section}.${name}`);
      }
    }
    assert.equal(released.cases.length, 121);
    const byId = new Map(current.cases.map((one) => [one.id, one]));
    for (const one of released.cases) {
      const vendored = byId.get(one.id);
      if (reference.version === "1.0.0" && one.id === "acceptance-unheld-successor") {
        // CAP 1.3 refuses a proposed predecessor before looking up descriptor history.
        assert.deepEqual(one.expected, {
          code: "acceptance_claims_mismatch", custody_called: false, shape: "invalid_input", snapshot_called: true,
        }, one.id);
        assert.deepEqual(vendored, {
          ...one,
          expected: { ...one.expected, code: "signing_refused", shape: "refused" },
        }, one.id);
      } else {
        assert.deepEqual(vendored, one, one.id);
      }
    }
    console.log(`Released Elixir signer table retained: ${released.cases.length} rows`);
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
