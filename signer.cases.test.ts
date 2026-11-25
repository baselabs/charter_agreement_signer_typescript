import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, test } from "node:test";
import { prepareSigning } from "@charter-agreement-protocol/verifier";
import { signPartyReplacement, type ChainView } from "./signer.ts";
import { SHARED_SOURCE, fixtureBytes, sharedTable, caseContext, expectedFailure, realKey, runCase, resultKey, verifySuccess } from "./test/signer-cases.ts";

// Every JSON row in this source table can be expressed by the TS signer.
// Any future exclusions must name the row id and the Elixir-only shape here.
const unexpressibleRows: Readonly<Record<string, string>> = {};
const expectedRunRows = 137;
let runRows = 0;
let edSuccesses = 0;
let mlSuccesses = 0;

test("the shared table matches the Elixir source bytes and accounts for every row", () => {
  assert.equal(createHash("sha256").update(fixtureBytes).digest("hex"), SHARED_SOURCE.sha256);
  assert.equal(sharedTable.format_version, 1);
  const ids = sharedTable.cases.map((row) => row.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(ids.length, expectedRunRows + Object.keys(unexpressibleRows).length);
  for (const [id, reason] of Object.entries(unexpressibleRows)) {
    assert.ok(ids.includes(id), id);
    assert.ok(reason.length > 0, id);
  }
});

test("replacement list length faults agree with preparation before reading any index", async () => {
  const row = sharedTable.cases.find((one) => one.id === "signing-assignment-departing-party");
  assert.ok(row);
  const key = sharedTable.keys[row.key];
  const set = caseContext(row) as ChainView;
  const { handle, counts } = realKey(row);
  assert.ok(prepareSigning("party_replacement", key.kid, row.claims, key.public_key, set).ok);

  for (const [length, code] of [
    [2 ** 32 - 1, "limit_exceeded"],
    [2 ** 32, "invalid_type"],
  ] as const) {
    let indexedReads = 0;
    const revisions = new Proxy<string[]>([], { get(target, member) {
      if (member === "length") return length;
      if (member === "0") { indexedReads++; throw new Error("oversized item read"); }
      return Reflect.get(target, member);
    } });
    const context = { ...set, revisions };
    assert.deepEqual(prepareSigning("party_replacement", key.kid, row.claims, key.public_key, context),
      { ok: false, code });
    assert.equal(indexedReads, 0);
    assert.deepEqual(await signPartyReplacement(row.claims, handle, context),
      { ok: false, error: "invalid_input", code });
    assert.equal(indexedReads, 0);
  }
  assert.deepEqual(counts, { snapshots: 0, custody: 0 });
});

for (const row of sharedTable.cases) {
  if (Object.hasOwn(unexpressibleRows, row.id)) continue;
  test(`shared case ${row.id}`, async () => {
    runRows += 1;
    const { result, counts, context, algorithm } = await runCase(row);
    const expected = row.expected;
    const evidence = `${row.id}: Elixir=${JSON.stringify(expected)} TS=${JSON.stringify({ result, counts })}`;
    assert.deepEqual(counts, {
      snapshots: Number(expected.snapshot_called), custody: Number(expected.custody_called),
    }, evidence);
    if (expected.shape === "refused") assert.equal(counts.custody, 0, evidence);
    if (expected.shape !== "ok") {
      assert.deepEqual(result, expectedFailure(expected), evidence);
      return;
    }
    assert.ok(result.ok, evidence);
    const compact = result.result[resultKey(row.kind)];
    assert.equal(typeof compact, "string", evidence);
    assert.deepEqual(result, { ok: true, result: { [resultKey(row.kind)]: compact } }, evidence);
    if (algorithm === "Ed25519") {
      assert.equal(typeof expected.compact, "string", row.id);
      assert.equal(compact, expected.compact, evidence);
      edSuccesses += 1;
    } else {
      mlSuccesses += 1;
    }
    const verified = verifySuccess(row, compact, context);
    assert.ok(verified.ok, `${evidence} verification=${JSON.stringify(verified)}`);
  });
}

after(() => {
  assert.equal(runRows, expectedRunRows);
  assert.equal(edSuccesses, 17);
  assert.equal(mlSuccesses, 8);
  process.stdout.write(`Shared table: ${runRows} run, ${Object.keys(unexpressibleRows).length} unexpressible, ${edSuccesses} exact Ed25519 successes, ${mlSuccesses} verified ML-DSA-65 successes.\n`);
});
