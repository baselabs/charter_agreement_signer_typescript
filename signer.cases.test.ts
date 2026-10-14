import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, test } from "node:test";
import { SHARED_SOURCE, fixtureBytes, sharedTable, expectedFailure, runCase, verifySuccess } from "./test/signer-cases.ts";

// Every JSON row in this source table can be expressed by the TS signer.
// Any future exclusions must name the row id and the Elixir-only shape here.
const unexpressibleRows: Readonly<Record<string, string>> = {};
const expectedRunRows = 121;
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
    const compact = result.result[row.kind];
    assert.equal(typeof compact, "string", evidence);
    assert.deepEqual(result, { ok: true, result: { [row.kind]: compact } }, evidence);
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
  assert.equal(edSuccesses, 12);
  assert.equal(mlSuccesses, 5);
  process.stdout.write(`Shared table: ${runRows} run, ${Object.keys(unexpressibleRows).length} unexpressible, ${edSuccesses} exact Ed25519 successes, ${mlSuccesses} verified ML-DSA-65 successes.\n`);
});
