import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, test } from "node:test";
import type { Alert } from "../src/alerts.js";
import { JsonlAlertSink, TerminalAlertSink } from "../src/sinks.js";
import { FIXED_CREATED_AT } from "./fixtures.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function sampleAlert(id: string): Alert {
  return {
    id,
    chain: "ethereum",
    ruleId: "GOVERNANCE_PAYLOAD_EXECUTED",
    ruleName: "Governance Payload Executed",
    severity: "INFO",
    eventSignature: "PayloadExecuted(uint40)",
    blockNumber: "25423360",
    transactionHash: "0x14c3acdb367a62c25d2a405f97a08ddae6399714032f1060167af4cc7b9d47c8",
    logIndex: 678,
    address: "0xdabad81af85554e9ae636395611c58f7ec1aaec5",
    topics: ["0xda6084bb0aa902a7f6da10ba185d4aa129414651c90772417eff02a52112af2a"],
    data: "0x00000000000000000000000000000000000000000000000000000000000001c5",
    summary: "Governance payload executed: payloadId 453.",
    metadata: { source: "eth_getLogs", decoded: { payloadId: 453 } },
    createdAt: FIXED_CREATED_AT
  };
}

describe("JSONL sink", () => {
  test("creates parent directories and writes one valid alert per line", () => {
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-sinks-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "nested", "alerts.jsonl");
    const alerts = [sampleAlert("one"), sampleAlert("two")];

    new JsonlAlertSink(path).write(alerts);
    const lines = readFileSync(path, "utf8").trim().split("\n");

    assert.equal(lines.length, 2);
    assert.deepEqual(lines.map((line) => JSON.parse(line)), alerts);
  });

  test("preserves the current overwrite behavior", () => {
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-overwrite-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "alerts.jsonl");
    const sink = new JsonlAlertSink(path);

    sink.write([sampleAlert("old-one"), sampleAlert("old-two")]);
    sink.write([sampleAlert("replacement")]);

    const lines = readFileSync(path, "utf8").trim().split("\n");
    assert.equal(lines.length, 1);
    assert.equal((JSON.parse(lines[0]!) as Alert).id, "replacement");
  });
});

describe("terminal sink", () => {
  test("is invocable offline and preserves the v0.1 summary format", () => {
    const lines: string[] = [];
    const alert = sampleAlert("terminal");

    new TerminalAlertSink((line) => lines.push(line)).write([alert]);

    assert.deepEqual(lines, [
      "[INFO] GOVERNANCE_PAYLOAD_EXECUTED",
      "  summary: Governance payload executed: payloadId 453.",
      "  blockNumber: 25423360",
      `  transactionHash: ${alert.transactionHash}`,
      `  address: ${alert.address}`,
      "  eventSignature: PayloadExecuted(uint40)",
      ""
    ]);
  });
});
