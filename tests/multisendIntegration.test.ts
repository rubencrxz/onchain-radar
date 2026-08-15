import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Alert } from "../src/alerts.js";
import { loadCheckpoint, writeCheckpoint } from "../src/checkpoint.js";
import { executeHistoricalScan } from "../src/historicalScanner.js";
import { LiveRequiredAnalysisError, runLiveCycle } from "../src/liveScanner.js";
import type { LiveRpcClient, RpcClient } from "../src/rpc.js";
import type { AlertSink } from "../src/sinks.js";
import { FIXED_CREATED_AT } from "./fixtures.js";
import { MULTISEND, administrativeMultiSendConfig, multiSendData, multiSendExecInput, packSuboperation } from "./multisendFixtures.js";
import { execTransactionInput, innerTransfer, rpcReceipt, rpcTransaction, safeExecutionLog, safeMonitorConfig } from "./safeFixtures.js";

const hash = (block: bigint) => `0x${block.toString(16).padStart(64, "0")}` as `0x${string}`;

class CaptureSink implements AlertSink {
  readonly alerts: Alert[] = [];
  write(alerts: readonly Alert[]): void { this.alerts.push(...alerts); }
}

function config() {
  const result = safeMonitorConfig(administrativeMultiSendConfig().multisigs[0]!);
  result.administrativeMonitoring = administrativeMultiSendConfig();
  return result;
}

function rpcBase(input = multiSendExecInput([packSuboperation({ data: innerTransfer() })])): RpcClient {
  return {
    async getLogs() { return [safeExecutionLog()]; },
    async getStorageAt() { return undefined; },
    async getErc20Balance() { return 0n; },
    async getTransaction() { return rpcTransaction(input); },
    async getTransactionReceipt() { return rpcReceipt(); }
  };
}

test("historical scanner inserts MultiSend alerts after outer Safe alerts and remains fail-closed", async () => {
  const sink = new CaptureSink();
  const result = await executeHistoricalScan({ rpc: rpcBase(), config: config(), startBlock: 100n, endBlock: 100n,
    maxBlockRange: 10n, clock: () => FIXED_CREATED_AT, sinks: [sink] });
  assert.deepEqual(result.alerts.map((alert) => alert.ruleId), [
    "SAFE_EXECUTION_SUCCESS",
    "SAFE_TRANSACTION_EXECUTED", "SAFE_DELEGATECALL_EXECUTED",
    "SAFE_MULTISEND_EXECUTED"
  ]);
  assert.deepEqual(sink.alerts.map((alert) => alert.id), result.alerts.map((alert) => alert.id));

  let sinkCalled = false;
  await assert.rejects(() => executeHistoricalScan({
    rpc: { ...rpcBase(), async getTransaction() { throw new Error("required MultiSend transaction unavailable"); } },
    config: config(), startBlock: 100n, endBlock: 100n, maxBlockRange: 10n, clock: () => FIXED_CREATED_AT,
    sinks: [{ write() { sinkCalled = true; } }]
  }), /required MultiSend transaction unavailable/);
  assert.equal(sinkCalled, false);
});

test("live MultiSend processing restores checkpoint and journal without duplicate alerts", async () => {
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-multisend-live-"));
  const checkpointPath = join(directory, "checkpoint.json");
  const journalPath = join(directory, "journal.jsonl");
  const base = rpcBase();
  const rpc: LiveRpcClient = {
    ...base,
    async getBlockNumber() { return 100n; },
    async getBlock(blockNumber) { return { number: blockNumber, hash: hash(blockNumber), parentHash: hash(blockNumber > 0n ? blockNumber - 1n : 0n), timestamp: blockNumber }; }
  };
  const firstSink = new CaptureSink();
  const common = { rpc, config: config(), confirmations: 0, maxBlocksPerCycle: 1n, checkpointPath, journalPath, clock: () => FIXED_CREATED_AT };
  const first = await runLiveCycle({ ...common, startBlock: 100n, sinks: [firstSink] });
  assert.ok(first.alertsEmitted > 0);
  assert.ok(firstSink.alerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_EXECUTED"));

  writeCheckpoint(checkpointPath, { version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: 99n,
    lastProcessedBlockHash: hash(99n), updatedAt: FIXED_CREATED_AT });
  const restartSink = new CaptureSink();
  const replay = await runLiveCycle({ ...common, sinks: [restartSink] });
  assert.equal(replay.alertsEmitted, 0);
  assert.equal(restartSink.alerts.length, 0);
  assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 100n);
});

test("live required-analysis failure does not advance the affected checkpoint", async () => {
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-multisend-live-failure-"));
  const checkpointPath = join(directory, "checkpoint.json");
  const base = rpcBase();
  const rpc: LiveRpcClient = {
    ...base,
    async getBlockNumber() { return 100n; },
    async getBlock(blockNumber) { return { number: blockNumber, hash: hash(blockNumber), parentHash: hash(blockNumber > 0n ? blockNumber - 1n : 0n), timestamp: blockNumber }; },
    async getTransaction() { throw new Error("required MultiSend analysis failed"); }
  };
  await assert.rejects(() => runLiveCycle({ rpc, config: config(), confirmations: 0, maxBlocksPerCycle: 1n,
    checkpointPath, journalPath: join(directory, "journal.jsonl"), startBlock: 100n, sinks: [], clock: () => FIXED_CREATED_AT }),
  /required MultiSend analysis failed/);
  assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 99n);
});

test("live journals a malformed MultiSend alert exactly once but pins the checkpoint", async () => {
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-multisend-live-malformed-"));
  const checkpointPath = join(directory, "checkpoint.json");
  const journalPath = join(directory, "journal.jsonl");
  const malformed = execTransactionInput({ target: MULTISEND, operation: "DELEGATECALL",
    data: multiSendData([packSuboperation({ data: innerTransfer() }), "0x00"]) });
  const base = rpcBase(malformed);
  const rpc: LiveRpcClient = {
    ...base,
    async getBlockNumber() { return 100n; },
    async getBlock(blockNumber) { return { number: blockNumber, hash: hash(blockNumber), parentHash: hash(blockNumber > 0n ? blockNumber - 1n : 0n), timestamp: blockNumber }; }
  };
  const firstSink = new CaptureSink();
  const common = { rpc, config: config(), confirmations: 0, maxBlocksPerCycle: 1n, checkpointPath, journalPath,
    startBlock: 100n, clock: () => FIXED_CREATED_AT };
  await assert.rejects(() => runLiveCycle({ ...common, sinks: [firstSink] }), LiveRequiredAnalysisError);
  assert.equal(firstSink.alerts.filter((alert) => alert.ruleId === "SAFE_MULTISEND_MALFORMED").length, 1);
  assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 99n);

  const replaySink = new CaptureSink();
  await assert.rejects(() => runLiveCycle({ ...common, sinks: [replaySink] }), LiveRequiredAnalysisError);
  assert.equal(replaySink.alerts.length, 0);
  assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 99n);
});
