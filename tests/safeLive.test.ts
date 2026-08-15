import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Alert } from "../src/alerts.js";
import { loadCheckpoint, writeCheckpoint } from "../src/checkpoint.js";
import { runLiveCycle } from "../src/liveScanner.js";
import type { LiveRpcClient } from "../src/rpc.js";
import type { AlertSink } from "../src/sinks.js";
import { FIXED_CREATED_AT } from "./fixtures.js";
import { rpcReceipt, rpcTransaction, safeExecutionLog, safeMonitorConfig } from "./safeFixtures.js";

const hash = (block: bigint) => `0x${block.toString(16).padStart(64, "0")}` as `0x${string}`;

class CaptureSink implements AlertSink {
  readonly alerts: Alert[] = [];
  write(alerts: readonly Alert[]): void { this.alerts.push(...alerts); }
}

function liveRpc(overrides: Partial<LiveRpcClient> = {}): LiveRpcClient {
  return {
    async getBlockNumber() { return 100n; },
    async getBlock(blockNumber) { return { number: blockNumber, hash: hash(blockNumber), parentHash: hash(blockNumber === 0n ? 0n : blockNumber - 1n), timestamp: blockNumber }; },
    async getLogs() { return [safeExecutionLog()]; },
    async getStorageAt() { return undefined; },
    async getErc20Balance() { return 0n; },
    async getTransaction() { return rpcTransaction(); },
    async getTransactionReceipt() { return rpcReceipt(); },
    ...overrides
  };
}

test("live Safe replay, overlap and restart are deduplicated by the durable journal", async () => {
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-live-"));
  const checkpointPath = join(directory, "checkpoint.json");
  const journalPath = join(directory, "journal.jsonl");
  const firstSink = new CaptureSink();
  const common = { rpc: liveRpc(), config: safeMonitorConfig(), confirmations: 0, maxBlocksPerCycle: 1n, checkpointPath, journalPath, clock: () => FIXED_CREATED_AT };
  const first = await runLiveCycle({ ...common, startBlock: 100n, sinks: [firstSink] });
  assert.equal(first.alertsEmitted, 3);
  assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 100n);

  writeCheckpoint(checkpointPath, { version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: 99n, lastProcessedBlockHash: hash(99n), updatedAt: FIXED_CREATED_AT });
  const restartSink = new CaptureSink();
  const replay = await runLiveCycle({ ...common, sinks: [restartSink] });
  assert.equal(replay.alertsEmitted, 0);
  assert.equal(restartSink.alerts.length, 0);
  assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 100n);
});

test("Safe RPC failure leaves checkpoint before the affected block and writes no journal state", async () => {
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-failure-"));
  const checkpointPath = join(directory, "checkpoint.json");
  const journalPath = join(directory, "journal.jsonl");
  const rpc = liveRpc({ async getTransaction() { throw new Error("simulated transaction RPC failure"); } });
  await assert.rejects(() => runLiveCycle({ rpc, config: safeMonitorConfig(), confirmations: 0, maxBlocksPerCycle: 1n, checkpointPath, journalPath, startBlock: 100n, sinks: [], clock: () => FIXED_CREATED_AT }), /simulated transaction RPC failure/);
  assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 99n);
});
