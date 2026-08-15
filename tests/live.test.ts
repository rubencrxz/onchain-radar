import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { MonitorConfig } from "../src/config.js";
import { loadCheckpoint, writeCheckpoint, CanonicalityError } from "../src/checkpoint.js";
import { nextLiveRange } from "../src/liveCursor.js";
import { runLiveCycle } from "../src/liveScanner.js";
import type { LiveRpcClient } from "../src/rpc.js";
import { AlertJournal } from "../src/alertJournal.js";

const config: MonitorConfig = { chain: "ethereum", monitoredAddresses: [], knownMultisigs: [], eventSignatures: [], allowlists: { knownActors: [], knownAdmins: [], knownImplementations: [], knownGovernanceContracts: [], knownProxyAddresses: [] } };
const hash = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;

test("confirmed cursor is inclusive, bounded and gap-free", () => {
  assert.deepEqual(nextLiveRange(4n, 10n, 2, 3n), { fromBlock: 5n, toBlock: 7n });
  assert.equal(nextLiveRange(8n, 10n, 2, 3n), undefined);
  assert.equal(nextLiveRange(0n, 1n, 3, 3n), undefined);
  assert.throws(() => nextLiveRange(9n, 8n, 0, 1n), /below the checkpoint/);
});

test("checkpoint round-trips bigint and rejects corruption", () => {
  const dir = mkdtempSync(join(tmpdir(), "onchain-radar-live-"));
  const path = join(dir, "checkpoint.json");
  writeCheckpoint(path, { version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: 12n, lastProcessedBlockHash: hash(12), updatedAt: "fixed" });
  assert.equal(loadCheckpoint(path)?.lastProcessedBlock, 12n);
  writeFileSync(path, "{bad", "utf8");
  assert.throws(() => loadCheckpoint(path), /Cannot parse checkpoint/);
});

test("journal deduplicates after reload and rejects corrupt lines", () => {
  const dir = mkdtempSync(join(tmpdir(), "onchain-radar-journal-"));
  const path = join(dir, "journal.jsonl");
  const journal = new AlertJournal(path);
  const alert = { id: "a", blockNumber: "4", transactionHash: "tx", ruleId: "R" } as any;
  journal.append([alert], new Map([["4", hash(4)]]), "fixed");
  const reloaded = new AlertJournal(path);
  assert.equal(reloaded.filterNew([alert]).length, 0);
  writeFileSync(path, "not-json\n", "utf8");
  assert.throws(() => new AlertJournal(path).load(), /Corrupt journal/);
});

test("live cycle writes checkpoint only after successful processing and resumes idempotently", { timeout: 60000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "onchain-radar-cycle-"));
  const rpc: LiveRpcClient = {
    async getBlockNumber() { return 5n; },
    async getBlock(blockNumber) { return { number: blockNumber, hash: hash(Number(blockNumber)), parentHash: hash(Number(blockNumber) - 1), timestamp: blockNumber }; },
    async getLogs() { return []; },
    async getStorageAt() { return undefined; },
    async getErc20Balance() { return 0n; }
  };
  const first = await runLiveCycle({ rpc, config, confirmations: 0, maxBlocksPerCycle: 2n, checkpointPath: join(dir, "checkpoint.json"), journalPath: join(dir, "journal.jsonl"), startBlock: 4n, sinks: [] , clock: () => "fixed" });
  assert.equal(first.range?.fromBlock, 4n);
  assert.equal(first.range?.toBlock, 5n);
  const second = await runLiveCycle({ rpc, config, confirmations: 0, maxBlocksPerCycle: 2n, checkpointPath: join(dir, "checkpoint.json"), journalPath: join(dir, "journal.jsonl"), sinks: [], clock: () => "fixed" });
  assert.equal(second.range, undefined);
});

test("canonicality mismatch stops without deleting state", async () => {
  const dir = mkdtempSync(join(tmpdir(), "onchain-radar-canon-"));
  const path = join(dir, "checkpoint.json");
  writeCheckpoint(path, { version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: 4n, lastProcessedBlockHash: hash(4), updatedAt: "fixed" });
  const rpc: LiveRpcClient = { async getBlockNumber() { return 5n; }, async getBlock(blockNumber) { return { number: blockNumber, hash: hash(99), parentHash: hash(98), timestamp: 0n }; }, async getLogs() { return []; }, async getStorageAt() { return undefined; }, async getErc20Balance() { return 0n; } };
  await assert.rejects(() => runLiveCycle({ rpc, config, confirmations: 0, maxBlocksPerCycle: 1n, checkpointPath: path, journalPath: join(dir, "journal.jsonl"), sinks: [] }), CanonicalityError);
  assert.equal(loadCheckpoint(path)?.lastProcessedBlock, 4n);
});
