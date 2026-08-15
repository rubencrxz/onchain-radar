import type { Alert } from "./alerts.js";
import { AlertJournal } from "./alertJournal.js";
import { CanonicalityError, loadCheckpoint, writeCheckpoint, type Checkpoint } from "./checkpoint.js";
import type { MonitorConfig } from "./config.js";
import { analyzeEconomicActivity } from "./economic/analyzer.js";
import { nextLiveRange, type LiveRange } from "./liveCursor.js";
import type { LiveRpcClient } from "./rpc.js";
import { TerminalAlertSink, type AlertSink } from "./sinks.js";

export type LiveCycleSummary = {
  initialized: boolean;
  latestBlock: bigint;
  confirmedHead: bigint;
  range?: LiveRange;
  alertsProcessed: number;
  alertsEmitted: number;
  lastProcessedBlock?: bigint;
};

export type LiveRunnerOptions = {
  rpc: LiveRpcClient;
  config: MonitorConfig;
  confirmations: number;
  maxBlocksPerCycle: bigint;
  checkpointPath: string;
  journalPath: string;
  startBlock?: bigint;
  clock?: () => string;
  sinks?: readonly AlertSink[];
  journal?: AlertJournal;
};

export class LiveRequiredAnalysisError extends Error {
  constructor(message: string, readonly alertIds: readonly string[]) {
    super(message);
    this.name = "LiveRequiredAnalysisError";
  }
}

const BLOCKING_ANALYSIS_RULES = new Set([
  "SAFE_MULTISEND_MALFORMED",
  "SAFE_MULTISEND_LIMIT_EXCEEDED",
  "SAFE_MULTISEND_DEPTH_EXCEEDED"
]);

export async function runLiveCycle(options: LiveRunnerOptions): Promise<LiveCycleSummary> {
  const { executeHistoricalScan } = await import("./historicalScanner.js");
  const clock = options.clock ?? (() => new Date().toISOString());
  const journal = options.journal ?? new AlertJournal(options.journalPath);
  const latestBlock = await options.rpc.getBlockNumber();
  const head = latestBlock >= BigInt(options.confirmations) ? latestBlock - BigInt(options.confirmations) : 0n;
  let checkpoint = loadCheckpoint(options.checkpointPath);
  let initialized = false;

  if (checkpoint === undefined) {
    initialized = true;
    const initial = options.startBlock ?? head;
    if (initial > head + 1n) throw new Error(`LIVE_START_BLOCK ${initial} is beyond confirmed head ${head}.`);
    const previous = initial - 1n;
    checkpoint = await makeCheckpoint(options.rpc, previous, clock);
    writeCheckpoint(options.checkpointPath, checkpoint);
    console.log(`Live checkpoint initialized at ${previous.toString()}; next block ${initial.toString()}.`);
  } else if (checkpoint.lastProcessedBlock >= 0n) {
    const canonical = await options.rpc.getBlock(checkpoint.lastProcessedBlock);
    if (canonical.hash.toLowerCase() !== checkpoint.lastProcessedBlockHash.toLowerCase()) {
      throw new CanonicalityError(`Checkpoint block ${checkpoint.lastProcessedBlock.toString()} hash no longer matches canonical chain.`);
    }
  }

  const range = nextLiveRange(checkpoint.lastProcessedBlock, latestBlock, options.confirmations, options.maxBlocksPerCycle);
  if (range === undefined) return { initialized, latestBlock, confirmedHead: head, alertsProcessed: 0, alertsEmitted: 0, lastProcessedBlock: checkpoint.lastProcessedBlock };

  const allAlerts: Alert[] = [];
  const blockHashes = new Map<string, string>();
  for (let block = range.fromBlock; block <= range.toBlock; block += 1n) {
    const blockInfo = await options.rpc.getBlock(block);
    blockHashes.set(block.toString(), blockInfo.hash);
    const lookback = economicLookback(options.config, block);
    const result = await executeHistoricalScan({ rpc: options.rpc, config: options.config, startBlock: lookback, endBlock: block, maxBlockRange: options.maxBlocksPerCycle, clock, sinks: [] });
    allAlerts.push(...result.alerts);
  }

  const unique = deduplicateById(allAlerts);
  const fresh = journal.filterNew(unique);
  for (const alert of fresh) {
    if (!blockHashes.has(alert.blockNumber) && /^\d+$/.test(alert.blockNumber)) {
      blockHashes.set(alert.blockNumber, (await options.rpc.getBlock(BigInt(alert.blockNumber))).hash);
    }
  }
  const sinks = options.sinks ?? [new TerminalAlertSink()];
  for (const sink of sinks) await sink.write(fresh);
  journal.append(fresh, blockHashes, clock());
  const incompleteAnalysis = unique.filter((alert) => BLOCKING_ANALYSIS_RULES.has(alert.ruleId));
  if (incompleteAnalysis.length > 0) {
    throw new LiveRequiredAnalysisError(
      `Required MultiSend analysis was incomplete for live range ${range.fromBlock.toString()}-${range.toBlock.toString()}; checkpoint was not advanced.`,
      incompleteAnalysis.map((alert) => alert.id)
    );
  }
  const lastBlock = await options.rpc.getBlock(range.toBlock);
  writeCheckpoint(options.checkpointPath, {
    version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: range.toBlock,
    lastProcessedBlockHash: lastBlock.hash, updatedAt: clock()
  });
  return { initialized, latestBlock, confirmedHead: head, range, alertsProcessed: unique.length, alertsEmitted: fresh.length, lastProcessedBlock: range.toBlock };
}

function economicLookback(config: MonitorConfig, block: bigint): bigint {
  if (config.economicMonitoring === undefined) return block;
  const windows = config.economicMonitoring?.assets.map((asset) => BigInt(asset.windowBlocks)) ?? [];
  const lookback = windows.length === 0 ? 0n : windows.reduce((max, value) => value > max ? value : max, 0n);
  return block > lookback ? block - lookback : 0n;
}

async function makeCheckpoint(rpc: LiveRpcClient, previous: bigint, clock: () => string): Promise<Checkpoint> {
  if (previous < 0n) return { version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: -1n, lastProcessedBlockHash: `0x${"0".repeat(64)}`, updatedAt: clock() };
  const block = await rpc.getBlock(previous);
  return { version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: previous, lastProcessedBlockHash: block.hash, updatedAt: clock() };
}

function deduplicateById(alerts: readonly Alert[]): Alert[] {
  const seen = new Set<string>();
  return alerts.filter((alert) => !seen.has(alert.id) && (seen.add(alert.id), true));
}
