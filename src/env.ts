import "dotenv/config";
import {
  DEFAULT_RPC_MAX_BLOCK_RANGE,
  DEFAULT_RPC_MAX_RETRIES,
  DEFAULT_RPC_MAX_SPLIT_DEPTH,
  DEFAULT_RPC_RETRY_BASE_DELAY_MS,
  DEFAULT_RPC_RETRY_MAX_DELAY_MS,
  DEFAULT_RPC_TIMEOUT_MS,
  validateRpcPolicyConfig,
  type RpcPolicyConfig
} from "./rpc.js";

export type ScanEnv = {
  rpcUrl: string;
  startBlock: bigint;
  endBlock: bigint;
  rpcPolicy: RpcPolicyConfig;
};

export type LiveEnv = ScanEnv & {
  confirmations: number;
  pollIntervalMs: number;
  maxBlocksPerCycle: bigint;
  checkpointPath: string;
  alertJournalPath: string;
  alertOutputPath: string;
  startBlock?: bigint;
};

export function loadScanEnv(source: Record<string, string | undefined> = process.env): ScanEnv {
  const rpcUrl = source.ETH_RPC_URL;
  const startBlock = source.START_BLOCK;
  const endBlock = source.END_BLOCK;

  const missing = [
    ["ETH_RPC_URL", rpcUrl],
    ["START_BLOCK", startBlock],
    ["END_BLOCK", endBlock]
  ]
    .filter(([, value]) => value === undefined || value === "")
    .map(([name]) => name);

  if (missing.length > 0) {
    throw new Error(`Missing required environment variable(s): ${missing.join(", ")}. Copy .env.example to .env and fill them in.`);
  }

  return {
    rpcUrl: requireEnvValue(rpcUrl, "ETH_RPC_URL"),
    startBlock: parseBlockNumber(requireEnvValue(startBlock, "START_BLOCK"), "START_BLOCK"),
    endBlock: parseBlockNumber(requireEnvValue(endBlock, "END_BLOCK"), "END_BLOCK"),
    rpcPolicy: validateRpcPolicyConfig({
      timeoutMs: parseOptionalInteger(source.RPC_TIMEOUT_MS, "RPC_TIMEOUT_MS", DEFAULT_RPC_TIMEOUT_MS),
      maxRetries: parseOptionalInteger(source.RPC_MAX_RETRIES, "RPC_MAX_RETRIES", DEFAULT_RPC_MAX_RETRIES),
      retryBaseDelayMs: parseOptionalInteger(
        source.RPC_RETRY_BASE_DELAY_MS,
        "RPC_RETRY_BASE_DELAY_MS",
        DEFAULT_RPC_RETRY_BASE_DELAY_MS
      ),
      retryMaxDelayMs: parseOptionalInteger(
        source.RPC_RETRY_MAX_DELAY_MS,
        "RPC_RETRY_MAX_DELAY_MS",
        DEFAULT_RPC_RETRY_MAX_DELAY_MS
      ),
      maxBlockRange: parseOptionalBigInt(
        source.RPC_MAX_BLOCK_RANGE,
        "RPC_MAX_BLOCK_RANGE",
        DEFAULT_RPC_MAX_BLOCK_RANGE
      ),
      maxSplitDepth: parseOptionalInteger(
        source.RPC_MAX_SPLIT_DEPTH,
        "RPC_MAX_SPLIT_DEPTH",
        DEFAULT_RPC_MAX_SPLIT_DEPTH
      )
    })
  };
}

export function loadLiveEnv(source: Record<string, string | undefined> = process.env): LiveEnv {
  const base = loadRpcEnv(source);
  const startBlock = source.LIVE_START_BLOCK === undefined || source.LIVE_START_BLOCK === ""
    ? undefined
    : parseBlockNumber(source.LIVE_START_BLOCK, "LIVE_START_BLOCK");
  const checkpointPath = requireNonEmpty(source.LIVE_CHECKPOINT_PATH ?? "state/live-checkpoint.json", "LIVE_CHECKPOINT_PATH");
  const alertJournalPath = requireNonEmpty(source.LIVE_ALERT_JOURNAL_PATH ?? "state/live-alert-journal.jsonl", "LIVE_ALERT_JOURNAL_PATH");
  const alertOutputPath = requireNonEmpty(source.LIVE_ALERT_OUTPUT_PATH ?? "state/live-alerts.jsonl", "LIVE_ALERT_OUTPUT_PATH");
  const maxBlocksPerCycle = parsePositiveBigInt(source.LIVE_MAX_BLOCKS_PER_CYCLE ?? "100", "LIVE_MAX_BLOCKS_PER_CYCLE");
  const confirmations = parseNonNegativeInteger(source.LIVE_CONFIRMATIONS ?? "3", "LIVE_CONFIRMATIONS");
  const pollIntervalMs = parsePositiveInteger(source.LIVE_POLL_INTERVAL_MS ?? "12000", "LIVE_POLL_INTERVAL_MS");
  return { ...base, confirmations, pollIntervalMs, maxBlocksPerCycle, checkpointPath, alertJournalPath, alertOutputPath, ...(startBlock === undefined ? {} : { startBlock }) };
}

function loadRpcEnv(source: Record<string, string | undefined>): ScanEnv {
  const rpcUrl = source.ETH_RPC_URL;
  const missing = [["ETH_RPC_URL", rpcUrl]].filter(([, value]) => value === undefined || value === "").map(([name]) => name);
  if (missing.length > 0) throw new Error(`Missing required environment variable(s): ${missing.join(", ")}. Copy .env.example to .env and fill them in.`);
  return {
    rpcUrl: requireEnvValue(rpcUrl, "ETH_RPC_URL"), startBlock: 0n, endBlock: 0n,
    rpcPolicy: validateRpcPolicyConfig({
      timeoutMs: parseOptionalInteger(source.RPC_TIMEOUT_MS, "RPC_TIMEOUT_MS", DEFAULT_RPC_TIMEOUT_MS),
      maxRetries: parseOptionalInteger(source.RPC_MAX_RETRIES, "RPC_MAX_RETRIES", DEFAULT_RPC_MAX_RETRIES),
      retryBaseDelayMs: parseOptionalInteger(source.RPC_RETRY_BASE_DELAY_MS, "RPC_RETRY_BASE_DELAY_MS", DEFAULT_RPC_RETRY_BASE_DELAY_MS),
      retryMaxDelayMs: parseOptionalInteger(source.RPC_RETRY_MAX_DELAY_MS, "RPC_RETRY_MAX_DELAY_MS", DEFAULT_RPC_RETRY_MAX_DELAY_MS),
      maxBlockRange: parseOptionalBigInt(source.RPC_MAX_BLOCK_RANGE, "RPC_MAX_BLOCK_RANGE", DEFAULT_RPC_MAX_BLOCK_RANGE),
      maxSplitDepth: parseOptionalInteger(source.RPC_MAX_SPLIT_DEPTH, "RPC_MAX_SPLIT_DEPTH", DEFAULT_RPC_MAX_SPLIT_DEPTH)
    })
  };
}

function requireEnvValue(value: string | undefined, name: string): string {
  if (value === undefined || value === "") {
    throw new Error(`Missing required environment variable: ${name}.`);
  }

  return value;
}

function parseBlockNumber(value: string, name: string): bigint {
  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be a non-negative integer block number.`);
  }

  return BigInt(value);
}

function parseOptionalInteger(value: string | undefined, name: string, fallback: number): number {
  if (value === undefined || value === "") {
    return fallback;
  }

  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer.`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${name} must be a safe integer.`);
  }

  return parsed;
}

function parseOptionalBigInt(value: string | undefined, name: string, fallback: bigint): bigint {
  if (value === undefined || value === "") {
    return fallback;
  }

  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer.`);
  }

  return BigInt(value);
}

function parsePositiveInteger(value: string, name: string): number {
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a positive integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error(`${name} must be a positive integer.`);
  return parsed;
}

function parseNonNegativeInteger(value: string, name: string): number {
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a non-negative integer.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} must be a safe integer.`);
  return parsed;
}

function parsePositiveBigInt(value: string, name: string): bigint {
  if (!/^\d+$/.test(value) || BigInt(value) <= 0n) throw new Error(`${name} must be a positive integer.`);
  return BigInt(value);
}

function requireNonEmpty(value: string, name: string): string {
  if (value.trim() === "") throw new Error(`${name} must be a non-empty path.`);
  return value;
}
