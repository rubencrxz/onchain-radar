import "dotenv/config";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Alert } from "./alerts.js";
import { writeAlertsJsonl } from "./alertWriter.js";
import { parseMonitorConfig, type MonitorConfig } from "./config.js";
import { loadScanEnv } from "./env.js";
import { executeHistoricalScan, type HistoricalScanResult } from "./historicalScanner.js";
import {
  createViemRpcProvider,
  PolicyRpcClient,
  type RawRpcProvider,
  type RpcPolicyEvent
} from "./rpc.js";

const CONFIG_PATH = resolve("config/economic.historical-calibration-001.json");
const PROFILE_NAMES = ["conservative", "balanced", "sensitive"] as const;
const WINDOW_NAMES = ["incident", "control"] as const;

type ProfileName = (typeof PROFILE_NAMES)[number];
type WindowName = (typeof WINDOW_NAMES)[number];
type BlockRange = { startBlock: bigint; endBlock: bigint };

type CalibrationDefinition = {
  caseId: string;
  baselineProfile: ProfileName;
  fixedCreatedAt: string;
  rpcMaxBlockRange: bigint;
  incidentRange: BlockRange;
  controlRange: BlockRange;
  outputFile: string;
  resultsFile: string;
  profiles: Record<ProfileName, Record<string, unknown>>;
};

type RpcCounters = {
  logRequests: number;
  storageRequests: number;
  balanceRequests: number;
};

type CalibrationRun = {
  profile: ProfileName;
  window: WindowName;
  range: { startBlock: string; endBlock: string; inclusiveBlockCount: string };
  rpc: RpcCounters & { retries: number; splits: number; exhausted: number };
  metrics: {
    detectedLogCount: number;
    economicTransferCount: number;
    balanceObservationCount: number;
    eventAlertCount: number;
    slotAlertCount: number;
    economicAlertCount: number;
    totalAlertCount: number;
    alertsByRuleId: Record<string, number>;
    alertsBySeverity: Record<string, number>;
    firstAlert: AlertReference | null;
    firstWarning: AlertReference | null;
    firstCritical: AlertReference | null;
  };
  alerts: Alert[];
};

type AlertReference = {
  id: string;
  ruleId: string;
  severity: string;
  blockNumber: string;
  transactionHash: string;
};

async function main(): Promise<void> {
  if (!existsSync(CONFIG_PATH)) {
    throw new Error(`Missing calibration config: ${CONFIG_PATH}`);
  }

  const rawConfig = parseJsonObject(readFileSync(CONFIG_PATH, "utf8"), "calibration config");
  const definition = parseCalibrationDefinition(rawConfig._calibration);
  const baseConfig = parseMonitorConfig(rawConfig);
  if (baseConfig.economicMonitoring === undefined) {
    throw new Error("Historical economic calibration requires economicMonitoring.");
  }

  const rpcUrl = process.env.ETH_RPC_URL;
  if (rpcUrl === undefined || rpcUrl === "") {
    throw new Error("Missing ETH_RPC_URL. Historical calibration requires a functional archive-capable RPC.");
  }

  console.log(`Historical economic calibration: ${definition.caseId}`);
  console.log(`Profiles: ${PROFILE_NAMES.join(", ")}`);
  console.log(`RPC max inclusive block range: ${definition.rpcMaxBlockRange.toString()}`);
  console.log("Execution is sequential and artifacts are written only after every run succeeds.");

  const completed: CalibrationRun[] = [];
  for (const profile of PROFILE_NAMES) {
    const config = configForProfile(rawConfig, definition.profiles[profile]);
    for (const window of WINDOW_NAMES) {
      const range = window === "incident" ? definition.incidentRange : definition.controlRange;
      console.log(
        `Running ${profile}/${window}: blocks ${range.startBlock.toString()}-${range.endBlock.toString()}...`
      );
      completed.push(await runCalibration({ profile, window, range, config, definition, rpcUrl }));
    }
  }

  const baselineIncident = completed.find(
    (run) => run.profile === definition.baselineProfile && run.window === "incident"
  );
  if (baselineIncident === undefined) {
    throw new Error("Baseline incident run was not produced.");
  }

  writeAlertsJsonl(resolve(definition.outputFile), baselineIncident.alerts);
  const serializableRuns = completed.map(({ alerts: _alerts, ...run }) => run);
  const resultsPath = resolve(definition.resultsFile);
  mkdirSync(dirname(resultsPath), { recursive: true });
  writeFileSync(
    resultsPath,
    `${JSON.stringify(
      {
        schemaVersion: 1,
        caseId: definition.caseId,
        fixedCreatedAt: definition.fixedCreatedAt,
        baselineProfile: definition.baselineProfile,
        configFile: "config/economic.historical-calibration-001.json",
        alertArtifact: definition.outputFile,
        runs: serializableRuns
      },
      null,
      2
    )}\n`,
    "utf8"
  );

  console.log(`Baseline alert artifact: ${definition.outputFile}`);
  console.log(`Calibration metrics: ${definition.resultsFile}`);
  for (const run of completed) {
    console.log(
      `${run.profile}/${run.window}: transfers=${run.metrics.economicTransferCount}, balances=${run.metrics.balanceObservationCount}, alerts=${run.metrics.totalAlertCount}, first=${run.metrics.firstAlert?.ruleId ?? "none"}@${run.metrics.firstAlert?.blockNumber ?? "n/a"}`
    );
  }
}

async function runCalibration(params: {
  profile: ProfileName;
  window: WindowName;
  range: BlockRange;
  config: MonitorConfig;
  definition: CalibrationDefinition;
  rpcUrl: string;
}): Promise<CalibrationRun> {
  const env = loadScanEnv({
    ...process.env,
    ETH_RPC_URL: params.rpcUrl,
    START_BLOCK: params.range.startBlock.toString(),
    END_BLOCK: params.range.endBlock.toString(),
    RPC_MAX_BLOCK_RANGE: params.definition.rpcMaxBlockRange.toString()
  });
  const counters: RpcCounters = { logRequests: 0, storageRequests: 0, balanceRequests: 0 };
  const policyEvents: RpcPolicyEvent[] = [];
  const provider = countingProvider(createViemRpcProvider(params.rpcUrl, env.rpcPolicy.timeoutMs), counters);
  const rpc = new PolicyRpcClient(provider, env.rpcPolicy, {
    logger: (event) => {
      policyEvents.push(event);
      printPolicyEvent(event);
    }
  });

  const result = await executeHistoricalScan({
    rpc,
    config: params.config,
    startBlock: params.range.startBlock,
    endBlock: params.range.endBlock,
    maxBlockRange: env.rpcPolicy.maxBlockRange,
    clock: () => params.definition.fixedCreatedAt,
    sinks: []
  });

  return summarizeRun(params.profile, params.window, params.range, counters, policyEvents, result);
}

function summarizeRun(
  profile: ProfileName,
  window: WindowName,
  range: BlockRange,
  counters: RpcCounters,
  policyEvents: readonly RpcPolicyEvent[],
  result: HistoricalScanResult
): CalibrationRun {
  const firstAlert = earliestAlert(result.alerts);
  const firstWarning = earliestAlert(result.alerts.filter((alert) => alert.severity === "WARNING"));
  const firstCritical = earliestAlert(result.alerts.filter((alert) => alert.severity === "CRITICAL"));

  return {
    profile,
    window,
    range: {
      startBlock: range.startBlock.toString(),
      endBlock: range.endBlock.toString(),
      inclusiveBlockCount: (range.endBlock - range.startBlock + 1n).toString()
    },
    rpc: {
      ...counters,
      retries: policyEvents.filter((event) => event.type === "retry").length,
      splits: policyEvents.filter((event) => event.type === "split").length,
      exhausted: policyEvents.filter((event) => event.type === "exhausted").length
    },
    metrics: {
      detectedLogCount: result.detectedLogCount,
      economicTransferCount: result.economicTransferCount,
      balanceObservationCount: counters.balanceRequests,
      eventAlertCount: result.eventAlertCount,
      slotAlertCount: result.slotAlertCount,
      economicAlertCount: result.economicAlertCount,
      totalAlertCount: result.alerts.length,
      alertsByRuleId: countBy(result.alerts, (alert) => alert.ruleId),
      alertsBySeverity: countBy(result.alerts, (alert) => alert.severity),
      firstAlert: toAlertReference(firstAlert),
      firstWarning: toAlertReference(firstWarning),
      firstCritical: toAlertReference(firstCritical)
    },
    alerts: result.alerts
  };
}

function countingProvider(provider: RawRpcProvider, counters: RpcCounters): RawRpcProvider {
  return {
    async getLogs(request) {
      counters.logRequests += 1;
      return provider.getLogs(request);
    },
    async getStorageAt(request) {
      counters.storageRequests += 1;
      return provider.getStorageAt(request);
    },
    async getErc20Balance(request) {
      counters.balanceRequests += 1;
      return provider.getErc20Balance(request);
    }
  };
}

function configForProfile(rawConfig: Record<string, unknown>, thresholds: Record<string, unknown>): MonitorConfig {
  const copy = structuredClone(rawConfig);
  const economicMonitoring = requireRecord(copy.economicMonitoring, "economicMonitoring");
  if (!Array.isArray(economicMonitoring.assets)) {
    throw new Error('Calibration field "economicMonitoring.assets" must be an array.');
  }

  for (const [index, asset] of economicMonitoring.assets.entries()) {
    requireRecord(asset, `economicMonitoring.assets[${index}]`).thresholds = structuredClone(thresholds);
  }

  return parseMonitorConfig(copy);
}

function parseCalibrationDefinition(value: unknown): CalibrationDefinition {
  const raw = requireRecord(value, "_calibration");
  const baselineProfile = requireProfileName(raw.baselineProfile, "_calibration.baselineProfile");
  const incidentRange = parseRange(raw.incidentRange, "_calibration.incidentRange");
  const controlRange = parseRange(raw.controlRange, "_calibration.controlRange");
  if (incidentRange.endBlock - incidentRange.startBlock !== controlRange.endBlock - controlRange.startBlock) {
    throw new Error("Incident and control calibration ranges must have the same inclusive length.");
  }

  const profilesRaw = requireRecord(raw.profiles, "_calibration.profiles");
  const profiles = Object.fromEntries(
    PROFILE_NAMES.map((name) => [name, requireRecord(profilesRaw[name], `_calibration.profiles.${name}`)])
  ) as Record<ProfileName, Record<string, unknown>>;

  return {
    caseId: requireString(raw.caseId, "_calibration.caseId"),
    baselineProfile,
    fixedCreatedAt: requireIsoTimestamp(raw.fixedCreatedAt, "_calibration.fixedCreatedAt"),
    rpcMaxBlockRange: requirePositiveBigInt(raw.rpcMaxBlockRange, "_calibration.rpcMaxBlockRange"),
    incidentRange,
    controlRange,
    outputFile: requireString(raw.outputFile, "_calibration.outputFile"),
    resultsFile: requireString(raw.resultsFile, "_calibration.resultsFile"),
    profiles
  };
}

function parseRange(value: unknown, field: string): BlockRange {
  const raw = requireRecord(value, field);
  const startBlock = requirePositiveBigInt(raw.startBlock, `${field}.startBlock`);
  const endBlock = requirePositiveBigInt(raw.endBlock, `${field}.endBlock`);
  if (startBlock > endBlock) {
    throw new Error(`${field}.startBlock must not exceed endBlock.`);
  }
  return { startBlock, endBlock };
}

function parseJsonObject(source: string, field: string): Record<string, unknown> {
  try {
    return requireRecord(JSON.parse(source), field);
  } catch (error: unknown) {
    if (error instanceof SyntaxError) {
      throw new Error(`Invalid JSON in ${field}.`, { cause: error });
    }
    throw error;
  }
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${field} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} must be a non-empty string.`);
  }
  return value;
}

function requireIsoTimestamp(value: unknown, field: string): string {
  const timestamp = requireString(value, field);
  if (!Number.isFinite(Date.parse(timestamp))) {
    throw new Error(`${field} must be an ISO timestamp.`);
  }
  return timestamp;
}

function requirePositiveBigInt(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value) || BigInt(value) <= 0n) {
    throw new Error(`${field} must be a positive base-10 integer string.`);
  }
  return BigInt(value);
}

function requireProfileName(value: unknown, field: string): ProfileName {
  if (typeof value !== "string" || !PROFILE_NAMES.includes(value as ProfileName)) {
    throw new Error(`${field} must be one of: ${PROFILE_NAMES.join(", ")}.`);
  }
  return value as ProfileName;
}

function earliestAlert(alerts: readonly Alert[]): Alert | undefined {
  return [...alerts].sort((left, right) => {
    const leftBlock = parseAlertBlock(left.blockNumber);
    const rightBlock = parseAlertBlock(right.blockNumber);
    if (leftBlock !== rightBlock) {
      return leftBlock < rightBlock ? -1 : 1;
    }
    return left.id.localeCompare(right.id);
  })[0];
}

function parseAlertBlock(value: string): bigint {
  return /^\d+$/.test(value) ? BigInt(value) : 2n ** 256n - 1n;
}

function toAlertReference(alert: Alert | undefined): AlertReference | null {
  return alert === undefined
    ? null
    : {
        id: alert.id,
        ruleId: alert.ruleId,
        severity: alert.severity,
        blockNumber: alert.blockNumber,
        transactionHash: alert.transactionHash
      };
}

function countBy<T>(items: readonly T[], key: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const value = key(item);
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}

function printPolicyEvent(event: RpcPolicyEvent): void {
  if (event.type === "retry") {
    console.log(
      `RPC retry: operation=${event.operation}, classification=${event.classification}, attempt=${event.failedAttempt}/${event.maxAttempts}, delayMs=${event.delayMs}`
    );
  } else if (event.type === "split") {
    console.log(
      `RPC split: blocks=${event.fromBlock.toString()}-${event.toBlock.toString()}, depth=${event.depth}`
    );
  } else {
    console.error(
      `RPC exhausted: operation=${event.operation}, classification=${event.classification}, attempts=${event.attempts}`
    );
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Historical economic calibration failed: ${message}`);
  process.exitCode = 1;
});
