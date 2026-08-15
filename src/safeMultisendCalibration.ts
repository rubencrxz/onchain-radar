import "dotenv/config";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { getAddress, isAddress, toEventSelector, type Address, type Hex } from "viem";
import type { Alert } from "./alerts.js";
import { AlertJournal } from "./alertJournal.js";
import { writeAlertsJsonl } from "./alertWriter.js";
import { parseMonitorConfig, type MonitorConfig } from "./config.js";
import { loadScanEnv } from "./env.js";
import { executeHistoricalScan } from "./historicalScanner.js";
import {
  createViemRpcProvider,
  PolicyRpcClient,
  type RawRpcProvider,
  type RpcBlock,
  type RpcPolicyEvent,
  type RpcTransaction,
  type RpcTransactionReceipt
} from "./rpc.js";
import { decodeSafeExecTransaction } from "./safe/decoder.js";
import { analyzeMultiSendTransaction } from "./safe/multisend.js";
import type { AnalyzedSafeSubOperation } from "./safe/types.js";

const CONFIG_PATH = resolve("config/safe-multisend-historical-calibration-001.json");
const PROFILE_NAMES = ["strict", "balanced", "permissive"] as const;
const CATEGORIES = ["routine", "sensitive", "composed"] as const;

type ProfileName = (typeof PROFILE_NAMES)[number];
type TransactionCategory = (typeof CATEGORIES)[number];

type CalibrationTransaction = {
  category: TransactionCategory;
  label: string;
  transactionHash: Hex;
  blockNumber: bigint;
};

type CalibrationDefinition = {
  caseId: string;
  baselineProfile: ProfileName;
  postAnalysisProfile: ProfileName;
  fixedCreatedAt: string;
  expectedSafeSingleton: Address;
  expectedSafeVersion: string;
  rpcMaxBlockRange: bigint;
  controlRange: { startBlock: bigint; endBlock: bigint; rpcMaxBlockRange: bigint };
  controlTransactions: Array<{ transactionHash: Hex; blockNumber: bigint }>;
  outputFile: string;
  resultsFile: string;
  transactions: CalibrationTransaction[];
  profiles: Record<ProfileName, Record<string, unknown>>;
};

type RpcCounters = {
  logRequests: number;
  storageRequests: number;
  balanceRequests: number;
  blockRequests: number;
  transactionRequests: number;
  receiptRequests: number;
  safeStateRequests: number;
};

type ParserInspection = {
  payloadBytes: number;
  consumedBytes: number;
  consumedCompletely: boolean;
  suboperationCount: number;
  calls: number;
  delegatecalls: number;
  nativeValueTotalWei: string;
  uniqueTargets: string[];
  classifiedCount: number;
  unknownCount: number;
  observedReceiptEvents: string[];
  operations: Array<{
    path: string;
    operation: string;
    target: string;
    valueWei: string;
    selector: string;
    classifiedAction: string;
    parameters: Record<string, unknown>;
    offsetBytes: number;
    dataLengthBytes: number;
    encodedLengthBytes: number;
    policyCompliant: boolean;
    violations: string[];
  }>;
};

type TransactionRun = {
  category: TransactionCategory;
  label: string;
  transactionHash: string;
  blockNumber: string;
  blockHash: string;
  blockTimestamp: string;
  receiptStatus: string;
  parser: ParserInspection;
  alertCount: number;
  alertsByRuleId: Record<string, number>;
  alertsBySeverity: Record<string, number>;
  policyViolationAlerts: number;
  confirmedCorrelations: number;
  inconsistentCorrelations: number;
  ambiguousCorrelations: number;
  alerts: Alert[];
};

type ProfileRun = {
  profile: ProfileName;
  metrics: {
    totalAlerts: number;
    warnings: number;
    infos: number;
    criticals: number;
    policyViolationAlerts: number;
    totalSuboperations: number;
    classifiedSuboperations: number;
    unknownSuboperations: number;
    classificationCoveragePercent: number;
    confirmedCorrelations: number;
    inconsistentCorrelations: number;
    ambiguousCorrelations: number;
    subcallAlerts: number;
  };
  transactions: TransactionRun[];
};

type ControlRun = {
  profile: ProfileName;
  startBlock: string;
  endBlock: string;
  transactionCount: number;
  multiSendCount: number;
  suboperationCount: number;
  financialOperationCount: number;
  administrativeActionCount: number;
  unknownOperationCount: number;
  alertCount: number;
  warnings: number;
  criticals: number;
  policyViolationAlerts: number;
  confirmedCorrelations: number;
  newTargets: string[];
  newSelectors: string[];
  alerts: Alert[];
};

const OBSERVABLE_EVENT_TOPICS = new Map<string, string>([
  [toEventSelector("ExecutionSuccess(bytes32,uint256)").toLowerCase(), "ExecutionSuccess"],
  [toEventSelector("ExecutionFailure(bytes32,uint256)").toLowerCase(), "ExecutionFailure"],
  [toEventSelector("AddedOwner(address)").toLowerCase(), "AddedOwner"],
  [toEventSelector("RemovedOwner(address)").toLowerCase(), "RemovedOwner"],
  [toEventSelector("ChangedThreshold(uint256)").toLowerCase(), "ChangedThreshold"],
  [toEventSelector("Transfer(address,address,uint256)").toLowerCase(), "Transfer"],
  [toEventSelector("Approval(address,address,uint256)").toLowerCase(), "Approval"],
  [toEventSelector("Deposit(address,uint256)").toLowerCase(), "Deposit"]
]);

async function main(): Promise<void> {
  if (!existsSync(CONFIG_PATH)) throw new Error(`Missing calibration config: ${CONFIG_PATH}`);
  const rawConfig = parseJsonObject(readFileSync(CONFIG_PATH, "utf8"), "calibration config");
  const definition = parseCalibrationDefinition(rawConfig._calibration);
  const baseConfig = parseMonitorConfig(rawConfig);

  const rpcUrl = process.env.ETH_RPC_URL;
  if (rpcUrl === undefined || rpcUrl === "") {
    throw new Error("Missing ETH_RPC_URL. Historical Safe MultiSend calibration requires a functional Ethereum RPC.");
  }
  const env = loadScanEnv({
    ...process.env,
    ETH_RPC_URL: rpcUrl,
    START_BLOCK: "0",
    END_BLOCK: "0",
    RPC_MAX_BLOCK_RANGE: (definition.controlRange.rpcMaxBlockRange > definition.rpcMaxBlockRange
      ? definition.controlRange.rpcMaxBlockRange
      : definition.rpcMaxBlockRange).toString()
  });
  const counters = emptyCounters();
  const policyEvents: RpcPolicyEvent[] = [];
  const provider = countingProvider(createViemRpcProvider(rpcUrl, env.rpcPolicy.timeoutMs), counters);
  const rpc = new PolicyRpcClient(provider, env.rpcPolicy, {
    logger: (event) => {
      policyEvents.push(event);
      if (event.type === "retry") {
        console.warn(`RPC retry ${event.operation}: ${event.reason}; delay=${event.delayMs}ms`);
      } else if (event.type === "split") {
        console.warn(`RPC split ${event.fromBlock.toString()}-${event.toBlock.toString()} at ${event.leftToBlock.toString()}.`);
      } else {
        console.warn(`RPC retries exhausted for ${event.operation}: ${event.reason}`);
      }
    }
  });
  const safeAddress = baseConfig.administrativeMonitoring?.multisigs[0]?.address;
  if (safeAddress === undefined) throw new Error("Calibration requires one configured Safe.");
  const singletonObservations = await verifySafeSingleton(
    rpc,
    safeAddress,
    definition.transactions,
    definition.expectedSafeSingleton
  );

  console.log(`Historical Safe MultiSend calibration: ${definition.caseId}`);
  console.log(`Transactions: ${definition.transactions.length}; profiles: ${PROFILE_NAMES.join(", ")}`);
  console.log("RPC endpoint and credentials are intentionally not printed.");
  console.log("Artifacts are written only after every transaction/profile run succeeds.");

  const runs: ProfileRun[] = [];
  const controlRuns: ControlRun[] = [];
  for (const profile of PROFILE_NAMES) {
    const config = configForProfile(rawConfig, definition.profiles[profile]);
    const transactionRuns: TransactionRun[] = [];
    for (const transaction of definition.transactions) {
      console.log(`Running ${profile}/${transaction.category}: ${transaction.transactionHash} at ${transaction.blockNumber.toString()}...`);
      transactionRuns.push(await runTransaction({ rpc, config, definition, transaction }));
    }
    runs.push(summarizeProfile(profile, transactionRuns));
    console.log(`Running ${profile} expanded control ${definition.controlRange.startBlock.toString()}-${definition.controlRange.endBlock.toString()}...`);
    controlRuns.push(await runControlWindow({ rpc, config, definition, profile }));
  }

  const baseline = runs.find((run) => run.profile === definition.baselineProfile);
  if (baseline === undefined) throw new Error("Baseline profile was not produced.");
  const baselineAlerts = baseline.transactions.flatMap((transaction) => transaction.alerts);
  const regeneratedAlerts = await regenerateBaselineAlerts({
    rpc,
    config: configForProfile(rawConfig, definition.profiles[definition.baselineProfile]),
    definition
  });
  const replay = await verifyReplayIdempotency(
    baselineAlerts,
    regeneratedAlerts,
    baseline.transactions,
    definition.fixedCreatedAt
  );

  const baselineControl = controlRuns.find((run) => run.profile === definition.baselineProfile);
  const artifactAlerts = deduplicateById([...baselineAlerts, ...(baselineControl?.alerts ?? [])]);
  writeAlertsJsonl(resolve(definition.outputFile), artifactAlerts);
  const resultsPath = resolve(definition.resultsFile);
  mkdirSync(dirname(resultsPath), { recursive: true });
  writeFileSync(resultsPath, `${JSON.stringify({
    schemaVersion: 1,
    caseId: definition.caseId,
    chain: "ethereum",
    chainId: 1,
    selectedSafe: safeAddress,
    safeSingleton: {
      expectedAddress: definition.expectedSafeSingleton,
      expectedVersion: definition.expectedSafeVersion,
      observations: singletonObservations
    },
    fixedCreatedAt: definition.fixedCreatedAt,
    baselineProfile: definition.baselineProfile,
    postAnalysisProfile: definition.postAnalysisProfile,
    configFile: "config/safe-multisend-historical-calibration-001.json",
    alertArtifact: definition.outputFile,
    rpc: {
      ...counters,
      retries: policyEvents.filter((event) => event.type === "retry").length,
      splits: policyEvents.filter((event) => event.type === "split").length,
      exhausted: policyEvents.filter((event) => event.type === "exhausted").length
    },
    replay,
    controlRuns: controlRuns.map(({ alerts: _alerts, ...run }) => run),
    runs: runs.map((run) => ({
      ...run,
      transactions: run.transactions.map(({ alerts: _alerts, ...transaction }) => transaction)
    }))
  }, null, 2)}\n`, "utf8");

  console.log(`Baseline alert artifact: ${definition.outputFile}`);
  console.log(`Calibration metrics: ${definition.resultsFile}`);
  for (const run of runs) {
    console.log(`${run.profile}: alerts=${run.metrics.totalAlerts}, info=${run.metrics.infos}, warnings=${run.metrics.warnings}, criticals=${run.metrics.criticals}, policyViolations=${run.metrics.policyViolationAlerts}, correlations=${run.metrics.confirmedCorrelations}, subcalls=${run.metrics.subcallAlerts}, classified=${run.metrics.classifiedSuboperations}/${run.metrics.totalSuboperations}`);
  }
  for (const control of controlRuns) console.log(`${control.profile} control: transactions=${control.transactionCount}, multisends=${control.multiSendCount}, suboperations=${control.suboperationCount}, alerts=${control.alertCount}, policyViolations=${control.policyViolationAlerts}`);
  console.log(`Replay: stableIds=${replay.stableIds}, duplicateAlertsAfterJournalReload=${replay.duplicateAlertsAfterJournalReload}`);
}

async function runTransaction(params: {
  rpc: PolicyRpcClient;
  config: MonitorConfig;
  definition: CalibrationDefinition;
  transaction: CalibrationTransaction;
}): Promise<TransactionRun> {
  const result = await executeHistoricalScan({
    rpc: params.rpc,
    config: params.config,
    startBlock: params.transaction.blockNumber,
    endBlock: params.transaction.blockNumber,
    maxBlockRange: params.definition.rpcMaxBlockRange,
    clock: () => params.definition.fixedCreatedAt,
    sinks: []
  });
  const alerts = result.alerts.filter((alert) => alert.transactionHash.toLowerCase() === params.transaction.transactionHash.toLowerCase());
  if (result.safeTransactionCount !== 1 || alerts.length === 0) {
    throw new Error(`Expected exactly one reconstructed Safe transaction at block ${params.transaction.blockNumber.toString()}; reconstructed=${result.safeTransactionCount}, selectedAlerts=${alerts.length}.`);
  }

  const transaction = await requireTransaction(params.rpc, params.transaction.transactionHash);
  const receipt = await requireReceipt(params.rpc, params.transaction.transactionHash);
  const block = await requireBlock(params.rpc, params.transaction.blockNumber);
  if (transaction.blockNumber !== params.transaction.blockNumber || receipt.blockNumber !== params.transaction.blockNumber) {
    throw new Error(`Configured block does not match RPC transaction/receipt for ${params.transaction.transactionHash}.`);
  }
  if (receipt.status !== "success") throw new Error(`Calibration transaction ${params.transaction.transactionHash} reverted.`);

  const monitoring = params.config.administrativeMonitoring;
  const policy = monitoring?.multisigs[0];
  if (monitoring === undefined || policy === undefined) throw new Error("Calibration requires administrativeMonitoring.");
  const decoded = decodeSafeExecTransaction({ safeAddress: policy.address, transaction });
  if (!decoded.decoded) throw new Error(`Safe transaction could not be decoded: ${decoded.error}`);
  const expansion = analyzeMultiSendTransaction({ transaction: decoded.transaction, policy, config: monitoring });
  if (!expansion.recognized || !expansion.complete) {
    throw new Error(`Configured calibration transaction is not a completely decoded MultiSend: ${params.transaction.transactionHash}.`);
  }
  const parser = inspectExpansion(expansion.operations, expansion.totalPayloadBytes, receipt);
  if (!parser.consumedCompletely) throw new Error(`MultiSend payload was not consumed completely for ${params.transaction.transactionHash}.`);

  return {
    category: params.transaction.category,
    label: params.transaction.label,
    transactionHash: params.transaction.transactionHash,
    blockNumber: params.transaction.blockNumber.toString(),
    blockHash: block.hash,
    blockTimestamp: new Date(Number(block.timestamp) * 1000).toISOString(),
    receiptStatus: receipt.status,
    parser,
    alertCount: alerts.length,
    alertsByRuleId: countBy(alerts, (alert) => alert.ruleId),
    alertsBySeverity: countBy(alerts, (alert) => alert.severity),
    policyViolationAlerts: alerts.filter((alert) => alert.ruleId === "SAFE_POLICY_VIOLATION" || alert.ruleId === "SAFE_MULTISEND_POLICY_VIOLATION").length,
    confirmedCorrelations: alerts.filter((alert) => alert.ruleId === "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED").length,
    inconsistentCorrelations: alerts.filter((alert) => alert.ruleId === "SAFE_ADMINISTRATIVE_EFFECT_INCONSISTENCY").length,
    ambiguousCorrelations: alerts.filter((alert) => alert.ruleId === "SAFE_ADMINISTRATIVE_EFFECT_AMBIGUOUS").length,
    alerts
  };
}

function inspectExpansion(
  operations: readonly AnalyzedSafeSubOperation[],
  payloadBytes: number,
  receipt: RpcTransactionReceipt
): ParserInspection {
  let offsetBytes = 0;
  const rows = operations.map((operation) => {
    const dataLengthBytes = (operation.data.length - 2) / 2;
    const encodedLengthBytes = 1 + 20 + 32 + 32 + dataLengthBytes;
    const row = {
      path: operation.path,
      operation: operation.operation,
      target: operation.target,
      valueWei: operation.value.toString(),
      selector: operation.selector,
      classifiedAction: operation.action.functionSignature,
      parameters: operation.action.parameters,
      offsetBytes,
      dataLengthBytes,
      encodedLengthBytes,
      policyCompliant: operation.evaluation.compliant,
      violations: operation.evaluation.violations.map((violation) => violation.kind)
    };
    offsetBytes += encodedLengthBytes;
    return row;
  });
  const observedReceiptEvents = [...new Set(receipt.logs.flatMap((log) => {
    const topic = log.topics[0]?.toLowerCase();
    const name = topic === undefined ? undefined : OBSERVABLE_EVENT_TOPICS.get(topic);
    return name === undefined ? [] : [name];
  }))];
  return {
    payloadBytes,
    consumedBytes: offsetBytes,
    consumedCompletely: offsetBytes === payloadBytes,
    suboperationCount: operations.length,
    calls: operations.filter((operation) => operation.operation === "CALL").length,
    delegatecalls: operations.filter((operation) => operation.operation === "DELEGATECALL").length,
    nativeValueTotalWei: operations.reduce((total, operation) => total + operation.value, 0n).toString(),
    uniqueTargets: [...new Set(operations.map((operation) => operation.target))],
    classifiedCount: operations.filter((operation) => operation.action.known).length,
    unknownCount: operations.filter((operation) => !operation.action.known).length,
    observedReceiptEvents,
    operations: rows
  };
}

function summarizeProfile(profile: ProfileName, transactions: TransactionRun[]): ProfileRun {
  const totalAlerts = transactions.reduce((total, transaction) => total + transaction.alertCount, 0);
  const totalSuboperations = transactions.reduce((total, transaction) => total + transaction.parser.suboperationCount, 0);
  const classifiedSuboperations = transactions.reduce((total, transaction) => total + transaction.parser.classifiedCount, 0);
  const unknownSuboperations = totalSuboperations - classifiedSuboperations;
  return {
    profile,
    metrics: {
      totalAlerts,
      infos: transactions.reduce((total, transaction) => total + (transaction.alertsBySeverity.INFO ?? 0), 0),
      warnings: transactions.reduce((total, transaction) => total + (transaction.alertsBySeverity.WARNING ?? 0), 0),
      criticals: transactions.reduce((total, transaction) => total + (transaction.alertsBySeverity.CRITICAL ?? 0), 0),
      policyViolationAlerts: transactions.reduce((total, transaction) => total + transaction.policyViolationAlerts, 0),
      totalSuboperations,
      classifiedSuboperations,
      unknownSuboperations,
      classificationCoveragePercent: totalSuboperations === 0 ? 0 : Number(((classifiedSuboperations * 10_000) / totalSuboperations / 100).toFixed(2)),
      confirmedCorrelations: transactions.reduce((total, transaction) => total + transaction.confirmedCorrelations, 0),
      inconsistentCorrelations: transactions.reduce((total, transaction) => total + transaction.inconsistentCorrelations, 0),
      ambiguousCorrelations: transactions.reduce((total, transaction) => total + transaction.ambiguousCorrelations, 0),
      subcallAlerts: transactions.reduce((total, transaction) => total + (transaction.alertsByRuleId.SAFE_MULTISEND_SUBCALL ?? 0), 0)
    },
    transactions
  };
}

async function runControlWindow(params: {
  rpc: PolicyRpcClient;
  config: MonitorConfig;
  definition: CalibrationDefinition;
  profile: ProfileName;
}): Promise<ControlRun> {
  const range = params.definition.controlRange;
  const alerts: Alert[] = [];
  let transactionCount = 0;
  for (const transaction of params.definition.controlTransactions) {
    const result = await executeHistoricalScan({
      rpc: params.rpc,
      config: params.config,
      startBlock: transaction.blockNumber,
      endBlock: transaction.blockNumber,
      maxBlockRange: range.rpcMaxBlockRange,
      clock: () => params.definition.fixedCreatedAt,
      sinks: []
    });
    const selected = result.alerts.filter((alert) => alert.transactionHash.toLowerCase() === transaction.transactionHash.toLowerCase());
    if (selected.length === 0) throw new Error(`Control transaction ${transaction.transactionHash} produced no alerts at block ${transaction.blockNumber.toString()}.`);
    const rpcTransaction = await requireTransaction(params.rpc, transaction.transactionHash);
    const receipt = await requireReceipt(params.rpc, transaction.transactionHash);
    if (rpcTransaction.blockNumber !== transaction.blockNumber || receipt.blockNumber !== transaction.blockNumber || receipt.status !== "success") {
      throw new Error(`Control transaction ${transaction.transactionHash} failed direct RPC block/status validation.`);
    }
    transactionCount += result.safeTransactionCount;
    alerts.push(...selected);
  }
  const uniqueAlerts = deduplicateById(alerts);
  const summaries = uniqueAlerts.filter((alert) => alert.ruleId === "SAFE_MULTISEND_EXECUTED");
  const summaryRows = summaries.map((alert) => requireRecord(alert.metadata.multiSend, "alert.metadata.multiSend"));
  const policy = params.config.administrativeMonitoring?.multisigs[0];
  const subcalls = uniqueAlerts.filter((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL");
  const targets = subcalls.flatMap((alert) => {
    const multiSend = asOptionalRecord(alert.metadata.multiSend);
    const suboperation = asOptionalRecord(multiSend?.suboperation);
    return typeof suboperation?.target === "string" ? [suboperation.target] : [];
  });
  const selectors = subcalls.flatMap((alert) => {
    const multiSend = asOptionalRecord(alert.metadata.multiSend);
    const suboperation = asOptionalRecord(multiSend?.suboperation);
    return typeof suboperation?.selector === "string" ? [suboperation.selector] : [];
  });
  return {
    profile: params.profile,
    startBlock: range.startBlock.toString(),
    endBlock: range.endBlock.toString(),
    transactionCount,
    multiSendCount: summaries.length,
    suboperationCount: sumNumber(summaryRows, "suboperationCount"),
    financialOperationCount: sumNumber(summaryRows, "financialOperationCount"),
    administrativeActionCount: sumNumber(summaryRows, "sensitiveActionCount"),
    unknownOperationCount: sumNumber(summaryRows, "unknownOperationCount"),
    alertCount: uniqueAlerts.length,
    warnings: uniqueAlerts.filter((alert) => alert.severity === "WARNING").length,
    criticals: uniqueAlerts.filter((alert) => alert.severity === "CRITICAL").length,
    policyViolationAlerts: uniqueAlerts.filter((alert) => alert.ruleId === "SAFE_POLICY_VIOLATION" || alert.ruleId === "SAFE_MULTISEND_POLICY_VIOLATION").length,
    confirmedCorrelations: uniqueAlerts.filter((alert) => alert.ruleId === "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED").length,
    newTargets: uniqueStrings(targets.filter((target) => policy === undefined || !policy.allowedTargets.some((allowed) => allowed.toLowerCase() === target.toLowerCase()))),
    newSelectors: uniqueStrings(selectors.filter((selector) => policy === undefined || !policy.allowedSelectors.some((allowed) => allowed.toLowerCase() === selector.toLowerCase()))),
    alerts: uniqueAlerts
  };
}

function sumNumber(rows: readonly Record<string, unknown>[], key: string): number {
  return rows.reduce((total, row) => total + (typeof row[key] === "number" ? row[key] as number : 0), 0);
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.toLowerCase()))].sort();
}

function deduplicateById(alerts: readonly Alert[]): Alert[] {
  const ids = new Set<string>();
  return alerts.filter((alert) => !ids.has(alert.id) && (ids.add(alert.id), true));
}

function asOptionalRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

async function verifyReplayIdempotency(
  baselineAlerts: readonly Alert[],
  regeneratedAlerts: readonly Alert[],
  transactions: readonly TransactionRun[],
  recordedAt: string
): Promise<{ stableIds: boolean; regeneratedAlertCount: number; duplicateAlertsAfterJournalReload: number }> {
  const baselineIds = baselineAlerts.map((alert) => alert.id);
  const regeneratedIds = regeneratedAlerts.map((alert) => alert.id);
  const stableIds = baselineIds.length === new Set(baselineIds).size &&
    baselineIds.length === regeneratedIds.length &&
    baselineIds.every((id, index) => id === regeneratedIds[index]);
  if (!stableIds) throw new Error("Baseline replay produced different alert IDs or ordering.");
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-calibration-"));
  const journalPath = join(temporaryDirectory, "journal.jsonl");
  try {
    const hashes = new Map(transactions.map((transaction) => [transaction.blockNumber, transaction.blockHash]));
    const journal = new AlertJournal(journalPath);
    journal.append(baselineAlerts, hashes, recordedAt);
    const restored = new AlertJournal(journalPath);
    return {
      stableIds,
      regeneratedAlertCount: regeneratedAlerts.length,
      duplicateAlertsAfterJournalReload: restored.filterNew(regeneratedAlerts).length
    };
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

async function regenerateBaselineAlerts(params: {
  rpc: PolicyRpcClient;
  config: MonitorConfig;
  definition: CalibrationDefinition;
}): Promise<Alert[]> {
  const alerts: Alert[] = [];
  for (const transaction of params.definition.transactions) {
    const result = await executeHistoricalScan({
      rpc: params.rpc,
      config: params.config,
      startBlock: transaction.blockNumber,
      endBlock: transaction.blockNumber,
      maxBlockRange: params.definition.rpcMaxBlockRange,
      clock: () => params.definition.fixedCreatedAt,
      sinks: []
    });
    alerts.push(...result.alerts.filter((alert) => alert.transactionHash.toLowerCase() === transaction.transactionHash.toLowerCase()));
  }
  return alerts;
}

function configForProfile(rawConfig: Record<string, unknown>, profile: Record<string, unknown>): MonitorConfig {
  const copy = structuredClone(rawConfig);
  const administrative = requireRecord(copy.administrativeMonitoring, "administrativeMonitoring");
  if (!Array.isArray(administrative.multisigs) || administrative.multisigs.length !== 1) {
    throw new Error("Calibration requires exactly one administrativeMonitoring.multisigs entry.");
  }
  administrative.multisigs[0] = { ...requireRecord(administrative.multisigs[0], "administrativeMonitoring.multisigs[0]"), ...structuredClone(profile) };
  return parseMonitorConfig(copy);
}

function parseCalibrationDefinition(value: unknown): CalibrationDefinition {
  const raw = requireRecord(value, "_calibration");
  const profiles = requireRecord(raw.profiles, "_calibration.profiles");
  if (!Array.isArray(raw.transactions) || raw.transactions.length < 3) {
    throw new Error("_calibration.transactions must contain routine, sensitive and composed transactions.");
  }
  const transactions = raw.transactions.map((value, index) => parseCalibrationTransaction(value, index));
  for (const category of CATEGORIES) {
    if (!transactions.some((transaction) => transaction.category === category)) {
      throw new Error(`_calibration.transactions is missing category ${category}.`);
    }
  }
  const rpcMaxBlockRange = parsePositiveBigInt(raw.rpcMaxBlockRange, "_calibration.rpcMaxBlockRange");
  const control = requireRecord(raw.controlRange, "_calibration.controlRange");
  const controlRange = {
    startBlock: parsePositiveBigInt(control.startBlock, "_calibration.controlRange.startBlock"),
    endBlock: parsePositiveBigInt(control.endBlock, "_calibration.controlRange.endBlock"),
    rpcMaxBlockRange: parsePositiveBigInt(control.rpcMaxBlockRange, "_calibration.controlRange.rpcMaxBlockRange")
  };
  if (controlRange.startBlock > controlRange.endBlock) throw new Error("_calibration.controlRange startBlock must not exceed endBlock.");
  if (!Array.isArray(raw.controlTransactions) || raw.controlTransactions.length < 2) {
    throw new Error("_calibration.controlTransactions must contain at least two real transactions.");
  }
  const controlTransactions = raw.controlTransactions.map((value, index) => {
    const transaction = requireRecord(value, `_calibration.controlTransactions[${index}]`);
    if (typeof transaction.transactionHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(transaction.transactionHash)) {
      throw new Error(`_calibration.controlTransactions[${index}].transactionHash must be a transaction hash.`);
    }
    return {
      transactionHash: transaction.transactionHash.toLowerCase() as Hex,
      blockNumber: parsePositiveBigInt(transaction.blockNumber, `_calibration.controlTransactions[${index}].blockNumber`)
    };
  });
  return {
    caseId: parseNonEmptyString(raw.caseId, "_calibration.caseId"),
    baselineProfile: parseProfileName(raw.baselineProfile, "_calibration.baselineProfile"),
    postAnalysisProfile: parseProfileName(raw.postAnalysisProfile, "_calibration.postAnalysisProfile"),
    fixedCreatedAt: parseIsoTimestamp(raw.fixedCreatedAt, "_calibration.fixedCreatedAt"),
    expectedSafeSingleton: parseAddress(raw.expectedSafeSingleton, "_calibration.expectedSafeSingleton"),
    expectedSafeVersion: parseNonEmptyString(raw.expectedSafeVersion, "_calibration.expectedSafeVersion"),
    rpcMaxBlockRange,
    controlRange,
    controlTransactions,
    outputFile: parseNonEmptyString(raw.outputFile, "_calibration.outputFile"),
    resultsFile: parseNonEmptyString(raw.resultsFile, "_calibration.resultsFile"),
    transactions,
    profiles: Object.fromEntries(PROFILE_NAMES.map((name) => [name, requireRecord(profiles[name], `_calibration.profiles.${name}`)])) as Record<ProfileName, Record<string, unknown>>
  };
}

function parseCalibrationTransaction(value: unknown, index: number): CalibrationTransaction {
  const raw = requireRecord(value, `_calibration.transactions[${index}]`);
  if (typeof raw.category !== "string" || !CATEGORIES.includes(raw.category as TransactionCategory)) {
    throw new Error(`_calibration.transactions[${index}].category is invalid.`);
  }
  if (typeof raw.transactionHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(raw.transactionHash)) {
    throw new Error(`_calibration.transactions[${index}].transactionHash must be a 32-byte hex hash.`);
  }
  return {
    category: raw.category as TransactionCategory,
    label: parseNonEmptyString(raw.label, `_calibration.transactions[${index}].label`),
    transactionHash: raw.transactionHash.toLowerCase() as Hex,
    blockNumber: parsePositiveBigInt(raw.blockNumber, `_calibration.transactions[${index}].blockNumber`)
  };
}

function countingProvider(provider: RawRpcProvider, counters: RpcCounters): RawRpcProvider {
  return {
    async getLogs(request) { counters.logRequests += 1; return provider.getLogs(request); },
    async getStorageAt(request) { counters.storageRequests += 1; return provider.getStorageAt(request); },
    async getErc20Balance(request) { counters.balanceRequests += 1; return provider.getErc20Balance(request); },
    async getBlockNumber() {
      counters.blockRequests += 1;
      if (provider.getBlockNumber === undefined) throw new Error("Provider does not implement getBlockNumber.");
      return provider.getBlockNumber();
    },
    async getBlock(blockNumber) {
      counters.blockRequests += 1;
      if (provider.getBlock === undefined) throw new Error("Provider does not implement getBlock.");
      return provider.getBlock(blockNumber);
    },
    async getTransaction(transactionHash) {
      counters.transactionRequests += 1;
      if (provider.getTransaction === undefined) throw new Error("Provider does not implement getTransaction.");
      return provider.getTransaction(transactionHash);
    },
    async getTransactionReceipt(transactionHash) {
      counters.receiptRequests += 1;
      if (provider.getTransactionReceipt === undefined) throw new Error("Provider does not implement getTransactionReceipt.");
      return provider.getTransactionReceipt(transactionHash);
    },
    async getSafeThreshold(request) {
      counters.safeStateRequests += 1;
      if (provider.getSafeThreshold === undefined) throw new Error("Provider does not implement getSafeThreshold.");
      return provider.getSafeThreshold(request);
    },
    async isSafeOwner(request) {
      counters.safeStateRequests += 1;
      if (provider.isSafeOwner === undefined) throw new Error("Provider does not implement isSafeOwner.");
      return provider.isSafeOwner(request);
    },
    async isSafeModuleEnabled(request) {
      counters.safeStateRequests += 1;
      if (provider.isSafeModuleEnabled === undefined) throw new Error("Provider does not implement isSafeModuleEnabled.");
      return provider.isSafeModuleEnabled(request);
    }
  };
}

async function requireTransaction(rpc: PolicyRpcClient, hash: Hex): Promise<RpcTransaction> {
  if (rpc.getTransaction === undefined) throw new Error("RPC client does not implement getTransaction.");
  return rpc.getTransaction(hash);
}

async function requireReceipt(rpc: PolicyRpcClient, hash: Hex): Promise<RpcTransactionReceipt> {
  if (rpc.getTransactionReceipt === undefined) throw new Error("RPC client does not implement getTransactionReceipt.");
  return rpc.getTransactionReceipt(hash);
}

async function requireBlock(rpc: PolicyRpcClient, blockNumber: bigint): Promise<RpcBlock> {
  if (rpc.getBlock === undefined) throw new Error("RPC client does not implement getBlock.");
  return rpc.getBlock(blockNumber);
}

async function verifySafeSingleton(
  rpc: PolicyRpcClient,
  safeAddress: Address,
  transactions: readonly CalibrationTransaction[],
  expected: Address
): Promise<Array<{ blockNumber: string; singleton: Address; matchesExpected: boolean }>> {
  const observations = [];
  for (const transaction of transactions) {
    const value = await rpc.getStorageAt({ address: safeAddress, slot: `0x${"00".repeat(32)}`, blockNumber: transaction.blockNumber });
    if (value === undefined || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
      throw new Error(`Cannot read Safe singleton slot at block ${transaction.blockNumber.toString()}.`);
    }
    const singleton = getAddress(`0x${value.slice(-40)}`);
    const matchesExpected = singleton.toLowerCase() === expected.toLowerCase();
    if (!matchesExpected) {
      throw new Error(`Safe singleton ${singleton} at block ${transaction.blockNumber.toString()} does not match expected ${expected}.`);
    }
    observations.push({ blockNumber: transaction.blockNumber.toString(), singleton, matchesExpected });
  }
  return observations;
}

function countBy<T>(values: readonly T[], key: (value: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    const item = key(value);
    counts[item] = (counts[item] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function emptyCounters(): RpcCounters {
  return { logRequests: 0, storageRequests: 0, balanceRequests: 0, blockRequests: 0, transactionRequests: 0, receiptRequests: 0, safeStateRequests: 0 };
}

function parseJsonObject(contents: string, field: string): Record<string, unknown> {
  let value: unknown;
  try { value = JSON.parse(contents); } catch (error) { throw new Error(`Invalid JSON in ${field}.`, { cause: error }); }
  return requireRecord(value, field);
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${field} must be an object.`);
  return value as Record<string, unknown>;
}

function parseNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${field} must be a non-empty string.`);
  return value;
}

function parseAddress(value: unknown, field: string): Address {
  if (typeof value !== "string" || !isAddress(value)) throw new Error(`${field} must be an Ethereum address.`);
  return getAddress(value);
}

function parsePositiveBigInt(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value) || BigInt(value) <= 0n) throw new Error(`${field} must be a positive base-10 integer string.`);
  return BigInt(value);
}

function parseProfileName(value: unknown, field: string): ProfileName {
  if (typeof value !== "string" || !PROFILE_NAMES.includes(value as ProfileName)) throw new Error(`${field} must be strict, balanced or permissive.`);
  return value as ProfileName;
}

function parseIsoTimestamp(value: unknown, field: string): string {
  const text = parseNonEmptyString(value, field);
  if (Number.isNaN(Date.parse(text))) throw new Error(`${field} must be an ISO timestamp.`);
  return text;
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
  process.exitCode = 1;
});
