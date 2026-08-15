import "dotenv/config";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  createPublicClient,
  decodeFunctionData,
  getAddress,
  http,
  isAddress,
  parseAbi,
  type Address,
  type Hex
} from "viem";
import { mainnet } from "viem/chains";
import type { Alert } from "./alerts.js";
import { AlertJournal } from "./alertJournal.js";
import { writeAlertsJsonl } from "./alertWriter.js";
import { parseMonitorConfig, type MonitorConfig } from "./config.js";
import { loadScanEnv } from "./env.js";
import { buildEventTopicMap } from "./events.js";
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
import { selectorOf } from "./safe/decoder.js";
import { decodeSafeExecTransaction } from "./safe/decoder.js";
import {
  decodeSafeModuleExecutionEvent,
  SAFE_MODULE_EXECUTION_EVENT_SIGNATURES
} from "./safe/module.js";
import { decodeMultiSendCalldata, MULTISEND_SELECTOR, parseMultiSendPayload } from "./safe/multisend.js";
import {
  assessZodiacStructuralAuthorization,
  decodeRoleKeyAscii,
  hashAbiEncodedAddress,
  readZodiacRolePermission,
  readZodiacTransactionUnwrapper,
  ZODIAC_MULTI_SEND_UNWRAPPER_2_1,
  ZODIAC_ROLES_V2_MASTERCOPY_2_1,
  type ZodiacRolePermissionObservation
} from "./safe/zodiacPermissions.js";

const CONFIG_PATH = resolve("config/safe-modules-historical-calibration-001.json");
const PROFILE_NAMES = ["strict", "balanced", "permissive"] as const;
type ProfileName = (typeof PROFILE_NAMES)[number];

type CalibrationTransaction = {
  category: string;
  label: string;
  transactionHash: Hex;
  blockNumber: bigint;
  referenceTopLevelOperations: number;
  referenceLeafOperations: number;
  referenceSummary: string;
};

type CalibrationDefinition = {
  caseId: string;
  fixedCreatedAt: string;
  baselineProfile: ProfileName;
  recommendedProfile: ProfileName;
  expectedSafeSingleton: Address;
  expectedModuleAvatar: Address;
  expectedModuleTarget: Address;
  expectedModuleOwner: Address;
  expectedOuterManagerSafe: Address;
  expectedRoleKey: Hex;
  rpcMaxBlockRange: bigint;
  outputFile: string;
  permissionOutputFile: string;
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
  codeRequests: number;
};

type TransactionRun = {
  category: string;
  label: string;
  transactionHash: string;
  blockNumber: string;
  blockHash: string;
  blockTimestamp: string;
  receiptStatus: string;
  outerTarget: string | null;
  outerSelector: string;
  outerCalldataBytes: number;
  referenceTopLevelOperations: number;
  referenceLeafOperations: number;
  referenceSummary: string;
  observedModuleEvents: number;
  observedModules: string[];
  moduleOutcomes: string[];
  moduleEnabledBefore: boolean;
  moduleEnabledAfter: boolean;
  reconstructedOperations: number;
  reconstructedLeafOperations: number;
  undecodedOperations: number;
  decodeFailureKinds: string[];
  staticEnvelopeRecovery: {
    managerSafeDecoded: boolean;
    moduleCallSites: number;
    zodiacCallsDecoded: number;
    leafOperationsRecovered: number;
    operations: Array<{
      path: string;
      target: string;
      selector: string;
      operation: string;
      valueWei: string;
      nestedLeafOperations: number;
    }>;
  };
  administrativeEffects: string[];
  eip1967SlotAlerts: number;
  correlationAlerts: number;
  alertCount: number;
  alertsByRuleId: Record<string, number>;
  alertsBySeverity: Record<string, number>;
  alerts: Alert[];
};

type ProfileRun = {
  profile: ProfileName;
  metrics: {
    totalAlerts: number;
    infos: number;
    warnings: number;
    criticals: number;
    moduleEvents: number;
    referenceTopLevelOperations: number;
    referenceLeafOperations: number;
    reconstructedOperations: number;
    reconstructedLeafOperations: number;
    reconstructionCoveragePercent: number;
    staticallyRecoverableTopLevelOperations: number;
    staticRecoveryCoveragePercent: number;
    undecodedOperations: number;
    unknownModuleAlerts: number;
    policyViolationAlerts: number;
    correlations: number;
    eip1967SlotAlerts: number;
  };
  transactions: TransactionRun[];
};

const ROLES_IDENTITY_ABI = parseAbi([
  "function avatar() view returns (address)",
  "function target() view returns (address)",
  "function owner() view returns (address)"
]);

const ZODIAC_ROLES_EXECUTION_ABI = parseAbi([
  "function execTransactionWithRole(address to,uint256 value,bytes data,uint8 operation,bytes32 roleKey,bool shouldRevert) returns (bool success)",
  "function execTransactionWithRoleReturnData(address to,uint256 value,bytes data,uint8 operation,bytes32 roleKey,bool shouldRevert) returns (bool success,bytes returnData)"
]);

const APPROVE_ABI = parseAbi(["function approve(address spender,uint256 amount) returns (bool)"]);
const BAL_COW_TRANSACTION_HASH = "0x1bb8d5d64359b002aa6d5d2bfd449d5593e51568bbac0baed05c6705abf3e13e" as Hex;
const BAL_TOKEN = getAddress("0xba100000625a3754423978a60c9317c58a424e3D");
const COW_ORDER_SIGNER = getAddress("0x23dA9AdE38E4477b23770DeD512fD37b12381FAB");
const GPV2_VAULT_RELAYER = getAddress("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110");
const USDC_TOKEN = getAddress("0xA0b86991c6218b36c1d19d4a2e9eb0cE3606eB48");

const ADMIN_EFFECT_TOPICS = buildEventTopicMap([
  "Upgraded(address)",
  "AdminChanged(address,address)",
  "OwnershipTransferred(address,address)",
  "RoleGranted(bytes32,address,address)",
  "RoleRevoked(bytes32,address,address)",
  "Paused(address)",
  "Unpaused(address)",
  "AddedOwner(address)",
  "RemovedOwner(address)",
  "ChangedThreshold(uint256)",
  "EnabledModule(address)",
  "DisabledModule(address)",
  "ChangedGuard(address)",
  "ChangedFallbackHandler(address)"
]);

async function main(): Promise<void> {
  if (!existsSync(CONFIG_PATH)) throw new Error(`Missing calibration config: ${CONFIG_PATH}`);
  const rawConfig = parseJsonObject(readFileSync(CONFIG_PATH, "utf8"), "calibration config");
  const definition = parseDefinition(rawConfig._calibration);
  const baseConfig = parseMonitorConfig(rawConfig);
  const safe = baseConfig.administrativeMonitoring?.multisigs[0];
  if (safe === undefined || baseConfig.administrativeMonitoring?.multisigs.length !== 1) {
    throw new Error("Calibration requires exactly one configured Safe.");
  }

  const rpcUrl = process.env.ETH_RPC_URL;
  if (rpcUrl === undefined || rpcUrl === "") {
    throw new Error("Missing ETH_RPC_URL. Historical Safe module calibration requires Ethereum archive-capable RPC.");
  }
  const env = loadScanEnv({
    ...process.env,
    ETH_RPC_URL: rpcUrl,
    START_BLOCK: "0",
    END_BLOCK: "0",
    RPC_MAX_BLOCK_RANGE: definition.rpcMaxBlockRange.toString()
  });
  const counters = emptyCounters();
  const policyEvents: RpcPolicyEvent[] = [];
  const rawProvider = countingProvider(createViemRpcProvider(rpcUrl, env.rpcPolicy.timeoutMs), counters);
  const rpc = new PolicyRpcClient(rawProvider, env.rpcPolicy, {
    logger: (event) => {
      policyEvents.push(event);
      if (event.type === "retry") console.warn(`RPC retry ${event.operation}: ${event.reason}; delay=${event.delayMs}ms`);
      else if (event.type === "split") console.warn(`RPC split ${event.fromBlock}-${event.toBlock} at ${event.leftToBlock}.`);
      else console.warn(`RPC retries exhausted for ${event.operation}: ${event.reason}`);
    }
  });

  const moduleAddress = getAddress("0x703806E61847984346d2D7DDd853049627e50A40");
  const firstBlock = definition.transactions.reduce((lowest, transaction) =>
    transaction.blockNumber < lowest ? transaction.blockNumber : lowest, definition.transactions[0]!.blockNumber);
  const preflight = await verifyIdentity({
    rpcUrl,
    timeoutMs: env.rpcPolicy.timeoutMs,
    blockNumber: firstBlock,
    safeAddress: safe.address,
    moduleAddress,
    definition
  });

  console.log(`Historical Safe module calibration: ${definition.caseId}`);
  console.log(`Safe: ${safe.address}; module: ${moduleAddress}; transactions: ${definition.transactions.length}.`);
  console.log("RPC endpoint and credentials are intentionally not printed.");
  console.log("Artifacts are written only after all profiles and replay validation succeed.");

  const runs: ProfileRun[] = [];
  for (const profile of PROFILE_NAMES) {
    const config = configForProfile(rawConfig, definition.profiles[profile]);
    const transactions: TransactionRun[] = [];
    for (const transaction of definition.transactions) {
      console.log(`Running ${profile}/${transaction.category}: ${transaction.transactionHash} at ${transaction.blockNumber}...`);
      transactions.push(await runTransaction({ rpc, config, definition, transaction, safeAddress: safe.address, moduleAddress }));
    }
    runs.push(summarizeProfile(profile, transactions));
  }

  const zodiacPermissions = await calibrateBalCowZodiacPermissions({
    rpc,
    definition,
    moduleAddress,
    safeAddress: safe.address
  });

  const baseline = requireProfile(runs, definition.baselineProfile);
  const regenerated = await regenerateProfile({
    rpc,
    config: configForProfile(rawConfig, definition.profiles[definition.baselineProfile]),
    definition,
    safeAddress: safe.address,
    moduleAddress
  });
  const replay = verifyReplay(
    baseline.transactions.flatMap((transaction) => transaction.alerts),
    regenerated.flatMap((transaction) => transaction.alerts),
    baseline.transactions,
    definition.fixedCreatedAt
  );

  const baselineAlerts = deduplicateAlerts(baseline.transactions.flatMap((transaction) => transaction.alerts));
  writeAlertsJsonl(resolve(definition.outputFile), baselineAlerts);
  const balancedBalCow = requireProfile(runs, "balanced").transactions.find((transaction) => transaction.transactionHash === BAL_COW_TRANSACTION_HASH);
  if (balancedBalCow === undefined) throw new Error("Balanced BAL/CoW transaction result is missing.");
  writeAlertsJsonl(resolve(definition.permissionOutputFile), deduplicateAlerts(balancedBalCow.alerts));
  const resultsPath = resolve(definition.resultsFile);
  mkdirSync(dirname(resultsPath), { recursive: true });
  writeFileSync(resultsPath, `${JSON.stringify({
    schemaVersion: 1,
    caseId: definition.caseId,
    chain: "ethereum",
    chainId: preflight.chainId,
    selectedSafe: safe.address,
    selectedModule: moduleAddress,
    identity: preflight,
    zodiacPermissions,
    evidenceBoundary: {
      detectorUsesTraces: false,
      safeTransactionServiceUsedByDetector: false,
      referenceOperationsSource: "Safe Transaction Service research index; execution identity, receipts, blocks, logs and state revalidated through RPC",
      administrativeOperationFoundInIndexedHistory: false,
      indexedHistoryReviewed: { moduleTransactions: 850, rolesV2ModuleTransactions: 546 }
    },
    fixedCreatedAt: definition.fixedCreatedAt,
    baselineProfile: definition.baselineProfile,
    recommendedProfile: definition.recommendedProfile,
    configFile: "config/safe-modules-historical-calibration-001.json",
    alertArtifact: definition.outputFile,
    zodiacPermissionAlertArtifact: definition.permissionOutputFile,
    rpc: {
      ...counters,
      retries: policyEvents.filter((event) => event.type === "retry").length,
      splits: policyEvents.filter((event) => event.type === "split").length,
      exhausted: policyEvents.filter((event) => event.type === "exhausted").length
    },
    replay,
    runs: runs.map((run) => ({
      ...run,
      transactions: run.transactions.map(({ alerts: _alerts, ...transaction }) => transaction)
    }))
  }, null, 2)}\n`, "utf8");

  console.log(`Baseline alert artifact: ${definition.outputFile}`);
  console.log(`BAL/CoW permission-calibrated artifact: ${definition.permissionOutputFile}`);
  console.log(`Calibration metrics: ${definition.resultsFile}`);
  for (const run of runs) {
    const m = run.metrics;
    console.log(`${run.profile}: alerts=${m.totalAlerts}, info=${m.infos}, warnings=${m.warnings}, criticals=${m.criticals}, unknownModule=${m.unknownModuleAlerts}, policyViolations=${m.policyViolationAlerts}, reconstructed=${m.reconstructedOperations}/${m.referenceTopLevelOperations}, correlations=${m.correlations}`);
  }
  console.log(`Replay: stableIds=${replay.stableIds}, duplicateAlertsAfterJournalReload=${replay.duplicateAlertsAfterJournalReload}`);
}

async function runTransaction(params: {
  rpc: PolicyRpcClient;
  config: MonitorConfig;
  definition: CalibrationDefinition;
  transaction: CalibrationTransaction;
  safeAddress: Address;
  moduleAddress: Address;
}): Promise<TransactionRun> {
  const scan = await executeHistoricalScan({
    rpc: params.rpc,
    config: params.config,
    startBlock: params.transaction.blockNumber,
    endBlock: params.transaction.blockNumber,
    maxBlockRange: params.definition.rpcMaxBlockRange,
    clock: () => params.definition.fixedCreatedAt,
    sinks: []
  });
  const alerts = scan.alerts.filter((alert) =>
    alert.transactionHash.toLowerCase() === params.transaction.transactionHash.toLowerCase());
  if (alerts.length === 0) throw new Error(`Transaction ${params.transaction.transactionHash} produced no alerts.`);

  const transaction = await requireTransaction(params.rpc, params.transaction.transactionHash);
  const receipt = await requireReceipt(params.rpc, params.transaction.transactionHash);
  const block = await requireBlock(params.rpc, params.transaction.blockNumber);
  if (transaction.blockNumber !== params.transaction.blockNumber || receipt.blockNumber !== params.transaction.blockNumber) {
    throw new Error(`Configured block does not match RPC transaction/receipt for ${params.transaction.transactionHash}.`);
  }
  if (receipt.status !== "success") throw new Error(`Calibration outer transaction ${params.transaction.transactionHash} reverted.`);
  if (transaction.to?.toLowerCase() !== params.definition.expectedOuterManagerSafe.toLowerCase()) {
    throw new Error(`Outer transaction ${params.transaction.transactionHash} does not target the verified ENS Endowment manager Safe.`);
  }
  const moduleLogs = receipt.logs
    .filter((log) => log.address.toLowerCase() === params.safeAddress.toLowerCase())
    .flatMap((log) => {
      const decoded = decodeSafeModuleExecutionEvent(log);
      return decoded === undefined ? [] : [{ decoded, log }];
    });
  if (moduleLogs.length !== params.transaction.referenceTopLevelOperations) {
    throw new Error(`RPC receipt module event count ${moduleLogs.length} does not match reference operation count ${params.transaction.referenceTopLevelOperations} for ${params.transaction.transactionHash}.`);
  }
  if (moduleLogs.some(({ decoded }) => decoded.moduleAddress.toLowerCase() !== params.moduleAddress.toLowerCase())) {
    throw new Error(`Unexpected executing module in ${params.transaction.transactionHash}.`);
  }
  const beforeBlock = params.transaction.blockNumber === 0n ? 0n : params.transaction.blockNumber - 1n;
  const enabledBefore = await params.rpc.isSafeModuleEnabled?.({ safe: params.safeAddress, module: params.moduleAddress, blockNumber: beforeBlock });
  const enabledAfter = await params.rpc.isSafeModuleEnabled?.({ safe: params.safeAddress, module: params.moduleAddress, blockNumber: params.transaction.blockNumber });
  if (enabledBefore !== true || enabledAfter !== true) {
    throw new Error(`Roles v2 module was not enabled before and after ${params.transaction.transactionHash}.`);
  }
  const singleton = await params.rpc.getStorageAt({ address: params.safeAddress, slot: `0x${"00".repeat(32)}`, blockNumber: params.transaction.blockNumber });
  if (singleton === undefined || getAddress(`0x${singleton.slice(-40)}`).toLowerCase() !== params.definition.expectedSafeSingleton.toLowerCase()) {
    throw new Error(`Safe singleton mismatch at block ${params.transaction.blockNumber}.`);
  }
  const managerSingleton = await params.rpc.getStorageAt({ address: params.definition.expectedOuterManagerSafe, slot: `0x${"00".repeat(32)}`, blockNumber: params.transaction.blockNumber });
  if (managerSingleton === undefined || getAddress(`0x${managerSingleton.slice(-40)}`).toLowerCase() !== params.definition.expectedSafeSingleton.toLowerCase()) {
    throw new Error(`Endowment manager Safe singleton mismatch at block ${params.transaction.blockNumber}.`);
  }

  const administrativeEffects = receipt.logs.flatMap((log) => {
    const topic = log.topics[0];
    const signature = topic === undefined ? undefined : ADMIN_EFFECT_TOPICS.get(topic);
    return signature === undefined ? [] : [signature];
  });
  const reconstructedOperations = alerts.filter((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_EXECUTED").length;
  const undecodedAlerts = alerts.filter((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_UNDECODED");
  if (reconstructedOperations + undecodedAlerts.length !== moduleLogs.length) {
    throw new Error(`Module reconstruction accounting is incomplete for ${params.transaction.transactionHash}.`);
  }
  if (scan.safeLeafOperationCount !== params.transaction.referenceLeafOperations) {
    throw new Error(`Detector reconstructed ${scan.safeLeafOperationCount} leaf operation(s), expected ${params.transaction.referenceLeafOperations}, for ${params.transaction.transactionHash}.`);
  }
  const staticEnvelopeRecovery = inspectStaticEnvelope({
    transaction,
    managerSafe: params.definition.expectedOuterManagerSafe,
    moduleAddress: params.moduleAddress,
    multiSendAddresses: [
      getAddress("0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"),
      getAddress("0x40A2aCCbd92BCA938b02010E17A5b8929b49130D")
    ]
  });
  if (staticEnvelopeRecovery.moduleCallSites !== params.transaction.referenceTopLevelOperations ||
      staticEnvelopeRecovery.zodiacCallsDecoded !== params.transaction.referenceTopLevelOperations ||
      staticEnvelopeRecovery.leafOperationsRecovered !== params.transaction.referenceLeafOperations) {
    throw new Error(`Static Safe/Zodiac envelope recovery does not match the research reference for ${params.transaction.transactionHash}: ${JSON.stringify(staticEnvelopeRecovery)}.`);
  }

  return {
    category: params.transaction.category,
    label: params.transaction.label,
    transactionHash: params.transaction.transactionHash,
    blockNumber: params.transaction.blockNumber.toString(),
    blockHash: block.hash,
    blockTimestamp: new Date(Number(block.timestamp) * 1000).toISOString(),
    receiptStatus: receipt.status,
    outerTarget: transaction.to,
    outerSelector: selectorOf(transaction.input),
    outerCalldataBytes: (transaction.input.length - 2) / 2,
    referenceTopLevelOperations: params.transaction.referenceTopLevelOperations,
    referenceLeafOperations: params.transaction.referenceLeafOperations,
    referenceSummary: params.transaction.referenceSummary,
    observedModuleEvents: moduleLogs.length,
    observedModules: [...new Set(moduleLogs.map(({ decoded }) => decoded.moduleAddress))],
    moduleOutcomes: moduleLogs.map(({ decoded }) => decoded.outcome),
    moduleEnabledBefore: enabledBefore,
    moduleEnabledAfter: enabledAfter,
    reconstructedOperations,
    reconstructedLeafOperations: scan.safeLeafOperationCount,
    undecodedOperations: undecodedAlerts.length,
    decodeFailureKinds: uniqueStrings(undecodedAlerts.flatMap((alert) => {
      const kind = alert.metadata.failureKind;
      return typeof kind === "string" ? [kind] : [];
    })),
    staticEnvelopeRecovery,
    administrativeEffects: uniqueStrings(administrativeEffects),
    eip1967SlotAlerts: alerts.filter((alert) => alert.ruleId === "PROXY_IMPLEMENTATION_SLOT_CHANGED" || alert.ruleId === "PROXY_ADMIN_CHANGED").length,
    correlationAlerts: alerts.filter((alert) => alert.ruleId.startsWith("SAFE_ADMINISTRATIVE_EFFECT_")).length,
    alertCount: alerts.length,
    alertsByRuleId: countBy(alerts, (alert) => alert.ruleId),
    alertsBySeverity: countBy(alerts, (alert) => alert.severity),
    alerts
  };
}

function summarizeProfile(profile: ProfileName, transactions: TransactionRun[]): ProfileRun {
  const referenceTopLevelOperations = sum(transactions, (transaction) => transaction.referenceTopLevelOperations);
  const reconstructedOperations = sum(transactions, (transaction) => transaction.reconstructedOperations);
  return {
    profile,
    metrics: {
      totalAlerts: sum(transactions, (transaction) => transaction.alertCount),
      infos: sum(transactions, (transaction) => transaction.alertsBySeverity.INFO ?? 0),
      warnings: sum(transactions, (transaction) => transaction.alertsBySeverity.WARNING ?? 0),
      criticals: sum(transactions, (transaction) => transaction.alertsBySeverity.CRITICAL ?? 0),
      moduleEvents: sum(transactions, (transaction) => transaction.observedModuleEvents),
      referenceTopLevelOperations,
      referenceLeafOperations: sum(transactions, (transaction) => transaction.referenceLeafOperations),
      reconstructedOperations,
      reconstructedLeafOperations: sum(transactions, (transaction) => transaction.reconstructedLeafOperations),
      reconstructionCoveragePercent: referenceTopLevelOperations === 0 ? 0 : Number((reconstructedOperations * 100 / referenceTopLevelOperations).toFixed(2)),
      staticallyRecoverableTopLevelOperations: sum(transactions, (transaction) => transaction.staticEnvelopeRecovery.zodiacCallsDecoded),
      staticRecoveryCoveragePercent: referenceTopLevelOperations === 0 ? 0 : Number((sum(transactions, (transaction) => transaction.staticEnvelopeRecovery.zodiacCallsDecoded) * 100 / referenceTopLevelOperations).toFixed(2)),
      undecodedOperations: sum(transactions, (transaction) => transaction.undecodedOperations),
      unknownModuleAlerts: sum(transactions, (transaction) => transaction.alertsByRuleId.SAFE_MODULE_UNKNOWN ?? 0),
      policyViolationAlerts: sum(transactions, (transaction) => transaction.alertsByRuleId.SAFE_MODULE_POLICY_VIOLATION ?? 0),
      correlations: sum(transactions, (transaction) => transaction.correlationAlerts),
      eip1967SlotAlerts: sum(transactions, (transaction) => transaction.eip1967SlotAlerts)
    },
    transactions
  };
}

function inspectStaticEnvelope(params: {
  transaction: RpcTransaction;
  managerSafe: Address;
  moduleAddress: Address;
  multiSendAddresses: readonly Address[];
}): TransactionRun["staticEnvelopeRecovery"] {
  const decodedManager = decodeSafeExecTransaction({ safeAddress: params.managerSafe, transaction: params.transaction });
  if (!decodedManager.decoded) {
    return { managerSafeDecoded: false, moduleCallSites: 0, zodiacCallsDecoded: 0, leafOperationsRecovered: 0, operations: [] };
  }
  const managerCall = decodedManager.transaction;
  const managerMultiSend = params.multiSendAddresses.some((address) => address.toLowerCase() === managerCall.innerTarget.toLowerCase());
  const callSites = managerCall.innerTarget.toLowerCase() === params.moduleAddress.toLowerCase()
    ? [{ path: "manager.direct", target: managerCall.innerTarget, data: managerCall.innerData }]
    : managerMultiSend && managerCall.innerSelector.toLowerCase() === MULTISEND_SELECTOR.toLowerCase()
      ? parseMultiSendPayload(decodeMultiSendCalldata(managerCall.innerData)).flatMap((operation) =>
          operation.target.toLowerCase() === params.moduleAddress.toLowerCase()
            ? [{ path: `manager.multisend.${operation.index}`, target: operation.target, data: operation.data }]
            : [])
      : [];

  const operations: TransactionRun["staticEnvelopeRecovery"]["operations"] = [];
  for (const callSite of callSites) {
    try {
      const decoded = decodeFunctionData({ abi: ZODIAC_ROLES_EXECUTION_ABI, data: callSite.data });
      const [target, value, data, operationValue] = decoded.args;
      const operation = operationValue === 0 ? "CALL" : operationValue === 1 ? "DELEGATECALL" : `INVALID_${operationValue}`;
      const nestedLeafOperations = params.multiSendAddresses.some((address) => address.toLowerCase() === getAddress(target).toLowerCase()) && selectorOf(data).toLowerCase() === MULTISEND_SELECTOR.toLowerCase()
        ? parseMultiSendPayload(decodeMultiSendCalldata(data)).length
        : 1;
      operations.push({
        path: callSite.path,
        target: getAddress(target),
        selector: selectorOf(data),
        operation,
        valueWei: value.toString(),
        nestedLeafOperations
      });
    } catch {
      // The calibration reports an undecoded call site below; it never substitutes guessed values.
    }
  }
  return {
    managerSafeDecoded: true,
    moduleCallSites: callSites.length,
    zodiacCallsDecoded: operations.length,
    leafOperationsRecovered: operations.reduce((total, operation) => total + operation.nestedLeafOperations, 0),
    operations
  };
}

async function calibrateBalCowZodiacPermissions(params: {
  rpc: PolicyRpcClient;
  definition: CalibrationDefinition;
  moduleAddress: Address;
  safeAddress: Address;
}) {
  const sample = params.definition.transactions.find((transaction) => transaction.transactionHash === BAL_COW_TRANSACTION_HASH);
  if (sample === undefined) throw new Error("BAL/CoW calibration transaction is missing from the case definition.");
  const transaction = await requireTransaction(params.rpc, sample.transactionHash);
  const manager = decodeSafeExecTransaction({ safeAddress: params.definition.expectedOuterManagerSafe, transaction });
  if (!manager.decoded || manager.transaction.innerTarget.toLowerCase() !== params.moduleAddress.toLowerCase()) {
    throw new Error("BAL/CoW transaction does not contain the expected direct Manager Safe to Zodiac Roles call.");
  }

  const decoded = decodeFunctionData({ abi: ZODIAC_ROLES_EXECUTION_ABI, data: manager.transaction.innerData });
  const [multiSendTargetRaw, multiSendValue, multiSendData, multiSendOperationRaw, roleKey, shouldRevert] = decoded.args;
  const multiSendTarget = getAddress(multiSendTargetRaw);
  const multiSendOperation = multiSendOperationRaw === 0 ? "CALL" : multiSendOperationRaw === 1 ? "DELEGATECALL" : undefined;
  if (multiSendOperation === undefined || roleKey.toLowerCase() !== params.definition.expectedRoleKey.toLowerCase()) {
    throw new Error("BAL/CoW transaction roleKey or outer operation differs from the expected verified envelope.");
  }
  if (selectorOf(multiSendData).toLowerCase() !== MULTISEND_SELECTOR.toLowerCase()) {
    throw new Error("BAL/CoW Zodiac operation does not invoke multiSend(bytes).");
  }
  const leaves = parseMultiSendPayload(decodeMultiSendCalldata(multiSendData));
  if (leaves.length !== 2) throw new Error(`BAL/CoW permission calibration expected two leaves, received ${leaves.length}.`);

  const unwrapper = await readZodiacTransactionUnwrapper({
    rpc: params.rpc,
    moduleAddress: params.moduleAddress,
    target: multiSendTarget,
    selector: MULTISEND_SELECTOR,
    blockNumber: sample.blockNumber
  });
  const multiSendPermission = await readZodiacRolePermission({
    rpc: params.rpc,
    moduleAddress: params.moduleAddress,
    roleKey,
    target: multiSendTarget,
    selector: MULTISEND_SELECTOR,
    blockNumber: sample.blockNumber
  });

  const observations = [];
  for (const leaf of leaves) {
    const permission = await readZodiacRolePermission({
      rpc: params.rpc,
      moduleAddress: params.moduleAddress,
      roleKey,
      target: leaf.target,
      selector: leaf.selector,
      blockNumber: sample.blockNumber
    });
    if (permission.status === "unsupported") {
      observations.push({
        path: leaf.index.toString(),
        target: leaf.target,
        selector: leaf.selector,
        operation: leaf.operation,
        valueWei: leaf.value.toString(),
        status: "unsupported",
        reason: permission.reason
      });
      continue;
    }
    const assessment = assessZodiacStructuralAuthorization(permission, leaf.operation, leaf.value);
    const matching = leaf.target.toLowerCase() === BAL_TOKEN.toLowerCase()
      ? matchBalApproveConditions(leaf.data, permission)
      : leaf.target.toLowerCase() === COW_ORDER_SIGNER.toLowerCase()
        ? matchCowOrderConditions(leaf.data, params.safeAddress, permission)
        : { coverage: "unsupported-leaf", matched: false };
    observations.push({
      path: leaf.index.toString(),
      target: leaf.target,
      selector: leaf.selector,
      operation: leaf.operation,
      valueWei: leaf.value.toString(),
      status: "observed",
      permission: serializePermission(permission),
      structuralAuthorization: assessment,
      executedArgumentEvidence: matching
    });
  }

  const unsupported = observations.filter((observation) => observation.status === "unsupported");
  return {
    status: unsupported.length === 0 ? "observed" : "partial",
    transactionHash: sample.transactionHash,
    blockNumber: sample.blockNumber.toString(),
    safe: params.safeAddress,
    module: params.moduleAddress,
    roleKey,
    roleName: decodeRoleKeyAscii(roleKey) ?? null,
    shouldRevert,
    supportedMastercopy: ZODIAC_ROLES_V2_MASTERCOPY_2_1,
    outerOperation: {
      target: multiSendTarget,
      selector: MULTISEND_SELECTOR,
      operation: multiSendOperation,
      valueWei: multiSendValue.toString(),
      directRolePermission: multiSendPermission.status === "observed" ? serializePermission(multiSendPermission) : multiSendPermission,
      configuredUnwrapper: unwrapper,
      expectedUnwrapper: ZODIAC_MULTI_SEND_UNWRAPPER_2_1,
      unwrapperMatched: unwrapper.toLowerCase() === ZODIAC_MULTI_SEND_UNWRAPPER_2_1.toLowerCase(),
      interpretation: "MultiSend is authorized through the configured transaction unwrapper; each decoded leaf remains subject to its own role permission."
    },
    leafOperations: observations,
    verificationBoundary: {
      structurallyVerified: observations.every((observation) => observation.status === "observed" && observation.structuralAuthorization?.structurallyAllowed === true),
      exactExecutedHashMembershipVerified: observations.every((observation) => observation.status === "observed" && observation.executedArgumentEvidence?.matched === true),
      fullGenericConditionEvaluation: false,
      fallback: "Condition bytecode is consumed and selected executed address hashes are matched; arbitrary Zodiac condition trees and non-reversible allowlist hashes remain explicitly unevaluated."
    },
    previousBalancedCriticalAssessment: [
      { ruleId: "SAFE_MULTISEND_EXECUTED", classification: "POLICY_CONFIGURATION_FALSE_POSITIVE", reason: "Summary inherited prohibited-leaf severity from a Onchain Radar policy that omitted role-authorized BAL/CoW leaves." },
      { ruleId: "SAFE_MULTISEND_SUBCALL", classification: "POLICY_CONFIGURATION_FALSE_POSITIVE", reason: "CoW delegatecall leaf was permitted by the role but absent from both Onchain Radar policy layers." },
      { ruleId: "SAFE_NESTED_DELEGATECALL", classification: "POLICY_CONFIGURATION_FALSE_POSITIVE", reason: "The role explicitly permits DELEGATECALL for the configured signOrder selector; visibility remains as WARNING after calibration." },
      { ruleId: "SAFE_MULTISEND_POLICY_VIOLATION", classification: "POLICY_CONFIGURATION_FALSE_POSITIVE", reason: "All reported leaf violations were omissions from the local policy, not violations of the on-chain role." },
      { ruleId: "SAFE_BATCH_ADMINISTRATIVE_ANOMALY", classification: "TRUE_SENSITIVITY_SIGNAL_NOT_INCIDENT", reason: "Max approval plus delegatecall is genuinely sensitive and remains observable, but the on-chain role authorized the exact execution." }
    ]
  };
}

function serializePermission(permission: Extract<ZodiacRolePermissionObservation, { status: "observed" }>) {
  return {
    mastercopy: permission.mastercopy,
    clearance: permission.clearance,
    targetExecutionOptions: permission.targetExecutionOptions,
    functionPermission: permission.functionPermission
  };
}

function matchBalApproveConditions(
  data: Hex,
  permission: Extract<ZodiacRolePermissionObservation, { status: "observed" }>
) {
  const decoded = decodeFunctionData({ abi: APPROVE_ABI, data });
  const [spender, amount] = decoded.args;
  const spenderHash = hashAbiEncodedAddress(getAddress(spender));
  const configuredHashes = comparisonHashes(permission);
  return {
    coverage: "executed-spender-hash",
    matched: getAddress(spender).toLowerCase() === GPV2_VAULT_RELAYER.toLowerCase() && configuredHashes.includes(spenderHash.toLowerCase()),
    spender: getAddress(spender),
    spenderHash,
    amount: amount.toString(),
    amountConstrainedByObservedTree: false,
    configuredAddressHashCount: configuredHashes.length
  };
}

function matchCowOrderConditions(
  data: Hex,
  safeAddress: Address,
  permission: Extract<ZodiacRolePermissionObservation, { status: "observed" }>
) {
  if (data.length < 10 + 64 * 3) throw new Error("CoW signOrder calldata is truncated before sellToken, buyToken and receiver.");
  const sellToken = calldataWordAddress(data, 0);
  const buyToken = calldataWordAddress(data, 1);
  const receiver = calldataWordAddress(data, 2);
  const configuredHashes = comparisonHashes(permission);
  const sellHash = hashAbiEncodedAddress(sellToken);
  const buyHash = hashAbiEncodedAddress(buyToken);
  return {
    coverage: "executed-order-token-hashes-and-avatar",
    matched: sellToken.toLowerCase() === BAL_TOKEN.toLowerCase() &&
      buyToken.toLowerCase() === USDC_TOKEN.toLowerCase() &&
      receiver.toLowerCase() === safeAddress.toLowerCase() &&
      configuredHashes.includes(sellHash.toLowerCase()) &&
      configuredHashes.includes(buyHash.toLowerCase()) &&
      permission.functionPermission.conditions.some((condition) => condition.operator === "EQUAL_TO_AVATAR"),
    sellToken,
    sellTokenHash: sellHash,
    buyToken,
    buyTokenHash: buyHash,
    receiver,
    receiverMatchesAvatar: receiver.toLowerCase() === safeAddress.toLowerCase(),
    constrainedFieldsObserved: ["sellToken", "buyToken", "receiver"],
    fieldsNotConstrainedByObservedTree: ["sellAmount", "buyAmount", "validTo", "appData", "feeAmount", "kind", "partiallyFillable", "sellTokenBalance", "buyTokenBalance", "validDuration", "feeAmountBP"],
    configuredAddressHashCount: configuredHashes.length
  };
}

function calldataWordAddress(data: Hex, wordIndex: number): Address {
  const start = 10 + wordIndex * 64;
  const word = data.slice(start, start + 64);
  if (word.length !== 64) throw new Error(`Calldata word ${wordIndex} is truncated.`);
  return getAddress(`0x${word.slice(24)}`);
}

function comparisonHashes(permission: Extract<ZodiacRolePermissionObservation, { status: "observed" }>): string[] {
  return permission.functionPermission.conditions.flatMap((condition) =>
    condition.comparisonHash === undefined ? [] : [condition.comparisonHash.toLowerCase()]);
}

async function verifyIdentity(params: {
  rpcUrl: string;
  timeoutMs: number;
  blockNumber: bigint;
  safeAddress: Address;
  moduleAddress: Address;
  definition: CalibrationDefinition;
}) {
  const client = createPublicClient({ chain: mainnet, transport: http(params.rpcUrl, { timeout: params.timeoutMs }) });
  const chainId = await client.getChainId();
  if (chainId !== 1) throw new Error(`Expected Ethereum chain ID 1, received ${chainId}.`);
  const [safeCode, managerSafeCode, moduleCode, avatar, target, owner] = await Promise.all([
    client.getCode({ address: params.safeAddress, blockNumber: params.blockNumber }),
    client.getCode({ address: params.definition.expectedOuterManagerSafe, blockNumber: params.blockNumber }),
    client.getCode({ address: params.moduleAddress, blockNumber: params.blockNumber }),
    client.readContract({ address: params.moduleAddress, abi: ROLES_IDENTITY_ABI, functionName: "avatar", blockNumber: params.blockNumber }),
    client.readContract({ address: params.moduleAddress, abi: ROLES_IDENTITY_ABI, functionName: "target", blockNumber: params.blockNumber }),
    client.readContract({ address: params.moduleAddress, abi: ROLES_IDENTITY_ABI, functionName: "owner", blockNumber: params.blockNumber })
  ]);
  if (safeCode === undefined || safeCode === "0x" || managerSafeCode === undefined || managerSafeCode === "0x" || moduleCode === undefined || moduleCode === "0x") {
    throw new Error("Endowment Safe, manager Safe or module had no bytecode at the first calibration block.");
  }
  const observed = { avatar: getAddress(avatar), target: getAddress(target), owner: getAddress(owner) };
  if (observed.avatar.toLowerCase() !== params.definition.expectedModuleAvatar.toLowerCase() ||
      observed.target.toLowerCase() !== params.definition.expectedModuleTarget.toLowerCase() ||
      observed.owner.toLowerCase() !== params.definition.expectedModuleOwner.toLowerCase()) {
    throw new Error("Roles Modifier avatar/target/owner identity does not match calibration evidence.");
  }
  return {
    chainId,
    verificationBlock: params.blockNumber.toString(),
    safeCodeBytes: (safeCode.length - 2) / 2,
    managerSafeAddress: params.definition.expectedOuterManagerSafe,
    managerSafeCodeBytes: (managerSafeCode.length - 2) / 2,
    moduleCodeBytes: (moduleCode.length - 2) / 2,
    ...observed
  };
}

async function regenerateProfile(params: {
  rpc: PolicyRpcClient;
  config: MonitorConfig;
  definition: CalibrationDefinition;
  safeAddress: Address;
  moduleAddress: Address;
}): Promise<TransactionRun[]> {
  const transactions: TransactionRun[] = [];
  for (const transaction of params.definition.transactions) {
    transactions.push(await runTransaction({ ...params, transaction }));
  }
  return transactions;
}

function verifyReplay(
  baselineAlerts: readonly Alert[],
  replayAlerts: readonly Alert[],
  transactions: readonly TransactionRun[],
  recordedAt: string
) {
  const baselineIds = baselineAlerts.map((alert) => alert.id);
  const replayIds = replayAlerts.map((alert) => alert.id);
  const stableIds = baselineIds.length === new Set(baselineIds).size &&
    baselineIds.length === replayIds.length && baselineIds.every((id, index) => id === replayIds[index]);
  if (!stableIds) throw new Error("Calibration replay changed alert IDs or order.");
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-module-calibration-"));
  try {
    const journal = new AlertJournal(join(directory, "journal.jsonl"));
    journal.append(baselineAlerts, new Map(transactions.map((transaction) => [transaction.blockNumber, transaction.blockHash])), recordedAt);
    return {
      stableIds,
      regeneratedAlertCount: replayAlerts.length,
      duplicateAlertsAfterJournalReload: new AlertJournal(join(directory, "journal.jsonl")).filterNew(replayAlerts).length
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function configForProfile(rawConfig: Record<string, unknown>, profile: Record<string, unknown>): MonitorConfig {
  const copy = structuredClone(rawConfig);
  const administrative = requireRecord(copy.administrativeMonitoring, "administrativeMonitoring");
  if (!Array.isArray(administrative.multisigs) || administrative.multisigs.length !== 1) {
    throw new Error("Calibration requires one administrativeMonitoring.multisigs entry.");
  }
  administrative.multisigs[0] = {
    ...requireRecord(administrative.multisigs[0], "administrativeMonitoring.multisigs[0]"),
    ...structuredClone(profile)
  };
  return parseMonitorConfig(copy);
}

function parseDefinition(value: unknown): CalibrationDefinition {
  const raw = requireRecord(value, "_calibration");
  const profiles = requireRecord(raw.profiles, "_calibration.profiles");
  if (!Array.isArray(raw.transactions) || raw.transactions.length < 3) {
    throw new Error("_calibration.transactions must contain at least three transactions.");
  }
  return {
    caseId: nonEmpty(raw.caseId, "_calibration.caseId"),
    fixedCreatedAt: isoTimestamp(raw.fixedCreatedAt, "_calibration.fixedCreatedAt"),
    baselineProfile: profileName(raw.baselineProfile, "_calibration.baselineProfile"),
    recommendedProfile: profileName(raw.recommendedProfile, "_calibration.recommendedProfile"),
    expectedSafeSingleton: address(raw.expectedSafeSingleton, "_calibration.expectedSafeSingleton"),
    expectedModuleAvatar: address(raw.expectedModuleAvatar, "_calibration.expectedModuleAvatar"),
    expectedModuleTarget: address(raw.expectedModuleTarget, "_calibration.expectedModuleTarget"),
    expectedModuleOwner: address(raw.expectedModuleOwner, "_calibration.expectedModuleOwner"),
    expectedOuterManagerSafe: address(raw.expectedOuterManagerSafe, "_calibration.expectedOuterManagerSafe"),
    expectedRoleKey: bytes32(raw.expectedRoleKey, "_calibration.expectedRoleKey"),
    rpcMaxBlockRange: positiveBigInt(raw.rpcMaxBlockRange, "_calibration.rpcMaxBlockRange"),
    outputFile: nonEmpty(raw.outputFile, "_calibration.outputFile"),
    permissionOutputFile: nonEmpty(raw.permissionOutputFile, "_calibration.permissionOutputFile"),
    resultsFile: nonEmpty(raw.resultsFile, "_calibration.resultsFile"),
    transactions: raw.transactions.map((entry, index) => transaction(entry, index)),
    profiles: Object.fromEntries(PROFILE_NAMES.map((name) => [name, requireRecord(profiles[name], `_calibration.profiles.${name}`)])) as Record<ProfileName, Record<string, unknown>>
  };
}

function transaction(value: unknown, index: number): CalibrationTransaction {
  const raw = requireRecord(value, `_calibration.transactions[${index}]`);
  const hash = nonEmpty(raw.transactionHash, `_calibration.transactions[${index}].transactionHash`);
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new Error(`Invalid transaction hash at index ${index}.`);
  return {
    category: nonEmpty(raw.category, `_calibration.transactions[${index}].category`),
    label: nonEmpty(raw.label, `_calibration.transactions[${index}].label`),
    transactionHash: hash.toLowerCase() as Hex,
    blockNumber: positiveBigInt(raw.blockNumber, `_calibration.transactions[${index}].blockNumber`),
    referenceTopLevelOperations: positiveInteger(raw.referenceTopLevelOperations, `_calibration.transactions[${index}].referenceTopLevelOperations`),
    referenceLeafOperations: positiveInteger(raw.referenceLeafOperations, `_calibration.transactions[${index}].referenceLeafOperations`),
    referenceSummary: nonEmpty(raw.referenceSummary, `_calibration.transactions[${index}].referenceSummary`)
  };
}

function countingProvider(provider: RawRpcProvider, counters: RpcCounters): RawRpcProvider {
  return {
    async getLogs(request) { counters.logRequests += 1; return provider.getLogs(request); },
    async getStorageAt(request) { counters.storageRequests += 1; return provider.getStorageAt(request); },
    async getCode(request) { counters.codeRequests += 1; if (provider.getCode === undefined) throw new Error("getCode unavailable"); return provider.getCode(request); },
    async getErc20Balance(request) { counters.balanceRequests += 1; return provider.getErc20Balance(request); },
    async getBlockNumber() { counters.blockRequests += 1; if (provider.getBlockNumber === undefined) throw new Error("getBlockNumber unavailable"); return provider.getBlockNumber(); },
    async getBlock(blockNumber) { counters.blockRequests += 1; if (provider.getBlock === undefined) throw new Error("getBlock unavailable"); return provider.getBlock(blockNumber); },
    async getTransaction(hash) { counters.transactionRequests += 1; if (provider.getTransaction === undefined) throw new Error("getTransaction unavailable"); return provider.getTransaction(hash); },
    async getTransactionReceipt(hash) { counters.receiptRequests += 1; if (provider.getTransactionReceipt === undefined) throw new Error("getTransactionReceipt unavailable"); return provider.getTransactionReceipt(hash); },
    async getSafeThreshold(request) { counters.safeStateRequests += 1; if (provider.getSafeThreshold === undefined) throw new Error("getSafeThreshold unavailable"); return provider.getSafeThreshold(request); },
    async isSafeOwner(request) { counters.safeStateRequests += 1; if (provider.isSafeOwner === undefined) throw new Error("isSafeOwner unavailable"); return provider.isSafeOwner(request); },
    async isSafeModuleEnabled(request) { counters.safeStateRequests += 1; if (provider.isSafeModuleEnabled === undefined) throw new Error("isModuleEnabled unavailable"); return provider.isSafeModuleEnabled(request); }
  };
}

async function requireTransaction(rpc: PolicyRpcClient, hash: Hex): Promise<RpcTransaction> {
  if (rpc.getTransaction === undefined) throw new Error("getTransaction unavailable");
  return rpc.getTransaction(hash);
}

async function requireReceipt(rpc: PolicyRpcClient, hash: Hex): Promise<RpcTransactionReceipt> {
  if (rpc.getTransactionReceipt === undefined) throw new Error("getTransactionReceipt unavailable");
  return rpc.getTransactionReceipt(hash);
}

async function requireBlock(rpc: PolicyRpcClient, number: bigint): Promise<RpcBlock> {
  if (rpc.getBlock === undefined) throw new Error("getBlock unavailable");
  return rpc.getBlock(number);
}

function requireProfile(runs: readonly ProfileRun[], name: ProfileName): ProfileRun {
  const run = runs.find((candidate) => candidate.profile === name);
  if (run === undefined) throw new Error(`Profile ${name} was not produced.`);
  return run;
}

function deduplicateAlerts(alerts: readonly Alert[]): Alert[] {
  const seen = new Set<string>();
  return alerts.filter((alert) => !seen.has(alert.id) && (seen.add(alert.id), true));
}

function countBy<T>(values: readonly T[], key: (value: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[key(value)] = (counts[key(value)] ?? 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function sum<T>(values: readonly T[], read: (value: T) => number): number {
  return values.reduce((total, value) => total + read(value), 0);
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function emptyCounters(): RpcCounters {
  return { logRequests: 0, storageRequests: 0, balanceRequests: 0, blockRequests: 0, transactionRequests: 0, receiptRequests: 0, safeStateRequests: 0, codeRequests: 0 };
}

function parseJsonObject(contents: string, field: string): Record<string, unknown> {
  try { return requireRecord(JSON.parse(contents) as unknown, field); }
  catch (error) { throw new Error(`Invalid JSON in ${field}.`, { cause: error }); }
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${field} must be an object.`);
  return value as Record<string, unknown>;
}

function nonEmpty(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${field} must be a non-empty string.`);
  return value;
}

function isoTimestamp(value: unknown, field: string): string {
  const result = nonEmpty(value, field);
  if (Number.isNaN(Date.parse(result))) throw new Error(`${field} must be an ISO timestamp.`);
  return result;
}

function profileName(value: unknown, field: string): ProfileName {
  if (typeof value !== "string" || !PROFILE_NAMES.includes(value as ProfileName)) throw new Error(`${field} must be strict, balanced or permissive.`);
  return value as ProfileName;
}

function address(value: unknown, field: string): Address {
  if (typeof value !== "string" || !isAddress(value)) throw new Error(`${field} must be an address.`);
  return getAddress(value);
}

function bytes32(value: unknown, field: string): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`${field} must be exactly 32 bytes.`);
  return value.toLowerCase() as Hex;
}

function positiveBigInt(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value) || BigInt(value) <= 0n) throw new Error(`${field} must be a positive integer string.`);
  return BigInt(value);
}

function positiveInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value) || (value as number) <= 0) throw new Error(`${field} must be a positive integer.`);
  return value as number;
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
  process.exitCode = 1;
});
