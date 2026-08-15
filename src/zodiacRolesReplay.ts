import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  concatHex,
  encodeFunctionData,
  getAddress,
  numberToHex,
  size,
  type Address,
  type Hex
} from "viem";
import { AlertJournal } from "./alertJournal.js";
import type { Alert, RawLogForAlert } from "./alerts.js";
import { buildEventTopicMap } from "./events.js";
import { processLogs } from "./processor.js";
import type { RpcClient } from "./rpc.js";
import { SAFE_ACTION_SELECTORS } from "./safe/actions.js";
import { analyzeSafeTransactions } from "./safe/analyzer.js";
import { SAFE_EXEC_TRANSACTION_ABI } from "./safe/decoder.js";
import { SAFE_MODULE_EXECUTION_EVENT_SIGNATURES } from "./safe/module.js";
import { MULTISEND_ABI, MULTISEND_SELECTOR } from "./safe/multisend.js";
import type { AdministrativeMonitoringConfig, SafeOperation } from "./safe/types.js";
import { ZODIAC_ROLES_EXECUTION_ABI } from "./safe/zodiacRoles.js";

const SAFE = getAddress("0x1000000000000000000000000000000000000001");
const MANAGER = getAddress("0x2000000000000000000000000000000000000002");
const MODULE = getAddress("0x3000000000000000000000000000000000000003");
const TARGET = getAddress("0x4000000000000000000000000000000000000004");
const IMPLEMENTATION = getAddress("0x5000000000000000000000000000000000000005");
const MANAGER_MULTISEND = getAddress("0x6000000000000000000000000000000000000006");
const MODULE_MULTISEND = getAddress("0x7000000000000000000000000000000000000007");
const UNKNOWN_MANAGER = getAddress("0x8000000000000000000000000000000000000008");
const ZERO = getAddress("0x0000000000000000000000000000000000000000");
const ROLE_A = `0x${"11".repeat(32)}` as Hex;
const ROLE_B = `0x${"22".repeat(32)}` as Hex;
const HASH_A = `0x${"aa".repeat(32)}` as Hex;
const HASH_B = `0x${"bb".repeat(32)}` as Hex;
const HASH_C = `0x${"cc".repeat(32)}` as Hex;
const BLOCK_HASH = `0x${"dd".repeat(32)}` as Hex;
const CREATED_AT = "2026-08-02T00:00:00.000Z";

async function main(): Promise<void> {
  const direct = await run({
    hash: HASH_A,
    outerTarget: MANAGER,
    input: managerInput(MODULE, zodiacData(TARGET, transferData(), "CALL", ROLE_A)),
    logs: [moduleLog(HASH_A, 2)]
  });

  const nestedMultiSend = multiSendData([
    pack({ target: TARGET, data: transferData() })
  ]);
  const composed = await run({
    hash: HASH_B,
    outerTarget: MANAGER,
    input: managerInput(MANAGER_MULTISEND, multiSendData([
      pack({ target: MODULE, data: zodiacData(TARGET, transferData(), "CALL", ROLE_A) }),
      pack({ target: MODULE, data: zodiacData(MODULE_MULTISEND, nestedMultiSend, "DELEGATECALL", ROLE_B) })
    ]), "DELEGATECALL"),
    logs: [moduleLog(HASH_B, 2), moduleLog(HASH_B, 3)]
  });

  const upgradeAlerts = processLogs({
    chain: "ethereum",
    logs: [upgradedLog(HASH_C)],
    topicMap: buildEventTopicMap(["Upgraded(address)"]),
    allowlists: { knownActors: [], knownAdmins: [], knownImplementations: [], knownGovernanceContracts: [], knownProxyAddresses: [] },
    clock: () => CREATED_AT
  }).alerts;
  const correlated = await run({
    hash: HASH_C,
    outerTarget: MANAGER,
    input: managerInput(MODULE, zodiacData(TARGET, upgradeData(), "CALL", ROLE_A)),
    logs: [moduleLog(HASH_C, 2)],
    administrativeAlerts: upgradeAlerts
  });
  const unknown = await run({
    hash: `0x${"ee".repeat(32)}` as Hex,
    outerTarget: UNKNOWN_MANAGER,
    input: managerInput(MODULE, zodiacData()),
    logs: [moduleLog(`0x${"ee".repeat(32)}` as Hex, 2)]
  });

  const all = [...direct.alerts, ...composed.alerts, ...correlated.alerts, ...unknown.alerts];
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-zodiac-replay-"));
  const journalPath = join(directory, "journal.jsonl");
  new AlertJournal(journalPath).append(all, new Map([["100", BLOCK_HASH]]), CREATED_AT);
  const duplicates = new AlertJournal(journalPath).filterNew(all).length;

  const composedExecuted = composed.outerTransactionAlerts.filter((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_EXECUTED");
  const roles = composedExecuted.map((alert) =>
    ((alert.metadata.zodiacRoles as Record<string, unknown>).roleKey as string));
  console.log("Zodiac Roles v2 offline replay (synthetic fixture; bounded calldata only, no traces or human-intent inference)");
  console.log(`Manager Safe direct: reconstructed=${direct.reconstructedCount}; role=${roleOf(direct.alerts)}`);
  console.log(`Manager Safe MultiSend: reconstructed=${composed.reconstructedCount}; orderedRoles=${roles.join(",")}`);
  console.log(`module-initiated MultiSend: leaves=${composed.multiSendContexts.flatMap((context) => context.operations).length}; rules=${rules(composed.multisendAlerts)}`);
  console.log(`confirmed upgrade effect: ${rules(correlated.correlationAlerts)}`);
  console.log(`unknown Manager wrapper: undecoded=${unknown.undecodedCount}; rules=${rules(unknown.outerTransactionAlerts)}`);
  console.log("restart: durable journal restored");
  console.log(`replay: ${duplicates} duplicate alerts emitted`);

  if (direct.reconstructedCount !== 1 || composed.reconstructedCount !== 2) throw new Error("Zodiac replay reconstruction count changed.");
  if (roles[0] !== ROLE_A || roles[1] !== ROLE_B) throw new Error("Zodiac replay role ordering changed.");
  if (!composed.multisendAlerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_EXECUTED")) throw new Error("Zodiac replay lost MultiSend expansion.");
  if (!correlated.correlationAlerts.some((alert) => alert.ruleId === "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED")) throw new Error("Zodiac replay lost administrative correlation.");
  if (!unknown.outerTransactionAlerts.some((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_UNDECODED")) throw new Error("Unknown wrapper was not explicit.");
  if (duplicates !== 0) throw new Error("Zodiac replay emitted duplicate alerts after journal reload.");
}

async function run(params: {
  hash: Hex;
  outerTarget: Address;
  input: Hex;
  logs: RawLogForAlert[];
  administrativeAlerts?: Alert[];
}) {
  const rpc: RpcClient = {
    async getLogs() { return []; },
    async getStorageAt() { return undefined; },
    async getErc20Balance() { return 0n; },
    async getTransaction() { return { hash: params.hash, to: params.outerTarget, input: params.input, value: 0n, blockNumber: 100n }; },
    async getTransactionReceipt() { return { transactionHash: params.hash, blockNumber: 100n, blockHash: BLOCK_HASH, status: "success", logs: [] }; },
    async isSafeModuleEnabled() { return true; }
  };
  return analyzeSafeTransactions({
    rpc,
    chain: "ethereum",
    config: config(),
    executionLogs: params.logs,
    administrativeAlerts: params.administrativeAlerts ?? [],
    slotAlerts: [],
    clock: () => CREATED_AT
  });
}

function config(): AdministrativeMonitoringConfig {
  const selectors = [
    SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!,
    SAFE_ACTION_SELECTORS["upgradeTo(address)"]!,
    MULTISEND_SELECTOR
  ];
  const targets = [TARGET, MODULE_MULTISEND];
  return {
    multisigs: [{
      name: "Synthetic Safe", address: SAFE, criticality: "critical",
      allowedTargets: targets, allowedSelectors: selectors, allowedOperations: ["CALL", "DELEGATECALL"],
      allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: 0n,
      allowedOwners: [], allowedThresholds: [], allowedModules: [MODULE], allowedGuards: [], allowedFallbackHandlers: [],
      multisendAlertDetail: "sensitive-only",
      financialOperationPolicy: { emitAllowedTransfers: false, emitAllowedApprovals: false, maxNativeValueWei: 0n, notableTokenTargets: [] },
      modulePolicies: [{
        name: "Synthetic Zodiac Roles v2", address: MODULE,
        allowedTargets: targets, allowedSelectors: selectors, allowedOperations: ["CALL", "DELEGATECALL"],
        allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: 0n,
        adapter: { type: "ZODIAC_ROLES_V2", managerSafes: [MANAGER] }
      }]
    }],
    multisendContracts: [
      { name: "Manager MultiSendCallOnly", address: MANAGER_MULTISEND, mode: "CALL_ONLY" },
      { name: "Module MultiSend", address: MODULE_MULTISEND, mode: "MULTISEND" }
    ],
    multisendLimits: { maxDepth: 2, maxSuboperations: 20, maxTotalPayloadBytes: 20_000, maxSuboperationDataBytes: 5_000 }
  };
}

function zodiacData(
  target: Address = TARGET,
  data: Hex = transferData(),
  operation: SafeOperation = "CALL",
  roleKey: Hex = ROLE_A
): Hex {
  return encodeFunctionData({
    abi: ZODIAC_ROLES_EXECUTION_ABI,
    functionName: "execTransactionWithRole",
    args: [target, 0n, data, operation === "CALL" ? 0 : 1, roleKey, true]
  });
}

function managerInput(target: Address, data: Hex, operation: SafeOperation = "CALL"): Hex {
  return encodeFunctionData({
    abi: SAFE_EXEC_TRANSACTION_ABI,
    functionName: "execTransaction",
    args: [target, 0n, data, operation === "CALL" ? 0 : 1, 0n, 0n, 0n, ZERO, ZERO, "0x"]
  });
}

function multiSendData(operations: readonly Hex[]): Hex {
  return encodeFunctionData({ abi: MULTISEND_ABI, functionName: "multiSend", args: [concatHex(operations)] });
}

function pack(params: { target: Address; data: Hex; operation?: SafeOperation }): Hex {
  return concatHex([
    numberToHex(params.operation === "DELEGATECALL" ? 1 : 0, { size: 1 }),
    params.target,
    numberToHex(0n, { size: 32 }),
    numberToHex(BigInt(size(params.data)), { size: 32 }),
    params.data
  ]);
}

function transferData(): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] }],
    functionName: "transfer", args: [TARGET, 1n]
  });
}

function upgradeData(): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "upgradeTo", stateMutability: "nonpayable", inputs: [{ name: "implementation", type: "address" }], outputs: [] }],
    functionName: "upgradeTo", args: [IMPLEMENTATION]
  });
}

function moduleLog(hash: Hex, logIndex: number): RawLogForAlert {
  const topic = [...buildEventTopicMap([SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[0]]).keys()][0]!;
  return { blockNumber: "0x64", transactionHash: hash, transactionIndex: "0x1", logIndex: numberToHex(logIndex), address: SAFE,
    topics: [topic, `0x${"0".repeat(24)}${MODULE.slice(2).toLowerCase()}` as Hex], data: "0x" };
}

function upgradedLog(hash: Hex): RawLogForAlert {
  const topic = [...buildEventTopicMap(["Upgraded(address)"]).keys()][0]!;
  return { blockNumber: "0x64", transactionHash: hash, transactionIndex: "0x1", logIndex: "0x1", address: TARGET,
    topics: [topic, `0x${"0".repeat(24)}${IMPLEMENTATION.slice(2).toLowerCase()}` as Hex], data: "0x" };
}

function rules(alerts: readonly Alert[]): string { return alerts.map((alert) => alert.ruleId).join(", "); }
function roleOf(alerts: readonly Alert[]): string {
  const executed = alerts.find((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_EXECUTED");
  return ((executed?.metadata.zodiacRoles as Record<string, unknown> | undefined)?.roleKey as string | undefined) ?? "missing";
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
