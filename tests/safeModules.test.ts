import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { encodeFunctionData, getAddress, numberToHex, type Address, type Hex } from "viem";
import { AlertJournal } from "../src/alertJournal.js";
import { loadCheckpoint, writeCheckpoint } from "../src/checkpoint.js";
import type { MonitorConfig } from "../src/config.js";
import { runLiveCycle } from "../src/liveScanner.js";
import { createEip1967SlotChangeAlertFromValues, EIP1967_IMPLEMENTATION_SLOT } from "../src/eip1967.js";
import { processLogs } from "../src/processor.js";
import { buildEventTopicMap } from "../src/events.js";
import { analyzeSafeTransactions, SAFE_MONITORING_EVENT_SIGNATURES } from "../src/safe/analyzer.js";
import {
  decodeSafeModuleExecutionEvent,
  decodeSafeModuleTransaction,
  SAFE_EXEC_FROM_MODULE_RETURN_DATA_SELECTOR,
  SAFE_EXEC_FROM_MODULE_SELECTOR,
  SAFE_MODULE_EXECUTION_ABI,
  SAFE_MODULE_EXECUTION_EVENT_SIGNATURES
} from "../src/safe/module.js";
import type { AdministrativeMonitoringConfig, SafeModulePolicyConfig } from "../src/safe/types.js";
import type { RawLogForAlert } from "../src/alerts.js";
import type { LiveRpcClient, RpcClient } from "../src/rpc.js";
import { addressToStorageWord, emptyAllowlists, FIXED_CREATED_AT } from "./fixtures.js";
import {
  BLOCK_HASH,
  IMPLEMENTATION,
  SAFE,
  SAFE_TX_HASH,
  TARGET,
  UNKNOWN_IMPLEMENTATION,
  UNKNOWN_TARGET,
  rpcReceipt,
  safePolicy,
  upgradedLog
} from "./safeFixtures.js";
import { MULTISEND, administrativeMultiSendConfig, multiSendData, packSuboperation } from "./multisendFixtures.js";
import { SAFE_ACTION_SELECTORS } from "../src/safe/actions.js";

const MODULE = getAddress("0x9000000000000000000000000000000000000009");
const UNKNOWN_MODULE = getAddress("0x9100000000000000000000000000000000000009");

describe("Safe module event and calldata decoding", () => {
  test("decodes success/failure events and produces stable first-class event rules", () => {
    const logs = [moduleLog("success", MODULE, 2), moduleLog("failure", MODULE, 3)];
    assert.deepEqual(logs.map(decodeSafeModuleExecutionEvent).map((event) => event?.outcome), ["success", "failure"]);
    const first = processLogs({ chain: "ethereum", logs, topicMap: buildEventTopicMap([...SAFE_MODULE_EXECUTION_EVENT_SIGNATURES]), allowlists: emptyAllowlists(), clock: () => FIXED_CREATED_AT });
    const replay = processLogs({ chain: "ethereum", logs, topicMap: buildEventTopicMap([...SAFE_MODULE_EXECUTION_EVENT_SIGNATURES]), allowlists: emptyAllowlists(), clock: () => "2030-01-01T00:00:00.000Z" });
    assert.deepEqual(first.alerts.map((alert) => alert.ruleId), ["SAFE_MODULE_EXECUTION_SUCCESS", "SAFE_MODULE_EXECUTION_FAILURE"]);
    assert.deepEqual(first.alerts.map((alert) => alert.id), replay.alerts.map((alert) => alert.id));
    assert.equal((first.alerts[0]?.metadata.decoded as Record<string, unknown>).module, MODULE);
  });

  test("reconstructs both standard module entrypoints with CALL and DELEGATECALL", () => {
    const direct = decode(SAFE_EXEC_FROM_MODULE_SELECTOR, moduleInput("execTransactionFromModule", TARGET, 4n, "0x12345678", 0));
    const returnData = decode(SAFE_EXEC_FROM_MODULE_RETURN_DATA_SELECTOR, moduleInput("execTransactionFromModuleReturnData", TARGET, 5n, "0x", 1));
    assert.ok(direct.decoded && returnData.decoded);
    if (!direct.decoded || !returnData.decoded) throw new Error("module fixtures did not decode");
    assert.equal(direct.moduleTransaction.transaction.operation, "CALL");
    assert.equal(direct.moduleTransaction.transaction.innerValue, 4n);
    assert.equal(returnData.moduleTransaction.transaction.operation, "DELEGATECALL");
    assert.equal(returnData.moduleTransaction.entrypoint, "execTransactionFromModuleReturnData");
  });

  test("distinguishes unsupported, malformed, invalid-operation and ambiguous calldata", () => {
    const unsupported = decode("0x12345678", "0x12345678");
    const malformed = decode(SAFE_EXEC_FROM_MODULE_SELECTOR, SAFE_EXEC_FROM_MODULE_SELECTOR);
    const invalid = decode(SAFE_EXEC_FROM_MODULE_SELECTOR, moduleInput("execTransactionFromModule", TARGET, 0n, "0x", 2));
    const ambiguous = decode(SAFE_EXEC_FROM_MODULE_SELECTOR, moduleInput("execTransactionFromModule", TARGET, 0n, "0x", 0), 2);
    assert.deepEqual([unsupported, malformed, invalid, ambiguous].map((result) => result.decoded ? "decoded" : result.failureKind), [
      "UNSUPPORTED_OUTER_SELECTOR", "MALFORMED_CALLDATA", "UNSUPPORTED_OPERATION", "AMBIGUOUS_MULTIPLE_MODULE_EXECUTIONS"
    ]);
  });
});

describe("Safe module analysis, policy, MultiSend and correlation", () => {
  test("applies Safe/module policy intersection and confirms enabled state", async () => {
    const input = moduleInput("execTransactionFromModule", TARGET, 0n, transferData(), 0);
    const result = await analyze(input);
    assert.ok(result.outerTransactionAlerts.some((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_EXECUTED" && alert.severity === "INFO"));
    assert.ok(!result.outerTransactionAlerts.some((alert) => alert.ruleId === "SAFE_MODULE_POLICY_VIOLATION"));
    const metadata = result.outerTransactionAlerts.find((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_EXECUTED")?.metadata;
    assert.equal((metadata?.enabledState as Record<string, unknown>).enabledAtExecution, true);
  });

  test("detects unknown/disabled modules and undecodable indirect executions", async () => {
    const result = await analyze("0x12345678", { module: UNKNOWN_MODULE, enabled: false, modulePolicies: [] });
    assert.deepEqual(result.outerTransactionAlerts.map((alert) => alert.ruleId), [
      "SAFE_MODULE_UNKNOWN", "SAFE_MODULE_DISABLED_EXECUTOR", "SAFE_MODULE_TRANSACTION_UNDECODED"
    ]);
    assert.equal(result.outerTransactionAlerts[0]?.severity, "CRITICAL");
  });

  test("a module-specific policy cannot override Safe allowedModules", async () => {
    const config = moduleConfig();
    config.multisigs[0]!.allowedModules = [];
    const result = await analyze(moduleInput("execTransactionFromModule", TARGET, 0n, transferData(), 0), { config });
    const violation = result.outerTransactionAlerts.find((alert) => alert.ruleId === "SAFE_MODULE_POLICY_VIOLATION");
    assert.ok(violation);
    const violations = violation.metadata.violations as Array<Record<string, unknown>>;
    assert.ok(violations.some((entry) => entry.kind === "module" && entry.scope === "safe"));
  });

  test("detects delegatecall, prohibited target/selector and unknown implementation", async () => {
    const input = moduleInput("execTransactionFromModule", UNKNOWN_TARGET, 0n, upgradeData(UNKNOWN_IMPLEMENTATION), 1);
    const config = moduleConfig();
    config.multisigs[0]!.allowedSelectors = [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!];
    config.multisigs[0]!.modulePolicies[0]!.allowedSelectors = [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!];
    const result = await analyze(input, { config });
    const ids = result.outerTransactionAlerts.map((alert) => alert.ruleId);
    assert.ok(ids.includes("SAFE_MODULE_UNKNOWN_TARGET"));
    assert.ok(ids.includes("SAFE_MODULE_UNKNOWN_SELECTOR"));
    assert.ok(ids.includes("SAFE_MODULE_DELEGATECALL"));
    assert.ok(ids.includes("SAFE_MODULE_UNKNOWN_IMPLEMENTATION_UPGRADE"));
    assert.ok(ids.includes("SAFE_MODULE_POLICY_VIOLATION"));
  });

  test("reuses bounded MultiSend expansion under the intersected module policy", async () => {
    const config = moduleConfig();
    config.multisendContracts = administrativeMultiSendConfig().multisendContracts;
    config.multisendLimits = administrativeMultiSendConfig().multisendLimits;
    const modulePolicy = config.multisigs[0]!.modulePolicies[0]!;
    modulePolicy.allowedTargets = [MULTISEND, TARGET];
    modulePolicy.allowedSelectors = [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!];
    config.multisigs[0]!.allowedTargets = [MULTISEND, TARGET];
    config.multisigs[0]!.allowedSelectors = [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!];
    const input = moduleInput("execTransactionFromModule", MULTISEND, 0n, multiSendData([packSuboperation({ target: TARGET, data: transferData() })]), 0);
    const result = await analyze(input, { config });
    assert.ok(result.multisendAlerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_EXECUTED"));
    assert.ok(result.multisendAlerts.every((alert) => alert.id.includes(MODULE)));
  });

  test("correlates a module upgrade with the matching administrative effect", async () => {
    const input = moduleInput("execTransactionFromModule", TARGET, 0n, upgradeData(IMPLEMENTATION), 0);
    const event = processLogs({ chain: "ethereum", logs: [upgradedLog()], topicMap: buildEventTopicMap(["Upgraded(address)"]), allowlists: emptyAllowlists(), clock: () => FIXED_CREATED_AT }).alerts;
    const slot = createEip1967SlotChangeAlertFromValues({
      chain: "ethereum", proxy: { address: TARGET, checkImplementationSlot: true, checkAdminSlot: false },
      slotKind: "implementation", slot: EIP1967_IMPLEMENTATION_SLOT, beforeBlock: 99n, afterBlock: 100n,
      beforeValue: addressToStorageWord(UNKNOWN_TARGET), afterValue: addressToStorageWord(IMPLEMENTATION), createdAt: FIXED_CREATED_AT
    });
    assert.ok(slot);
    const result = await analyze(input, { administrativeAlerts: event, slotAlerts: [slot] });
    const correlation = result.correlationAlerts.find((alert) => alert.ruleId === "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED");
    assert.ok(correlation);
    assert.equal(correlation.metadata.executionPath, "MODULE");
    assert.equal(correlation.metadata.moduleAddress, MODULE);
  });

  test("fails closed when module enabled-state RPC is unavailable", async () => {
    const rpc = rpcFor(moduleInput("execTransactionFromModule", TARGET, 0n, transferData(), 0));
    delete (rpc as Partial<RpcClient>).isSafeModuleEnabled;
    await assert.rejects(() => analyzeSafeTransactions({
      rpc, chain: "ethereum", config: moduleConfig(), executionLogs: [moduleLog("success")], administrativeAlerts: [], slotAlerts: [], clock: () => FIXED_CREATED_AT
    }), /isModuleEnabled required/);
  });

  test("journal reload prevents duplicate module alerts", async () => {
    const result = await analyze(moduleInput("execTransactionFromModule", TARGET, 0n, transferData(), 0));
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-module-"));
    const path = join(directory, "journal.jsonl");
    new AlertJournal(path).append(result.alerts, new Map([["100", BLOCK_HASH]]), FIXED_CREATED_AT);
    assert.equal(new AlertJournal(path).filterNew(result.alerts).length, 0);
  });

  test("live restart and overlapping module block emit no duplicates", async () => {
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-module-live-"));
    const checkpointPath = join(directory, "checkpoint.json");
    const journalPath = join(directory, "journal.jsonl");
    const rpc = liveRpc(moduleInput("execTransactionFromModule", TARGET, 0n, transferData(), 0));
    const common = {
      rpc, config: monitorConfig(), confirmations: 0, maxBlocksPerCycle: 1n,
      checkpointPath, journalPath, startBlock: 100n, clock: () => FIXED_CREATED_AT, sinks: []
    };
    const first = await runLiveCycle(common);
    assert.ok(first.alertsEmitted > 0);
    writeCheckpoint(checkpointPath, {
      version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: 99n,
      lastProcessedBlockHash: hash(99n), updatedAt: FIXED_CREATED_AT
    });
    const replay = await runLiveCycle({ ...common, startBlock: undefined });
    assert.equal(replay.alertsEmitted, 0);
    assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 100n);
  });

  test("live module-state failure does not advance checkpoint", async () => {
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-module-live-failure-"));
    const checkpointPath = join(directory, "checkpoint.json");
    const rpc = liveRpc(moduleInput("execTransactionFromModule", TARGET, 0n, transferData(), 0));
    rpc.isSafeModuleEnabled = async () => { throw new Error("module state unavailable"); };
    await assert.rejects(() => runLiveCycle({
      rpc, config: monitorConfig(), confirmations: 0, maxBlocksPerCycle: 1n,
      checkpointPath, journalPath: join(directory, "journal.jsonl"), startBlock: 100n,
      clock: () => FIXED_CREATED_AT, sinks: []
    }), /module state unavailable/);
    assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 99n);
  });
});

function modulePolicy(): SafeModulePolicyConfig {
  return {
    name: "Automation Module", address: MODULE,
    allowedTargets: [TARGET], allowedSelectors: [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!, SAFE_ACTION_SELECTORS["upgradeTo(address)"]!],
    allowedOperations: ["CALL"], allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: 0n
  };
}

function moduleConfig(): AdministrativeMonitoringConfig {
  return { multisigs: [safePolicy({
    allowedTargets: [TARGET],
    allowedSelectors: [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!, SAFE_ACTION_SELECTORS["upgradeTo(address)"]!],
    allowedOperations: ["CALL"], allowedModules: [MODULE], modulePolicies: [modulePolicy()]
  })] };
}

async function analyze(input: Hex, options: {
  module?: Address;
  enabled?: boolean;
  modulePolicies?: SafeModulePolicyConfig[];
  config?: AdministrativeMonitoringConfig;
  administrativeAlerts?: ReturnType<typeof processLogs>["alerts"];
  slotAlerts?: ReturnType<typeof processLogs>["alerts"];
} = {}) {
  const config = options.config ?? moduleConfig();
  if (options.modulePolicies !== undefined) config.multisigs[0]!.modulePolicies = options.modulePolicies;
  return analyzeSafeTransactions({
    rpc: rpcFor(input, options.enabled ?? true), chain: "ethereum", config,
    executionLogs: [moduleLog("success", options.module ?? MODULE)],
    administrativeAlerts: options.administrativeAlerts ?? [], slotAlerts: options.slotAlerts ?? [], clock: () => FIXED_CREATED_AT
  });
}

function rpcFor(input: Hex, enabled = true): RpcClient {
  return {
    async getLogs() { return []; }, async getStorageAt() { return undefined; }, async getErc20Balance() { return 0n; },
    async getTransaction() { return { hash: SAFE_TX_HASH, to: SAFE, input, value: 0n, blockNumber: 100n }; },
    async getTransactionReceipt() { return rpcReceipt(); },
    async isSafeModuleEnabled() { return enabled; }
  };
}

function liveRpc(input: Hex): LiveRpcClient {
  const base = rpcFor(input);
  const moduleTopic = [...buildEventTopicMap([SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[0]]).keys()][0]!;
  return {
    ...base,
    async getLogs(request) { return request.topics.includes(moduleTopic) ? [moduleLog("success")] : []; },
    async getBlockNumber() { return 100n; },
    async getBlock(blockNumber) {
      return { number: blockNumber, hash: hash(blockNumber), parentHash: hash(blockNumber === 0n ? 0n : blockNumber - 1n), timestamp: blockNumber };
    }
  };
}

function monitorConfig(): MonitorConfig {
  return {
    chain: "ethereum", monitoredAddresses: [SAFE, TARGET], knownMultisigs: [SAFE], eventSignatures: [],
    administrativeMonitoring: moduleConfig(), allowlists: emptyAllowlists()
  };
}

function hash(block: bigint): Hex {
  return `0x${block.toString(16).padStart(64, "0")}` as Hex;
}

function moduleLog(outcome: "success" | "failure", module = MODULE, logIndex = 2): RawLogForAlert {
  const signature = outcome === "success" ? SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[0] : SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[1];
  const topic0 = [...buildEventTopicMap([signature]).keys()][0]!;
  return {
    blockNumber: "0x64", transactionHash: SAFE_TX_HASH, transactionIndex: "0x1", logIndex: numberToHex(logIndex),
    address: SAFE, topics: [topic0, `0x${"0".repeat(24)}${module.slice(2).toLowerCase()}` as Hex], data: "0x"
  };
}

function moduleInput(entrypoint: "execTransactionFromModule" | "execTransactionFromModuleReturnData", target: Address, value: bigint, data: Hex, operation: number): Hex {
  return encodeFunctionData({ abi: SAFE_MODULE_EXECUTION_ABI, functionName: entrypoint, args: [target, value, data, operation] });
}

function decode(_selector: Hex, input: Hex, executionEventsInTransaction = 1) {
  return decodeSafeModuleTransaction({
    safeAddress: SAFE, moduleAddress: MODULE, modulePolicy: modulePolicy(),
    transaction: { hash: SAFE_TX_HASH, to: SAFE, input, value: 0n, blockNumber: 100n },
    eventLogIndex: 2, executionEventsInTransaction
  });
}

function transferData(): Hex {
  return encodeFunctionData({ abi: [{ type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] }], functionName: "transfer", args: [TARGET, 1n] });
}

function upgradeData(implementation: Address): Hex {
  return encodeFunctionData({ abi: [{ type: "function", name: "upgradeTo", stateMutability: "nonpayable", inputs: [{ name: "implementation", type: "address" }], outputs: [] }], functionName: "upgradeTo", args: [implementation] });
}

assert.ok(SAFE_MONITORING_EVENT_SIGNATURES.includes("ExecutionFromModuleSuccess(address)"));
