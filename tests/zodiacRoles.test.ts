import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { encodeFunctionData, getAddress, numberToHex, type Address, type Hex } from "viem";
import type { RawLogForAlert } from "../src/alerts.js";
import type { LiveRpcClient, RpcClient, RpcTransaction } from "../src/rpc.js";
import type { MonitorConfig } from "../src/config.js";
import { loadCheckpoint, writeCheckpoint } from "../src/checkpoint.js";
import { runLiveCycle } from "../src/liveScanner.js";
import { buildEventTopicMap } from "../src/events.js";
import { analyzeSafeTransactions } from "../src/safe/analyzer.js";
import { SAFE_ACTION_SELECTORS } from "../src/safe/actions.js";
import { SAFE_EXEC_TRANSACTION_ABI } from "../src/safe/decoder.js";
import { SAFE_MODULE_EXECUTION_EVENT_SIGNATURES } from "../src/safe/module.js";
import { MULTISEND_SELECTOR } from "../src/safe/multisend.js";
import type { AdministrativeMonitoringConfig, SafeModulePolicyConfig } from "../src/safe/types.js";
import {
  decodeConfiguredZodiacRolesTransaction,
  ZODIAC_EXEC_WITH_ROLE_SELECTOR,
  ZODIAC_ROLES_EXECUTION_ABI,
  ZodiacRolesAdapterError
} from "../src/safe/zodiacRoles.js";
import { FIXED_CREATED_AT } from "./fixtures.js";
import { MULTISEND, multiSendData, packSuboperation } from "./multisendFixtures.js";
import { BLOCK_HASH, IMPLEMENTATION, SAFE, SAFE_TX_HASH, TARGET, USER, ZERO, innerTransfer, rpcReceipt } from "./safeFixtures.js";

const MODULE = getAddress("0x9000000000000000000000000000000000000009");
const MANAGER = getAddress("0x9100000000000000000000000000000000000009");
const UNKNOWN_MANAGER = getAddress("0x9200000000000000000000000000000000000009");
const ROLE = `0x${"11".repeat(32)}` as Hex;

describe("bounded Zodiac Roles v2 decoding", () => {
  test("decodes a configured direct execTransactionWithRole and preserves role metadata", () => {
    const result = decodeZodiac(transaction(MODULE, zodiacData(TARGET, 7n, innerTransfer(), "CALL")));
    assert.ok(result.decoded);
    if (!result.decoded) throw new Error("fixture did not decode");
    assert.equal(result.moduleTransaction.entrypoint, "execTransactionWithRole");
    assert.equal(result.moduleTransaction.transaction.innerTarget, TARGET);
    assert.equal(result.moduleTransaction.transaction.innerValue, 7n);
    assert.equal(result.moduleTransaction.zodiacRoles?.roleKey, ROLE);
    assert.equal(result.moduleTransaction.zodiacRoles?.wrapperPath, "module.direct");
  });

  test("decodes the configured return-data entrypoint", () => {
    const result = decodeZodiac(transaction(MODULE, zodiacData(
      TARGET, 0n, innerTransfer(), "CALL", ROLE, "execTransactionWithRoleReturnData"
    )));
    assert.ok(result.decoded);
    if (result.decoded) assert.equal(result.moduleTransaction.entrypoint, "execTransactionWithRoleReturnData");
  });

  test("unwraps an explicitly configured Manager Safe", () => {
    const input = managerInput(MODULE, zodiacData(TARGET, 0n, innerTransfer(), "CALL"));
    const result = decodeZodiac(transaction(MANAGER, input));
    assert.ok(result.decoded);
    if (!result.decoded) throw new Error("fixture did not decode");
    assert.equal(result.moduleTransaction.transaction.innerSelector, SAFE_ACTION_SELECTORS["transfer(address,uint256)"]);
    assert.equal(result.moduleTransaction.zodiacRoles?.managerSafe, MANAGER);
    assert.equal(result.moduleTransaction.zodiacRoles?.wrapperPath, "manager.direct");
  });

  test("maps multiple Manager Safe MultiSend calls to module events in payload order", async () => {
    const first = zodiacData(TARGET, 0n, innerTransfer(), "CALL", ROLE);
    const secondRole = `0x${"22".repeat(32)}` as Hex;
    const second = zodiacData(TARGET, 0n, innerTransfer(), "CALL", secondRole);
    const input = managerInput(MULTISEND, multiSendData([
      packSuboperation({ target: MODULE, data: first }),
      packSuboperation({ target: MODULE, data: second })
    ]), "DELEGATECALL");
    const result = await analyze(input, [moduleLog(2), moduleLog(3)]);
    assert.equal(result.reconstructedCount, 2);
    assert.equal(result.undecodedCount, 0);
    const executed = result.outerTransactionAlerts.filter((alert) => alert.ruleId === "SAFE_MODULE_TRANSACTION_EXECUTED");
    assert.equal(executed.length, 2);
    assert.equal(new Set(executed.map((alert) => alert.id)).size, 2);
    assert.deepEqual(executed.map((alert) => ((alert.metadata.zodiacRoles as Record<string, unknown>).roleKey)), [ROLE, secondRole]);
  });

  test("keeps unknown managers and unsupported Zodiac selectors explicitly undecoded", () => {
    const unknown = decodeZodiac(transaction(UNKNOWN_MANAGER, managerInput(MODULE, zodiacData())));
    assert.ok(!unknown.decoded);
    if (!unknown.decoded) assert.equal(unknown.failureKind, "ZODIAC_WRAPPER_NOT_FOUND");
    const selector = decodeZodiac(transaction(MANAGER, managerInput(MODULE, "0x12345678")));
    assert.ok(!selector.decoded);
    if (!selector.decoded) assert.equal(selector.failureKind, "ZODIAC_UNSUPPORTED_SELECTOR");
  });

  test("does not assign an ambiguous call site to multiple module events", () => {
    const result = decodeZodiac(transaction(MANAGER, managerInput(MODULE, zodiacData())), 0, 2);
    assert.ok(!result.decoded);
    if (!result.decoded) assert.equal(result.failureKind, "ZODIAC_WRAPPER_AMBIGUOUS");
  });

  test("fails closed on malformed configured Manager Safe calldata and wrapper limits", () => {
    const malformed = transaction(MANAGER, "0x6a761202");
    assert.throws(() => decodeZodiac(malformed), ZodiacRolesAdapterError);
    const limits = config();
    limits.multisendLimits = { maxDepth: 1, maxSuboperations: 2, maxTotalPayloadBytes: 10, maxSuboperationDataBytes: 10 };
    assert.throws(() => decodeZodiac(transaction(MANAGER, managerInput(MODULE, zodiacData())), 0, 1, limits), /exceeds configured limit/);
  });

  test("supports bounded nested Manager MultiSend and rejects excess depth", () => {
    const nested = multiSendData([packSuboperation({ target: MODULE, data: zodiacData() })]);
    const outer = multiSendData([packSuboperation({ target: MULTISEND, data: nested })]);
    const transactionValue = transaction(MANAGER, managerInput(MULTISEND, outer, "DELEGATECALL"));
    const decoded = decodeZodiac(transactionValue);
    assert.ok(decoded.decoded);
    if (decoded.decoded) assert.equal(decoded.moduleTransaction.zodiacRoles?.wrapperPath, "manager.multisend.0.0");
    const limited = config();
    if (limited.multisendLimits === undefined) throw new Error("fixture missing limits");
    limited.multisendLimits.maxDepth = 1;
    assert.throws(() => decodeZodiac(transactionValue, 0, 1, limited), /depth 2 exceeds/);
  });

  test("reuses downstream MultiSend analysis and the intersected module policy", async () => {
    const configValue = config();
    const policy = configValue.multisigs[0]!;
    const modulePolicyValue = policy.modulePolicies[0]!;
    policy.allowedTargets = [MULTISEND, TARGET];
    policy.allowedSelectors = [MULTISEND_SELECTOR, SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!];
    policy.allowedOperations = ["CALL", "DELEGATECALL"];
    modulePolicyValue.allowedTargets = [...policy.allowedTargets];
    modulePolicyValue.allowedSelectors = [...policy.allowedSelectors];
    modulePolicyValue.allowedOperations = [...policy.allowedOperations];
    const nested = multiSendData([packSuboperation({ target: TARGET, data: innerTransfer() })]);
    const input = managerInput(MODULE, zodiacData(MULTISEND, 0n, nested, "DELEGATECALL"));
    const result = await analyze(input, [moduleLog(2)], configValue);
    assert.equal(result.reconstructedCount, 1);
    assert.ok(result.multisendAlerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_EXECUTED"));
    assert.ok(result.outerTransactionAlerts.some((alert) => alert.ruleId === "SAFE_MODULE_DELEGATECALL"));
    assert.doesNotThrow(() => JSON.stringify(result.alerts));
  });

  test("produces stable IDs and journal-compatible unique identities through analysis replay", async () => {
    const input = managerInput(MODULE, zodiacData());
    const first = await analyze(input, [moduleLog(2)]);
    const replay = await analyze(input, [moduleLog(2)]);
    assert.deepEqual(first.alerts.map((alert) => alert.id), replay.alerts.map((alert) => alert.id));
    assert.equal(new Set(first.alerts.map((alert) => alert.id)).size, first.alerts.length);
  });

  test("live reconstruction survives checkpoint rewind without duplicate delivery", async () => {
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-zodiac-live-"));
    const checkpointPath = join(directory, "checkpoint.json");
    const journalPath = join(directory, "journal.jsonl");
    const input = managerInput(MODULE, zodiacData());
    const rpc = liveRpc(input);
    const common = {
      rpc,
      config: monitorConfig(),
      confirmations: 0,
      maxBlocksPerCycle: 1n,
      checkpointPath,
      journalPath,
      startBlock: 100n,
      clock: () => FIXED_CREATED_AT,
      sinks: []
    };
    const first = await runLiveCycle(common);
    assert.ok(first.alertsEmitted > 0);
    writeCheckpoint(checkpointPath, {
      version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: 99n,
      lastProcessedBlockHash: blockHash(99n), updatedAt: FIXED_CREATED_AT
    });
    const replay = await runLiveCycle({ ...common, startBlock: undefined });
    assert.equal(replay.alertsEmitted, 0);
    assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 100n);
  });

  test("live wrapper limit failure does not advance its initialized checkpoint", async () => {
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-zodiac-live-limit-"));
    const checkpointPath = join(directory, "checkpoint.json");
    const configValue = monitorConfig();
    if (configValue.administrativeMonitoring === undefined) throw new Error("fixture missing admin config");
    configValue.administrativeMonitoring.multisendLimits = {
      maxDepth: 1, maxSuboperations: 1, maxTotalPayloadBytes: 10, maxSuboperationDataBytes: 10
    };
    await assert.rejects(() => runLiveCycle({
      rpc: liveRpc(managerInput(MODULE, zodiacData())),
      config: configValue,
      confirmations: 0,
      maxBlocksPerCycle: 1n,
      checkpointPath,
      journalPath: join(directory, "journal.jsonl"),
      startBlock: 100n,
      clock: () => FIXED_CREATED_AT,
      sinks: []
    }), /exceeds configured limit/);
    assert.equal(loadCheckpoint(checkpointPath)?.lastProcessedBlock, 99n);
  });
});

function decodeZodiac(
  rpcTransaction: RpcTransaction,
  moduleEventIndex = 0,
  moduleEventsInTransaction = 1,
  configValue = config()
) {
  return decodeConfiguredZodiacRolesTransaction({
    safeAddress: SAFE,
    moduleAddress: MODULE,
    modulePolicy: configValue.multisigs[0]!.modulePolicies[0]!,
    transaction: rpcTransaction,
    config: configValue,
    eventLogIndex: 2,
    moduleEventIndex,
    moduleEventsInTransaction
  });
}

async function analyze(input: Hex, logs: RawLogForAlert[], configValue = config()) {
  const rpc: RpcClient = {
    async getLogs() { return []; },
    async getStorageAt() { return undefined; },
    async getErc20Balance() { return 0n; },
    async getTransaction() { return transaction(MANAGER, input); },
    async getTransactionReceipt() { return rpcReceipt(); },
    async isSafeModuleEnabled() { return true; }
  };
  return analyzeSafeTransactions({
    rpc,
    chain: "ethereum",
    config: configValue,
    executionLogs: logs,
    administrativeAlerts: [],
    slotAlerts: [],
    clock: () => FIXED_CREATED_AT
  });
}

function config(): AdministrativeMonitoringConfig {
  return {
    multisigs: [{
      name: "Critical Safe",
      address: SAFE,
      criticality: "critical",
      allowedTargets: [TARGET],
      allowedSelectors: [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!],
      allowedOperations: ["CALL"],
      allowedImplementations: [IMPLEMENTATION],
      maxNativeValueWei: 10n,
      allowedOwners: [],
      allowedThresholds: [],
      allowedModules: [MODULE],
      allowedGuards: [],
      allowedFallbackHandlers: [],
      multisendAlertDetail: "sensitive-only",
      financialOperationPolicy: { emitAllowedTransfers: false, emitAllowedApprovals: false, maxNativeValueWei: 10n, notableTokenTargets: [] },
      modulePolicies: [modulePolicy()]
    }],
    multisendContracts: [{ name: "MultiSend", address: MULTISEND, mode: "CALL_ONLY" }],
    multisendLimits: { maxDepth: 2, maxSuboperations: 20, maxTotalPayloadBytes: 10_000, maxSuboperationDataBytes: 2_000 }
  };
}

function modulePolicy(): SafeModulePolicyConfig {
  return {
    name: "Zodiac Roles v2",
    address: MODULE,
    allowedTargets: [TARGET],
    allowedSelectors: [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!],
    allowedOperations: ["CALL"],
    allowedImplementations: [IMPLEMENTATION],
    maxNativeValueWei: 10n,
    adapter: { type: "ZODIAC_ROLES_V2", managerSafes: [MANAGER] }
  };
}

function zodiacData(
  target: Address = TARGET,
  value = 0n,
  data: Hex = innerTransfer(),
  operation: "CALL" | "DELEGATECALL" = "CALL",
  roleKey: Hex = ROLE,
  entrypoint: "execTransactionWithRole" | "execTransactionWithRoleReturnData" = "execTransactionWithRole"
): Hex {
  return encodeFunctionData({
    abi: ZODIAC_ROLES_EXECUTION_ABI,
    functionName: entrypoint,
    args: [target, value, data, operation === "CALL" ? 0 : 1, roleKey, true]
  });
}

function managerInput(target: Address, data: Hex, operation: "CALL" | "DELEGATECALL" = "CALL"): Hex {
  return encodeFunctionData({
    abi: SAFE_EXEC_TRANSACTION_ABI,
    functionName: "execTransaction",
    args: [target, 0n, data, operation === "CALL" ? 0 : 1, 0n, 0n, 0n, ZERO, ZERO, "0x"]
  });
}

function transaction(to: Address, input: Hex): RpcTransaction {
  return { hash: SAFE_TX_HASH, to, input, value: 0n, blockNumber: 100n };
}

function moduleLog(logIndex: number): RawLogForAlert {
  const topic0 = [...buildEventTopicMap([SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[0]]).keys()][0]!;
  return {
    blockNumber: "0x64",
    transactionHash: SAFE_TX_HASH,
    transactionIndex: "0x1",
    logIndex: numberToHex(logIndex),
    address: SAFE,
    topics: [topic0, `0x${"0".repeat(24)}${MODULE.slice(2).toLowerCase()}` as Hex],
    data: "0x"
  };
}

function monitorConfig(): MonitorConfig {
  return {
    chain: "ethereum",
    monitoredAddresses: [SAFE, TARGET],
    knownMultisigs: [SAFE],
    eventSignatures: [],
    administrativeMonitoring: config(),
    allowlists: { knownActors: [], knownAdmins: [], knownImplementations: [], knownGovernanceContracts: [], knownProxyAddresses: [] }
  };
}

function liveRpc(input: Hex): LiveRpcClient {
  const moduleTopic = [...buildEventTopicMap([SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[0]]).keys()][0]!;
  return {
    async getLogs(request) { return request.topics.includes(moduleTopic) ? [moduleLog(2)] : []; },
    async getStorageAt() { return undefined; },
    async getErc20Balance() { return 0n; },
    async getTransaction() { return transaction(MANAGER, input); },
    async getTransactionReceipt() { return rpcReceipt(); },
    async isSafeModuleEnabled() { return true; },
    async getBlockNumber() { return 100n; },
    async getBlock(blockNumber) {
      return {
        number: blockNumber,
        hash: blockNumber === 100n ? BLOCK_HASH : blockHash(blockNumber),
        parentHash: blockHash(blockNumber === 0n ? 0n : blockNumber - 1n),
        timestamp: blockNumber
      };
    }
  };
}

function blockHash(blockNumber: bigint): Hex {
  return `0x${blockNumber.toString(16).padStart(64, "0")}` as Hex;
}

assert.equal(ZODIAC_EXEC_WITH_ROLE_SELECTOR.length, 10);
assert.equal(BLOCK_HASH.length, 66);
