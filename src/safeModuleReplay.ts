import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeFunctionData, getAddress, type Address, type Hex } from "viem";
import { AlertJournal } from "./alertJournal.js";
import type { Alert, RawLogForAlert } from "./alerts.js";
import { buildEventTopicMap } from "./events.js";
import { processLogs } from "./processor.js";
import type { RpcClient } from "./rpc.js";
import { analyzeSafeTransactions } from "./safe/analyzer.js";
import { SAFE_ACTION_SELECTORS } from "./safe/actions.js";
import { SAFE_MODULE_EXECUTION_ABI, SAFE_MODULE_EXECUTION_EVENT_SIGNATURES } from "./safe/module.js";
import { MULTISEND_ABI, MULTISEND_SELECTOR } from "./safe/multisend.js";
import type { AdministrativeMonitoringConfig, SafeMultisigConfig } from "./safe/types.js";

const SAFE = getAddress("0x1000000000000000000000000000000000000001");
const TARGET = getAddress("0x2000000000000000000000000000000000000002");
const MODULE = getAddress("0x3000000000000000000000000000000000000003");
const UNKNOWN_MODULE = getAddress("0x4000000000000000000000000000000000000004");
const IMPLEMENTATION = getAddress("0x5000000000000000000000000000000000000005");
const UNKNOWN = getAddress("0x6000000000000000000000000000000000000006");
const MULTISEND = getAddress("0x7000000000000000000000000000000000000007");
const HASH = `0x${"ab".repeat(32)}` as Hex;
const BLOCK_HASH = `0x${"cd".repeat(32)}` as Hex;
const CREATED_AT = "2026-08-01T00:00:00.000Z";

async function main(): Promise<void> {
  const allowed = await run(moduleInput(TARGET, transferData(), "CALL"), MODULE, true);
  const unknown = await run("0x12345678", UNKNOWN_MODULE, false, []);
  const delegate = await run(moduleInput(UNKNOWN, upgradeData(UNKNOWN), "DELEGATECALL"), MODULE, true);
  const multi = await run(moduleInput(MULTISEND, multiSendData(), "CALL"), MODULE, true, undefined, multiSendConfig());
  const upgradeEvent = processLogs({
    chain: "ethereum", logs: [upgradedLog()], topicMap: buildEventTopicMap(["Upgraded(address)"]),
    allowlists: emptyAllowlists(), clock: () => CREATED_AT
  }).alerts;
  const correlated = await run(moduleInput(TARGET, upgradeData(IMPLEMENTATION), "CALL"), MODULE, true, undefined, undefined, upgradeEvent);
  const all = [...allowed.alerts, ...unknown.alerts, ...delegate.alerts, ...multi.alerts, ...correlated.alerts];
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-module-replay-"));
  const journalPath = join(directory, "journal.jsonl");
  new AlertJournal(journalPath).append(all, new Map([["100", BLOCK_HASH]]), CREATED_AT);
  const duplicates = new AlertJournal(journalPath).filterNew(all).length;

  console.log("Safe module execution offline replay (synthetic fixture; no traces, mempool, simulation, or human-intent inference)");
  console.log(`allowed module: ${rules(allowed.alerts)}; enabled=true; policyViolation=false`);
  console.log(`unknown/disabled module: ${rules(unknown.alerts)}`);
  console.log(`delegatecall + unknown upgrade: ${rules(delegate.alerts)}`);
  console.log(`module MultiSend: ${rules(multi.alerts)}`);
  console.log(`confirmed administrative effect: ${rules(correlated.correlationAlerts)}`);
  console.log(`undecodable indirect calldata: ${unknown.undecodedCount} explicit result`);
  console.log("restart: durable journal restored");
  console.log(`replay: ${duplicates} duplicate alerts emitted`);
  if (duplicates !== 0) throw new Error("Safe module replay emitted duplicate alerts after journal reload.");
}

async function run(
  input: Hex,
  module: Address,
  enabled: boolean,
  modulePolicies?: SafeMultisigConfig["modulePolicies"],
  config = baseConfig(),
  administrativeAlerts: Alert[] = []
) {
  if (modulePolicies !== undefined) config.multisigs[0]!.modulePolicies = modulePolicies;
  const rpc: RpcClient = {
    async getLogs() { return []; }, async getStorageAt() { return undefined; }, async getErc20Balance() { return 0n; },
    async getTransaction() { return { hash: HASH, to: SAFE, input, value: 0n, blockNumber: 100n }; },
    async getTransactionReceipt() { return { transactionHash: HASH, blockNumber: 100n, blockHash: BLOCK_HASH, status: "success", logs: [] }; },
    async isSafeModuleEnabled() { return enabled; }
  };
  return analyzeSafeTransactions({
    rpc, chain: "ethereum", config, executionLogs: [moduleLog(module)], administrativeAlerts, slotAlerts: [], clock: () => CREATED_AT
  });
}

function baseConfig(): AdministrativeMonitoringConfig {
  const policy: SafeMultisigConfig = {
    name: "Synthetic Critical Safe", address: SAFE, criticality: "critical",
    allowedTargets: [TARGET, MULTISEND],
    allowedSelectors: [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!, SAFE_ACTION_SELECTORS["upgradeTo(address)"]!, MULTISEND_SELECTOR],
    allowedOperations: ["CALL"], allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: 0n,
    allowedOwners: [], allowedThresholds: [], allowedModules: [MODULE], allowedGuards: [], allowedFallbackHandlers: [],
    multisendAlertDetail: "sensitive-only",
    financialOperationPolicy: { emitAllowedTransfers: false, emitAllowedApprovals: false, maxNativeValueWei: 0n, notableTokenTargets: [] },
    modulePolicies: [{
      name: "Synthetic Automation Module", address: MODULE, allowedTargets: [TARGET, MULTISEND],
      allowedSelectors: [SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!, SAFE_ACTION_SELECTORS["upgradeTo(address)"]!, MULTISEND_SELECTOR],
      allowedOperations: ["CALL"], allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: 0n
    }]
  };
  return { multisigs: [policy] };
}

function multiSendConfig(): AdministrativeMonitoringConfig {
  const config = baseConfig();
  config.multisendContracts = [{ name: "Synthetic MultiSend", address: MULTISEND, mode: "MULTISEND" }];
  return config;
}

function moduleInput(target: Address, data: Hex, operation: "CALL" | "DELEGATECALL"): Hex {
  return encodeFunctionData({
    abi: SAFE_MODULE_EXECUTION_ABI, functionName: "execTransactionFromModule",
    args: [target, 0n, data, operation === "CALL" ? 0 : 1]
  });
}

function transferData(): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] }],
    functionName: "transfer", args: [TARGET, 1n]
  });
}

function upgradeData(implementation: Address): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "upgradeTo", stateMutability: "nonpayable", inputs: [{ name: "implementation", type: "address" }], outputs: [] }],
    functionName: "upgradeTo", args: [implementation]
  });
}

function multiSendData(): Hex {
  const call = `00${TARGET.slice(2)}${"0".repeat(64)}${"0".repeat(62)}44${transferData().slice(2)}` as const;
  return encodeFunctionData({ abi: MULTISEND_ABI, functionName: "multiSend", args: [`0x${call}`] });
}

function moduleLog(module: Address): RawLogForAlert {
  const topic0 = [...buildEventTopicMap([SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[0]]).keys()][0]!;
  return { blockNumber: "0x64", transactionHash: HASH, transactionIndex: "0x1", logIndex: "0x2", address: SAFE,
    topics: [topic0, `0x${"0".repeat(24)}${module.slice(2).toLowerCase()}` as Hex], data: "0x" };
}

function upgradedLog(): RawLogForAlert {
  const topic0 = [...buildEventTopicMap(["Upgraded(address)"]).keys()][0]!;
  return { blockNumber: "0x64", transactionHash: HASH, transactionIndex: "0x1", logIndex: "0x1", address: TARGET,
    topics: [topic0, `0x${"0".repeat(24)}${IMPLEMENTATION.slice(2).toLowerCase()}` as Hex], data: "0x" };
}

function emptyAllowlists() {
  return { knownActors: [], knownAdmins: [], knownImplementations: [], knownGovernanceContracts: [], knownProxyAddresses: [] };
}

function rules(alerts: readonly Alert[]): string {
  return alerts.map((alert) => alert.ruleId).join(", ");
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
