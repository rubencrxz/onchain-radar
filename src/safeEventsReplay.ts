import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  numberToHex,
  parseAbi,
  size,
  type Address,
  type Hex
} from "viem";
import type { Alert, RawLogForAlert } from "./alerts.js";
import { AlertJournal } from "./alertJournal.js";
import { buildEventTopicMap } from "./events.js";
import { processLogs } from "./processor.js";
import { correlateMultiSendAdministrativeEffects } from "./safe/correlation.js";
import { decodeSafeExecTransaction, SAFE_EXEC_TRANSACTION_ABI } from "./safe/decoder.js";
import { analyzeMultiSendTransaction, MULTISEND_ABI, MULTISEND_SELECTOR } from "./safe/multisend.js";
import { createMultiSendAlerts } from "./safe/multisendAlerts.js";
import { refineSafeNativeEventAlerts, SAFE_NATIVE_ADMIN_EVENT_SIGNATURES } from "./safe/nativeEvents.js";
import type { AdministrativeMonitoringConfig, SafeMultisigConfig } from "./safe/types.js";

const SAFE = getAddress("0x1000000000000000000000000000000000000001");
const MULTISEND = getAddress("0x2000000000000000000000000000000000000002");
const TOKEN = getAddress("0x3000000000000000000000000000000000000003");
const OLD_OWNER = getAddress("0x4000000000000000000000000000000000000004");
const NEW_OWNER = getAddress("0x5000000000000000000000000000000000000005");
const ALLOWED_MODULE = getAddress("0x6000000000000000000000000000000000000006");
const UNKNOWN_MODULE = getAddress("0x7000000000000000000000000000000000000007");
const CREATED_AT = "2026-08-01T00:00:00.000Z";
const BLOCK_HASH = `0x${"aa".repeat(32)}` as Hex;
const ACTION_ABI = parseAbi([
  "function swapOwner(address prevOwner,address oldOwner,address newOwner)",
  "function changeThreshold(uint256 threshold)",
  "function enableModule(address module)",
  "function transfer(address to,uint256 amount) returns (bool)"
]);

function main(): void {
  console.log("Safe native administrative events offline replay (synthetic fixture; no module execution or human-intent inference)");
  const management = batch("01", [
    pack(SAFE, encodeFunctionData({ abi: ACTION_ABI, functionName: "swapOwner", args: [ALLOWED_MODULE, OLD_OWNER, NEW_OWNER] })),
    pack(SAFE, encodeFunctionData({ abi: ACTION_ABI, functionName: "changeThreshold", args: [2n] }))
  ]);
  const native = nativeAlerts([
    eventLog("RemovedOwner(address)", "address", OLD_OWNER, 0, management.transaction.outerTransactionHash),
    eventLog("AddedOwner(address)", "address", NEW_OWNER, 1, management.transaction.outerTransactionHash),
    eventLog("ChangedThreshold(uint256)", "uint256", 2n, 2, management.transaction.outerTransactionHash)
  ]);
  const correlations = correlateMultiSendAdministrativeEffects({
    chain: "ethereum", transaction: management.transaction, operations: management.operations,
    administrativeAlerts: native, slotAlerts: [], createdAt: CREATED_AT
  });
  console.log(`swapOwner: RemovedOwner + AddedOwner; correlation=${statusFor(correlations, "0")}`);
  console.log(`changeThreshold: ChangedThreshold(2); correlation=${statusFor(correlations, "1")}`);

  const moduleBatch = batch("02", [pack(SAFE, encodeFunctionData({ abi: ACTION_ABI, functionName: "enableModule", args: [UNKNOWN_MODULE] }))]);
  const moduleEvent = nativeAlerts([eventLog("EnabledModule(address)", "address", UNKNOWN_MODULE, 0, moduleBatch.transaction.outerTransactionHash)]);
  const moduleAlerts = [...moduleBatch.alerts, ...moduleEvent];
  console.log(`unknown module: SAFE_MODULE_ENABLED severity=${moduleEvent[0]?.severity}; policy severity=${moduleBatch.alerts.find((alert) => alert.ruleId === "SAFE_MULTISEND_POLICY_VIOLATION")?.severity}`);

  const financial = batch("03", [pack(TOKEN, encodeFunctionData({ abi: ACTION_ABI, functionName: "transfer", args: [NEW_OWNER, 1_000_000n] }))]);
  console.log(`allowed financial operation: semanticCategory=${financial.operations[0]?.action.semanticCategory}; sensitiveAdmin=${has(financial.alerts, "SAFE_SENSITIVE_ADMIN_ACTION")}`);
  console.log(`sensitive-only routine transfer: subcalls=${financial.alerts.filter((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL").length}; summary=${has(financial.alerts, "SAFE_MULTISEND_EXECUTED")}`);

  const all = [...management.alerts, ...native, ...correlations, ...moduleAlerts, ...financial.alerts];
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-events-replay-"));
  try {
    const journalPath = join(directory, "journal.jsonl");
    new AlertJournal(journalPath).append(all, new Map([["100", BLOCK_HASH]]), CREATED_AT);
    const restored = new AlertJournal(journalPath);
    console.log("restart: durable journal restored");
    console.log(`replay: ${restored.filterNew(all).length} duplicate alerts emitted`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function batch(hashSuffix: string, operations: Hex[]) {
  const payload = concatHex(operations);
  const multiSendData = encodeFunctionData({ abi: MULTISEND_ABI, functionName: "multiSend", args: [payload] });
  const hash = `0x${hashSuffix.padStart(64, "0")}` as Hex;
  const input = encodeFunctionData({
    abi: SAFE_EXEC_TRANSACTION_ABI,
    functionName: "execTransaction",
    args: [MULTISEND, 0n, multiSendData, 1, 100_000n, 0n, 0n, SAFE, SAFE, "0x1234"]
  });
  const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: { hash, to: SAFE, input, value: 0n, blockNumber: 100n } });
  if (!decoded.decoded) throw new Error(decoded.error);
  const expansion = analyzeMultiSendTransaction({ transaction: decoded.transaction, policy: policy(), config: config() });
  if (!expansion.recognized || !expansion.complete) throw new Error("Synthetic MultiSend did not decode completely.");
  return {
    transaction: decoded.transaction,
    operations: expansion.operations,
    alerts: createMultiSendAlerts({ chain: "ethereum", policy: policy(), transaction: decoded.transaction, expansion, outcome: "success", createdAt: CREATED_AT })
  };
}

function nativeAlerts(logs: RawLogForAlert[]): Alert[] {
  const alerts = processLogs({
    chain: "ethereum", logs, topicMap: buildEventTopicMap([...SAFE_NATIVE_ADMIN_EVENT_SIGNATURES]),
    allowlists: { knownActors: [], knownAdmins: [], knownImplementations: [], knownGovernanceContracts: [], knownProxyAddresses: [] },
    clock: () => CREATED_AT
  }).alerts;
  return refineSafeNativeEventAlerts(alerts, config());
}

function eventLog(signature: string, type: "address" | "uint256", value: Address | bigint, index: number, hash: Hex): RawLogForAlert {
  return {
    blockNumber: "0x64", transactionHash: hash, transactionIndex: "0x1", logIndex: numberToHex(index),
    address: SAFE, topics: [...buildEventTopicMap([signature]).keys()],
    data: encodeAbiParameters([{ type }], [value] as never)
  };
}

function pack(target: Address, data: Hex): Hex {
  return concatHex(["0x00", target, numberToHex(0n, { size: 32 }), numberToHex(BigInt(size(data)), { size: 32 }), data]);
}

function policy(): SafeMultisigConfig {
  return {
    name: "Synthetic Critical Safe", address: SAFE, criticality: "critical",
    allowedTargets: [MULTISEND, SAFE, TOKEN],
    allowedSelectors: [MULTISEND_SELECTOR, ...["swapOwner", "changeThreshold", "enableModule", "transfer"].map((name) =>
      encodeFunctionData({ abi: ACTION_ABI, functionName: name as never, args: (name === "changeThreshold" ? [2n] : name === "enableModule" ? [ALLOWED_MODULE] : name === "transfer" ? [NEW_OWNER, 1n] : [ALLOWED_MODULE, OLD_OWNER, NEW_OWNER]) as never }).slice(0, 10) as Hex
    )],
    allowedOperations: ["CALL", "DELEGATECALL"], allowedImplementations: [], maxNativeValueWei: 0n,
    allowedOwners: [OLD_OWNER, NEW_OWNER], minimumThreshold: 2, allowedThresholds: [2, 3],
    allowedModules: [ALLOWED_MODULE], allowedGuards: [], allowedFallbackHandlers: [],
    multisendAlertDetail: "sensitive-only",
    financialOperationPolicy: { emitAllowedTransfers: false, emitAllowedApprovals: false, maxNativeValueWei: 0n, notableTokenTargets: [] },
    modulePolicies: []
  };
}

function config(): AdministrativeMonitoringConfig {
  return { multisigs: [policy()], multisendContracts: [{ name: "Synthetic MultiSend", address: MULTISEND, mode: "CALL_ONLY" }] };
}

function statusFor(alerts: Alert[], path: string): unknown {
  return alerts.find((alert) => (alert.metadata.safeCorrelation as Record<string, unknown>)?.suboperationPath === path)?.metadata.correlationStatus;
}

function has(alerts: Alert[], ruleId: string): boolean { return alerts.some((alert) => alert.ruleId === ruleId); }

main();
