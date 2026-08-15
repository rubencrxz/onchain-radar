import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { concatHex, encodeFunctionData, getAddress, numberToHex, parseAbi, size, type Address, type Hex } from "viem";
import type { Alert } from "./alerts.js";
import { AlertJournal } from "./alertJournal.js";
import { loadCheckpoint, writeCheckpoint } from "./checkpoint.js";
import { createEip1967SlotChangeAlertFromValues, EIP1967_IMPLEMENTATION_SLOT } from "./eip1967.js";
import { correlateMultiSendAdministrativeEffects } from "./safe/correlation.js";
import { decodeSafeExecTransaction, SAFE_EXEC_TRANSACTION_ABI } from "./safe/decoder.js";
import { analyzeMultiSendTransaction, MULTISEND_ABI, MULTISEND_SELECTOR } from "./safe/multisend.js";
import { createMultiSendAlerts } from "./safe/multisendAlerts.js";
import type { AdministrativeMonitoringConfig, SafeMultisigConfig, SafeOperation } from "./safe/types.js";

const SAFE = getAddress("0x1000000000000000000000000000000000000001");
const TARGET = getAddress("0x2000000000000000000000000000000000000002");
const UNKNOWN_TARGET = getAddress("0x3000000000000000000000000000000000000003");
const IMPLEMENTATION = getAddress("0x4000000000000000000000000000000000000004");
const UNKNOWN_IMPLEMENTATION = getAddress("0x5000000000000000000000000000000000000005");
const MULTISEND = getAddress("0x7000000000000000000000000000000000000007");
const BLOCK_HASH = `0x${"aa".repeat(32)}` as Hex;
const CREATED_AT = "2026-08-01T00:00:00.000Z";
const UPGRADE_ABI = parseAbi(["function upgradeTo(address newImplementation)"]);
const TRANSFER_ABI = parseAbi(["function transfer(address to, uint256 amount) returns (bool)"]);
const APPROVE_ABI = parseAbi(["function approve(address spender, uint256 amount) returns (bool)"]);

function main(): void {
  console.log("Safe MultiSend monitoring offline replay (synthetic fixture, not live RPC and not human-intent evidence)");
  const allowed = scenario("01", [
    pack("CALL", TARGET, transfer(UNKNOWN_TARGET, 1n)),
    pack("CALL", TARGET, transfer(UNKNOWN_TARGET, 2n))
  ]);
  console.log(`allowed batch: ${rules(allowed)}; policy violation=${has(allowed, "SAFE_MULTISEND_POLICY_VIOLATION")}`);

  const unknownTarget = scenario("02", [pack("CALL", TARGET, transfer(UNKNOWN_TARGET, 1n)), pack("CALL", UNKNOWN_TARGET, transfer(TARGET, 1n))]);
  console.log(`unknown target: ${rules(unknownTarget)}`);

  const delegatecall = scenario("03", [pack("DELEGATECALL", UNKNOWN_TARGET, transfer(TARGET, 1n))]);
  console.log(`delegatecall: ${rules(delegatecall)}; severity=${delegatecall.find((alert) => alert.ruleId === "SAFE_NESTED_DELEGATECALL")?.severity}`);

  const unknownUpgrade = scenario("04", [pack("CALL", TARGET, upgrade(UNKNOWN_IMPLEMENTATION))]);
  console.log(`unknown upgrade: ${rules(unknownUpgrade)}`);

  const composed = scenario("05", [
    pack("CALL", TARGET, upgrade(UNKNOWN_IMPLEMENTATION)),
    pack("CALL", TARGET, approve(UNKNOWN_TARGET, 2n ** 255n)),
    pack("CALL", TARGET, transfer(UNKNOWN_TARGET, 10n ** 18n))
  ]);
  const anomaly = composed.find((alert) => alert.ruleId === "SAFE_BATCH_ADMINISTRATIVE_ANOMALY");
  console.log(`composed anomaly: ${anomaly?.ruleId}; components=${((anomaly?.metadata.multiSend as Record<string, unknown>)?.componentSignals as unknown[])?.length ?? 0}`);

  const confirmedScenario = expand("06", [pack("CALL", TARGET, upgrade(IMPLEMENTATION))]);
  if (!confirmedScenario.expansion.complete) throw new Error("Expected complete synthetic expansion.");
  const slot = createEip1967SlotChangeAlertFromValues({
    chain: "ethereum", proxy: { address: TARGET, checkImplementationSlot: true, checkAdminSlot: false },
    slotKind: "implementation", slot: EIP1967_IMPLEMENTATION_SLOT, beforeBlock: 99n, afterBlock: 100n,
    beforeValue: storageWord(UNKNOWN_IMPLEMENTATION), afterValue: storageWord(IMPLEMENTATION), createdAt: CREATED_AT
  });
  if (slot === undefined) throw new Error("Synthetic slot fixture did not produce a change.");
  const confirmed = correlateMultiSendAdministrativeEffects({ chain: "ethereum", transaction: confirmedScenario.transaction,
    operations: confirmedScenario.expansion.operations, administrativeAlerts: [], slotAlerts: [slot], createdAt: CREATED_AT });
  console.log(`confirmed effect: ${rules(confirmed)}; suboperation=${confirmed[0]?.metadata.candidateSuboperations}`);

  const malformed = malformedScenario("07");
  console.log(`malformed payload: ${rules(malformed)}; partial interpretation=false`);

  const all = [...allowed, ...unknownTarget, ...delegatecall, ...unknownUpgrade, ...composed, ...confirmed, ...malformed];
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-multisend-replay-"));
  try {
    const checkpointPath = join(directory, "checkpoint.json");
    const journalPath = join(directory, "journal.jsonl");
    writeCheckpoint(checkpointPath, { version: 1, chain: "ethereum", chainId: 1, lastProcessedBlock: 100n,
      lastProcessedBlockHash: BLOCK_HASH, updatedAt: CREATED_AT });
    new AlertJournal(journalPath).append(all, new Map([["100", BLOCK_HASH]]), CREATED_AT);
    const checkpoint = loadCheckpoint(checkpointPath);
    const restarted = new AlertJournal(journalPath);
    console.log(`restart: checkpoint ${checkpoint?.lastProcessedBlock.toString()} and durable journal restored`);
    console.log(`replay: ${restarted.filterNew(all).length} duplicate alerts emitted`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function scenario(hashSuffix: string, operations: readonly Hex[]): Alert[] {
  const result = expand(hashSuffix, operations);
  return createMultiSendAlerts({ chain: "ethereum", policy: policy(), transaction: result.transaction,
    expansion: result.expansion, outcome: "success", createdAt: CREATED_AT });
}

function malformedScenario(hashSuffix: string): Alert[] {
  const malformedPayload = concatHex([
    pack("CALL", TARGET, transfer(UNKNOWN_TARGET, 1n)),
    concatHex(["0x00", TARGET, numberToHex(0n, { size: 32 }), numberToHex(10n, { size: 32 }), "0x1234"])
  ]);
  const data = encodeFunctionData({ abi: MULTISEND_ABI, functionName: "multiSend", args: [malformedPayload] });
  const result = decode(hashSuffix, data);
  const expansion = analyzeMultiSendTransaction({ transaction: result, policy: policy(), config: config() });
  if (!expansion.recognized) throw new Error("Expected configured MultiSend.");
  return createMultiSendAlerts({ chain: "ethereum", policy: policy(), transaction: result, expansion, outcome: "success", createdAt: CREATED_AT });
}

function expand(hashSuffix: string, operations: readonly Hex[]) {
  const transaction = decode(hashSuffix, encodeFunctionData({ abi: MULTISEND_ABI, functionName: "multiSend", args: [concatHex(operations)] }));
  const expansion = analyzeMultiSendTransaction({ transaction, policy: policy(), config: config() });
  if (!expansion.recognized) throw new Error("Expected configured MultiSend.");
  return { transaction, expansion };
}

function decode(hashSuffix: string, data: Hex) {
  const hash = `0x${hashSuffix.padStart(64, "0")}` as Hex;
  const input = encodeFunctionData({ abi: SAFE_EXEC_TRANSACTION_ABI, functionName: "execTransaction",
    args: [MULTISEND, 0n, data, 1, 100_000n, 0n, 0n, SAFE, SAFE, "0x1234"] });
  const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: { hash, to: SAFE, input, value: 0n, blockNumber: 100n } });
  if (!decoded.decoded) throw new Error(decoded.error);
  return decoded.transaction;
}

function pack(operation: SafeOperation, target: Address, data: Hex, value = 0n): Hex {
  return concatHex([numberToHex(operation === "CALL" ? 0 : 1, { size: 1 }), target,
    numberToHex(value, { size: 32 }), numberToHex(BigInt(size(data)), { size: 32 }), data]);
}
function transfer(to: Address, amount: bigint): Hex { return encodeFunctionData({ abi: TRANSFER_ABI, functionName: "transfer", args: [to, amount] }); }
function approve(spender: Address, amount: bigint): Hex { return encodeFunctionData({ abi: APPROVE_ABI, functionName: "approve", args: [spender, amount] }); }
function upgrade(implementation: Address): Hex { return encodeFunctionData({ abi: UPGRADE_ABI, functionName: "upgradeTo", args: [implementation] }); }

function policy(): SafeMultisigConfig {
  const selectors = [MULTISEND_SELECTOR, transfer(TARGET, 0n).slice(0, 10), approve(TARGET, 0n).slice(0, 10), upgrade(IMPLEMENTATION).slice(0, 10)] as Hex[];
  return { name: "Synthetic Security Council", address: SAFE, criticality: "critical", allowedTargets: [MULTISEND, TARGET],
    allowedSelectors: selectors, allowedOperations: ["CALL", "DELEGATECALL"], allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: 0n,
    allowedOwners: [], allowedThresholds: [], allowedModules: [], allowedGuards: [], allowedFallbackHandlers: [],
    multisendAlertDetail: "all",
    financialOperationPolicy: { emitAllowedTransfers: true, emitAllowedApprovals: true, maxNativeValueWei: 0n, notableTokenTargets: [] }, modulePolicies: [] };
}
function config(): AdministrativeMonitoringConfig {
  return { multisigs: [policy()], multisendContracts: [{ name: "Synthetic MultiSend", address: MULTISEND, mode: "MULTISEND" }],
    multisendLimits: { maxDepth: 2, maxSuboperations: 50, maxTotalPayloadBytes: 20_000, maxSuboperationDataBytes: 5_000 } };
}
function storageWord(address: string): Hex { return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}` as Hex; }
function rules(alerts: readonly Alert[]): string { return alerts.map((alert) => alert.ruleId).join(", "); }
function has(alerts: readonly Alert[], ruleId: string): boolean { return alerts.some((alert) => alert.ruleId === ruleId); }

main();
