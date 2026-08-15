import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeFunctionData, getAddress, parseAbi, type Hex } from "viem";
import type { Alert } from "./alerts.js";
import { AlertJournal } from "./alertJournal.js";
import { createEip1967SlotChangeAlertFromValues, EIP1967_IMPLEMENTATION_SLOT } from "./eip1967.js";
import { classifySafeAction } from "./safe/actions.js";
import { createSafeMonitoringAlerts } from "./safe/alerts.js";
import { correlateSafeAdministrativeEffects } from "./safe/correlation.js";
import { decodeSafeExecTransaction, SAFE_EXEC_TRANSACTION_ABI } from "./safe/decoder.js";
import { evaluateSafePolicy } from "./safe/policy.js";
import type { SafeMultisigConfig, SafeOperation } from "./safe/types.js";

const SAFE = getAddress("0x1000000000000000000000000000000000000001");
const TARGET = getAddress("0x2000000000000000000000000000000000000002");
const UNKNOWN_TARGET = getAddress("0x3000000000000000000000000000000000000003");
const IMPLEMENTATION = getAddress("0x4000000000000000000000000000000000000004");
const UNKNOWN_IMPLEMENTATION = getAddress("0x5000000000000000000000000000000000000005");
const ZERO = getAddress("0x0000000000000000000000000000000000000000");
const BLOCK_HASH = `0x${"aa".repeat(32)}`;
const CREATED_AT = "2026-07-31T00:00:00.000Z";
const UPGRADE_ABI = parseAbi(["function upgradeTo(address newImplementation)"]);
const TRANSFER_ABI = parseAbi(["function transfer(address to, uint256 amount)"]);

function main(): void {
  console.log("Safe administrative monitoring offline replay (synthetic fixture, not Bybit and not live RPC)");
  const allowed = scenario("01", TARGET, encodeFunctionData({ abi: TRANSFER_ABI, functionName: "transfer", args: [UNKNOWN_TARGET, 1n] }), "CALL");
  console.log(`allowed operation: ${rules(allowed)}; policy violation=${allowed.some((alert) => alert.ruleId === "SAFE_POLICY_VIOLATION")}`);

  const unknownTarget = scenario("02", UNKNOWN_TARGET, encodeFunctionData({ abi: TRANSFER_ABI, functionName: "transfer", args: [TARGET, 1n] }), "CALL");
  console.log(`unknown target: ${rules(unknownTarget)}`);

  const delegatecall = scenario("03", TARGET, encodeFunctionData({ abi: TRANSFER_ABI, functionName: "transfer", args: [TARGET, 1n] }), "DELEGATECALL");
  console.log(`delegatecall: ${rules(delegatecall)}`);

  const unknownUpgrade = scenario("04", TARGET, encodeFunctionData({ abi: UPGRADE_ABI, functionName: "upgradeTo", args: [UNKNOWN_IMPLEMENTATION] }), "CALL");
  console.log(`unknown upgrade: ${rules(unknownUpgrade)}`);

  const upgradeTransaction = decode("05", TARGET, encodeFunctionData({ abi: UPGRADE_ABI, functionName: "upgradeTo", args: [IMPLEMENTATION] }), "CALL");
  const action = classifySafeAction(upgradeTransaction.innerTarget, upgradeTransaction.innerData);
  const slot = createEip1967SlotChangeAlertFromValues({
    chain: "ethereum",
    proxy: { address: TARGET, checkImplementationSlot: true, checkAdminSlot: false },
    slotKind: "implementation",
    slot: EIP1967_IMPLEMENTATION_SLOT,
    beforeBlock: 99n,
    afterBlock: 100n,
    beforeValue: storageWord(UNKNOWN_IMPLEMENTATION),
    afterValue: storageWord(IMPLEMENTATION),
    createdAt: CREATED_AT
  });
  if (slot === undefined) throw new Error("Synthetic slot fixture did not produce a change.");
  const confirmed = correlateSafeAdministrativeEffects({ chain: "ethereum", transaction: upgradeTransaction, action, administrativeAlerts: [], slotAlerts: [slot], createdAt: CREATED_AT });
  console.log(`confirmed effect: ${rules(confirmed)}`);

  const all = [...allowed, ...unknownTarget, ...delegatecall, ...unknownUpgrade, ...confirmed];
  const directory = mkdtempSync(join(tmpdir(), "onchain-radar-safe-replay-"));
  try {
    const journalPath = join(directory, "safe-journal.jsonl");
    const journal = new AlertJournal(journalPath);
    journal.append(all, new Map([["100", BLOCK_HASH]]), CREATED_AT);
    const restarted = new AlertJournal(journalPath);
    console.log("restart: durable journal restored");
    console.log(`replay: ${restarted.filterNew(all).length} duplicate alerts emitted`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function scenario(hashSuffix: string, target: typeof TARGET, data: Hex, operation: SafeOperation): Alert[] {
  const transaction = decode(hashSuffix, target, data, operation);
  const action = classifySafeAction(transaction.innerTarget, transaction.innerData);
  const policyEvaluation = evaluateSafePolicy(transaction, action, policy());
  return createSafeMonitoringAlerts({ chain: "ethereum", policy: policy(), transaction, action, evaluation: policyEvaluation, outcome: "success", createdAt: CREATED_AT });
}

function decode(hashSuffix: string, target: typeof TARGET, data: Hex, operation: SafeOperation) {
  const hash = `0x${hashSuffix.padStart(64, "0")}` as Hex;
  const input = encodeFunctionData({ abi: SAFE_EXEC_TRANSACTION_ABI, functionName: "execTransaction", args: [target, 0n, data, operation === "CALL" ? 0 : 1, 100_000n, 0n, 0n, ZERO, ZERO, "0x1234"] });
  const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: { hash, to: SAFE, input, value: 0n, blockNumber: 100n } });
  if (!decoded.decoded) throw new Error(decoded.error);
  return decoded.transaction;
}

function policy(): SafeMultisigConfig {
  return {
    name: "Synthetic Security Council",
    address: SAFE,
    criticality: "critical",
    allowedTargets: [TARGET],
    allowedSelectors: [encodeFunctionData({ abi: TRANSFER_ABI, functionName: "transfer", args: [TARGET, 0n] }).slice(0, 10) as Hex, encodeFunctionData({ abi: UPGRADE_ABI, functionName: "upgradeTo", args: [IMPLEMENTATION] }).slice(0, 10) as Hex],
    allowedOperations: ["CALL"],
    allowedImplementations: [IMPLEMENTATION],
    maxNativeValueWei: 0n,
    allowedOwners: [], allowedThresholds: [], allowedModules: [], allowedGuards: [], allowedFallbackHandlers: [],
    multisendAlertDetail: "sensitive-only",
    financialOperationPolicy: { emitAllowedTransfers: false, emitAllowedApprovals: false, maxNativeValueWei: 0n, notableTokenTargets: [] },
    modulePolicies: []
  };
}

function storageWord(address: string): Hex { return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}` as Hex; }
function rules(alerts: readonly Alert[]): string { return alerts.map((alert) => alert.ruleId).join(", "); }

main();
