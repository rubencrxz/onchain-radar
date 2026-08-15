import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Alert } from "../src/alerts.js";
import { createEip1967SlotChangeAlertFromValues, EIP1967_IMPLEMENTATION_SLOT } from "../src/eip1967.js";
import { buildEventTopicMap } from "../src/events.js";
import { executeHistoricalScan } from "../src/historicalScanner.js";
import { processLogs } from "../src/processor.js";
import type { RpcClient } from "../src/rpc.js";
import { classifySafeAction } from "../src/safe/actions.js";
import { createSafeMonitoringAlerts } from "../src/safe/alerts.js";
import { correlateSafeAdministrativeEffects } from "../src/safe/correlation.js";
import { decodeSafeExecTransaction } from "../src/safe/decoder.js";
import { evaluateSafePolicy } from "../src/safe/policy.js";
import { addressToStorageWord, emptyAllowlists, FIXED_CREATED_AT } from "./fixtures.js";
import {
  IMPLEMENTATION,
  SAFE,
  SAFE_TX_HASH,
  TARGET,
  UNKNOWN_IMPLEMENTATION,
  UNKNOWN_TARGET,
  execTransactionInput,
  innerUpgrade,
  rpcReceipt,
  rpcTransaction,
  safeExecutionLog,
  safeMonitorConfig,
  safePolicy,
  upgradedLog
} from "./safeFixtures.js";

function reconstruct(input = execTransactionInput()) {
  const result = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(input) });
  assert.ok(result.decoded);
  return result.transaction;
}

describe("Safe monitoring signals", () => {
  test("emits only execution and sensitive-action signals for an allowed operation", () => {
    const transaction = reconstruct();
    const action = classifySafeAction(TARGET, transaction.innerData);
    const evaluation = evaluateSafePolicy(transaction, action, safePolicy());
    const ruleIds = createSafeMonitoringAlerts({ chain: "ethereum", policy: safePolicy(), transaction, action, evaluation, outcome: "success", createdAt: "fixed" }).map((alert) => alert.ruleId);
    assert.deepEqual(ruleIds, ["SAFE_TRANSACTION_EXECUTED", "SAFE_SENSITIVE_ADMIN_ACTION"]);
  });

  test("emits unknown target and aggregated policy violation for CALL", () => {
    const transaction = reconstruct(execTransactionInput({ target: UNKNOWN_TARGET }));
    const action = classifySafeAction(UNKNOWN_TARGET, transaction.innerData);
    const evaluation = evaluateSafePolicy(transaction, action, safePolicy());
    const alerts = createSafeMonitoringAlerts({ chain: "ethereum", policy: safePolicy(), transaction, action, evaluation, outcome: "success", createdAt: "fixed" });
    assert.equal(alerts.find((alert) => alert.ruleId === "SAFE_UNKNOWN_TARGET")?.severity, "WARNING");
    assert.ok(alerts.some((alert) => alert.ruleId === "SAFE_POLICY_VIOLATION"));
  });

  test("never hides DELEGATECALL and elevates a prohibited one", () => {
    const transaction = reconstruct(execTransactionInput({ operation: "DELEGATECALL" }));
    const action = classifySafeAction(TARGET, transaction.innerData);
    const evaluation = evaluateSafePolicy(transaction, action, safePolicy());
    const alert = createSafeMonitoringAlerts({ chain: "ethereum", policy: safePolicy(), transaction, action, evaluation, outcome: "success", createdAt: "fixed" }).find((item) => item.ruleId === "SAFE_DELEGATECALL_EXECUTED");
    assert.equal(alert?.severity, "CRITICAL");

    const allowlisted = evaluateSafePolicy(transaction, action, safePolicy({ allowedOperations: ["CALL", "DELEGATECALL"] }));
    const reduced = createSafeMonitoringAlerts({ chain: "ethereum", policy: safePolicy({ allowedOperations: ["CALL", "DELEGATECALL"] }), transaction, action, evaluation: allowlisted, outcome: "success", createdAt: "fixed" }).find((item) => item.ruleId === "SAFE_DELEGATECALL_EXECUTED");
    assert.equal(reduced?.severity, "WARNING");
  });

  test("reports unknown selector, excessive native value and unknown implementation explicitly", () => {
    const unknownSelectorTx = reconstruct(execTransactionInput({ data: "0x12345678", value: 1n }));
    const unknownAction = classifySafeAction(TARGET, unknownSelectorTx.innerData);
    const unknownEvaluation = evaluateSafePolicy(unknownSelectorTx, unknownAction, safePolicy());
    const unknownRules = createSafeMonitoringAlerts({ chain: "ethereum", policy: safePolicy(), transaction: unknownSelectorTx, action: unknownAction, evaluation: unknownEvaluation, outcome: "success", createdAt: "fixed" }).map((alert) => alert.ruleId);
    assert.ok(unknownRules.includes("SAFE_UNKNOWN_SELECTOR"));
    assert.ok(unknownRules.includes("SAFE_NATIVE_VALUE_ANOMALY"));

    const upgradeTx = reconstruct(execTransactionInput({ data: innerUpgrade(UNKNOWN_IMPLEMENTATION) }));
    const upgradeAction = classifySafeAction(TARGET, upgradeTx.innerData);
    const upgradeEvaluation = evaluateSafePolicy(upgradeTx, upgradeAction, safePolicy());
    const upgradeRules = createSafeMonitoringAlerts({ chain: "ethereum", policy: safePolicy(), transaction: upgradeTx, action: upgradeAction, evaluation: upgradeEvaluation, outcome: "success", createdAt: "fixed" }).map((alert) => alert.ruleId);
    assert.ok(upgradeRules.includes("SAFE_UNKNOWN_IMPLEMENTATION_UPGRADE"));
    assert.ok(upgradeRules.includes("SAFE_POLICY_VIOLATION"));
  });
});

describe("Safe administrative effect correlation", () => {
  function effects(implementation = IMPLEMENTATION) {
    const processed = processLogs({ chain: "ethereum", logs: [upgradedLog(implementation)], topicMap: buildEventTopicMap(["Upgraded(address)"]), allowlists: emptyAllowlists(), clock: () => FIXED_CREATED_AT });
    const slot = createEip1967SlotChangeAlertFromValues({ chain: "ethereum", proxy: { address: TARGET, checkImplementationSlot: true, checkAdminSlot: false }, slotKind: "implementation", slot: EIP1967_IMPLEMENTATION_SLOT, beforeBlock: 99n, afterBlock: 100n, beforeValue: addressToStorageWord(UNKNOWN_TARGET), afterValue: addressToStorageWord(implementation), createdAt: FIXED_CREATED_AT });
    assert.ok(slot);
    return { event: processed.alerts[0]!, slot };
  }

  test("confirms matching calldata, event and slot in one stable correlation", () => {
    const transaction = reconstruct();
    const action = classifySafeAction(TARGET, transaction.innerData);
    const { event, slot } = effects();
    const alerts = correlateSafeAdministrativeEffects({ chain: "ethereum", transaction, action, administrativeAlerts: [event], slotAlerts: [slot], createdAt: FIXED_CREATED_AT });
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED");
    assert.deepEqual((alerts[0]?.metadata.safeCorrelation as any).componentRuleIds, ["PROXY_UPGRADED", "PROXY_IMPLEMENTATION_SLOT_CHANGED"]);
  });

  test("reports implementation divergence and does not correlate absent counterparts", () => {
    const transaction = reconstruct();
    const action = classifySafeAction(TARGET, transaction.innerData);
    const { event, slot } = effects(UNKNOWN_IMPLEMENTATION);
    const mismatch = correlateSafeAdministrativeEffects({ chain: "ethereum", transaction, action, administrativeAlerts: [event], slotAlerts: [slot], createdAt: FIXED_CREATED_AT });
    assert.equal(mismatch[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_INCONSISTENCY");
    assert.equal(correlateSafeAdministrativeEffects({ chain: "ethereum", transaction, action, administrativeAlerts: [], slotAlerts: [], createdAt: FIXED_CREATED_AT }).length, 0);
  });
});

describe("historical Safe integration", () => {
  test("reconstructs once, preserves phase order and correlates event plus EIP-1967 slot", async () => {
    const storage = [addressToStorageWord(UNKNOWN_TARGET), addressToStorageWord(IMPLEMENTATION)];
    const rpc: RpcClient = {
      async getLogs() { return [upgradedLog(), safeExecutionLog()]; },
      async getStorageAt() { return storage.shift(); },
      async getErc20Balance() { return 0n; },
      async getTransaction() { return rpcTransaction(); },
      async getTransactionReceipt() { return rpcReceipt(); }
    };
    const result = await executeHistoricalScan({ rpc, config: safeMonitorConfig(safePolicy(), { proxy: true }), startBlock: 100n, endBlock: 100n, maxBlockRange: 10n, clock: () => FIXED_CREATED_AT, sinks: [] });
    assert.equal(result.safeTransactionCount, 1);
    assert.deepEqual(result.alerts.map((alert) => alert.ruleId), [
      "PROXY_UPGRADED", "SAFE_EXECUTION_SUCCESS",
      "SAFE_TRANSACTION_EXECUTED", "SAFE_SENSITIVE_ADMIN_ACTION",
      "PROXY_IMPLEMENTATION_SLOT_CHANGED", "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED"
    ]);
    assert.equal(new Set(result.alerts.map((alert) => alert.id)).size, result.alerts.length);
  });

  test("does not request transactions or receipts when administrativeMonitoring is absent", async () => {
    let transactionCalls = 0;
    const config = safeMonitorConfig();
    delete config.administrativeMonitoring;
    const rpc: RpcClient = {
      async getLogs() { return []; }, async getStorageAt() { return undefined; }, async getErc20Balance() { return 0n; },
      async getTransaction() { transactionCalls += 1; return rpcTransaction(); },
      async getTransactionReceipt() { transactionCalls += 1; return rpcReceipt(); }
    };
    const result = await executeHistoricalScan({ rpc, config, startBlock: 100n, endBlock: 100n, maxBlockRange: 10n, clock: () => FIXED_CREATED_AT, sinks: [] });
    assert.equal(transactionCalls, 0);
    assert.equal(result.safeAlertCount, 0);
  });
});
