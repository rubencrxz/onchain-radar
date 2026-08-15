import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, getAddress, type Hex } from "viem";
import { classifySafeAction } from "../src/safe/actions.js";
import { createMultiSendAlerts } from "../src/safe/multisendAlerts.js";
import { analyzeMultiSendTransaction } from "../src/safe/multisend.js";
import { evaluateSafePolicy } from "../src/safe/policy.js";
import { administrativeMultiSendConfig, multiSendExecInput, packSuboperation, MULTISEND } from "./multisendFixtures.js";
import { SAFE, TARGET, UNKNOWN_TARGET, USER, rpcTransaction, safePolicy } from "./safeFixtures.js";
import { decodeSafeExecTransaction } from "../src/safe/decoder.js";

describe("Safe semantic categories and MultiSend noise controls", () => {
  test("classifies administrative control, protocol administration, financial and unknown operations", () => {
    assert.equal(classifySafeAction(SAFE, actionData("changeThreshold", [2n])).semanticCategory, "ADMINISTRATIVE_CONTROL");
    assert.equal(classifySafeAction(TARGET, actionData("pause", [])).semanticCategory, "PROTOCOL_ADMINISTRATION");
    assert.equal(classifySafeAction(TARGET, actionData("transfer", [USER, 1n])).semanticCategory, "FINANCIAL_OPERATION");
    assert.equal(classifySafeAction(TARGET, actionData("approve", [USER, 1n])).semanticCategory, "FINANCIAL_OPERATION");
    assert.equal(classifySafeAction(TARGET, "0xd0e30db0").semanticCategory, "FINANCIAL_OPERATION");
    assert.equal(classifySafeAction(TARGET, "0x12345678").semanticCategory, "UNKNOWN_OPERATION");
    assert.equal(classifySafeAction(USER, "0x", 1n).semanticCategory, "FINANCIAL_OPERATION");
  });

  test("does not enforce SAFE_SENSITIVE_ADMIN_ACTION for transfer or approve", () => {
    for (const data of [actionData("transfer", [USER, 1n]), actionData("approve", [USER, 1n])]) {
      const alerts = alertsFor([packSuboperation({ target: TARGET, data })], "all");
      assert.ok(alerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL"));
      assert.ok(!alerts.some((alert) => alert.ruleId === "SAFE_SENSITIVE_ADMIN_ACTION"));
    }
  });

  test("supports all, sensitive-only and violations-only while always retaining the summary", () => {
    const transfer = packSuboperation({ target: TARGET, data: actionData("transfer", [USER, 1n]) });
    const all = alertsFor([transfer], "all");
    const sensitive = alertsFor([transfer], "sensitive-only");
    const violations = alertsFor([transfer], "violations-only");
    for (const alerts of [all, sensitive, violations]) {
      assert.ok(alerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_EXECUTED"));
    }
    assert.equal(all.filter((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL").length, 1);
    assert.equal(sensitive.filter((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL").length, 0);
    assert.equal(violations.filter((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL").length, 0);
  });

  test("emits only the violating routine subcall in violations-only", () => {
    const alerts = alertsFor([
      packSuboperation({ target: TARGET, data: actionData("transfer", [USER, 1n]) }),
      packSuboperation({ target: UNKNOWN_TARGET, data: actionData("transfer", [USER, 1n]) })
    ], "violations-only");
    const subcalls = alerts.filter((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL");
    assert.equal(subcalls.length, 1);
    assert.match(subcalls[0]!.summary, /suboperation 1/);
    assert.ok(alerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_POLICY_VIOLATION"));
  });

  test("treats unknown module and unsafe threshold as critical explicit policy violations", () => {
    const moduleData = actionData("enableModule", [UNKNOWN_TARGET]);
    const thresholdData = actionData("changeThreshold", [1n]);
    for (const data of [moduleData, thresholdData]) {
      const policy = safePolicy({
        allowedTargets: [SAFE],
        allowedSelectors: [data.slice(0, 10) as Hex],
        allowedOperations: ["CALL"],
        allowedModules: [TARGET],
        minimumThreshold: 2,
        allowedThresholds: [2, 3]
      });
      const transaction = {
        safeAddress: SAFE, outerTransactionHash: `0x${"ab".repeat(32)}` as Hex, blockNumber: 100n,
        innerTarget: SAFE, innerValue: 0n, innerData: data, innerSelector: data.slice(0, 10) as Hex,
        operation: "CALL" as const, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n,
        gasToken: getAddress("0x0000000000000000000000000000000000000000"),
        refundReceiver: getAddress("0x0000000000000000000000000000000000000000")
      };
      const evaluation = evaluateSafePolicy(transaction, classifySafeAction(SAFE, data), policy);
      assert.equal(evaluation.compliant, false);
      assert.ok(evaluation.violations.some((violation) => violation.kind === (data === moduleData ? "module" : "threshold")));
    }
  });
});

function alertsFor(operations: Hex[], detail: "all" | "sensitive-only" | "violations-only") {
  const config = administrativeMultiSendConfig();
  const base = config.multisigs[0]!;
  const policy = {
    ...base,
    multisendAlertDetail: detail,
    financialOperationPolicy: { ...base.financialOperationPolicy, emitAllowedTransfers: false, emitAllowedApprovals: false },
    allowedTargets: [...base.allowedTargets, MULTISEND]
  };
  config.multisigs = [policy];
  const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(multiSendExecInput(operations)) });
  assert.equal(decoded.decoded, true);
  if (!decoded.decoded) throw new Error("Safe fixture did not decode.");
  const expansion = analyzeMultiSendTransaction({ transaction: decoded.transaction, policy, config });
  assert.equal(expansion.recognized, true);
  if (!expansion.recognized) throw new Error("Expected MultiSend");
  return createMultiSendAlerts({
    chain: "ethereum", policy, transaction: decoded.transaction, expansion,
    outcome: "success", createdAt: "2026-01-01T00:00:00.000Z"
  });
}

function actionData(name: "changeThreshold" | "pause" | "transfer" | "approve" | "enableModule", args: readonly unknown[]): Hex {
  if (name === "pause") return SAFE_ACTION_SELECTORS_FOR_TEST.pause;
  if (name === "changeThreshold") return encodeFunctionData({ abi: [{ type: "function", name, stateMutability: "nonpayable", inputs: [{ name: "threshold", type: "uint256" }], outputs: [] }], functionName: name, args: [args[0] as bigint] });
  if (name === "enableModule") return encodeFunctionData({ abi: [{ type: "function", name, stateMutability: "nonpayable", inputs: [{ name: "module", type: "address" }], outputs: [] }], functionName: name, args: [args[0] as `0x${string}`] });
  if (name === "transfer") return encodeFunctionData({ abi: [{ type: "function", name, stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] }], functionName: name, args: [args[0] as `0x${string}`, args[1] as bigint] });
  return encodeFunctionData({ abi: [{ type: "function", name: "approve", stateMutability: "nonpayable", inputs: [{ name: "spender", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] }], functionName: "approve", args: [args[0] as `0x${string}`, args[1] as bigint] });
}

const SAFE_ACTION_SELECTORS_FOR_TEST = {
  pause: "0x8456cb59" as Hex
};
