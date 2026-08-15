import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, parseAbi, type Address, type Hex } from "viem";
import { classifySafeAction, SAFE_ACTION_SELECTORS } from "../src/safe/actions.js";
import { createSafeMonitoringAlerts } from "../src/safe/alerts.js";
import { decodeSafeExecTransaction, SAFE_EXEC_TRANSACTION_SELECTOR } from "../src/safe/decoder.js";
import { evaluateSafePolicy } from "../src/safe/policy.js";
import {
  IMPLEMENTATION,
  SAFE,
  TARGET,
  UNKNOWN_IMPLEMENTATION,
  UNKNOWN_TARGET,
  USER,
  execTransactionInput,
  innerTransfer,
  innerUpgrade,
  rpcTransaction,
  safePolicy
} from "./safeFixtures.js";

describe("Safe execTransaction decoding", () => {
  test("decodes CALL, bigint fields, empty inner data and known/unknown selectors", () => {
    const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction() });
    assert.equal(decoded.decoded, true);
    if (!decoded.decoded) return;
    assert.equal(decoded.transaction.operation, "CALL");
    assert.equal(decoded.transaction.innerTarget, TARGET);
    assert.equal(decoded.transaction.safeTxGas, 100_000n);
    assert.equal(classifySafeAction(TARGET, decoded.transaction.innerData).functionName, "upgradeTo");

    const empty = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(execTransactionInput({ data: "0x" })) });
    assert.equal(empty.decoded && empty.transaction.innerSelector, "0x");
    assert.equal(classifySafeAction(TARGET, "0x12345678").known, false);
  });

  test("distinguishes DELEGATECALL, unsupported selector and malformed calldata", () => {
    const delegate = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(execTransactionInput({ operation: "DELEGATECALL" })) });
    assert.equal(delegate.decoded && delegate.transaction.operation, "DELEGATECALL");
    const unsupported = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction("0x12345678") });
    assert.equal(!unsupported.decoded && unsupported.failureKind, "UNSUPPORTED_OUTER_SELECTOR");
    const malformed = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(`${SAFE_EXEC_TRANSACTION_SELECTOR}00` as Hex) });
    assert.equal(!malformed.decoded && malformed.failureKind, "MALFORMED_CALLDATA");
  });
});

describe("Safe action classification", () => {
  test("classifies upgrades, ownership, roles, pause, Safe management and ERC-20 actions", () => {
    const fixtures: Array<[string, readonly unknown[], string]> = [
      ["function upgradeTo(address newImplementation)", [IMPLEMENTATION], "upgradeTo"],
      ["function upgradeToAndCall(address newImplementation, bytes data)", [IMPLEMENTATION, "0x"], "upgradeToAndCall"],
      ["function changeAdmin(address newAdmin)", [USER], "changeAdmin"],
      ["function upgrade(address proxy, address implementation)", [TARGET, IMPLEMENTATION], "upgrade"],
      ["function upgradeAndCall(address proxy, address implementation, bytes data)", [TARGET, IMPLEMENTATION, "0x"], "upgradeAndCall"],
      ["function changeProxyAdmin(address proxy, address newAdmin)", [TARGET, USER], "changeProxyAdmin"],
      ["function transferOwnership(address newOwner)", [USER], "transferOwnership"],
      ["function grantRole(bytes32 role, address account)", [`0x${"11".repeat(32)}`, USER], "grantRole"],
      ["function revokeRole(bytes32 role, address account)", [`0x${"11".repeat(32)}`, USER], "revokeRole"],
      ["function pause()", [], "pause"],
      ["function unpause()", [], "unpause"],
      ["function enableModule(address module)", [USER], "enableModule"],
      ["function disableModule(address prevModule, address module)", [TARGET, USER], "disableModule"],
      ["function addOwnerWithThreshold(address owner, uint256 threshold)", [USER, 2n], "addOwnerWithThreshold"],
      ["function removeOwner(address prevOwner, address owner, uint256 threshold)", [TARGET, USER, 1n], "removeOwner"],
      ["function swapOwner(address prevOwner, address oldOwner, address newOwner)", [TARGET, IMPLEMENTATION, USER], "swapOwner"],
      ["function changeThreshold(uint256 threshold)", [3n], "changeThreshold"],
      ["function transfer(address to, uint256 amount)", [USER, 4n], "transfer"],
      ["function approve(address spender, uint256 amount)", [USER, 5n], "approve"]
    ];
    for (const [definition, args, expected] of fixtures) {
      const abi = parseAbi([definition]);
      const data = encodeFunctionData({ abi, functionName: expected, args } as any);
      const action = classifySafeAction(TARGET, data);
      assert.equal(action.functionName, expected);
    }
  });
});

describe("Safe policy evaluation", () => {
  function decodedTransaction(input = execTransactionInput()) {
    const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(input) });
    assert.ok(decoded.decoded);
    return decoded.transaction;
  }

  test("accepts allowlisted target, selector, CALL, value and implementation", () => {
    const transaction = decodedTransaction();
    const evaluation = evaluateSafePolicy(transaction, classifySafeAction(TARGET, transaction.innerData), safePolicy());
    assert.equal(evaluation.compliant, true);
    assert.deepEqual(evaluation.violations, []);
  });

  test("reports target, selector, operation, value and implementation violations together", () => {
    const input = execTransactionInput({ target: UNKNOWN_TARGET, value: 9n, data: innerUpgrade(UNKNOWN_IMPLEMENTATION), operation: "DELEGATECALL" });
    const transaction = decodedTransaction(input);
    const evaluation = evaluateSafePolicy(transaction, classifySafeAction(UNKNOWN_TARGET, transaction.innerData), safePolicy());
    assert.deepEqual(evaluation.violations.map((item) => item.kind), ["target", "operation", "native-value", "implementation"]);
    assert.equal(evaluation.compliant, false);
  });

  test("separates an unclassified selector from an explicitly allowed selector", () => {
    const input = execTransactionInput({ data: "0x12345678" });
    const transaction = decodedTransaction(input);
    const action = classifySafeAction(TARGET, transaction.innerData);
    const denied = evaluateSafePolicy(transaction, action, safePolicy());
    const allowed = evaluateSafePolicy(transaction, action, safePolicy({ allowedSelectors: ["0x12345678"] }));
    assert.equal(action.known, false);
    assert.equal(denied.selectorAllowed, false);
    assert.equal(allowed.selectorAllowed, true);
  });

  test("produces JSON-safe deterministic alerts for bigint parameters", () => {
    const transaction = decodedTransaction(execTransactionInput({ data: innerTransfer() }));
    const action = classifySafeAction(TARGET, transaction.innerData);
    const evaluation = evaluateSafePolicy(transaction, action, safePolicy());
    const alerts = createSafeMonitoringAlerts({ chain: "ethereum", policy: safePolicy(), transaction, action, evaluation, outcome: "success", createdAt: "fixed" });
    assert.doesNotThrow(() => JSON.stringify(alerts));
    assert.equal(alerts[0]?.id.includes("fixed"), false);
    assert.equal((alerts.find((alert) => alert.ruleId === "SAFE_TRANSACTION_EXECUTED")?.metadata.safe as any).action.parameters.amount, "123");
    assert.equal(alerts.some((alert) => alert.ruleId === "SAFE_SENSITIVE_ADMIN_ACTION"), false);
    assert.equal(SAFE_ACTION_SELECTORS["transfer(address,uint256)"], "0xa9059cbb");
  });
});
