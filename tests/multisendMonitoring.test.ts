import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, parseAbi, type Hex } from "viem";
import type { Alert } from "../src/alerts.js";
import { createEip1967SlotChangeAlertFromValues, EIP1967_IMPLEMENTATION_SLOT } from "../src/eip1967.js";
import { buildEventTopicMap } from "../src/events.js";
import { processLogs } from "../src/processor.js";
import { correlateMultiSendAdministrativeEffects } from "../src/safe/correlation.js";
import { decodeSafeExecTransaction } from "../src/safe/decoder.js";
import { analyzeMultiSendTransaction } from "../src/safe/multisend.js";
import { createMultiSendAlerts } from "../src/safe/multisendAlerts.js";
import { addressToStorageWord, emptyAllowlists, FIXED_CREATED_AT } from "./fixtures.js";
import {
  IMPLEMENTATION,
  MULTISEND,
  NESTED_MULTISEND,
  SAFE,
  TARGET,
  UNKNOWN_TARGET,
  administrativeMultiSendConfig,
  multiSendData,
  multiSendExecInput,
  packSuboperation
} from "./multisendFixtures.js";
import { UNKNOWN_IMPLEMENTATION, execTransactionInput, innerTransfer, innerUpgrade, rpcTransaction, upgradedLog } from "./safeFixtures.js";

const APPROVE_ABI = parseAbi(["function approve(address spender, uint256 amount) returns (bool)"]);

function analyze(operations: readonly Hex[], config = administrativeMultiSendConfig()) {
  const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(multiSendExecInput(operations)) });
  assert.ok(decoded.decoded);
  const policy = config.multisigs[0]!;
  const expansion = analyzeMultiSendTransaction({ transaction: decoded.transaction, policy, config });
  assert.equal(expansion.recognized, true);
  return { transaction: decoded.transaction, policy, expansion };
}

function alerts(operations: readonly Hex[], config = administrativeMultiSendConfig()) {
  const result = analyze(operations, config);
  assert.ok(result.expansion.recognized);
  return {
    ...result,
    alerts: createMultiSendAlerts({ chain: "ethereum", policy: result.policy, transaction: result.transaction,
      expansion: result.expansion, outcome: "success", createdAt: FIXED_CREATED_AT })
  };
}

describe("Safe MultiSend expansion, policy and identity", () => {
  test("recognizes only a configured target with exact selector", () => {
    const valid = analyze([packSuboperation()]).expansion;
    assert.ok(valid.recognized && valid.complete);

    const unknownTargetDecoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(multiSendExecInput([], { multiSend: UNKNOWN_TARGET })) });
    assert.ok(unknownTargetDecoded.decoded);
    assert.deepEqual(analyzeMultiSendTransaction({ transaction: unknownTargetDecoded.transaction, policy: administrativeMultiSendConfig().multisigs[0]!, config: administrativeMultiSendConfig() }),
      { recognized: false, reason: "TARGET_NOT_CONFIGURED" });

    const wrongSelectorDecoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(execTransactionInput({ target: MULTISEND, data: "0x12345678" })) });
    assert.ok(wrongSelectorDecoded.decoded);
    assert.deepEqual(analyzeMultiSendTransaction({ transaction: wrongSelectorDecoded.transaction, policy: administrativeMultiSendConfig().multisigs[0]!, config: administrativeMultiSendConfig() }),
      { recognized: false, reason: "UNEXPECTED_SELECTOR" });
  });

  test("analyzes all suboperations depth-first with stable paths and distinct IDs", () => {
    const nested = multiSendData([
      packSuboperation({ target: TARGET, data: innerTransfer() }),
      packSuboperation({ target: TARGET, data: innerTransfer() })
    ]);
    const allDetail = administrativeMultiSendConfig();
    allDetail.multisigs[0]!.multisendAlertDetail = "all";
    const result = alerts([
      packSuboperation({ target: NESTED_MULTISEND, data: nested }),
      packSuboperation({ target: TARGET, data: innerTransfer() })
    ], allDetail);
    assert.ok(result.expansion.recognized && result.expansion.complete);
    assert.deepEqual(result.expansion.operations.map((operation) => operation.path), ["0", "0.0", "0.1", "1"]);
    const subcalls = result.alerts.filter((alert) => alert.ruleId === "SAFE_MULTISEND_SUBCALL");
    assert.equal(subcalls.length, 4);
    assert.equal(new Set(subcalls.map((alert) => alert.id)).size, 4);
    const replay = alerts([
      packSuboperation({ target: NESTED_MULTISEND, data: nested }),
      packSuboperation({ target: TARGET, data: innerTransfer() })
    ], allDetail).alerts;
    assert.deepEqual(result.alerts.map((alert) => alert.id), replay.map((alert) => alert.id));
  });

  test("does not let an allowlisted MultiSend authorize an unknown inner target", () => {
    const result = alerts([packSuboperation({ target: UNKNOWN_TARGET, data: innerTransfer() })]);
    assert.ok(result.expansion.recognized && result.expansion.complete);
    assert.equal(result.expansion.operations[0]?.evaluation.targetAllowed, false);
    assert.ok(result.alerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_POLICY_VIOLATION"));
  });

  test("CALL_ONLY makes a nested DELEGATECALL critical even when Safe policy permits it", () => {
    const result = alerts([packSuboperation({ operation: "DELEGATECALL", target: TARGET, data: innerTransfer() })], administrativeMultiSendConfig("CALL_ONLY"));
    assert.equal(result.alerts.find((alert) => alert.ruleId === "SAFE_NESTED_DELEGATECALL")?.severity, "CRITICAL");
    assert.ok(result.expansion.recognized && result.expansion.complete);
    assert.ok(result.expansion.operations[0]?.evaluation.violations.some((violation) => violation.kind === "multisend-mode"));
  });

  test("checks unknown implementations and native value per subcall and in aggregate", () => {
    const result = alerts([
      packSuboperation({ target: TARGET, value: 6n, data: innerUpgrade(UNKNOWN_IMPLEMENTATION) }),
      packSuboperation({ target: TARGET, value: 6n, data: innerTransfer() })
    ]);
    assert.ok(result.alerts.some((alert) => alert.ruleId === "SAFE_UNKNOWN_IMPLEMENTATION_UPGRADE"));
    const policy = result.alerts.find((alert) => alert.ruleId === "SAFE_MULTISEND_POLICY_VIOLATION");
    assert.ok(policy);
    const metadata = policy.metadata.multiSend as any;
    assert.ok(metadata.violations.some((violation: any) => violation.suboperationPath === "batch"));
  });

  test("emits a composed anomaly only for a meaningful combination of risks", () => {
    const approve = encodeFunctionData({ abi: APPROVE_ABI, functionName: "approve", args: [UNKNOWN_TARGET, 2n ** 255n] });
    const result = alerts([
      packSuboperation({ target: TARGET, data: innerUpgrade(UNKNOWN_IMPLEMENTATION) }),
      packSuboperation({ target: TARGET, data: approve }),
      packSuboperation({ target: TARGET, data: innerTransfer() })
    ]);
    const anomaly = result.alerts.find((alert) => alert.ruleId === "SAFE_BATCH_ADMINISTRATIVE_ANOMALY");
    assert.equal(anomaly?.severity, "CRITICAL");
    assert.deepEqual((anomaly?.metadata.multiSend as any).componentSignals.map((item: any) => item.kind), ["upgrade", "approval", "asset-transfer"]);
    assert.equal(alerts([packSuboperation({ target: TARGET, data: innerTransfer() })]).alerts.some((alert) => alert.ruleId === "SAFE_BATCH_ADMINISTRATIVE_ANOMALY"), false);
  });

  test("reports malformed and over-limit payloads without accepting partial operations", () => {
    const malformedData = multiSendData([
      packSuboperation({ target: TARGET, data: innerTransfer() }),
      `0x00${TARGET.slice(2)}${"0".repeat(64)}${(10).toString(16).padStart(64, "0")}1234` as Hex
    ]);
    const decoded = decodeSafeExecTransaction({ safeAddress: SAFE, transaction: rpcTransaction(
      encodeFunctionData({ abi: (awaitImportSafeAbi()), functionName: "execTransaction", args: [MULTISEND, 0n, malformedData, 1, 0n, 0n, 0n, SAFE, SAFE, "0x"] })
    ) });
    assert.ok(decoded.decoded);
    const config = administrativeMultiSendConfig();
    const expansion = analyzeMultiSendTransaction({ transaction: decoded.transaction, policy: config.multisigs[0]!, config });
    assert.ok(expansion.recognized && !expansion.complete);
    const generated = createMultiSendAlerts({ chain: "ethereum", policy: config.multisigs[0]!, transaction: decoded.transaction, expansion, outcome: "success", createdAt: FIXED_CREATED_AT });
    assert.deepEqual(generated.map((alert) => alert.ruleId), ["SAFE_MULTISEND_MALFORMED"]);
    assert.equal((generated[0]?.metadata.multiSend as any).partialInterpretationAccepted, false);
  });

  test("stops nested expansion at configured depth and operation count", () => {
    const levelThree = multiSendData([packSuboperation({ target: NESTED_MULTISEND, data: multiSendData([packSuboperation()]) })]);
    const result = alerts([packSuboperation({ target: NESTED_MULTISEND, data: levelThree })]);
    assert.ok(result.alerts.some((alert) => alert.ruleId === "SAFE_MULTISEND_DEPTH_EXCEEDED"));
    const limited = administrativeMultiSendConfig();
    limited.multisendLimits = { ...limited.multisendLimits!, maxSuboperations: 1 };
    const over = alerts([packSuboperation(), packSuboperation()], limited);
    assert.deepEqual(over.alerts.map((alert) => alert.ruleId), ["SAFE_MULTISEND_LIMIT_EXCEEDED"]);
    const payloadLimited = administrativeMultiSendConfig();
    payloadLimited.multisendLimits = { ...payloadLimited.multisendLimits!, maxTotalPayloadBytes: 1 };
    assert.deepEqual(alerts([packSuboperation()], payloadLimited).alerts.map((alert) => alert.ruleId), ["SAFE_MULTISEND_LIMIT_EXCEEDED"]);
  });
});

describe("Safe MultiSend administrative correlation", () => {
  function effects() {
    const event = processLogs({ chain: "ethereum", logs: [upgradedLog()], topicMap: buildEventTopicMap(["Upgraded(address)"]), allowlists: emptyAllowlists(), clock: () => FIXED_CREATED_AT }).alerts[0]!;
    const slot = createEip1967SlotChangeAlertFromValues({ chain: "ethereum", proxy: { address: TARGET, checkImplementationSlot: true, checkAdminSlot: false }, slotKind: "implementation", slot: EIP1967_IMPLEMENTATION_SLOT, beforeBlock: 99n, afterBlock: 100n, beforeValue: addressToStorageWord(UNKNOWN_TARGET), afterValue: addressToStorageWord(IMPLEMENTATION), createdAt: FIXED_CREATED_AT });
    assert.ok(slot);
    return { event, slot };
  }

  test("confirms one concrete upgrade suboperation with event and slot", () => {
    const result = analyze([packSuboperation({ target: TARGET, data: innerUpgrade(IMPLEMENTATION) })]);
    assert.ok(result.expansion.recognized && result.expansion.complete);
    const { event, slot } = effects();
    const correlated = correlateMultiSendAdministrativeEffects({ chain: "ethereum", transaction: result.transaction, operations: result.expansion.operations, administrativeAlerts: [event], slotAlerts: [slot], createdAt: FIXED_CREATED_AT });
    assert.equal(correlated[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED");
    assert.equal(correlated[0]?.metadata.correlationStatus, "confirmed");
    assert.deepEqual(correlated[0]?.metadata.candidateSuboperations, ["0"]);
  });

  test("marks attribution ambiguous when identical suboperations can explain the same effect", () => {
    const result = analyze([
      packSuboperation({ target: TARGET, data: innerUpgrade(IMPLEMENTATION) }),
      packSuboperation({ target: TARGET, data: innerUpgrade(IMPLEMENTATION) })
    ]);
    assert.ok(result.expansion.recognized && result.expansion.complete);
    const { event } = effects();
    const correlated = correlateMultiSendAdministrativeEffects({ chain: "ethereum", transaction: result.transaction, operations: result.expansion.operations, administrativeAlerts: [event], slotAlerts: [], createdAt: FIXED_CREATED_AT });
    assert.equal(correlated.length, 1);
    assert.equal(correlated[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_AMBIGUOUS");
    assert.deepEqual(correlated[0]?.metadata.candidateSuboperations, ["0", "1"]);
  });

  test("reports inconsistent values and leaves unobserved suboperations uncorrelated", () => {
    const result = analyze([packSuboperation({ target: TARGET, data: innerUpgrade(UNKNOWN_IMPLEMENTATION) })]);
    assert.ok(result.expansion.recognized && result.expansion.complete);
    const { event } = effects();
    const mismatch = correlateMultiSendAdministrativeEffects({ chain: "ethereum", transaction: result.transaction, operations: result.expansion.operations, administrativeAlerts: [event], slotAlerts: [], createdAt: FIXED_CREATED_AT });
    assert.equal(mismatch[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_INCONSISTENCY");
    assert.deepEqual(correlateMultiSendAdministrativeEffects({ chain: "ethereum", transaction: result.transaction, operations: result.expansion.operations, administrativeAlerts: [], slotAlerts: [], createdAt: FIXED_CREATED_AT }), []);
  });

  test("correlates a classified ERC-20 transfer with a relevant observed economic transfer", () => {
    const result = analyze([packSuboperation({ target: TARGET, data: innerTransfer() })]);
    assert.ok(result.expansion.recognized && result.expansion.complete);
    const action = result.expansion.operations[0]?.action;
    assert.ok(action?.known && action.functionName === "transfer");
    const economicAlert: Alert = {
      id: "economic-transfer", chain: "ethereum", ruleId: "LARGE_ASSET_TRANSFER", ruleName: "Large Asset Transfer",
      severity: "INFO", eventSignature: "Transfer(address,address,uint256)", blockNumber: "100",
      transactionHash: SAFE_TX_HASH_FOR_TEST, address: TARGET, topics: [], data: "0x", summary: "fixture",
      metadata: { to: action.parameters.to, value: action.parameters.amount }, createdAt: FIXED_CREATED_AT
    };
    const correlated = correlateMultiSendAdministrativeEffects({ chain: "ethereum", transaction: result.transaction,
      operations: result.expansion.operations, administrativeAlerts: [economicAlert], slotAlerts: [], createdAt: FIXED_CREATED_AT });
    assert.equal(correlated[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED");
  });
});

const SAFE_TX_HASH_FOR_TEST = `0x${"ab".repeat(32)}`;

function awaitImportSafeAbi() {
  return parseAbi(["function execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,bytes signatures) returns (bool)"]);
}
