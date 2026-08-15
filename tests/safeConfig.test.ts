import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseMonitorConfig } from "../src/config.js";
import { SAFE, TARGET, IMPLEMENTATION } from "./safeFixtures.js";

function raw(multisig?: Record<string, unknown>) {
  return {
    chain: "ethereum",
    monitoredAddresses: [],
    knownMultisigs: [],
    eventSignatures: ["ExecutionSuccess(bytes32,uint256)"],
    ...(multisig === undefined ? {} : { administrativeMonitoring: { multisigs: [multisig] } })
  };
}

const valid = () => ({
  name: "Council", address: SAFE, criticality: "critical", allowedTargets: [TARGET],
  allowedSelectors: ["0x3659cfe6"], allowedOperations: ["CALL"],
  allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: "0"
});

describe("Safe administrative configuration", () => {
  test("is optional and parses a normalized valid policy", () => {
    assert.equal(parseMonitorConfig(raw()).administrativeMonitoring, undefined);
    const parsed = parseMonitorConfig(raw(valid())).administrativeMonitoring?.multisigs[0];
    assert.equal(parsed?.address, SAFE);
    assert.equal(parsed?.maxNativeValueWei, 0n);
    assert.equal(parsed?.allowedSelectors[0], "0x3659cfe6");
    assert.equal(parsed?.multisendAlertDetail, "sensitive-only");
    assert.deepEqual(parsed?.allowedOwners, []);
    assert.equal(parsed?.financialOperationPolicy.emitAllowedTransfers, false);
  });

  test("rejects duplicate Safes and duplicate policy entries", () => {
    const base = raw(valid()) as any;
    base.administrativeMonitoring.multisigs.push(valid());
    assert.throws(() => parseMonitorConfig(base), /duplicate Safe addresses/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), allowedTargets: [TARGET, TARGET] })), /duplicate targets/);
  });

  test("rejects invalid address, selector, operation, implementation and native value", () => {
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), address: "bad" })), /invalid Ethereum address/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), allowedSelectors: ["0x123"] })), /four-byte/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), allowedOperations: ["STATICCALL"] })), /CALL or DELEGATECALL/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), allowedImplementations: ["bad"] })), /invalid Ethereum address/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), maxNativeValueWei: "-1" })), /non-negative/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), criticality: "urgent" })), /standard, high, or critical/);
  });

  test("validates owner, threshold, module, guard, fallback and financial policy", () => {
    const parsed = parseMonitorConfig(raw({
      ...valid(),
      allowedOwners: [TARGET], minimumThreshold: 2, allowedThresholds: [2, 3],
      allowedModules: [TARGET], allowedGuards: [TARGET], allowedFallbackHandlers: [TARGET],
      multisendAlertDetail: "violations-only",
      financialOperationPolicy: {
        emitAllowedTransfers: true, emitAllowedApprovals: false,
        maxNativeValueWei: "10", notableTokenTargets: [TARGET]
      }
    })).administrativeMonitoring?.multisigs[0];
    assert.equal(parsed?.minimumThreshold, 2);
    assert.deepEqual(parsed?.allowedThresholds, [2, 3]);
    assert.equal(parsed?.multisendAlertDetail, "violations-only");
    assert.equal(parsed?.financialOperationPolicy.maxNativeValueWei, 10n);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), allowedOwners: [TARGET, TARGET] })), /duplicate addresses/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), minimumThreshold: 2, allowedThresholds: [1] })), /below minimumThreshold/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), multisendAlertDetail: "quiet" })), /sensitive-only/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), financialOperationPolicy: { emitAllowedTransfers: "yes" } })), /boolean/);
  });

  test("validates explicit per-module policies and duplicate modules", () => {
    const modulePolicy = {
      name: "Automation Module", address: TARGET,
      allowedTargets: [TARGET], allowedSelectors: ["0x3659cfe6"], allowedOperations: ["CALL"],
      allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: "0"
    };
    const parsed = parseMonitorConfig(raw({ ...valid(), allowedModules: [TARGET], modulePolicies: [modulePolicy] }))
      .administrativeMonitoring?.multisigs[0]?.modulePolicies[0];
    assert.equal(parsed?.address, TARGET);
    assert.equal(parsed?.maxNativeValueWei, 0n);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), modulePolicies: [modulePolicy, modulePolicy] })), /duplicate module addresses/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), modulePolicies: [{ ...modulePolicy, allowedOperations: ["STATICCALL"] }] })), /CALL or DELEGATECALL/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), modulePolicies: [{ ...modulePolicy, allowedSelectors: ["0x12"] }] })), /four-byte/);
  });

  test("validates bounded Zodiac Roles v2 adapters", () => {
    const modulePolicy = {
      name: "Roles", address: TARGET,
      allowedTargets: [TARGET], allowedSelectors: ["0x3659cfe6"], allowedOperations: ["CALL"],
      allowedImplementations: [IMPLEMENTATION], maxNativeValueWei: "0",
      adapter: { type: "ZODIAC_ROLES_V2", managerSafes: [SAFE] }
    };
    const parsed = parseMonitorConfig(raw({ ...valid(), modulePolicies: [modulePolicy] }))
      .administrativeMonitoring?.multisigs[0]?.modulePolicies[0]?.adapter;
    assert.equal(parsed?.type, "ZODIAC_ROLES_V2");
    assert.deepEqual(parsed?.managerSafes, [SAFE]);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), modulePolicies: [{ ...modulePolicy, adapter: { type: "GENERIC", managerSafes: [] } }] })), /ZODIAC_ROLES_V2/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), modulePolicies: [{ ...modulePolicy, adapter: { type: "ZODIAC_ROLES_V2", managerSafes: [SAFE, SAFE] } }] })), /duplicate manager Safe addresses/);
    assert.throws(() => parseMonitorConfig(raw({ ...valid(), modulePolicies: [{ ...modulePolicy, adapter: { type: "ZODIAC_ROLES_V2", managerSafes: ["bad"] } }] })), /invalid Ethereum address/);
  });
});
