import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseMonitorConfig } from "../src/config.js";
import { MULTISEND, SAFE, TARGET } from "./multisendFixtures.js";

const safe = {
  name: "Council", address: SAFE, criticality: "critical", allowedTargets: [TARGET],
  allowedSelectors: ["0x3659cfe6"], allowedOperations: ["CALL"],
  allowedImplementations: [], maxNativeValueWei: "0"
};

function raw(administrativeMonitoring?: Record<string, unknown>) {
  return {
    chain: "ethereum", monitoredAddresses: [], knownMultisigs: [], eventSignatures: ["Upgraded(address)"],
    ...(administrativeMonitoring === undefined ? {} : { administrativeMonitoring })
  };
}

describe("Safe MultiSend configuration", () => {
  test("keeps the section optional and supplies defensive defaults for existing Safe config", () => {
    assert.equal(parseMonitorConfig(raw()).administrativeMonitoring, undefined);
    const parsed = parseMonitorConfig(raw({ multisigs: [safe] })).administrativeMonitoring;
    assert.deepEqual(parsed?.multisendContracts, []);
    assert.equal(parsed?.multisendLimits?.maxDepth, 2);
  });

  test("normalizes valid contracts and accepts both enumerated modes", () => {
    const parsed = parseMonitorConfig(raw({ multisigs: [safe], multisendContracts: [
      { name: "MultiSend", address: MULTISEND.toLowerCase(), mode: "MULTISEND" },
      { name: "Call Only", address: TARGET, mode: "CALL_ONLY" }
    ] })).administrativeMonitoring;
    assert.equal(parsed?.multisendContracts?.[0]?.address, MULTISEND);
    assert.deepEqual(parsed?.multisendContracts?.map((item) => item.mode), ["MULTISEND", "CALL_ONLY"]);
  });

  test("rejects invalid address, empty name, duplicate and invalid mode", () => {
    const config = (contracts: unknown[]) => raw({ multisigs: [safe], multisendContracts: contracts });
    assert.throws(() => parseMonitorConfig(config([{ name: "x", address: "bad", mode: "MULTISEND" }])), /invalid Ethereum address/);
    assert.throws(() => parseMonitorConfig(config([{ name: " ", address: MULTISEND, mode: "MULTISEND" }])), /non-empty/);
    assert.throws(() => parseMonitorConfig(config([
      { name: "a", address: MULTISEND, mode: "MULTISEND" },
      { name: "b", address: MULTISEND, mode: "CALL_ONLY" }
    ])), /duplicate MultiSend addresses/);
    assert.throws(() => parseMonitorConfig(config([{ name: "x", address: MULTISEND, mode: "MAGIC" }])), /MULTISEND or CALL_ONLY/);
  });

  test("validates every defensive limit as a positive safe integer", () => {
    const base = { maxDepth: 2, maxSuboperations: 10, maxTotalPayloadBytes: 1000, maxSuboperationDataBytes: 100 };
    for (const key of Object.keys(base)) {
      assert.throws(() => parseMonitorConfig(raw({ multisigs: [safe], multisendLimits: { ...base, [key]: 0 } })), /positive safe integer/);
    }
  });
});
