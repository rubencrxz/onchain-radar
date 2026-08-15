import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Address, Hex } from "viem";
import type { AllowlistConfig, ProxySlotMonitorConfig } from "../src/config.js";
import {
  createEip1967SlotChangeAlert,
  createEip1967SlotChangeAlertFromValues,
  EIP1967_ADMIN_SLOT,
  EIP1967_IMPLEMENTATION_SLOT,
  normalizeSlotValue
} from "../src/eip1967.js";
import { refineAlertSeverity } from "../src/severity.js";
import {
  AAVE_POOL,
  AAVE_POOL_IMPLEMENTATION,
  ADDRESS_A,
  ADDRESS_B,
  ADDRESS_C,
  FIXED_CREATED_AT,
  addressToStorageWord,
  emptyAllowlists
} from "./fixtures.js";

const PROXY: ProxySlotMonitorConfig = {
  name: "Test Proxy",
  address: ADDRESS_A,
  checkImplementationSlot: true,
  checkAdminSlot: true
};

function slotAlert(params: {
  slotKind: "implementation" | "admin";
  before: Address;
  after: Address;
  proxy?: ProxySlotMonitorConfig;
}) {
  return createEip1967SlotChangeAlertFromValues({
    chain: "ethereum",
    proxy: params.proxy ?? PROXY,
    slotKind: params.slotKind,
    slot: params.slotKind === "implementation" ? EIP1967_IMPLEMENTATION_SLOT : EIP1967_ADMIN_SLOT,
    beforeBlock: 99n,
    afterBlock: 100n,
    beforeValue: addressToStorageWord(params.before),
    afterValue: addressToStorageWord(params.after),
    createdAt: FIXED_CREATED_AT
  });
}

function refine(alert: NonNullable<ReturnType<typeof slotAlert>>, allowlists: AllowlistConfig) {
  return refineAlertSeverity(alert, allowlists);
}

describe("pure EIP-1967 boundary", () => {
  test("returns no alert for an unchanged implementation", () => {
    assert.equal(slotAlert({ slotKind: "implementation", before: ADDRESS_A, after: ADDRESS_A }), undefined);
  });

  test("returns WARNING for an implementation changed to an allowlisted address", () => {
    const alert = slotAlert({ slotKind: "implementation", before: ADDRESS_A, after: ADDRESS_B });
    assert.ok(alert);
    const refined = refine(alert, { ...emptyAllowlists(), knownImplementations: [{ address: ADDRESS_B }] });
    assert.equal(refined.severity, "WARNING");
    assert.equal((refined.metadata.severityReason as Record<string, unknown>).matchedAllowlist, true);
  });

  test("returns CRITICAL for an implementation changed to a non-allowlisted address", () => {
    const alert = slotAlert({ slotKind: "implementation", before: ADDRESS_A, after: ADDRESS_C });
    assert.ok(alert);
    assert.equal(refine(alert, emptyAllowlists()).severity, "CRITICAL");
  });

  test("returns no alert for an unchanged admin", () => {
    assert.equal(slotAlert({ slotKind: "admin", before: ADDRESS_A, after: ADDRESS_A }), undefined);
  });

  test("returns WARNING for an admin changed to an allowlisted address", () => {
    const alert = slotAlert({ slotKind: "admin", before: ADDRESS_A, after: ADDRESS_B });
    assert.ok(alert);
    const refined = refine(alert, { ...emptyAllowlists(), knownAdmins: [{ address: ADDRESS_B }] });
    assert.equal(refined.severity, "WARNING");
    assert.equal((refined.metadata.severityReason as Record<string, unknown>).matchedAllowlist, true);
  });

  test("returns CRITICAL for an admin changed to a non-allowlisted address", () => {
    const alert = slotAlert({ slotKind: "admin", before: ADDRESS_A, after: ADDRESS_C });
    assert.ok(alert);
    assert.equal(refine(alert, emptyAllowlists()).severity, "CRITICAL");
  });

  test("matches the previous snapshot path for the historical Aave Pool change", () => {
    const previousImplementation = "0x8147b99DF7672A21809c9093E6F6CE1a60F119Bd" as Address;
    const proxy: ProxySlotMonitorConfig = {
      name: "AaveV3Ethereum.POOL",
      address: AAVE_POOL,
      checkImplementationSlot: true,
      checkAdminSlot: true
    };
    const beforeValue = addressToStorageWord(previousImplementation);
    const afterValue = addressToStorageWord(AAVE_POOL_IMPLEMENTATION);
    const fromValues = createEip1967SlotChangeAlertFromValues({
      chain: "ethereum",
      proxy,
      slotKind: "implementation",
      slot: EIP1967_IMPLEMENTATION_SLOT,
      beforeBlock: 25199938n,
      afterBlock: 25199939n,
      beforeValue,
      afterValue,
      createdAt: FIXED_CREATED_AT
    });
    const previousPath = createEip1967SlotChangeAlert({
      chain: "ethereum",
      snapshot: {
        proxy,
        slotKind: "implementation",
        slot: EIP1967_IMPLEMENTATION_SLOT,
        beforeBlock: 25199938n,
        afterBlock: 25199939n,
        before: normalizeSlotValue(beforeValue),
        after: normalizeSlotValue(afterValue)
      },
      createdAt: FIXED_CREATED_AT
    });

    assert.deepEqual(fromValues, previousPath);
    assert.equal(
      fromValues?.id,
      "ethereum:PROXY_IMPLEMENTATION_SLOT_CHANGED:0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2:25199938:25199939:0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC"
    );
  });
});
