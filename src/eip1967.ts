import { getAddress, type Address, type Hex } from "viem";
import type { Alert } from "./alerts.js";
import type { ProxySlotMonitorConfig } from "./config.js";

export const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC" as Hex;
export const EIP1967_ADMIN_SLOT = "0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103" as Hex;

export type Eip1967SlotKind = "implementation" | "admin";

export type NormalizedSlotValue = {
  raw: Hex;
  address: Address | null;
};

export type Eip1967SlotSnapshot = {
  proxy: ProxySlotMonitorConfig;
  slotKind: Eip1967SlotKind;
  slot: Hex;
  beforeBlock: bigint;
  afterBlock: bigint;
  before: NormalizedSlotValue;
  after: NormalizedSlotValue;
};

export type Eip1967SlotObservation = {
  proxy: ProxySlotMonitorConfig;
  slotKind: Eip1967SlotKind;
  slot: Hex;
  beforeBlock: bigint;
  afterBlock: bigint;
  beforeValue: Hex | undefined;
  afterValue: Hex | undefined;
};

export function buildEip1967SlotSnapshot(observation: Eip1967SlotObservation): Eip1967SlotSnapshot {
  return {
    proxy: observation.proxy,
    slotKind: observation.slotKind,
    slot: observation.slot,
    beforeBlock: observation.beforeBlock,
    afterBlock: observation.afterBlock,
    before: normalizeSlotValue(observation.beforeValue),
    after: normalizeSlotValue(observation.afterValue)
  };
}

export function createEip1967SlotChangeAlertFromObservation(params: {
  chain: "ethereum";
  observation: Eip1967SlotObservation;
  createdAt?: string;
}): Alert | undefined {
  return createEip1967SlotChangeAlert({
    chain: params.chain,
    snapshot: buildEip1967SlotSnapshot(params.observation),
    ...(params.createdAt === undefined ? {} : { createdAt: params.createdAt })
  });
}

export function createEip1967SlotChangeAlertFromValues(params: {
  chain: "ethereum";
  proxy: ProxySlotMonitorConfig;
  slotKind: Eip1967SlotKind;
  slot: Hex;
  beforeBlock: bigint;
  afterBlock: bigint;
  beforeValue: Hex | undefined;
  afterValue: Hex | undefined;
  createdAt?: string;
}): Alert | undefined {
  return createEip1967SlotChangeAlertFromObservation({
    chain: params.chain,
    observation: {
      proxy: params.proxy,
      slotKind: params.slotKind,
      slot: params.slot,
      beforeBlock: params.beforeBlock,
      afterBlock: params.afterBlock,
      beforeValue: params.beforeValue,
      afterValue: params.afterValue
    },
    ...(params.createdAt === undefined ? {} : { createdAt: params.createdAt })
  });
}

export function createEip1967SlotChangeAlert(params: {
  chain: "ethereum";
  snapshot: Eip1967SlotSnapshot;
  createdAt?: string;
}): Alert | undefined {
  const beforeRaw = params.snapshot.before.raw.toLowerCase();
  const afterRaw = params.snapshot.after.raw.toLowerCase();

  if (beforeRaw === afterRaw) {
    return undefined;
  }

  const ruleId =
    params.snapshot.slotKind === "implementation" ? "PROXY_IMPLEMENTATION_SLOT_CHANGED" : "PROXY_ADMIN_SLOT_CHANGED";
  const ruleName =
    params.snapshot.slotKind === "implementation" ? "Proxy Implementation Slot Changed" : "Proxy Admin Slot Changed";
  const label = params.snapshot.proxy.name ?? params.snapshot.proxy.address;
  const beforeValue = formatNormalizedSlotValue(params.snapshot.before);
  const afterValue = formatNormalizedSlotValue(params.snapshot.after);
  const subject = params.snapshot.slotKind === "implementation" ? "implementation" : "admin";

  return {
    id: [
      params.chain,
      ruleId,
      params.snapshot.proxy.address,
      params.snapshot.beforeBlock.toString(),
      params.snapshot.afterBlock.toString(),
      params.snapshot.slot
    ].join(":"),
    chain: params.chain,
    ruleId,
    ruleName,
    severity: "WARNING",
    eventSignature: `EIP1967_${params.snapshot.slotKind.toUpperCase()}_SLOT`,
    blockNumber: params.snapshot.afterBlock.toString(),
    transactionHash: "storage-diff",
    address: params.snapshot.proxy.address,
    topics: [],
    data: params.snapshot.after.raw,
    summary: `Proxy ${subject} slot changed for ${label}: ${beforeValue} -> ${afterValue}.`,
    metadata: {
      source: "eth_getStorageAt",
      eip1967: {
        proxyName: params.snapshot.proxy.name ?? null,
        proxyAddress: params.snapshot.proxy.address,
        slotKind: params.snapshot.slotKind,
        slot: params.snapshot.slot,
        beforeBlock: params.snapshot.beforeBlock.toString(),
        afterBlock: params.snapshot.afterBlock.toString(),
        previousRawValue: params.snapshot.before.raw,
        newRawValue: params.snapshot.after.raw,
        previousAddress: params.snapshot.before.address,
        newAddress: params.snapshot.after.address
      }
    },
    createdAt: params.createdAt ?? new Date().toISOString()
  };
}

export function normalizeSlotValue(value: Hex | undefined | null): NormalizedSlotValue {
  const raw = normalizeStorageWord(value);

  if (/^0x0{64}$/i.test(raw)) {
    return {
      raw,
      address: null
    };
  }

  const candidate = `0x${raw.slice(-40)}` as Address;

  return {
    raw,
    address: getAddress(candidate)
  };
}

function normalizeStorageWord(value: Hex | undefined | null): Hex {
  if (value === undefined || value === null || value === "0x") {
    return `0x${"0".repeat(64)}` as Hex;
  }

  const stripped = value.slice(2);

  if (!/^[0-9a-fA-F]*$/.test(stripped) || stripped.length > 64) {
    throw new Error(`Invalid storage word: ${value}`);
  }

  return `0x${stripped.padStart(64, "0").toLowerCase()}` as Hex;
}

function formatNormalizedSlotValue(value: NormalizedSlotValue): string {
  return value.address ?? "empty";
}
