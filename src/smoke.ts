import { copyFileSync, existsSync, readFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { encodeAbiParameters, type Address, type Hex } from "viem";
import { writeAlertsJsonl } from "./alertWriter.js";
import { createAlertFromLog } from "./alerts.js";
import { loadMonitorConfig } from "./config.js";
import { decodeConfiguredEventLog } from "./decoders.js";
import {
  createEip1967SlotChangeAlert,
  EIP1967_ADMIN_SLOT,
  EIP1967_IMPLEMENTATION_SLOT,
  normalizeSlotValue,
  type Eip1967SlotSnapshot
} from "./eip1967.js";
import { buildEventTopicMap } from "./events.js";
import { processLogs } from "./processor.js";
import { chunkBlockRange } from "./ranges.js";
import { getRuleForEventSignature } from "./rules.js";
import { refineAlertSeverity } from "./severity.js";
import type { AllowlistConfig } from "./config.js";

const configPath = resolve("config/monitor.config.json");
const examplePath = resolve("config/monitor.config.example.json");
const createdTemporaryConfig = !existsSync(configPath);

const SAMPLE_ADDRESS_A = "0x1111111111111111111111111111111111111111" as Address;
const SAMPLE_ADDRESS_B = "0x2222222222222222222222222222222222222222" as Address;
const SAMPLE_ADDRESS_C = "0x3333333333333333333333333333333333333333" as Address;
const SAMPLE_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;
const SAMPLE_SAFE_TX_HASH = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex;
const SAMPLE_PAYLOAD_ID = 453;

if (createdTemporaryConfig) {
  copyFileSync(examplePath, configPath);
}

try {
  const config = loadMonitorConfig();
  const signaturesForSmoke = [...new Set([...config.eventSignatures, "PayloadExecuted(uint40)"])];
  const topicMap = buildEventTopicMap(signaturesForSmoke);
  const chunks = chunkBlockRange(100n, 4_250n);
  const smokeAlertPath = resolve("alerts/smoke-alerts.jsonl");
  const syntheticLogs = buildSyntheticLogs(topicMap);

  if (topicMap.size !== signaturesForSmoke.length) {
    throw new Error("Event topic map size does not match configured signature count.");
  }

  if (chunks.length !== 3) {
    throw new Error(`Expected 3 block chunks, got ${chunks.length}.`);
  }

  for (const eventSignature of signaturesForSmoke) {
    const log = syntheticLogs.get(eventSignature);

    if (log === undefined) {
      throw new Error(`Missing synthetic log for ${eventSignature}.`);
    }

    const decoded = decodeConfiguredEventLog(eventSignature, log);

    if (decoded.decoded === undefined) {
      throw new Error(`Synthetic log failed to decode for ${eventSignature}: ${decoded.decodeError}`);
    }

    JSON.stringify(decoded.decoded);
    assertExpectedDecodedFields(eventSignature, decoded.decoded);
  }

  const ownershipSignature = "OwnershipTransferred(address,address)";
  const ownershipRule = getRuleForEventSignature(ownershipSignature);
  const ownershipLog = syntheticLogs.get(ownershipSignature);

  if (ownershipRule === undefined) {
    throw new Error("OwnershipTransferred signature did not map to a rule.");
  }

  if (ownershipRule.ruleId !== "OWNERSHIP_TRANSFERRED") {
    throw new Error(`Expected OWNERSHIP_TRANSFERRED rule ID, got ${ownershipRule.ruleId}.`);
  }

  if (ownershipLog === undefined) {
    throw new Error("OwnershipTransferred synthetic log is missing.");
  }

  const alert = createAlertFromLog({
    chain: "ethereum",
    eventSignature: ownershipSignature,
    rule: ownershipRule,
    createdAt: "2026-07-03T00:00:00.000Z",
    log: {
      ...ownershipLog,
      blockNumber: "0x1312d03",
      transactionHash: "0xc477c7f3b2ed04ca2ffaade29e7aeb4655cd7965a9ae6ef61d20111be7399ec6",
      logIndex: "0x0",
      address: "0xc1f557873bdd9c56a69b47ac191bfac26520c25c"
    }
  });

  const sameAlert = createAlertFromLog({
    chain: "ethereum",
    eventSignature: ownershipSignature,
    rule: ownershipRule,
    createdAt: "2026-07-03T00:00:00.000Z",
    log: {
      ...ownershipLog,
      blockNumber: "0x1312d03",
      transactionHash: "0xc477c7f3b2ed04ca2ffaade29e7aeb4655cd7965a9ae6ef61d20111be7399ec6",
      logIndex: "0x0",
      address: "0xc1f557873bdd9c56a69b47ac191bfac26520c25c"
    }
  });

  if (alert.id !== sameAlert.id) {
    throw new Error("Alert ID generation is not consistent for the same log.");
  }

  if (!alert.summary.startsWith("Ownership transferred from ")) {
    throw new Error(`Expected decoded ownership summary, got: ${alert.summary}`);
  }

  const metadata = alert.metadata as { decoded?: unknown };

  if (metadata.decoded === undefined) {
    throw new Error("Decoded metadata was not attached to the alert.");
  }

  const malformedAlert = createAlertFromLog({
    chain: "ethereum",
    eventSignature: "Paused(address)",
    rule: requireRule("Paused(address)"),
    createdAt: "2026-07-03T00:00:00.000Z",
    log: {
      blockNumber: "0x1312d03",
      transactionHash: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      logIndex: "0x1",
      address: "0xc1f557873bdd9c56a69b47ac191bfac26520c25c",
      topics: [requireTopic(topicMap, "Paused(address)")],
      data: "0x"
    }
  });

  if (!("decodeError" in malformedAlert.metadata)) {
    throw new Error("Malformed alert did not preserve decode error metadata.");
  }

  const payloadSignature = "PayloadExecuted(uint40)";
  const payloadRule = requireRule(payloadSignature);
  const payloadLog = syntheticLogs.get(payloadSignature);

  if (payloadRule.ruleId !== "GOVERNANCE_PAYLOAD_EXECUTED") {
    throw new Error(`Expected GOVERNANCE_PAYLOAD_EXECUTED rule ID, got ${payloadRule.ruleId}.`);
  }

  if (payloadLog === undefined) {
    throw new Error("PayloadExecuted synthetic log is missing.");
  }

  const payloadAlert = createAlertFromLog({
    chain: "ethereum",
    eventSignature: payloadSignature,
    rule: payloadRule,
    createdAt: "2026-07-03T00:00:00.000Z",
    log: {
      ...payloadLog,
      blockNumber: "0x183ee00",
      transactionHash: "0x14c3acdb367a62c25d2a405f97a08ddae6399714032f1060167af4cc7b9d47c8",
      logIndex: "0x2a6",
      address: "0xdAbad81aF85554E9ae636395611C58F7eC1aAEc5"
    }
  });

  if (payloadAlert.summary !== "Governance payload executed: payloadId 453.") {
    throw new Error(`Expected decoded governance payload summary, got: ${payloadAlert.summary}`);
  }

  if ((payloadAlert.metadata.decoded as { payloadId?: unknown } | undefined)?.payloadId !== 453) {
    throw new Error("PayloadExecuted alert did not decode JSON-safe payloadId.");
  }

  const processorResult = processLogs({
    chain: "ethereum",
    topicMap,
    allowlists: config.allowlists,
    clock: () => "2026-07-03T00:00:00.000Z",
    logs: [
      {
        ...ownershipLog,
        blockNumber: "0x1312d03",
        transactionHash: "0xc477c7f3b2ed04ca2ffaade29e7aeb4655cd7965a9ae6ef61d20111be7399ec6",
        logIndex: "0x0",
        address: "0xc1f557873bdd9c56a69b47ac191bfac26520c25c"
      },
      {
        ...payloadLog,
        blockNumber: "0x183ee00",
        transactionHash: "0x14c3acdb367a62c25d2a405f97a08ddae6399714032f1060167af4cc7b9d47c8",
        logIndex: "0x2a6",
        address: "0xdAbad81aF85554E9ae636395611C58F7eC1aAEc5"
      }
    ]
  });

  if (processorResult.alerts.length !== 2 || processorResult.unprocessedLogs.length !== 0) {
    throw new Error("Reusable processor did not map the smoke event batch as expected.");
  }

  if (processorResult.alerts[0]?.id !== alert.id || processorResult.alerts[1]?.id !== payloadAlert.id) {
    throw new Error("Reusable processor did not preserve stable alert IDs.");
  }

  verifyEip1967SmokeChecks();
  verifySeverityRefinementSmokeChecks(payloadAlert);

  JSON.stringify(alert);
  writeAlertsJsonl(smokeAlertPath, [alert, sameAlert]);

  const lines = readFileSync(smokeAlertPath, "utf8").trim().split("\n");

  if (lines.length !== 2) {
    throw new Error(`Expected JSONL writer to write 2 lines, got ${lines.length}.`);
  }

  for (const line of lines) {
    const parsed = JSON.parse(line) as { ruleId?: unknown; blockNumber?: unknown };

    if (parsed.ruleId !== "OWNERSHIP_TRANSFERRED") {
      throw new Error("JSONL alert did not preserve ruleId.");
    }

    if (parsed.blockNumber !== "20000003") {
      throw new Error("JSONL alert did not serialize blockNumber as a decimal string.");
    }
  }

  console.log("Smoke check passed.");
  console.log(`Loaded signatures for smoke: ${signaturesForSmoke.length}`);
  console.log(`Computed topic0 hashes: ${topicMap.size}`);
  console.log(`Chunked sample block range into ${chunks.length} ranges.`);
  console.log(
    "Verified reusable processing, rule mapping, event decoding, EIP-1967 diffs, allowlist severity refinement, alert serialization, stable IDs, and JSONL writing."
  );
} finally {
  const smokeAlertPath = resolve("alerts/smoke-alerts.jsonl");

  if (existsSync(smokeAlertPath)) {
    unlinkSync(smokeAlertPath);
  }

  if (createdTemporaryConfig) {
    unlinkSync(configPath);
  }
}

type SyntheticLog = {
  topics: readonly Hex[];
  data: Hex;
};

function buildSyntheticLogs(topicMap: Map<Hex, string>): Map<string, SyntheticLog> {
  return new Map<string, SyntheticLog>([
    [
      "OwnershipTransferred(address,address)",
      {
        topics: [
          requireTopic(topicMap, "OwnershipTransferred(address,address)"),
          addressToTopic(SAMPLE_ADDRESS_A),
          addressToTopic(SAMPLE_ADDRESS_B)
        ],
        data: "0x"
      }
    ],
    [
      "RoleGranted(bytes32,address,address)",
      {
        topics: [
          requireTopic(topicMap, "RoleGranted(bytes32,address,address)"),
          SAMPLE_ROLE,
          addressToTopic(SAMPLE_ADDRESS_B),
          addressToTopic(SAMPLE_ADDRESS_C)
        ],
        data: "0x"
      }
    ],
    [
      "RoleRevoked(bytes32,address,address)",
      {
        topics: [
          requireTopic(topicMap, "RoleRevoked(bytes32,address,address)"),
          SAMPLE_ROLE,
          addressToTopic(SAMPLE_ADDRESS_B),
          addressToTopic(SAMPLE_ADDRESS_C)
        ],
        data: "0x"
      }
    ],
    [
      "Paused(address)",
      {
        topics: [requireTopic(topicMap, "Paused(address)")],
        data: encodeAbiParameters([{ type: "address", name: "account" }], [SAMPLE_ADDRESS_A])
      }
    ],
    [
      "Unpaused(address)",
      {
        topics: [requireTopic(topicMap, "Unpaused(address)")],
        data: encodeAbiParameters([{ type: "address", name: "account" }], [SAMPLE_ADDRESS_A])
      }
    ],
    [
      "Upgraded(address)",
      {
        topics: [requireTopic(topicMap, "Upgraded(address)"), addressToTopic(SAMPLE_ADDRESS_B)],
        data: "0x"
      }
    ],
    [
      "AdminChanged(address,address)",
      {
        topics: [requireTopic(topicMap, "AdminChanged(address,address)")],
        data: encodeAbiParameters(
          [
            { type: "address", name: "previousAdmin" },
            { type: "address", name: "newAdmin" }
          ],
          [SAMPLE_ADDRESS_A, SAMPLE_ADDRESS_B]
        )
      }
    ],
    [
      "ExecutionSuccess(bytes32,uint256)",
      {
        topics: [requireTopic(topicMap, "ExecutionSuccess(bytes32,uint256)")],
        data: encodeAbiParameters(
          [
            { type: "bytes32", name: "txHash" },
            { type: "uint256", name: "payment" }
          ],
          [SAMPLE_SAFE_TX_HASH, 123n]
        )
      }
    ],
    [
      "ExecutionFailure(bytes32,uint256)",
      {
        topics: [requireTopic(topicMap, "ExecutionFailure(bytes32,uint256)")],
        data: encodeAbiParameters(
          [
            { type: "bytes32", name: "txHash" },
            { type: "uint256", name: "payment" }
          ],
          [SAMPLE_SAFE_TX_HASH, 123n]
        )
      }
    ],
    [
      "PayloadExecuted(uint40)",
      {
        topics: [requireTopic(topicMap, "PayloadExecuted(uint40)")],
        data: encodeAbiParameters([{ type: "uint40", name: "payloadId" }], [SAMPLE_PAYLOAD_ID])
      }
    ]
  ]);
}

function assertExpectedDecodedFields(eventSignature: string, decoded: Record<string, unknown>): void {
  const expectedFieldsBySignature = new Map<string, string[]>([
    ["OwnershipTransferred(address,address)", ["previousOwner", "newOwner"]],
    ["RoleGranted(bytes32,address,address)", ["role", "account", "sender"]],
    ["RoleRevoked(bytes32,address,address)", ["role", "account", "sender"]],
    ["Paused(address)", ["account"]],
    ["Unpaused(address)", ["account"]],
    ["Upgraded(address)", ["implementation"]],
    ["AdminChanged(address,address)", ["previousAdmin", "newAdmin"]],
    ["ExecutionSuccess(bytes32,uint256)", ["txHash", "payment"]],
    ["ExecutionFailure(bytes32,uint256)", ["txHash", "payment"]],
    ["PayloadExecuted(uint40)", ["payloadId"]]
  ]);

  const expectedFields = expectedFieldsBySignature.get(eventSignature);

  if (expectedFields === undefined) {
    throw new Error(`No expected decoded fields configured for ${eventSignature}.`);
  }

  for (const field of expectedFields) {
    if (!(field in decoded)) {
      throw new Error(`Decoded ${eventSignature} missing field ${field}.`);
    }

    if (typeof decoded[field] === "bigint") {
      throw new Error(`Decoded ${eventSignature} field ${field} is not JSON-safe.`);
    }
  }
}

function requireTopic(topicMap: Map<Hex, string>, eventSignature: string): Hex {
  const topic = [...topicMap.entries()].find(([, signature]) => signature === eventSignature)?.[0];

  if (topic === undefined) {
    throw new Error(`${eventSignature} signature did not map to topic0.`);
  }

  return topic;
}

function requireRule(eventSignature: string) {
  const rule = getRuleForEventSignature(eventSignature);

  if (rule === undefined) {
    throw new Error(`${eventSignature} signature did not map to a rule.`);
  }

  return rule;
}

function addressToTopic(address: Address): Hex {
  return `0x${"0".repeat(24)}${address.slice(2)}`;
}

function verifyEip1967SmokeChecks(): void {
  if (!EIP1967_IMPLEMENTATION_SLOT.startsWith("0x360894")) {
    throw new Error("EIP-1967 implementation slot constant is not configured.");
  }

  if (!EIP1967_ADMIN_SLOT.startsWith("0xB53127")) {
    throw new Error("EIP-1967 admin slot constant is not configured.");
  }

  const empty = normalizeSlotValue("0x");

  if (empty.address !== null) {
    throw new Error("Empty EIP-1967 slot value did not normalize to null address.");
  }

  const previousImplementation = addressToStorageWord(SAMPLE_ADDRESS_A);
  const newImplementation = addressToStorageWord(SAMPLE_ADDRESS_B);
  const previousAdmin = addressToStorageWord(SAMPLE_ADDRESS_B);
  const newAdmin = addressToStorageWord(SAMPLE_ADDRESS_C);

  const unchangedSnapshot = buildSlotSnapshot({
    slotKind: "implementation",
    slot: EIP1967_IMPLEMENTATION_SLOT,
    beforeRaw: previousImplementation,
    afterRaw: previousImplementation
  });

  if (createEip1967SlotChangeAlert({ chain: "ethereum", snapshot: unchangedSnapshot }) !== undefined) {
    throw new Error("Unchanged EIP-1967 slot produced an alert.");
  }

  const implementationAlert = createEip1967SlotChangeAlert({
    chain: "ethereum",
    snapshot: buildSlotSnapshot({
      slotKind: "implementation",
      slot: EIP1967_IMPLEMENTATION_SLOT,
      beforeRaw: previousImplementation,
      afterRaw: newImplementation
    }),
    createdAt: "2026-07-03T00:00:00.000Z"
  });

  if (implementationAlert === undefined || implementationAlert.ruleId !== "PROXY_IMPLEMENTATION_SLOT_CHANGED") {
    throw new Error("Changed implementation slot did not produce PROXY_IMPLEMENTATION_SLOT_CHANGED.");
  }

  const adminAlert = createEip1967SlotChangeAlert({
    chain: "ethereum",
    snapshot: buildSlotSnapshot({
      slotKind: "admin",
      slot: EIP1967_ADMIN_SLOT,
      beforeRaw: previousAdmin,
      afterRaw: newAdmin
    }),
    createdAt: "2026-07-03T00:00:00.000Z"
  });

  if (adminAlert === undefined || adminAlert.ruleId !== "PROXY_ADMIN_SLOT_CHANGED") {
    throw new Error("Changed admin slot did not produce PROXY_ADMIN_SLOT_CHANGED.");
  }

  JSON.stringify(implementationAlert);
  JSON.stringify(adminAlert);
}

function verifySeverityRefinementSmokeChecks(knownPayloadAlert: ReturnType<typeof createAlertFromLog>): void {
  const knownImplementation = SAMPLE_ADDRESS_B;
  const knownAdmin = SAMPLE_ADDRESS_C;
  const knownGovernance = "0xdAbad81aF85554E9ae636395611C58F7eC1aAEc5" as Address;
  const allowlists: AllowlistConfig = {
    knownActors: [],
    knownAdmins: [{ name: "Known Admin", address: knownAdmin }],
    knownImplementations: [{ name: "Known Implementation", address: knownImplementation }],
    knownGovernanceContracts: [{ name: "Known Governance", address: knownGovernance }],
    knownProxyAddresses: []
  };

  const knownImplementationAlert = requireSlotAlert(
    createEip1967SlotChangeAlert({
      chain: "ethereum",
      snapshot: buildSlotSnapshot({
        slotKind: "implementation",
        slot: EIP1967_IMPLEMENTATION_SLOT,
        beforeRaw: addressToStorageWord(SAMPLE_ADDRESS_A),
        afterRaw: addressToStorageWord(knownImplementation)
      }),
      createdAt: "2026-07-03T00:00:00.000Z"
    })
  );
  const refinedKnownImplementation = refineAlertSeverity(knownImplementationAlert, allowlists);

  assertSeverity(refinedKnownImplementation, "WARNING", true);

  const unknownImplementationAlert = requireSlotAlert(
    createEip1967SlotChangeAlert({
      chain: "ethereum",
      snapshot: buildSlotSnapshot({
        slotKind: "implementation",
        slot: EIP1967_IMPLEMENTATION_SLOT,
        beforeRaw: addressToStorageWord(SAMPLE_ADDRESS_A),
        afterRaw: addressToStorageWord(SAMPLE_ADDRESS_C)
      }),
      createdAt: "2026-07-03T00:00:00.000Z"
    })
  );
  const refinedUnknownImplementation = refineAlertSeverity(unknownImplementationAlert, allowlists);

  assertSeverity(refinedUnknownImplementation, "CRITICAL", false);

  const knownAdminAlert = requireSlotAlert(
    createEip1967SlotChangeAlert({
      chain: "ethereum",
      snapshot: buildSlotSnapshot({
        slotKind: "admin",
        slot: EIP1967_ADMIN_SLOT,
        beforeRaw: addressToStorageWord(SAMPLE_ADDRESS_A),
        afterRaw: addressToStorageWord(knownAdmin)
      }),
      createdAt: "2026-07-03T00:00:00.000Z"
    })
  );
  const refinedKnownAdmin = refineAlertSeverity(knownAdminAlert, allowlists);

  assertSeverity(refinedKnownAdmin, "WARNING", true);

  const unknownAdminAlert = requireSlotAlert(
    createEip1967SlotChangeAlert({
      chain: "ethereum",
      snapshot: buildSlotSnapshot({
        slotKind: "admin",
        slot: EIP1967_ADMIN_SLOT,
        beforeRaw: addressToStorageWord(SAMPLE_ADDRESS_A),
        afterRaw: addressToStorageWord(SAMPLE_ADDRESS_B)
      }),
      createdAt: "2026-07-03T00:00:00.000Z"
    })
  );
  const refinedUnknownAdmin = refineAlertSeverity(unknownAdminAlert, allowlists);

  assertSeverity(refinedUnknownAdmin, "CRITICAL", false);

  const refinedKnownGovernance = refineAlertSeverity(knownPayloadAlert, allowlists);

  assertSeverity(refinedKnownGovernance, "INFO", true);

  const refinedUnknownGovernance = refineAlertSeverity(
    {
      ...knownPayloadAlert,
      address: SAMPLE_ADDRESS_A
    },
    allowlists
  );

  assertSeverity(refinedUnknownGovernance, "WARNING", false);

  JSON.stringify(refinedKnownImplementation.metadata.severityReason);
  JSON.stringify(refinedUnknownImplementation.metadata.severityReason);
  JSON.stringify(refinedKnownAdmin.metadata.severityReason);
  JSON.stringify(refinedUnknownAdmin.metadata.severityReason);
  JSON.stringify(refinedKnownGovernance.metadata.severityReason);
  JSON.stringify(refinedUnknownGovernance.metadata.severityReason);
}

function requireSlotAlert(alert: ReturnType<typeof createEip1967SlotChangeAlert>) {
  if (alert === undefined) {
    throw new Error("Expected EIP-1967 slot change alert.");
  }

  return alert;
}

function assertSeverity(alert: { severity: string; metadata: Record<string, unknown> }, expected: string, expectedMatch: boolean): void {
  if (alert.severity !== expected) {
    throw new Error(`Expected refined severity ${expected}, got ${alert.severity}.`);
  }

  const severityReason = alert.metadata.severityReason;

  if (!isSmokeRecord(severityReason)) {
    throw new Error("Refined alert missing severityReason metadata.");
  }

  if (severityReason.finalSeverity !== expected) {
    throw new Error("severityReason finalSeverity does not match alert severity.");
  }

  if (severityReason.matchedAllowlist !== expectedMatch) {
    throw new Error("severityReason matchedAllowlist did not match expected value.");
  }
}

function isSmokeRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function buildSlotSnapshot(params: {
  slotKind: "implementation" | "admin";
  slot: Hex;
  beforeRaw: Hex;
  afterRaw: Hex;
}): Eip1967SlotSnapshot {
  return {
    proxy: {
      name: "Smoke Proxy",
      address: SAMPLE_ADDRESS_A,
      checkImplementationSlot: true,
      checkAdminSlot: true
    },
    slotKind: params.slotKind,
    slot: params.slot,
    beforeBlock: 99n,
    afterBlock: 100n,
    before: normalizeSlotValue(params.beforeRaw),
    after: normalizeSlotValue(params.afterRaw)
  };
}

function addressToStorageWord(address: Address): Hex {
  return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}`;
}
