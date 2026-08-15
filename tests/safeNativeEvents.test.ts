import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  parseAbiItem,
  type AbiEvent,
  type Address,
  type Hex
} from "viem";
import type { RawLogForAlert } from "../src/alerts.js";
import { buildEventTopicMap } from "../src/events.js";
import { executeHistoricalScan } from "../src/historicalScanner.js";
import { processLogs } from "../src/processor.js";
import type { RpcClient } from "../src/rpc.js";
import { classifySafeAction } from "../src/safe/actions.js";
import { correlateSafeAdministrativeEffects } from "../src/safe/correlation.js";
import {
  refineSafeNativeEventAlerts,
  SAFE_NATIVE_ADMIN_EVENT_SIGNATURES
} from "../src/safe/nativeEvents.js";
import type { SafeTransaction } from "../src/safe/types.js";
import { emptyAllowlists } from "./fixtures.js";
import { SAFE, SAFE_TX_HASH, TARGET, USER, safeMonitorConfig, safePolicy } from "./safeFixtures.js";

const OLD_OWNER = getAddress("0x7000000000000000000000000000000000000007");
const MODULE = getAddress("0x8000000000000000000000000000000000000008");

const EVENT_CASES = [
  ["AddedOwner(address)", "SAFE_OWNER_ADDED", "address", USER],
  ["RemovedOwner(address)", "SAFE_OWNER_REMOVED", "address", OLD_OWNER],
  ["ChangedThreshold(uint256)", "SAFE_THRESHOLD_CHANGED", "uint256", 2n],
  ["EnabledModule(address)", "SAFE_MODULE_ENABLED", "address", MODULE],
  ["DisabledModule(address)", "SAFE_MODULE_DISABLED", "address", MODULE],
  ["ChangedGuard(address)", "SAFE_GUARD_CHANGED", "address", TARGET],
  ["ChangedFallbackHandler(address)", "SAFE_FALLBACK_HANDLER_CHANGED", "address", TARGET]
] as const;

describe("Safe native administrative events", () => {
  test("decodes every supported event into its own stable rule with JSON-safe values", () => {
    const topicMap = buildEventTopicMap([...SAFE_NATIVE_ADMIN_EVENT_SIGNATURES]);
    const logs = EVENT_CASES.map(([signature, , type, value], index) => nativeLog(signature, type, value, index));
    const first = processLogs({ chain: "ethereum", logs, topicMap, allowlists: emptyAllowlists(), clock: () => "2026-01-01T00:00:00.000Z" });
    const second = processLogs({ chain: "ethereum", logs, topicMap, allowlists: emptyAllowlists(), clock: () => "2030-01-01T00:00:00.000Z" });
    assert.deepEqual(first.alerts.map((alert) => alert.ruleId), EVENT_CASES.map((entry) => entry[1]));
    assert.deepEqual(first.alerts.map((alert) => alert.id), second.alerts.map((alert) => alert.id));
    assert.equal((first.alerts[2]?.metadata.decoded as Record<string, unknown>).threshold, "2");
  });

  test("leaves an unknown configured event explicitly unprocessed", () => {
    const signature = "UnexpectedSafeEvent(address)";
    const result = processLogs({
      chain: "ethereum",
      logs: [nativeLog(signature, "address", USER, 0)],
      topicMap: buildEventTopicMap([signature]),
      allowlists: emptyAllowlists(),
      clock: () => "2026-01-01T00:00:00.000Z"
    });
    assert.equal(result.alerts.length, 0);
    assert.equal(result.unprocessedLogs[0]?.matchedEventSignature, signature);
  });

  test("applies owner, threshold, module, guard and fallback policy with explicit reasons", () => {
    const policy = safePolicy({
      allowedOwners: [USER],
      minimumThreshold: 2,
      allowedThresholds: [2, 3],
      allowedModules: [TARGET],
      allowedGuards: [TARGET],
      allowedFallbackHandlers: [TARGET]
    });
    const config = { multisigs: [policy] };
    const topicMap = buildEventTopicMap([...SAFE_NATIVE_ADMIN_EVENT_SIGNATURES]);
    const alerts = processLogs({
      chain: "ethereum",
      logs: [
        nativeLog("AddedOwner(address)", "address", USER, 0),
        nativeLog("ChangedThreshold(uint256)", "uint256", 1n, 1),
        nativeLog("EnabledModule(address)", "address", MODULE, 2),
        nativeLog("ChangedGuard(address)", "address", MODULE, 3),
        nativeLog("ChangedFallbackHandler(address)", "address", TARGET, 4)
      ],
      topicMap,
      allowlists: emptyAllowlists(),
      clock: () => "2026-01-01T00:00:00.000Z"
    }).alerts;
    const refined = refineSafeNativeEventAlerts(alerts, config);
    assert.deepEqual(refined.map((alert) => alert.severity), ["INFO", "CRITICAL", "CRITICAL", "CRITICAL", "INFO"]);
    for (const alert of refined) {
      const metadata = alert.metadata.safeNativeEvent as Record<string, unknown>;
      assert.equal(metadata.semanticCategory, "ADMINISTRATIVE_CONTROL");
      assert.equal(typeof metadata.severityReason, "string");
      assert.ok("expectedPolicy" in metadata);
      assert.ok("policyMatched" in metadata);
    }
  });

  test("confirms swapOwner and changeThreshold from exact native effects", () => {
    const swapData = encodeFunctionData({
      abi: [{ type: "function", name: "swapOwner", stateMutability: "nonpayable", inputs: [
        { name: "prevOwner", type: "address" }, { name: "oldOwner", type: "address" }, { name: "newOwner", type: "address" }
      ], outputs: [] }],
      functionName: "swapOwner",
      args: [TARGET, OLD_OWNER, USER]
    });
    const thresholdData = encodeFunctionData({
      abi: [{ type: "function", name: "changeThreshold", stateMutability: "nonpayable", inputs: [{ name: "threshold", type: "uint256" }], outputs: [] }],
      functionName: "changeThreshold",
      args: [2n]
    });
    const eventAlerts = nativeAlerts([
      nativeLog("RemovedOwner(address)", "address", OLD_OWNER, 0),
      nativeLog("AddedOwner(address)", "address", USER, 1),
      nativeLog("ChangedThreshold(uint256)", "uint256", 2n, 2)
    ]);
    const swap = correlateSafeAdministrativeEffects({
      chain: "ethereum", transaction: transaction(swapData), action: classifySafeAction(SAFE, swapData),
      administrativeAlerts: eventAlerts, slotAlerts: [], createdAt: "2026-01-01T00:00:00.000Z"
    });
    const threshold = correlateSafeAdministrativeEffects({
      chain: "ethereum", transaction: transaction(thresholdData), action: classifySafeAction(SAFE, thresholdData),
      administrativeAlerts: eventAlerts, slotAlerts: [], createdAt: "2026-01-01T00:00:00.000Z"
    });
    assert.equal(swap[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED");
    assert.equal(threshold[0]?.ruleId, "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED");
  });

  test("distinguishes inconsistent, ambiguous and unobserved native effects", () => {
    const data = encodeFunctionData({
      abi: [{ type: "function", name: "enableModule", stateMutability: "nonpayable", inputs: [{ name: "module", type: "address" }], outputs: [] }],
      functionName: "enableModule",
      args: [TARGET]
    });
    const action = classifySafeAction(SAFE, data);
    const run = (alerts: ReturnType<typeof nativeAlerts>) => correlateSafeAdministrativeEffects({
      chain: "ethereum", transaction: transaction(data), action, administrativeAlerts: alerts, slotAlerts: [],
      createdAt: "2026-01-01T00:00:00.000Z"
    })[0]!;
    assert.equal(run(nativeAlerts([nativeLog("EnabledModule(address)", "address", MODULE, 0)])).metadata.correlationStatus, "inconsistent");
    assert.equal(run(nativeAlerts([
      nativeLog("EnabledModule(address)", "address", TARGET, 0),
      nativeLog("EnabledModule(address)", "address", TARGET, 1)
    ])).metadata.correlationStatus, "ambiguous");
    assert.equal(run([]).metadata.correlationStatus, "unobserved");
  });

  test("historical orchestration requests and emits native Safe events without transaction reconstruction", async () => {
    let logRequests = 0;
    const rpc: RpcClient = {
      async getLogs() {
        logRequests += 1;
        return logRequests === 1 ? [] : [nativeLog("ChangedThreshold(uint256)", "uint256", 2n, 0)];
      },
      async getStorageAt() { return undefined; },
      async getErc20Balance() { return 0n; },
      async getTransaction() { throw new Error("native-only fixture must not fetch a transaction"); },
      async getTransactionReceipt() { throw new Error("native-only fixture must not fetch a receipt"); }
    };
    const result = await executeHistoricalScan({
      rpc,
      config: safeMonitorConfig(),
      startBlock: 100n,
      endBlock: 100n,
      maxBlockRange: 10n,
      clock: () => "2026-01-01T00:00:00.000Z",
      sinks: []
    });
    assert.equal(logRequests, 2);
    assert.deepEqual(result.alerts.map((alert) => alert.ruleId), ["SAFE_THRESHOLD_CHANGED"]);
    assert.equal(result.safeTransactionCount, 0);
  });
});

function nativeAlerts(logs: RawLogForAlert[]) {
  return processLogs({
    chain: "ethereum", logs, topicMap: buildEventTopicMap([...SAFE_NATIVE_ADMIN_EVENT_SIGNATURES]),
    allowlists: emptyAllowlists(), clock: () => "2026-01-01T00:00:00.000Z"
  }).alerts;
}

function nativeLog(signature: string, type: "address" | "uint256", value: Address | bigint, index: number): RawLogForAlert {
  const name = signature.slice(0, signature.indexOf("("));
  const parameter = name === "ChangedThreshold" ? "threshold" :
    name.includes("Owner") ? "owner" : name.includes("Module") ? "module" :
      name === "ChangedGuard" ? "guard" : "handler";
  const abi = parseAbiItem(`event ${name}(${type} ${parameter})`) as AbiEvent;
  return {
    blockNumber: "0x64", transactionHash: SAFE_TX_HASH, transactionIndex: "0x1", logIndex: `0x${index.toString(16)}` as Hex,
    address: SAFE, topics: [...buildEventTopicMap([signature]).keys()], data: encodeAbiParameters([{ type }], [value] as never)
  };
}

function transaction(data: Hex): SafeTransaction {
  return {
    safeAddress: SAFE, outerTransactionHash: SAFE_TX_HASH, blockNumber: 100n,
    innerTarget: SAFE, innerValue: 0n, innerData: data, innerSelector: data.slice(0, 10) as Hex,
    operation: "CALL", safeTxGas: 0n, baseGas: 0n, gasPrice: 0n,
    gasToken: getAddress("0x0000000000000000000000000000000000000000"),
    refundReceiver: getAddress("0x0000000000000000000000000000000000000000")
  };
}
