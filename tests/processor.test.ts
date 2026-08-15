import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeAbiParameters, type Hex } from "viem";
import { createAlertFromLog } from "../src/alerts.js";
import { buildEventTopicMap } from "../src/events.js";
import { processLogs } from "../src/processor.js";
import { getRuleForEventSignature } from "../src/rules.js";
import { refineAlertSeverity } from "../src/severity.js";
import {
  AAVE_PAYLOADS_CONTROLLER,
  AAVE_POOL,
  AAVE_POOL_IMPLEMENTATION,
  ADDRESS_A,
  ADDRESS_B,
  EVENT_SIGNATURES,
  EXPECTED_RULE_IDS,
  FIXED_CREATED_AT,
  buildFixtureTopicMap,
  buildSyntheticEventLogs,
  emptyAllowlists,
  requireTopic
} from "./fixtures.js";

describe("processLogs", () => {
  test("decodes and maps every supported v0.1 event in input order", () => {
    const topicMap = buildFixtureTopicMap();
    const result = processLogs({
      chain: "ethereum",
      logs: buildSyntheticEventLogs(topicMap),
      topicMap,
      allowlists: emptyAllowlists(),
      clock: () => FIXED_CREATED_AT
    });

    assert.deepEqual(
      result.alerts.map((alert) => alert.ruleId),
      EXPECTED_RULE_IDS
    );
    assert.equal(result.unprocessedLogs.length, 0);
    assert.equal(new Set(result.alerts.map((alert) => alert.id)).size, result.alerts.length);

    for (const alert of result.alerts) {
      assert.ok("decoded" in alert.metadata);
      assert.doesNotThrow(() => JSON.stringify(alert));
    }
  });

  test("preserves a configured signature without a structured rule as unprocessed", () => {
    const signature = "CustomEvent(uint256)";
    const topicMap = buildEventTopicMap([signature]);
    const topic = requireTopic(topicMap, signature);
    const log = {
      blockNumber: "0x64" as Hex,
      transactionHash: `0x${"1".repeat(64)}` as Hex,
      logIndex: "0x0" as Hex,
      address: ADDRESS_A,
      topics: [topic],
      data: encodeAbiParameters([{ type: "uint256" }], [1n])
    };

    const result = processLogs({
      chain: "ethereum",
      logs: [log],
      topicMap,
      allowlists: emptyAllowlists(),
      clock: () => FIXED_CREATED_AT
    });

    assert.equal(result.alerts.length, 0);
    assert.deepEqual(result.unprocessedLogs, [{ log, matchedEventSignature: signature }]);
  });

  test("preserves the current malformed-log behavior: alert with decodeError", () => {
    const signature = "Paused(address)";
    const topicMap = buildEventTopicMap([signature]);
    const result = processLogs({
      chain: "ethereum",
      topicMap,
      allowlists: emptyAllowlists(),
      clock: () => FIXED_CREATED_AT,
      logs: [
        {
          blockNumber: "0x64",
          transactionHash: `0x${"2".repeat(64)}`,
          logIndex: "0x0",
          address: ADDRESS_A,
          topics: [requireTopic(topicMap, signature)],
          data: "0x"
        }
      ]
    });

    assert.equal(result.alerts.length, 1);
    assert.equal(result.alerts[0]?.ruleId, "PAUSED");
    assert.equal(typeof result.alerts[0]?.metadata.decodeError, "string");
  });

  test("converts decoded bigint fields to JSON-safe strings", () => {
    const topicMap = buildFixtureTopicMap();
    const result = processLogs({
      chain: "ethereum",
      logs: [buildSyntheticEventLogs(topicMap)[7]!],
      topicMap,
      allowlists: emptyAllowlists(),
      clock: () => FIXED_CREATED_AT
    });

    const decoded = result.alerts[0]?.metadata.decoded as Record<string, unknown>;
    assert.equal(decoded.payment, "123");
    assert.doesNotThrow(() => JSON.stringify(result.alerts[0]));
  });

  test("produces a stable ID for the same log while allowing a controlled clock", () => {
    const topicMap = buildFixtureTopicMap();
    const log = buildSyntheticEventLogs(topicMap)[0]!;
    const run = () =>
      processLogs({
        chain: "ethereum",
        logs: [log],
        topicMap,
        allowlists: emptyAllowlists(),
        clock: () => FIXED_CREATED_AT
      }).alerts[0]!;

    assert.deepEqual(run(), run());
  });

  test("does not duplicate the same alert within one processing batch", () => {
    const topicMap = buildFixtureTopicMap();
    const log = buildSyntheticEventLogs(topicMap)[0]!;
    const result = processLogs({
      chain: "ethereum",
      logs: [log, log],
      topicMap,
      allowlists: emptyAllowlists(),
      clock: () => FIXED_CREATED_AT
    });

    assert.equal(result.alerts.length, 1);
  });

  test("applies the existing governance and proxy allowlist decisions", () => {
    const topicMap = buildFixtureTopicMap();
    const logs = buildSyntheticEventLogs(topicMap);
    const payload = { ...logs[9]!, address: AAVE_PAYLOADS_CONTROLLER };
    const upgraded = { ...logs[5]!, address: AAVE_POOL };
    const allowlists = {
      ...emptyAllowlists(),
      knownGovernanceContracts: [{ name: "Aave Payloads Controller", address: AAVE_PAYLOADS_CONTROLLER }],
      knownProxyAddresses: [{ name: "Aave Pool", address: AAVE_POOL }]
    };

    const known = processLogs({
      chain: "ethereum",
      logs: [payload, upgraded],
      topicMap,
      allowlists,
      clock: () => FIXED_CREATED_AT
    }).alerts;
    const unknown = processLogs({
      chain: "ethereum",
      logs: [{ ...payload, address: ADDRESS_B }, { ...upgraded, address: ADDRESS_B }],
      topicMap,
      allowlists,
      clock: () => FIXED_CREATED_AT
    }).alerts;

    assert.deepEqual(known.map((alert) => alert.severity), ["INFO", "WARNING"]);
    assert.deepEqual(unknown.map((alert) => alert.severity), ["WARNING", "WARNING"]);
    assert.equal((known[0]!.metadata.severityReason as Record<string, unknown>).matchedAllowlist, true);
    assert.equal((unknown[0]!.metadata.severityReason as Record<string, unknown>).matchedAllowlist, false);
    assert.equal((known[1]!.metadata.severityReason as Record<string, unknown>).matchedAllowlist, true);
    assert.equal((unknown[1]!.metadata.severityReason as Record<string, unknown>).matchedAllowlist, false);
  });
});

describe("historical processor regressions", () => {
  test("matches the previous low-level path for Aave payload 453", () => {
    const signature = "PayloadExecuted(uint40)";
    const topicMap = buildEventTopicMap([signature]);
    const log = {
      blockNumber: "0x183ee00" as Hex,
      transactionHash: "0x14c3acdb367a62c25d2a405f97a08ddae6399714032f1060167af4cc7b9d47c8" as Hex,
      logIndex: "0x2a6" as Hex,
      address: AAVE_PAYLOADS_CONTROLLER,
      topics: [requireTopic(topicMap, signature)],
      data: encodeAbiParameters([{ type: "uint40", name: "payloadId" }], [453])
    };
    const allowlists = {
      ...emptyAllowlists(),
      knownGovernanceContracts: [{ address: AAVE_PAYLOADS_CONTROLLER }]
    };
    const rule = getRuleForEventSignature(signature);
    assert.ok(rule);
    const previousPath = refineAlertSeverity(
      createAlertFromLog({ chain: "ethereum", log, eventSignature: signature, rule, createdAt: FIXED_CREATED_AT }),
      allowlists
    );
    const processed = processLogs({
      chain: "ethereum",
      logs: [log],
      topicMap,
      allowlists,
      clock: () => FIXED_CREATED_AT
    }).alerts[0]!;

    assert.deepEqual(processed, previousPath);
    assert.equal(processed.id, "ethereum:GOVERNANCE_PAYLOAD_EXECUTED:25423360:0x14c3acdb367a62c25d2a405f97a08ddae6399714032f1060167af4cc7b9d47c8:678");
    assert.equal(processed.summary, "Governance payload executed: payloadId 453.");
  });

  test("matches the previous low-level path for the Aave Pool upgrade event", () => {
    const signature = "Upgraded(address)";
    const topicMap = buildEventTopicMap([signature]);
    const log = {
      blockNumber: "0x1808543" as Hex,
      transactionHash: "0xe9949c36e86fc9f481897dbac8de33d655bff20b267955a303e2e5643fbc2b35" as Hex,
      logIndex: "0x411" as Hex,
      address: AAVE_POOL,
      topics: [requireTopic(topicMap, signature), `0x${"0".repeat(24)}${AAVE_POOL_IMPLEMENTATION.slice(2).toLowerCase()}` as Hex],
      data: "0x" as Hex
    };
    const allowlists = { ...emptyAllowlists(), knownProxyAddresses: [{ address: AAVE_POOL }] };
    const rule = getRuleForEventSignature(signature);
    assert.ok(rule);
    const previousPath = refineAlertSeverity(
      createAlertFromLog({ chain: "ethereum", log, eventSignature: signature, rule, createdAt: FIXED_CREATED_AT }),
      allowlists
    );
    const processed = processLogs({
      chain: "ethereum",
      logs: [log],
      topicMap,
      allowlists,
      clock: () => FIXED_CREATED_AT
    }).alerts[0]!;

    assert.deepEqual(processed, previousPath);
    assert.equal(processed.id, "ethereum:PROXY_UPGRADED:25199939:0xe9949c36e86fc9f481897dbac8de33d655bff20b267955a303e2e5643fbc2b35:1041");
    assert.equal(processed.severity, "WARNING");
  });
});
