import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { encodeAbiParameters, type Hex } from "viem";
import type { Alert } from "../src/alerts.js";
import type { MonitorConfig } from "../src/config.js";
import { EIP1967_IMPLEMENTATION_SLOT } from "../src/eip1967.js";
import { buildEventTopicMap } from "../src/events.js";
import { executeHistoricalScan } from "../src/historicalScanner.js";
import {
  PolicyRpcClient,
  RpcPermanentError,
  type RawRpcProvider,
  type RpcClient,
  type RpcLogRequest,
  type RpcStorageRequest
} from "../src/rpc.js";
import { JsonlAlertSink, type AlertSink } from "../src/sinks.js";
import {
  AAVE_PAYLOADS_CONTROLLER,
  AAVE_POOL,
  AAVE_POOL_IMPLEMENTATION,
  FIXED_CREATED_AT,
  addressToStorageWord,
  emptyAllowlists,
  requireTopic
} from "./fixtures.js";
import {
  ECON_USER_A,
  ECON_USER_B,
  ECON_VAULT,
  economicConfig,
  monitorConfigWithEconomic,
  transferLog
} from "./economicFixtures.js";

function monitorConfig(withProxy = false): MonitorConfig {
  return {
    chain: "ethereum",
    monitoredAddresses: [AAVE_PAYLOADS_CONTROLLER],
    knownMultisigs: [],
    eventSignatures: ["PayloadExecuted(uint40)"],
    ...(withProxy
      ? {
          proxySlotMonitoring: {
            enabled: true,
            proxies: [
              {
                name: "AaveV3Ethereum.POOL",
                address: AAVE_POOL,
                checkImplementationSlot: true,
                checkAdminSlot: false
              }
            ]
          }
        }
      : {}),
    allowlists: {
      ...emptyAllowlists(),
      knownGovernanceContracts: [{ address: AAVE_PAYLOADS_CONTROLLER }],
      knownImplementations: [{ address: AAVE_POOL_IMPLEMENTATION }]
    }
  };
}

function payloadLog(blockNumber: bigint, logIndex = 0n) {
  const topicMap = buildEventTopicMap(["PayloadExecuted(uint40)"]);
  return {
    blockNumber: `0x${blockNumber.toString(16)}` as Hex,
    transactionHash: `0x${blockNumber.toString(16).padStart(64, "0")}` as Hex,
    logIndex: `0x${logIndex.toString(16)}` as Hex,
    address: AAVE_PAYLOADS_CONTROLLER,
    topics: [requireTopic(topicMap, "PayloadExecuted(uint40)")],
    data: encodeAbiParameters([{ type: "uint40", name: "payloadId" }], [Number(blockNumber)])
  };
}

class CaptureSink implements AlertSink {
  writes: Alert[][] = [];

  write(alerts: readonly Alert[]): void {
    this.writes.push([...alerts]);
  }
}

describe("historical scanner RPC integration", () => {
  test("processes multiple chunks sequentially and preserves alert order", async () => {
    const calls: RpcLogRequest[] = [];
    const rpc: RpcClient = {
      async getLogs(request) {
        calls.push(request);
        return [payloadLog(request.fromBlock)];
      },
      async getStorageAt() {
        return undefined;
      },
      async getErc20Balance() {
        return 0n;
      }
    };
    const sink = new CaptureSink();

    const result = await executeHistoricalScan({
      rpc,
      config: monitorConfig(),
      startBlock: 10n,
      endBlock: 14n,
      maxBlockRange: 2n,
      clock: () => FIXED_CREATED_AT,
      sinks: [sink]
    });

    assert.deepEqual(calls.map((call) => [call.fromBlock, call.toBlock]), [
      [10n, 11n],
      [12n, 13n],
      [14n, 14n]
    ]);
    assert.ok(calls.every((call) => call.toBlock - call.fromBlock + 1n <= 2n));
    assert.deepEqual(result.alerts.map((alert) => alert.blockNumber), ["10", "12", "14"]);
    assert.deepEqual(sink.writes[0], result.alerts);
    assert.equal(new Set(result.alerts.map((alert) => alert.id)).size, result.alerts.length);
  });

  test("routes EIP-1967 storage through the centralized client in deterministic order", async () => {
    const storageCalls: RpcStorageRequest[] = [];
    const previousImplementation = "0x8147b99DF7672A21809c9093E6F6CE1a60F119Bd";
    const values = [
      addressToStorageWord(previousImplementation),
      addressToStorageWord(AAVE_POOL_IMPLEMENTATION)
    ];
    const rpc: RpcClient = {
      async getLogs() {
        return [];
      },
      async getStorageAt(request) {
        storageCalls.push(request);
        return values.shift();
      },
      async getErc20Balance() {
        return 0n;
      }
    };

    const result = await executeHistoricalScan({
      rpc,
      config: monitorConfig(true),
      startBlock: 25199939n,
      endBlock: 25199939n,
      maxBlockRange: 100n,
      clock: () => FIXED_CREATED_AT,
      sinks: []
    });

    assert.deepEqual(storageCalls.map((call) => call.blockNumber), [25199938n, 25199939n]);
    assert.ok(storageCalls.every((call) => call.slot === EIP1967_IMPLEMENTATION_SLOT));
    assert.equal(result.alerts[0]?.ruleId, "PROXY_IMPLEMENTATION_SLOT_CHANGED");
    assert.equal(result.alerts[0]?.severity, "WARNING");
  });

  test("does not write any final sink when a later chunk fails", async () => {
    let callCount = 0;
    const rpc: RpcClient = {
      async getLogs(request) {
        callCount += 1;
        if (callCount === 2) {
          throw new RpcPermanentError(
            "eth_getLogs",
            { operation: "eth_getLogs", fromBlock: request.fromBlock, toBlock: request.toBlock },
            new Error("invalid params")
          );
        }
        return [payloadLog(request.fromBlock)];
      },
      async getStorageAt() {
        return undefined;
      },
      async getErc20Balance() {
        return 0n;
      }
    };
    const directory = mkdtempSync(join(tmpdir(), "onchain-radar-fail-closed-"));
    const outputPath = join(directory, "alerts", "result.jsonl");

    try {
      await assert.rejects(
        executeHistoricalScan({
          rpc,
          config: monitorConfig(),
          startBlock: 10n,
          endBlock: 14n,
          maxBlockRange: 2n,
          clock: () => FIXED_CREATED_AT,
          sinks: [new JsonlAlertSink(outputPath)]
        }),
        (error: unknown) => {
          assert.ok(error instanceof RpcPermanentError);
          assert.match(error.message, /blocks 12-13/);
          return true;
        }
      );
      assert.equal(callCount, 2);
      assert.equal(existsSync(outputPath), false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  test("does not duplicate alerts when a transient call is retried", async () => {
    let attempts = 0;
    const provider: RawRpcProvider = {
      async getLogs(request) {
        attempts += 1;
        if (attempts === 1) {
          throw Object.assign(new Error("Service Unavailable"), { status: 503 });
        }
        return [payloadLog(request.fromBlock)];
      },
      async getStorageAt() {
        return undefined;
      },
      async getErc20Balance() {
        return 0n;
      }
    };
    const rpc = new PolicyRpcClient(
      provider,
      {
        timeoutMs: 100,
        maxRetries: 1,
        retryBaseDelayMs: 1,
        retryMaxDelayMs: 1,
        maxBlockRange: 10n,
        maxSplitDepth: 2
      },
      { sleep: async () => undefined }
    );

    const result = await executeHistoricalScan({
      rpc,
      config: monitorConfig(),
      startBlock: 10n,
      endBlock: 10n,
      maxBlockRange: 10n,
      clock: () => FIXED_CREATED_AT,
      sinks: []
    });

    assert.equal(attempts, 2);
    assert.equal(result.alerts.length, 1);
    assert.equal(result.alerts[0]?.id, "ethereum:GOVERNANCE_PAYLOAD_EXECUTED:10:0x000000000000000000000000000000000000000000000000000000000000000a:0");
  });

  test("preserves the previous path without economicMonitoring and makes no balance calls", async () => {
    let balanceCalls = 0;
    const rpc: RpcClient = {
      async getLogs() {
        return [];
      },
      async getStorageAt() {
        return undefined;
      },
      async getErc20Balance() {
        balanceCalls += 1;
        return 0n;
      }
    };
    const result = await executeHistoricalScan({
      rpc,
      config: monitorConfigWithEconomic(),
      startBlock: 10n,
      endBlock: 10n,
      maxBlockRange: 10n,
      clock: () => FIXED_CREATED_AT,
      sinks: []
    });
    assert.equal(balanceCalls, 0);
    assert.equal(result.economicTransferCount, 0);
    assert.equal(result.economicAlertCount, 0);
  });

  test("runs the complete economic pipeline and appends deterministic alerts", async () => {
    const config = monitorConfigWithEconomic(economicConfig());
    let logCalls = 0;
    const balanceCalls: bigint[] = [];
    const balances = new Map<bigint, bigint>([
      [99n, 1000n],
      [104n, 1000n],
      [105n, 300n],
      [110n, 300n]
    ]);
    const rpc: RpcClient = {
      async getLogs() {
        logCalls += 1;
        if (logCalls === 1) {
          return [];
        }
        return [
          transferLog({ from: "0x0000000000000000000000000000000000000000", to: ECON_USER_A, value: 200n, blockNumber: 102n }),
          transferLog({ from: ECON_VAULT, to: ECON_USER_A, value: 600n, blockNumber: 105n }),
          transferLog({ from: ECON_VAULT, to: ECON_USER_B, value: 100n, blockNumber: 105n, logIndex: 1 })
        ];
      },
      async getStorageAt() {
        return undefined;
      },
      async getErc20Balance(request) {
        balanceCalls.push(request.blockNumber);
        const balance = balances.get(request.blockNumber);
        if (balance === undefined) {
          throw new Error(`Unexpected balance block ${request.blockNumber.toString()}`);
        }
        return balance;
      }
    };
    const sink = new CaptureSink();
    const result = await executeHistoricalScan({
      rpc,
      config,
      startBlock: 100n,
      endBlock: 110n,
      maxBlockRange: 20n,
      clock: () => FIXED_CREATED_AT,
      sinks: [sink]
    });

    assert.equal(logCalls, 2);
    assert.deepEqual(balanceCalls, [99n, 104n, 105n, 110n]);
    assert.equal(result.economicTransferCount, 3);
    assert.deepEqual(result.alerts.map((alert) => alert.ruleId), [
      "LARGE_ASSET_TRANSFER",
      "LARGE_ASSET_TRANSFER",
      "LARGE_TOKEN_MINT",
      "CRITICAL_CONTRACT_OUTFLOW",
      "LIQUIDITY_DRAWDOWN",
      "OUTFLOW_CONCENTRATION",
      "ECONOMIC_SECURITY_ANOMALY"
    ]);
    assert.equal(new Set(result.alerts.map((alert) => alert.id)).size, result.alerts.length);
    assert.deepEqual(sink.writes[0], result.alerts);
  });

  test("does not invoke final sinks when an economic balance read fails", async () => {
    const sink = new CaptureSink();
    const rpc: RpcClient = {
      async getLogs() {
        return [];
      },
      async getStorageAt() {
        return undefined;
      },
      async getErc20Balance(request) {
        throw new RpcPermanentError(
          "eth_call",
          {
            operation: "eth_call",
            method: "balanceOf",
            token: request.token,
            holder: request.holder,
            blockNumber: request.blockNumber
          },
          new Error("invalid params")
        );
      }
    };

    await assert.rejects(
      executeHistoricalScan({
        rpc,
        config: monitorConfigWithEconomic(economicConfig()),
        startBlock: 100n,
        endBlock: 101n,
        maxBlockRange: 10n,
        clock: () => FIXED_CREATED_AT,
        sinks: [sink]
      }),
      RpcPermanentError
    );
    assert.equal(sink.writes.length, 0);
  });
});
