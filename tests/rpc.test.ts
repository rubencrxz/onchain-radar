import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Address, Hex } from "viem";
import { loadScanEnv } from "../src/env.js";
import {
  PolicyRpcClient,
  RpcPermanentError,
  RpcPolicyConfigError,
  RpcRangeTooLargeError,
  RpcRetriesExhaustedError,
  RpcTimeoutError,
  calculateBackoffDelay,
  validateRpcPolicyConfig,
  type RawRpcProvider,
  type RpcCodeRequest,
  type RpcLogRequest,
  type RpcErc20BalanceRequest,
  type RpcPolicyConfig,
  type RpcPolicyEvent,
  type RpcStorageRequest,
  type RunWithTimeout
} from "../src/rpc.js";
import { ADDRESS_A } from "./fixtures.js";

const SLOT = `0x${"0".repeat(64)}` as Hex;
const STORAGE_VALUE = `0x${"0".repeat(24)}${ADDRESS_A.slice(2)}` as Hex;

function policy(overrides: Partial<RpcPolicyConfig> = {}): RpcPolicyConfig {
  return {
    timeoutMs: 100,
    maxRetries: 2,
    retryBaseDelayMs: 10,
    retryMaxDelayMs: 25,
    maxBlockRange: 100n,
    maxSplitDepth: 10,
    ...overrides
  };
}

function logRequest(fromBlock = 1n, toBlock = 2n): RpcLogRequest {
  return { addresses: [], topics: [SLOT], fromBlock, toBlock };
}

function storageRequest(): RpcStorageRequest {
  return { address: ADDRESS_A, slot: SLOT, blockNumber: 123n };
}

function sampleLog(blockNumber: bigint) {
  return {
    blockNumber: `0x${blockNumber.toString(16)}` as Hex,
    transactionHash: `0x${blockNumber.toString(16).padStart(64, "0")}` as Hex,
    logIndex: "0x0" as Hex,
    address: ADDRESS_A,
    topics: [SLOT],
    data: "0x" as Hex
  };
}

function statusError(status: number, message: string): Error {
  return Object.assign(new Error(message), { status });
}

class ScriptedProvider implements RawRpcProvider {
  readonly logCalls: RpcLogRequest[] = [];
  readonly storageCalls: RpcStorageRequest[] = [];
  readonly balanceCalls: RpcErc20BalanceRequest[] = [];
  readonly codeCalls: RpcCodeRequest[] = [];

  constructor(
    private readonly logSteps: Array<() => Promise<ReturnType<typeof sampleLog>[]>> = [],
    private readonly storageSteps: Array<() => Promise<Hex | undefined>> = [],
    private readonly balanceSteps: Array<() => Promise<bigint>> = [],
    private readonly codeSteps: Array<() => Promise<Hex | undefined>> = []
  ) {}

  async getLogs(request: RpcLogRequest) {
    this.logCalls.push(request);
    const step = this.logSteps.shift();
    return step === undefined ? [] : step();
  }

  async getStorageAt(request: RpcStorageRequest) {
    this.storageCalls.push(request);
    const step = this.storageSteps.shift();
    return step === undefined ? undefined : step();
  }

  async getErc20Balance(request: RpcErc20BalanceRequest) {
    this.balanceCalls.push(request);
    const step = this.balanceSteps.shift();
    return step === undefined ? 0n : step();
  }

  async getCode(request: RpcCodeRequest) {
    this.codeCalls.push(request);
    const step = this.codeSteps.shift();
    return step === undefined ? undefined : step();
  }
}

describe("RPC policy success and retries", () => {
  test("returns logs and storage on the first attempt", async () => {
    const provider = new ScriptedProvider(
      [async () => [sampleLog(1n)]],
      [async () => STORAGE_VALUE]
    );
    const rpc = new PolicyRpcClient(provider, policy());

    assert.deepEqual(await rpc.getLogs(logRequest()), [sampleLog(1n)]);
    assert.equal(await rpc.getStorageAt(storageRequest()), STORAGE_VALUE);
    assert.equal(provider.logCalls.length, 1);
    assert.equal(provider.storageCalls.length, 1);
  });

  test("retries a timeout and then succeeds", async () => {
    const timeout = Object.assign(new Error("request timed out"), { name: "TimeoutError" });
    const provider = new ScriptedProvider([
      async () => Promise.reject(timeout),
      async () => [sampleLog(1n)]
    ]);
    const delays: number[] = [];
    const rpc = new PolicyRpcClient(provider, policy(), { sleep: async (delay) => void delays.push(delay) });

    assert.equal((await rpc.getLogs(logRequest())).length, 1);
    assert.equal(provider.logCalls.length, 2);
    assert.deepEqual(delays, [10]);
  });

  test("retries HTTP 429 and 5xx errors", async () => {
    const provider = new ScriptedProvider([
      async () => Promise.reject(statusError(429, "Too Many Requests")),
      async () => Promise.reject(statusError(503, "Service Unavailable")),
      async () => [sampleLog(1n)]
    ]);
    const delays: number[] = [];
    const rpc = new PolicyRpcClient(provider, policy(), { sleep: async (delay) => void delays.push(delay) });

    await rpc.getLogs(logRequest());
    assert.equal(provider.logCalls.length, 3);
    assert.deepEqual(delays, [10, 20]);
  });

  test("caps exponential backoff and records exact delays", async () => {
    const provider = new ScriptedProvider([
      async () => Promise.reject(statusError(500, "Internal Server Error")),
      async () => Promise.reject(statusError(500, "Internal Server Error")),
      async () => Promise.reject(statusError(500, "Internal Server Error")),
      async () => [sampleLog(1n)]
    ]);
    const delays: number[] = [];
    const rpc = new PolicyRpcClient(provider, policy({ maxRetries: 3, retryMaxDelayMs: 15 }), {
      sleep: async (delay) => void delays.push(delay)
    });

    await rpc.getLogs(logRequest());
    assert.deepEqual(delays, [10, 15, 15]);
    assert.equal(calculateBackoffDelay(10, 10, 15), 15);
  });

  test("throws a contextual error after retries are exhausted", async () => {
    const provider = new ScriptedProvider([
      async () => Promise.reject(statusError(503, "Service Unavailable")),
      async () => Promise.reject(statusError(503, "Service Unavailable")),
      async () => Promise.reject(statusError(503, "Service Unavailable"))
    ]);
    const delays: number[] = [];
    const events: RpcPolicyEvent[] = [];
    const rpc = new PolicyRpcClient(provider, policy(), {
      sleep: async (delay) => void delays.push(delay),
      logger: (event) => events.push(event)
    });

    await assert.rejects(
      rpc.getLogs(logRequest(10n, 20n)),
      (error: unknown) => {
        assert.ok(error instanceof RpcRetriesExhaustedError);
        assert.equal(error.attempts, 3);
        assert.equal(error.classification, "transient");
        assert.match(error.message, /blocks 10-20/);
        assert.ok(error.cause instanceof Error);
        return true;
      }
    );
    assert.equal(provider.logCalls.length, 3);
    assert.deepEqual(delays, [10, 20]);
    const finalEvent = events.at(-1);
    assert.equal(finalEvent?.type, "exhausted");
    assert.equal(finalEvent?.type === "exhausted" ? finalEvent.reason : undefined, "HTTP 503");
  });

  test("does not retry permanent invalid-parameter errors", async () => {
    const invalid = Object.assign(new Error("invalid params"), { code: -32602 });
    const provider = new ScriptedProvider([async () => Promise.reject(invalid)]);
    const delays: number[] = [];
    const rpc = new PolicyRpcClient(provider, policy(), { sleep: async (delay) => void delays.push(delay) });

    await assert.rejects(rpc.getLogs(logRequest()), RpcPermanentError);
    assert.equal(provider.logCalls.length, 1);
    assert.deepEqual(delays, []);
  });
});

describe("explicit timeout", () => {
  const immediateTimeout: RunWithTimeout = async (operation, _timeoutMs, createTimeoutError) => {
    void operation();
    throw createTimeoutError();
  };

  test("classifies a never-resolving log operation without real waiting", async () => {
    const provider = new ScriptedProvider([async () => new Promise(() => undefined)]);
    const rpc = new PolicyRpcClient(provider, policy({ maxRetries: 0 }), { runWithTimeout: immediateTimeout });

    await assert.rejects(
      rpc.getLogs(logRequest(50n, 60n)),
      (error: unknown) => {
        assert.ok(error instanceof RpcRetriesExhaustedError);
        assert.equal(error.classification, "timeout");
        assert.match(error.message, /blocks 50-60/);
        assert.ok(error.cause instanceof RpcTimeoutError);
        return true;
      }
    );
  });

  test("includes address, slot and block in storage timeout context", async () => {
    const provider = new ScriptedProvider([], [async () => new Promise(() => undefined)]);
    const rpc = new PolicyRpcClient(provider, policy({ maxRetries: 0 }), { runWithTimeout: immediateTimeout });

    await assert.rejects(
      rpc.getStorageAt(storageRequest()),
      (error: unknown) => {
        assert.ok(error instanceof RpcRetriesExhaustedError);
        assert.match(error.message, new RegExp(ADDRESS_A, "i"));
        assert.match(error.message, /block 123/);
        assert.match(error.message, new RegExp(SLOT, "i"));
        return true;
      }
    );
  });

  test("classifies balanceOf timeout with token, holder and block context", async () => {
    const provider = new ScriptedProvider([], [], [async () => new Promise(() => undefined)]);
    const rpc = new PolicyRpcClient(provider, policy({ maxRetries: 0 }), { runWithTimeout: immediateTimeout });

    await assert.rejects(
      rpc.getErc20Balance({ token: ADDRESS_A, holder: ADDRESS_A, blockNumber: 456n }),
      (error: unknown) => {
        assert.ok(error instanceof RpcRetriesExhaustedError);
        assert.equal(error.operation, "eth_call");
        assert.match(error.message, new RegExp(ADDRESS_A, "i"));
        assert.match(error.message, /block 456/);
        assert.match(error.message, /balanceOf/);
        return true;
      }
    );
  });
});

describe("ERC-20 balance RPC policy", () => {
  test("returns balanceOf and caches successful token-holder-block requests", async () => {
    const provider = new ScriptedProvider([], [], [async () => 1234n]);
    const rpc = new PolicyRpcClient(provider, policy());
    const request = { token: ADDRESS_A, holder: ADDRESS_A, blockNumber: 99n };

    assert.equal(await rpc.getErc20Balance(request), 1234n);
    assert.equal(await rpc.getErc20Balance(request), 1234n);
    assert.equal(provider.balanceCalls.length, 1);
  });

  test("retries transient balanceOf failures and caches only the success", async () => {
    const provider = new ScriptedProvider([], [], [
      async () => Promise.reject(statusError(503, "Service Unavailable")),
      async () => 900n
    ]);
    const delays: number[] = [];
    const rpc = new PolicyRpcClient(provider, policy({ maxRetries: 1 }), {
      sleep: async (delay) => void delays.push(delay)
    });
    const request = { token: ADDRESS_A, holder: ADDRESS_A, blockNumber: 100n };

    assert.equal(await rpc.getErc20Balance(request), 900n);
    assert.equal(await rpc.getErc20Balance(request), 900n);
    assert.equal(provider.balanceCalls.length, 2);
    assert.deepEqual(delays, [10]);
  });
});

describe("contract code RPC policy", () => {
  test("returns and caches historical eth_getCode through the central policy", async () => {
    const provider = new ScriptedProvider([], [], [], [async () => "0x6000"]);
    const rpc = new PolicyRpcClient(provider, policy());
    const request = { address: ADDRESS_A, blockNumber: 321n };

    assert.equal(await rpc.getCode(request), "0x6000");
    assert.equal(await rpc.getCode(request), "0x6000");
    assert.equal(provider.codeCalls.length, 1);
  });

  test("retries eth_getCode and preserves address/block context on exhaustion", async () => {
    const provider = new ScriptedProvider([], [], [], [
      async () => Promise.reject(statusError(503, "Service Unavailable")),
      async () => Promise.reject(statusError(503, "Service Unavailable"))
    ]);
    const delays: number[] = [];
    const rpc = new PolicyRpcClient(provider, policy({ maxRetries: 1 }), { sleep: async (delay) => void delays.push(delay) });

    await assert.rejects(
      rpc.getCode({ address: ADDRESS_A, blockNumber: 321n }),
      (error: unknown) => {
        assert.ok(error instanceof RpcRetriesExhaustedError);
        assert.equal(error.operation, "eth_getCode");
        assert.match(error.message, new RegExp(ADDRESS_A, "i"));
        assert.match(error.message, /block 321/);
        return true;
      }
    );
    assert.equal(provider.codeCalls.length, 2);
    assert.deepEqual(delays, [10]);
  });
});

describe("adaptive log range splitting", () => {
  test("splits rejected ranges recursively and preserves left-to-right order", async () => {
    const calls: Array<[bigint, bigint]> = [];
    const events: RpcPolicyEvent[] = [];
    const provider: RawRpcProvider = {
      async getLogs(request) {
        calls.push([request.fromBlock, request.toBlock]);
        if (request.toBlock - request.fromBlock + 1n > 2n) {
          throw new Error("query returned more than allowed results; range too large");
        }
        return [sampleLog(request.fromBlock)];
      },
      async getStorageAt() {
        return undefined;
      },
      async getErc20Balance() {
        return 0n;
      }
    };
    const rpc = new PolicyRpcClient(provider, policy({ maxBlockRange: 8n }), { logger: (event) => events.push(event) });

    const logs = await rpc.getLogs(logRequest(0n, 7n));
    assert.deepEqual(logs.map((log) => BigInt(log.blockNumber!)), [0n, 2n, 4n, 6n]);
    assert.deepEqual(calls, [
      [0n, 7n],
      [0n, 3n],
      [0n, 1n],
      [2n, 3n],
      [4n, 7n],
      [4n, 5n],
      [6n, 7n]
    ]);
    assert.equal(events.filter((event) => event.type === "split").length, 3);
  });

  test("terminates when a single block remains rejected", async () => {
    const provider = new ScriptedProvider([async () => Promise.reject(new Error("range too large"))]);
    const rpc = new PolicyRpcClient(provider, policy());

    await assert.rejects(rpc.getLogs(logRequest(5n, 5n)), RpcRangeTooLargeError);
    assert.equal(provider.logCalls.length, 1);
  });

  test("terminates when configured split depth is exhausted", async () => {
    const provider = new ScriptedProvider([async () => Promise.reject(new Error("range too large"))]);
    const rpc = new PolicyRpcClient(provider, policy({ maxSplitDepth: 0 }));

    await assert.rejects(
      rpc.getLogs(logRequest(5n, 6n)),
      (error: unknown) => {
        assert.ok(error instanceof RpcRangeTooLargeError);
        assert.match(error.message, /depth 0 was exhausted/);
        return true;
      }
    );
    assert.equal(provider.logCalls.length, 1);
  });

  test("does not split unrelated transient errors", async () => {
    const provider = new ScriptedProvider([
      async () => Promise.reject(statusError(503, "Service Unavailable")),
      async () => [sampleLog(1n)]
    ]);
    const rpc = new PolicyRpcClient(provider, policy(), { sleep: async () => undefined });

    await rpc.getLogs(logRequest(1n, 4n));
    assert.deepEqual(provider.logCalls.map((call) => [call.fromBlock, call.toBlock]), [
      [1n, 4n],
      [1n, 4n]
    ]);
  });

  test("enforces configured maximum before calling the provider", async () => {
    const provider = new ScriptedProvider();
    const rpc = new PolicyRpcClient(provider, policy({ maxBlockRange: 2n }));

    await assert.rejects(rpc.getLogs(logRequest(1n, 3n)), RpcPolicyConfigError);
    assert.equal(provider.logCalls.length, 0);
  });
});

describe("RPC configuration", () => {
  test("loads documented defaults when optional environment values are absent", () => {
    const env = loadScanEnv({ ETH_RPC_URL: "http://example.invalid", START_BLOCK: "1", END_BLOCK: "2" });
    assert.equal(env.rpcPolicy.timeoutMs, 15_000);
    assert.equal(env.rpcPolicy.maxRetries, 3);
    assert.equal(env.rpcPolicy.maxBlockRange, 2_000n);
  });

  test("loads explicit policy environment values", () => {
    const env = loadScanEnv({
      ETH_RPC_URL: "http://example.invalid",
      START_BLOCK: "1",
      END_BLOCK: "2",
      RPC_TIMEOUT_MS: "1000",
      RPC_MAX_RETRIES: "4",
      RPC_RETRY_BASE_DELAY_MS: "20",
      RPC_RETRY_MAX_DELAY_MS: "80",
      RPC_MAX_BLOCK_RANGE: "50",
      RPC_MAX_SPLIT_DEPTH: "7"
    });
    assert.deepEqual(env.rpcPolicy, {
      timeoutMs: 1_000,
      maxRetries: 4,
      retryBaseDelayMs: 20,
      retryMaxDelayMs: 80,
      maxBlockRange: 50n,
      maxSplitDepth: 7
    });
  });

  test("rejects invalid timeout, retries, delays, chunk and split depth", () => {
    const base = policy();
    assert.throws(() => validateRpcPolicyConfig({ ...base, timeoutMs: 0 }), RpcPolicyConfigError);
    assert.throws(() => validateRpcPolicyConfig({ ...base, maxRetries: -1 }), RpcPolicyConfigError);
    assert.throws(() => validateRpcPolicyConfig({ ...base, retryBaseDelayMs: 0 }), RpcPolicyConfigError);
    assert.throws(() => validateRpcPolicyConfig({ ...base, retryMaxDelayMs: 5 }), RpcPolicyConfigError);
    assert.throws(() => validateRpcPolicyConfig({ ...base, maxBlockRange: 0n }), RpcPolicyConfigError);
    assert.throws(() => validateRpcPolicyConfig({ ...base, maxSplitDepth: -1 }), RpcPolicyConfigError);
  });
});
