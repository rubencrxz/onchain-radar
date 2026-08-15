import assert from "node:assert/strict";
import { test } from "node:test";
import { PolicyRpcClient, type RawRpcProvider } from "../src/rpc.js";
import { SAFE, TARGET, SAFE_TX_HASH, rpcReceipt, rpcTransaction } from "./safeFixtures.js";

function providerBase(): RawRpcProvider {
  return { async getLogs() { return []; }, async getStorageAt() { return undefined; }, async getErc20Balance() { return 0n; } };
}

const policy = { timeoutMs: 100, maxRetries: 1, retryBaseDelayMs: 2, retryMaxDelayMs: 2, maxBlockRange: 10n, maxSplitDepth: 2 };

test("transaction and receipt RPC calls are cached within one execution", async () => {
  let transactionCalls = 0;
  let receiptCalls = 0;
  const provider: RawRpcProvider = {
    ...providerBase(),
    async getTransaction() { transactionCalls += 1; return rpcTransaction(); },
    async getTransactionReceipt() { receiptCalls += 1; return rpcReceipt(); }
  };
  const rpc = new PolicyRpcClient(provider, policy, { sleep: async () => undefined });
  await Promise.all([rpc.getTransaction(SAFE_TX_HASH), rpc.getTransaction(SAFE_TX_HASH)]);
  await Promise.all([rpc.getTransactionReceipt(SAFE_TX_HASH), rpc.getTransactionReceipt(SAFE_TX_HASH)]);
  assert.equal(transactionCalls, 1);
  assert.equal(receiptCalls, 1);
});

test("receipt retries retain operation and transaction context without real waiting", async () => {
  let calls = 0;
  const delays: number[] = [];
  const provider: RawRpcProvider = {
    ...providerBase(),
    async getTransactionReceipt() {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error("Service unavailable"), { status: 503 });
      return rpcReceipt();
    }
  };
  const rpc = new PolicyRpcClient(provider, policy, { sleep: async (delay) => { delays.push(delay); } });
  const receipt = await rpc.getTransactionReceipt(SAFE_TX_HASH);
  assert.equal(receipt.transactionHash, SAFE_TX_HASH);
  assert.equal(calls, 2);
  assert.deepEqual(delays, [2]);
});

test("missing transaction capability fails permanently with explicit context", async () => {
  const rpc = new PolicyRpcClient(providerBase(), policy, { sleep: async () => undefined });
  await assert.rejects(() => rpc.getTransaction(SAFE_TX_HASH), (error: unknown) => {
    assert.match((error as Error).message, /eth_getTransactionByHash/);
    assert.match((error as Error).message, new RegExp(SAFE_TX_HASH));
    return true;
  });
});

test("Safe threshold, owner and module reads use policy caching per block", async () => {
  const calls = { threshold: 0, owner: 0, module: 0 };
  const provider: RawRpcProvider = {
    ...providerBase(),
    async getSafeThreshold() { calls.threshold += 1; return 2n; },
    async isSafeOwner() { calls.owner += 1; return true; },
    async isSafeModuleEnabled() { calls.module += 1; return false; }
  };
  const rpc = new PolicyRpcClient(provider, policy, { sleep: async () => undefined });
  assert.equal(rpc.supportsSafeStateReads, true);
  const threshold = { safe: SAFE, blockNumber: 100n };
  const owner = { safe: SAFE, owner: TARGET, blockNumber: 100n };
  const module = { safe: SAFE, module: TARGET, blockNumber: 100n };
  assert.equal(await rpc.getSafeThreshold(threshold), 2n);
  assert.equal(await rpc.getSafeThreshold(threshold), 2n);
  assert.equal(await rpc.isSafeOwner(owner), true);
  assert.equal(await rpc.isSafeOwner(owner), true);
  assert.equal(await rpc.isSafeModuleEnabled(module), false);
  assert.equal(await rpc.isSafeModuleEnabled(module), false);
  assert.deepEqual(calls, { threshold: 1, owner: 1, module: 1 });
});

test("Safe state retry errors retain method, Safe, subject and block context", async () => {
  let calls = 0;
  const provider: RawRpcProvider = {
    ...providerBase(),
    async getSafeThreshold() { return 2n; },
    async isSafeOwner() { return true; },
    async isSafeModuleEnabled() {
      calls += 1;
      throw Object.assign(new Error("Service unavailable"), { status: 503 });
    }
  };
  const rpc = new PolicyRpcClient(provider, { ...policy, maxRetries: 0 }, { sleep: async () => undefined });
  await assert.rejects(rpc.isSafeModuleEnabled({ safe: SAFE, module: TARGET, blockNumber: 99n }), (error: unknown) => {
    assert.match((error as Error).message, /isModuleEnabled/);
    assert.match((error as Error).message, new RegExp(SAFE, "i"));
    assert.match((error as Error).message, new RegExp(TARGET, "i"));
    assert.match((error as Error).message, /block 99/);
    return true;
  });
  assert.equal(calls, 1);
});
