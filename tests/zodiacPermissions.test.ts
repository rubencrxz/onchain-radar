import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { getAddress, toHex, type Address, type Hex } from "viem";
import type { RpcClient } from "../src/rpc.js";
import {
  assessZodiacStructuralAuthorization,
  decodeRoleKeyAscii,
  extractMinimalProxyMastercopy,
  hashAbiEncodedAddress,
  readZodiacRolePermission,
  readZodiacTransactionUnwrapper,
  ZODIAC_MULTI_SEND_UNWRAPPER_2_1,
  ZODIAC_ROLES_V2_MASTERCOPY_2_1,
  zodiacRoleFunctionSlot,
  zodiacRoleTargetSlot,
  zodiacUnwrapperSlot
} from "../src/safe/zodiacPermissions.js";

const MODULE = getAddress("0x703806E61847984346d2D7DDd853049627e50A40");
const TARGET = getAddress("0xba100000625a3754423978a60c9317c58a424e3D");
const POINTER = getAddress("0x0017c26c95c952353229529872ea7c9a95568844");
const ROLE = "0x4d414e4147455200000000000000000000000000000000000000000000000000" as Hex;
const SELECTOR = "0x095ea7b3" as Hex;
const BLOCK = 20_663_640n;
const PROXY_CODE = `0x363d3d373d3d3d363d73${ZODIAC_ROLES_V2_MASTERCOPY_2_1.slice(2).toLowerCase()}5af43d82803e903d91602b57fd5bf3` as Hex;

describe("bounded Zodiac Roles permission introspection", () => {
  test("decodes the supported minimal proxy and MANAGER role key", () => {
    assert.equal(extractMinimalProxyMastercopy(PROXY_CODE), ZODIAC_ROLES_V2_MASTERCOPY_2_1);
    assert.equal(decodeRoleKeyAscii(ROLE), "MANAGER");
    assert.equal(extractMinimalProxyMastercopy("0x1234"), undefined);
  });

  test("reads a scoped CALL permission and consumes condition bytecode exactly", async () => {
    const spenderHash = hashAbiEncodedAddress(getAddress("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110"));
    const targetHeader = 2n;
    const functionHeader = (2n << 240n) | BigInt(POINTER);
    const conditionCode = `0x0000a50030${spenderHash.slice(2)}` as Hex;
    const rpc = fixtureRpc(new Map([
      [zodiacRoleTargetSlot(ROLE, TARGET), toHex(targetHeader, { size: 32 })],
      [zodiacRoleFunctionSlot(ROLE, TARGET, SELECTOR), toHex(functionHeader, { size: 32 })]
    ]), new Map([[MODULE, PROXY_CODE], [POINTER, conditionCode]]));
    const observed = await readZodiacRolePermission({ rpc, moduleAddress: MODULE, roleKey: ROLE, target: TARGET, selector: SELECTOR, blockNumber: BLOCK });
    assert.equal(observed.status, "observed");
    if (observed.status !== "observed") throw new Error("expected observation");
    assert.equal(observed.clearance, "FUNCTION");
    assert.equal(observed.functionPermission.executionOptions, "NONE");
    assert.equal(observed.functionPermission.conditionCount, 2);
    assert.deepEqual(observed.functionPermission.conditions.map((condition) => condition.operator), ["MATCHES", "EQUAL_TO"]);
    assert.equal(observed.functionPermission.conditions[1]?.comparisonHash, spenderHash);
    const assessment = assessZodiacStructuralAuthorization(observed, "CALL", 0n);
    assert.equal(assessment.structurallyAllowed, true);
    assert.equal(assessment.fullyVerified, false);
    assert.equal(assessment.conditionEvaluation, "scoped-not-evaluated");
  });

  test("decodes delegatecall/send options and rejects operations outside them", async () => {
    const targetHeader = 2n;
    const wildcardDelegatecall = (2n << 224n) | (1n << 216n);
    const rpc = fixtureRpc(new Map([
      [zodiacRoleTargetSlot(ROLE, TARGET), toHex(targetHeader, { size: 32 })],
      [zodiacRoleFunctionSlot(ROLE, TARGET, SELECTOR), toHex(wildcardDelegatecall, { size: 32 })]
    ]), new Map([[MODULE, PROXY_CODE]]));
    const observed = await readZodiacRolePermission({ rpc, moduleAddress: MODULE, roleKey: ROLE, target: TARGET, selector: SELECTOR, blockNumber: BLOCK });
    assert.equal(observed.status, "observed");
    if (observed.status !== "observed") throw new Error("expected observation");
    assert.equal(assessZodiacStructuralAuthorization(observed, "DELEGATECALL", 0n).fullyVerified, true);
    assert.equal(assessZodiacStructuralAuthorization(observed, "CALL", 1n).nativeValueAllowed, false);
  });

  test("reads the configured MultiSend unwrapper without treating MultiSend as a role target", async () => {
    const multiSend = getAddress("0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761");
    const rpc = fixtureRpc(new Map([
      [zodiacUnwrapperSlot(multiSend, "0x8d80ff0a"), toHex(BigInt(ZODIAC_MULTI_SEND_UNWRAPPER_2_1), { size: 32 })]
    ]), new Map([[MODULE, PROXY_CODE]]));
    assert.equal(await readZodiacTransactionUnwrapper({ rpc, moduleAddress: MODULE, target: multiSend, selector: "0x8d80ff0a", blockNumber: BLOCK }), ZODIAC_MULTI_SEND_UNWRAPPER_2_1);
  });

  test("falls back explicitly for unsupported proxy forms and mastercopies", async () => {
    const unsupportedCode = `0x363d3d373d3d363d73${"11".repeat(20)}5af43d82803e903d91602b57fd5bf3` as Hex;
    const unsupported = await readZodiacRolePermission({ rpc: fixtureRpc(new Map(), new Map([[MODULE, unsupportedCode]])), moduleAddress: MODULE, roleKey: ROLE, target: TARGET, selector: SELECTOR, blockNumber: BLOCK });
    assert.equal(unsupported.status, "unsupported");
    assert.match(unsupported.reason, /Unsupported Zodiac Roles mastercopy|not the supported canonical EIP-1167/);
    const noCodeRpc: RpcClient = { async getLogs() { return []; }, async getStorageAt() { return undefined; }, async getErc20Balance() { return 0n; } };
    const noCode = await readZodiacRolePermission({ rpc: noCodeRpc, moduleAddress: MODULE, roleKey: ROLE, target: TARGET, selector: SELECTOR, blockNumber: BLOCK });
    assert.equal(noCode.status, "unsupported");
  });

  test("fails closed on truncated, trailing or over-limit condition data", async () => {
    const functionHeader = (2n << 240n) | BigInt(POINTER);
    const storage = new Map<Hex, Hex>([
      [zodiacRoleTargetSlot(ROLE, TARGET), toHex(2n, { size: 32 })],
      [zodiacRoleFunctionSlot(ROLE, TARGET, SELECTOR), toHex(functionHeader, { size: 32 })]
    ]);
    await assert.rejects(() => readZodiacRolePermission({ rpc: fixtureRpc(storage, new Map([[MODULE, PROXY_CODE], [POINTER, "0x0000a5"]])), moduleAddress: MODULE, roleKey: ROLE, target: TARGET, selector: SELECTOR, blockNumber: BLOCK }), /truncated/);
    await assert.rejects(() => readZodiacRolePermission({ rpc: fixtureRpc(storage, new Map([[MODULE, PROXY_CODE], [POINTER, `0x0000a50030${"11".repeat(33)}` as Hex]])), moduleAddress: MODULE, roleKey: ROLE, target: TARGET, selector: SELECTOR, blockNumber: BLOCK }), /trailing bytes/);
    await assert.rejects(() => readZodiacRolePermission({ rpc: fixtureRpc(storage, new Map([[MODULE, PROXY_CODE], [POINTER, `0x0000a50030${"11".repeat(32)}` as Hex]])), moduleAddress: MODULE, roleKey: ROLE, target: TARGET, selector: SELECTOR, blockNumber: BLOCK, maxConditionNodes: 1 }), /exceeds introspection limit/);
  });
});

function fixtureRpc(storage: Map<Hex, Hex>, code: Map<Address, Hex>): RpcClient {
  return {
    async getLogs() { return []; },
    async getStorageAt(request) { return storage.get(request.slot); },
    async getCode(request) { return code.get(getAddress(request.address)); },
    async getErc20Balance() { return 0n; }
  };
}
