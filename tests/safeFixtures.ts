import {
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  type Address,
  type Hex
} from "viem";
import type { RawLogForAlert } from "../src/alerts.js";
import type { MonitorConfig } from "../src/config.js";
import { SAFE_ACTION_SELECTORS } from "../src/safe/actions.js";
import { SAFE_EXEC_TRANSACTION_ABI } from "../src/safe/decoder.js";
import type { SafeMultisigConfig, SafeOperation } from "../src/safe/types.js";
import type { RpcTransaction, RpcTransactionReceipt } from "../src/rpc.js";
import { buildEventTopicMap } from "../src/events.js";
import { emptyAllowlists } from "./fixtures.js";

export const SAFE = getAddress("0x1000000000000000000000000000000000000001");
export const TARGET = getAddress("0x2000000000000000000000000000000000000002");
export const UNKNOWN_TARGET = getAddress("0x3000000000000000000000000000000000000003");
export const IMPLEMENTATION = getAddress("0x4000000000000000000000000000000000000004");
export const UNKNOWN_IMPLEMENTATION = getAddress("0x5000000000000000000000000000000000000005");
export const USER = getAddress("0x6000000000000000000000000000000000000006");
export const ZERO = getAddress("0x0000000000000000000000000000000000000000");
export const SAFE_TX_HASH = `0x${"ab".repeat(32)}` as Hex;
export const BLOCK_HASH = `0x${"cd".repeat(32)}` as Hex;

export function safePolicy(overrides: Partial<SafeMultisigConfig> = {}): SafeMultisigConfig {
  return {
    name: "Protocol Security Council",
    address: SAFE,
    criticality: "critical",
    allowedTargets: [TARGET],
    allowedSelectors: [SAFE_ACTION_SELECTORS["upgradeTo(address)"]!, SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!],
    allowedOperations: ["CALL"],
    allowedImplementations: [IMPLEMENTATION],
    maxNativeValueWei: 0n,
    allowedOwners: [USER],
    minimumThreshold: 2,
    allowedThresholds: [2, 3],
    allowedModules: [TARGET],
    allowedGuards: [TARGET],
    allowedFallbackHandlers: [TARGET],
    multisendAlertDetail: "sensitive-only",
    financialOperationPolicy: {
      emitAllowedTransfers: false,
      emitAllowedApprovals: false,
      maxNativeValueWei: 0n,
      notableTokenTargets: []
    },
    modulePolicies: [],
    ...overrides
  };
}

export function safeMonitorConfig(policy = safePolicy(), options: { proxy?: boolean } = {}): MonitorConfig {
  return {
    chain: "ethereum",
    monitoredAddresses: [SAFE, TARGET],
    knownMultisigs: [SAFE],
    eventSignatures: ["ExecutionSuccess(bytes32,uint256)", "ExecutionFailure(bytes32,uint256)", "Upgraded(address)"],
    administrativeMonitoring: { multisigs: [policy] },
    ...(options.proxy ? { proxySlotMonitoring: { enabled: true, proxies: [{ address: TARGET, checkImplementationSlot: true, checkAdminSlot: false }] } } : {}),
    allowlists: { ...emptyAllowlists(), knownImplementations: [{ address: IMPLEMENTATION }], knownProxyAddresses: [{ address: TARGET }] }
  };
}

export function innerUpgrade(implementation: Address = IMPLEMENTATION): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "upgradeTo", stateMutability: "nonpayable", inputs: [{ name: "newImplementation", type: "address" }], outputs: [] }],
    functionName: "upgradeTo",
    args: [implementation]
  });
}

export function innerTransfer(): Hex {
  return encodeFunctionData({
    abi: [{ type: "function", name: "transfer", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ name: "", type: "bool" }] }],
    functionName: "transfer",
    args: [USER, 123n]
  });
}

export function execTransactionInput(params: {
  target?: Address;
  value?: bigint;
  data?: Hex;
  operation?: SafeOperation;
} = {}): Hex {
  return encodeFunctionData({
    abi: SAFE_EXEC_TRANSACTION_ABI,
    functionName: "execTransaction",
    args: [
      params.target ?? TARGET,
      params.value ?? 0n,
      params.data ?? innerUpgrade(),
      params.operation === "DELEGATECALL" ? 1 : 0,
      100_000n,
      10_000n,
      1n,
      ZERO,
      ZERO,
      "0x1234"
    ]
  });
}

export function rpcTransaction(input = execTransactionInput(), hash = SAFE_TX_HASH): RpcTransaction {
  return { hash, to: SAFE, input, value: 0n, blockNumber: 100n };
}

export function rpcReceipt(hash = SAFE_TX_HASH): RpcTransactionReceipt {
  return { transactionHash: hash, blockNumber: 100n, blockHash: BLOCK_HASH, status: "success", logs: [] };
}

export function safeExecutionLog(signature: "ExecutionSuccess(bytes32,uint256)" | "ExecutionFailure(bytes32,uint256)" = "ExecutionSuccess(bytes32,uint256)", hash = SAFE_TX_HASH): RawLogForAlert {
  const topic = [...buildEventTopicMap([signature]).keys()][0]!;
  return {
    blockNumber: "0x64",
    transactionHash: hash,
    transactionIndex: "0x1",
    logIndex: "0x2",
    address: SAFE,
    topics: [topic],
    data: encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }], [`0x${"ef".repeat(32)}`, 0n])
  };
}

export function upgradedLog(implementation: Address = IMPLEMENTATION): RawLogForAlert {
  const topic = [...buildEventTopicMap(["Upgraded(address)"]).keys()][0]!;
  return {
    blockNumber: "0x64",
    transactionHash: SAFE_TX_HASH,
    transactionIndex: "0x1",
    logIndex: "0x1",
    address: TARGET,
    topics: [topic, `0x${"0".repeat(24)}${implementation.slice(2).toLowerCase()}` as Hex],
    data: "0x"
  };
}
