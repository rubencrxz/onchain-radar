import {
  decodeEventLog,
  decodeFunctionData,
  getAddress,
  parseAbi,
  parseAbiItem,
  toFunctionSelector,
  type AbiEvent,
  type Address,
  type Hex
} from "viem";
import type { RawLogForAlert } from "../alerts.js";
import type { RpcTransaction } from "../rpc.js";
import { buildEventTopicMap } from "../events.js";
import { selectorOf } from "./decoder.js";
import type {
  SafeModuleDecodeResult,
  SafeModuleEntrypoint,
  SafeModulePolicyConfig,
  SafeOperation
} from "./types.js";

export const SAFE_MODULE_EXECUTION_EVENT_SIGNATURES = [
  "ExecutionFromModuleSuccess(address)",
  "ExecutionFromModuleFailure(address)"
] as const;

export const SAFE_EXEC_FROM_MODULE_SIGNATURE = "execTransactionFromModule(address,uint256,bytes,uint8)";
export const SAFE_EXEC_FROM_MODULE_RETURN_DATA_SIGNATURE = "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)";
export const SAFE_EXEC_FROM_MODULE_SELECTOR = toFunctionSelector(SAFE_EXEC_FROM_MODULE_SIGNATURE);
export const SAFE_EXEC_FROM_MODULE_RETURN_DATA_SELECTOR = toFunctionSelector(SAFE_EXEC_FROM_MODULE_RETURN_DATA_SIGNATURE);

export const SAFE_MODULE_EXECUTION_ABI = parseAbi([
  "function execTransactionFromModule(address to,uint256 value,bytes data,uint8 operation) returns (bool success)",
  "function execTransactionFromModuleReturnData(address to,uint256 value,bytes data,uint8 operation) returns (bool success,bytes returnData)"
]);

const MODULE_EVENT_ABI = [
  parseAbiItem("event ExecutionFromModuleSuccess(address indexed module)"),
  parseAbiItem("event ExecutionFromModuleFailure(address indexed module)")
] as const;
const MODULE_EVENT_TOPICS = buildEventTopicMap([...SAFE_MODULE_EXECUTION_EVENT_SIGNATURES]);
const ZERO_ADDRESS = getAddress("0x0000000000000000000000000000000000000000");

export type DecodedSafeModuleExecutionEvent = {
  moduleAddress: Address;
  outcome: "success" | "failure";
};

export function decodeSafeModuleExecutionEvent(log: RawLogForAlert): DecodedSafeModuleExecutionEvent | undefined {
  const signature = log.topics[0] === undefined ? undefined : MODULE_EVENT_TOPICS.get(log.topics[0]);
  if (signature === undefined) return undefined;
  const event = decodeEventLog({
    abi: MODULE_EVENT_ABI as readonly AbiEvent[],
    data: log.data,
    topics: [...log.topics] as [] | [Hex, ...Hex[]],
    strict: true
  });
  const args = event.args as { module?: Address };
  if (args.module === undefined) throw new Error(`Safe module execution event ${signature} did not decode module.`);
  return {
    moduleAddress: getAddress(args.module),
    outcome: signature === SAFE_MODULE_EXECUTION_EVENT_SIGNATURES[0] ? "success" : "failure"
  };
}

export function decodeSafeModuleTransaction(params: {
  safeAddress: Address;
  moduleAddress: Address;
  modulePolicy?: SafeModulePolicyConfig;
  transaction: RpcTransaction;
  eventLogIndex?: number;
  executionEventsInTransaction: number;
}): SafeModuleDecodeResult {
  const outerSelector = selectorOf(params.transaction.input);
  const common = {
    safeAddress: getAddress(params.safeAddress),
    moduleAddress: getAddress(params.moduleAddress),
    outerTransactionHash: params.transaction.hash,
    blockNumber: params.transaction.blockNumber,
    outerTarget: params.transaction.to,
    ...(params.eventLogIndex === undefined ? {} : { eventLogIndex: params.eventLogIndex })
  };
  if (params.executionEventsInTransaction !== 1) {
    return {
      decoded: false,
      ...common,
      failureKind: "AMBIGUOUS_MULTIPLE_MODULE_EXECUTIONS",
      outerSelector,
      error: `${params.executionEventsInTransaction} module execution events share this outer transaction; without traces its calldata cannot be assigned to one event.`
    };
  }
  const entrypoint = entrypointForSelector(outerSelector);
  if (entrypoint === undefined) {
    return {
      decoded: false,
      ...common,
      failureKind: "UNSUPPORTED_OUTER_SELECTOR",
      outerSelector,
      error: `Outer selector ${outerSelector} is not a supported Safe module execution entrypoint; the internal Safe calldata is unavailable without traces.`
    };
  }
  try {
    const decoded = decodeFunctionData({ abi: SAFE_MODULE_EXECUTION_ABI, data: params.transaction.input });
    const [to, value, data, operationValue] = decoded.args;
    const operation = normalizeOperation(operationValue);
    if (operation === undefined) {
      return {
        decoded: false,
        ...common,
        failureKind: "UNSUPPORTED_OPERATION",
        outerSelector,
        error: `Safe module operation ${operationValue.toString()} is not CALL (0) or DELEGATECALL (1).`
      };
    }
    return {
      decoded: true,
      moduleTransaction: {
        moduleAddress: common.moduleAddress,
        ...(params.modulePolicy === undefined ? {} : { moduleName: params.modulePolicy.name }),
        entrypoint,
        outerTarget: params.transaction.to,
        ...(params.eventLogIndex === undefined ? {} : { eventLogIndex: params.eventLogIndex }),
        transaction: {
          safeAddress: common.safeAddress,
          outerTransactionHash: params.transaction.hash,
          blockNumber: params.transaction.blockNumber,
          innerTarget: getAddress(to),
          innerValue: value,
          innerData: data,
          innerSelector: selectorOf(data),
          operation,
          safeTxGas: 0n,
          baseGas: 0n,
          gasPrice: 0n,
          gasToken: ZERO_ADDRESS,
          refundReceiver: ZERO_ADDRESS
        }
      }
    };
  } catch (error: unknown) {
    return {
      decoded: false,
      ...common,
      failureKind: "MALFORMED_CALLDATA",
      outerSelector,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function entrypointForSelector(selector: Hex): SafeModuleEntrypoint | undefined {
  if (selector.toLowerCase() === SAFE_EXEC_FROM_MODULE_SELECTOR.toLowerCase()) return "execTransactionFromModule";
  if (selector.toLowerCase() === SAFE_EXEC_FROM_MODULE_RETURN_DATA_SELECTOR.toLowerCase()) return "execTransactionFromModuleReturnData";
  return undefined;
}

function normalizeOperation(value: number): SafeOperation | undefined {
  if (value === 0) return "CALL";
  if (value === 1) return "DELEGATECALL";
  return undefined;
}
