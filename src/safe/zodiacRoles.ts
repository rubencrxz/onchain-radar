import {
  decodeFunctionData,
  getAddress,
  parseAbi,
  toFunctionSelector,
  type Address,
  type Hex
} from "viem";
import type { RpcTransaction } from "../rpc.js";
import { decodeSafeExecTransaction, selectorOf } from "./decoder.js";
import {
  decodeMultiSendCalldata,
  MULTISEND_SELECTOR,
  MultiSendDecodeError,
  parseMultiSendPayload
} from "./multisend.js";
import type {
  AdministrativeMonitoringConfig,
  MultiSendContractConfig,
  MultiSendLimits,
  SafeModuleDecodeResult,
  SafeModulePolicyConfig,
  SafeOperation
} from "./types.js";
import { DEFAULT_MULTISEND_LIMITS } from "./types.js";

export const ZODIAC_EXEC_WITH_ROLE_SIGNATURE =
  "execTransactionWithRole(address,uint256,bytes,uint8,bytes32,bool)";
export const ZODIAC_EXEC_WITH_ROLE_RETURN_DATA_SIGNATURE =
  "execTransactionWithRoleReturnData(address,uint256,bytes,uint8,bytes32,bool)";
export const ZODIAC_EXEC_WITH_ROLE_SELECTOR = toFunctionSelector(ZODIAC_EXEC_WITH_ROLE_SIGNATURE);
export const ZODIAC_EXEC_WITH_ROLE_RETURN_DATA_SELECTOR = toFunctionSelector(
  ZODIAC_EXEC_WITH_ROLE_RETURN_DATA_SIGNATURE
);

export const ZODIAC_ROLES_EXECUTION_ABI = parseAbi([
  "function execTransactionWithRole(address to,uint256 value,bytes data,uint8 operation,bytes32 roleKey,bool shouldRevert) returns (bool success)",
  "function execTransactionWithRoleReturnData(address to,uint256 value,bytes data,uint8 operation,bytes32 roleKey,bool shouldRevert) returns (bool success,bytes returnData)"
]);

export class ZodiacRolesAdapterError extends Error {
  constructor(
    readonly kind: "MALFORMED_MANAGER_SAFE" | "MALFORMED_MULTISEND" | "WRAPPER_LIMIT_EXCEEDED",
    message: string,
    options?: { cause?: unknown }
  ) {
    super(message, options);
    this.name = "ZodiacRolesAdapterError";
  }
}

type ZodiacCallSite = {
  path: string;
  depth: number;
  data: Hex;
  managerSafe?: Address;
};

type TraversalState = {
  totalPayloadBytes: number;
  totalOperations: number;
};

export function decodeConfiguredZodiacRolesTransaction(params: {
  safeAddress: Address;
  moduleAddress: Address;
  modulePolicy: SafeModulePolicyConfig;
  transaction: RpcTransaction;
  config: AdministrativeMonitoringConfig;
  eventLogIndex?: number;
  moduleEventIndex: number;
  moduleEventsInTransaction: number;
}): SafeModuleDecodeResult {
  const adapter = params.modulePolicy.adapter;
  if (adapter?.type !== "ZODIAC_ROLES_V2") {
    throw new Error("Zodiac Roles decoder requires an explicit ZODIAC_ROLES_V2 module adapter.");
  }
  const common = {
    safeAddress: getAddress(params.safeAddress),
    moduleAddress: getAddress(params.moduleAddress),
    outerTransactionHash: params.transaction.hash,
    blockNumber: params.transaction.blockNumber,
    outerTarget: params.transaction.to,
    ...(params.eventLogIndex === undefined ? {} : { eventLogIndex: params.eventLogIndex })
  };
  const limits = params.config.multisendLimits ?? DEFAULT_MULTISEND_LIMITS;
  const outerBytes = hexByteLength(params.transaction.input);
  if (outerBytes > limits.maxTotalPayloadBytes) {
    throw new ZodiacRolesAdapterError(
      "WRAPPER_LIMIT_EXCEEDED",
      `Outer calldata size ${outerBytes} exceeds configured limit ${limits.maxTotalPayloadBytes}.`
    );
  }

  const sites = locateZodiacCallSites({
    transaction: params.transaction,
    moduleAddress: common.moduleAddress,
    managerSafes: adapter.managerSafes,
    contracts: params.config.multisendContracts ?? [],
    limits
  });
  if (sites.length === 0) {
    return {
      decoded: false,
      ...common,
      failureKind: "ZODIAC_WRAPPER_NOT_FOUND",
      outerSelector: selectorOf(params.transaction.input),
      error: "Configured Zodiac Roles v2 module was not found in a supported direct or Manager Safe calldata envelope."
    };
  }
  if (sites.length !== params.moduleEventsInTransaction || params.moduleEventIndex >= sites.length) {
    return {
      decoded: false,
      ...common,
      failureKind: "ZODIAC_WRAPPER_AMBIGUOUS",
      outerSelector: selectorOf(params.transaction.input),
      error: `${sites.length} configured Zodiac call site(s) cannot be assigned uniquely to ${params.moduleEventsInTransaction} module event(s).`
    };
  }

  const site = sites[params.moduleEventIndex]!;
  const outerSelector = selectorOf(site.data);
  const entrypoint = zodiacEntrypoint(outerSelector);
  if (entrypoint === undefined) {
    return {
      decoded: false,
      ...common,
      failureKind: "ZODIAC_UNSUPPORTED_SELECTOR",
      outerSelector,
      error: `Configured Zodiac module call at ${site.path} uses unsupported selector ${outerSelector}.`
    };
  }

  try {
    const decoded = decodeFunctionData({ abi: ZODIAC_ROLES_EXECUTION_ABI, data: site.data });
    const [to, value, data, operationValue, roleKey, shouldRevert] = decoded.args;
    const operation = normalizeOperation(operationValue);
    if (operation === undefined) {
      return {
        decoded: false,
        ...common,
        failureKind: "UNSUPPORTED_OPERATION",
        outerSelector,
        error: `Zodiac Roles operation ${operationValue.toString()} is not CALL (0) or DELEGATECALL (1).`
      };
    }
    const dataBytes = hexByteLength(data);
    if (dataBytes > limits.maxSuboperationDataBytes) {
      throw new ZodiacRolesAdapterError(
        "WRAPPER_LIMIT_EXCEEDED",
        `Zodiac inner calldata size ${dataBytes} exceeds configured limit ${limits.maxSuboperationDataBytes}.`
      );
    }
    return {
      decoded: true,
      moduleTransaction: {
        moduleAddress: common.moduleAddress,
        moduleName: params.modulePolicy.name,
        entrypoint,
        outerTarget: params.transaction.to,
        ...(params.eventLogIndex === undefined ? {} : { eventLogIndex: params.eventLogIndex }),
        zodiacRoles: {
          adapterType: "ZODIAC_ROLES_V2",
          roleKey,
          shouldRevert,
          wrapperPath: site.path,
          wrapperDepth: site.depth,
          ...(site.managerSafe === undefined ? {} : { managerSafe: site.managerSafe })
        },
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
          gasToken: common.safeAddress,
          refundReceiver: common.safeAddress
        }
      }
    };
  } catch (error: unknown) {
    if (error instanceof ZodiacRolesAdapterError) throw error;
    return {
      decoded: false,
      ...common,
      failureKind: "MALFORMED_CALLDATA",
      outerSelector,
      error: `Cannot decode configured Zodiac Roles v2 call at ${site.path}: ${error instanceof Error ? error.message : String(error)}`
    };
  }
}

function locateZodiacCallSites(params: {
  transaction: RpcTransaction;
  moduleAddress: Address;
  managerSafes: readonly Address[];
  contracts: readonly MultiSendContractConfig[];
  limits: MultiSendLimits;
}): ZodiacCallSite[] {
  const outerTarget = params.transaction.to;
  if (outerTarget?.toLowerCase() === params.moduleAddress.toLowerCase()) {
    return [{ path: "module.direct", depth: 0, data: params.transaction.input }];
  }
  if (outerTarget === null || !includesAddress(params.managerSafes, outerTarget)) return [];

  const manager = decodeSafeExecTransaction({ safeAddress: outerTarget, transaction: params.transaction });
  if (!manager.decoded) {
    if (manager.failureKind === "UNSUPPORTED_OUTER_SELECTOR") return [];
    throw new ZodiacRolesAdapterError(
      "MALFORMED_MANAGER_SAFE",
      `Configured Manager Safe calldata cannot be decoded: ${manager.failureKind}: ${manager.error}`
    );
  }
  const state: TraversalState = { totalPayloadBytes: 0, totalOperations: 0 };
  return traverseEnvelope({
    target: manager.transaction.innerTarget,
    data: manager.transaction.innerData,
    operation: manager.transaction.operation,
    path: "manager.direct",
    depth: 0,
    managerSafe: outerTarget,
    moduleAddress: params.moduleAddress,
    contracts: params.contracts,
    limits: params.limits,
    state
  });
}

function traverseEnvelope(params: {
  target: Address;
  data: Hex;
  operation: SafeOperation;
  path: string;
  depth: number;
  managerSafe: Address;
  moduleAddress: Address;
  contracts: readonly MultiSendContractConfig[];
  limits: MultiSendLimits;
  state: TraversalState;
}): ZodiacCallSite[] {
  if (params.target.toLowerCase() === params.moduleAddress.toLowerCase()) {
    if (params.operation !== "CALL") {
      throw new ZodiacRolesAdapterError(
        "MALFORMED_MANAGER_SAFE",
        `Configured Manager Safe reaches Zodiac module through ${params.operation}; only CALL preserves module identity.`
      );
    }
    return [{ path: params.path, depth: params.depth, data: params.data, managerSafe: params.managerSafe }];
  }

  const multiSend = params.contracts.find((contract) =>
    contract.address.toLowerCase() === params.target.toLowerCase());
  if (multiSend === undefined || selectorOf(params.data).toLowerCase() !== MULTISEND_SELECTOR.toLowerCase()) return [];
  const nextDepth = params.depth + 1;
  if (nextDepth > params.limits.maxDepth) {
    throw new ZodiacRolesAdapterError(
      "WRAPPER_LIMIT_EXCEEDED",
      `Manager Safe wrapper depth ${nextDepth} exceeds configured MultiSend depth ${params.limits.maxDepth}.`
    );
  }

  try {
    const payload = decodeMultiSendCalldata(params.data);
    params.state.totalPayloadBytes += hexByteLength(payload);
    if (params.state.totalPayloadBytes > params.limits.maxTotalPayloadBytes) {
      throw new ZodiacRolesAdapterError(
        "WRAPPER_LIMIT_EXCEEDED",
        `Manager Safe wrapper payload ${params.state.totalPayloadBytes} exceeds configured limit ${params.limits.maxTotalPayloadBytes}.`
      );
    }
    const operations = parseMultiSendPayload(payload, params.limits);
    params.state.totalOperations += operations.length;
    if (params.state.totalOperations > params.limits.maxSuboperations) {
      throw new ZodiacRolesAdapterError(
        "WRAPPER_LIMIT_EXCEEDED",
        `Manager Safe wrapper operation count ${params.state.totalOperations} exceeds configured limit ${params.limits.maxSuboperations}.`
      );
    }
    const sites: ZodiacCallSite[] = [];
    for (const operation of operations) {
      if (multiSend.mode === "CALL_ONLY" && operation.operation === "DELEGATECALL") {
        throw new ZodiacRolesAdapterError(
          "MALFORMED_MULTISEND",
          `Configured CALL_ONLY Manager Safe MultiSend contains DELEGATECALL at ${params.path}.${operation.index}.`
        );
      }
      sites.push(...traverseEnvelope({
        ...params,
        target: operation.target,
        data: operation.data,
        operation: operation.operation,
        path: `${params.path.replace(/\.direct$/, ".multisend")}.${operation.index}`,
        depth: nextDepth
      }));
    }
    return sites;
  } catch (error: unknown) {
    if (error instanceof ZodiacRolesAdapterError) throw error;
    if (error instanceof MultiSendDecodeError) {
      throw new ZodiacRolesAdapterError(
        error.validButOverLimit ? "WRAPPER_LIMIT_EXCEEDED" : "MALFORMED_MULTISEND",
        `Configured Manager Safe MultiSend cannot be consumed completely: ${error.kind}: ${error.message}`,
        { cause: error }
      );
    }
    throw new ZodiacRolesAdapterError(
      "MALFORMED_MULTISEND",
      `Configured Manager Safe MultiSend failed: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error }
    );
  }
}

function zodiacEntrypoint(selector: Hex): "execTransactionWithRole" | "execTransactionWithRoleReturnData" | undefined {
  if (selector.toLowerCase() === ZODIAC_EXEC_WITH_ROLE_SELECTOR.toLowerCase()) return "execTransactionWithRole";
  if (selector.toLowerCase() === ZODIAC_EXEC_WITH_ROLE_RETURN_DATA_SELECTOR.toLowerCase()) {
    return "execTransactionWithRoleReturnData";
  }
  return undefined;
}

function normalizeOperation(value: number): SafeOperation | undefined {
  if (value === 0) return "CALL";
  if (value === 1) return "DELEGATECALL";
  return undefined;
}

function includesAddress(addresses: readonly Address[], candidate: Address): boolean {
  return addresses.some((address) => address.toLowerCase() === candidate.toLowerCase());
}

function hexByteLength(value: Hex): number {
  return (value.length - 2) / 2;
}
