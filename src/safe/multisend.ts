import {
  decodeFunctionData,
  getAddress,
  parseAbi,
  toFunctionSelector,
  type Address,
  type Hex
} from "viem";
import { classifySafeAction } from "./actions.js";
import { selectorOf } from "./decoder.js";
import { evaluateSafeModulePolicy, evaluateSafePolicy, intersectSafePolicyEvaluations } from "./policy.js";
import type {
  AdministrativeMonitoringConfig,
  AnalyzedSafeSubOperation,
  MultiSendContractConfig,
  MultiSendLimits,
  SafeMultisigConfig,
  SafeModulePolicyConfig,
  SafeOperation,
  SafePolicyEvaluation,
  SafeSubOperation,
  SafeTransaction
} from "./types.js";
import { DEFAULT_MULTISEND_LIMITS } from "./types.js";

export const MULTISEND_SIGNATURE = "multiSend(bytes)";
export const MULTISEND_SELECTOR = toFunctionSelector(MULTISEND_SIGNATURE);
export const MULTISEND_ABI = parseAbi(["function multiSend(bytes transactions) payable"]);

export type ParsedMultiSendOperation = {
  index: number;
  operation: SafeOperation;
  target: Address;
  value: bigint;
  data: Hex;
  selector: Hex;
};

export type MultiSendFailureKind =
  | "MALFORMED_CALLDATA"
  | "TRUNCATED_ADDRESS"
  | "TRUNCATED_VALUE"
  | "TRUNCATED_DATA_LENGTH"
  | "DATA_LENGTH_EXCEEDS_REMAINING"
  | "INVALID_OPERATION"
  | "SUBOPERATION_DATA_LIMIT"
  | "TOTAL_PAYLOAD_LIMIT"
  | "SUBOPERATION_COUNT_LIMIT";

export class MultiSendDecodeError extends Error {
  constructor(
    readonly kind: MultiSendFailureKind,
    message: string,
    readonly offsetBytes?: number,
    readonly validButOverLimit = false,
    options?: { cause?: unknown }
  ) {
    super(message, options);
    this.name = "MultiSendDecodeError";
  }
}

export type MultiSendDepthIssue = {
  path: string;
  target: Address;
  attemptedDepth: number;
  maxDepth: number;
};

export type MultiSendExpansionResult =
  | { recognized: false; reason: "TARGET_NOT_CONFIGURED" | "UNEXPECTED_SELECTOR" }
  | {
      recognized: true;
      complete: false;
      contract: MultiSendContractConfig;
      failure: MultiSendDecodeError;
      operations: [];
      depthIssues: [];
    }
  | {
      recognized: true;
      complete: true;
      contract: MultiSendContractConfig;
      operations: AnalyzedSafeSubOperation[];
      depthIssues: MultiSendDepthIssue[];
      totalPayloadBytes: number;
    };

export function decodeMultiSendCalldata(data: Hex): Hex {
  if (selectorOf(data).toLowerCase() !== MULTISEND_SELECTOR.toLowerCase()) {
    throw new MultiSendDecodeError(
      "MALFORMED_CALLDATA",
      `Selector ${selectorOf(data)} is not ${MULTISEND_SELECTOR}.`
    );
  }
  try {
    const decoded = decodeFunctionData({ abi: MULTISEND_ABI, data });
    if (decoded.functionName !== "multiSend") {
      throw new Error(`Decoded unexpected function ${decoded.functionName}.`);
    }
    return decoded.args[0];
  } catch (error: unknown) {
    if (error instanceof MultiSendDecodeError) throw error;
    throw new MultiSendDecodeError(
      "MALFORMED_CALLDATA",
      `Cannot decode multiSend(bytes): ${error instanceof Error ? error.message : String(error)}`,
      undefined,
      false,
      { cause: error }
    );
  }
}

export function parseMultiSendPayload(
  payload: Hex,
  limits: Pick<MultiSendLimits, "maxSuboperationDataBytes"> = DEFAULT_MULTISEND_LIMITS
): ParsedMultiSendOperation[] {
  const bytes = stripHexPrefix(payload);
  if (bytes.length % 2 !== 0) {
    throw new MultiSendDecodeError("MALFORMED_CALLDATA", "MultiSend payload contains an odd number of hex digits.");
  }
  const byteLength = bytes.length / 2;
  const operations: ParsedMultiSendOperation[] = [];
  let offset = 0;

  while (offset < byteLength) {
    const start = offset;
    const remaining = byteLength - offset;
    if (remaining < 21) {
      throw new MultiSendDecodeError("TRUNCATED_ADDRESS", `Suboperation ${operations.length} has a truncated target address.`, offset);
    }
    const operationByte = Number.parseInt(readHex(bytes, offset, 1), 16);
    const operation = operationByte === 0 ? "CALL" : operationByte === 1 ? "DELEGATECALL" : undefined;
    if (operation === undefined) {
      throw new MultiSendDecodeError("INVALID_OPERATION", `Suboperation ${operations.length} uses unsupported operation ${operationByte}.`, offset);
    }
    offset += 1;
    const target = getAddress(`0x${readHex(bytes, offset, 20)}`);
    offset += 20;

    if (byteLength - offset < 32) {
      throw new MultiSendDecodeError("TRUNCATED_VALUE", `Suboperation ${operations.length} has a truncated value.`, offset);
    }
    const value = BigInt(`0x${readHex(bytes, offset, 32)}`);
    offset += 32;

    if (byteLength - offset < 32) {
      throw new MultiSendDecodeError("TRUNCATED_DATA_LENGTH", `Suboperation ${operations.length} has a truncated dataLength.`, offset);
    }
    const dataLengthBigInt = BigInt(`0x${readHex(bytes, offset, 32)}`);
    offset += 32;
    if (dataLengthBigInt > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new MultiSendDecodeError("DATA_LENGTH_EXCEEDS_REMAINING", `Suboperation ${operations.length} dataLength cannot be represented safely.`, offset);
    }
    const dataLength = Number(dataLengthBigInt);
    if (dataLength > limits.maxSuboperationDataBytes) {
      throw new MultiSendDecodeError(
        "SUBOPERATION_DATA_LIMIT",
        `Suboperation ${operations.length} dataLength ${dataLength} exceeds limit ${limits.maxSuboperationDataBytes}.`,
        offset,
        true
      );
    }
    if (dataLength > byteLength - offset) {
      throw new MultiSendDecodeError(
        "DATA_LENGTH_EXCEEDS_REMAINING",
        `Suboperation ${operations.length} declares ${dataLength} data bytes but only ${byteLength - offset} remain.`,
        offset
      );
    }
    const data = `0x${readHex(bytes, offset, dataLength)}` as Hex;
    offset += dataLength;
    operations.push({ index: operations.length, operation, target, value, data, selector: selectorOf(data) });
    if (offset <= start) throw new MultiSendDecodeError("MALFORMED_CALLDATA", "MultiSend parser made no progress.", offset);
  }
  return operations;
}

export function analyzeMultiSendTransaction(params: {
  transaction: SafeTransaction;
  policy: SafeMultisigConfig;
  config: AdministrativeMonitoringConfig;
  modulePolicy?: SafeModulePolicyConfig;
}): MultiSendExpansionResult {
  const contracts = params.config.multisendContracts ?? [];
  const contract = findMultiSendContract(contracts, params.transaction.innerTarget);
  if (contract === undefined) return { recognized: false, reason: "TARGET_NOT_CONFIGURED" };
  if (params.transaction.innerSelector.toLowerCase() !== MULTISEND_SELECTOR.toLowerCase()) {
    return { recognized: false, reason: "UNEXPECTED_SELECTOR" };
  }

  const limits = params.config.multisendLimits ?? DEFAULT_MULTISEND_LIMITS;
  const state = { totalPayloadBytes: 0, totalOperations: 0, depthIssues: [] as MultiSendDepthIssue[] };
  try {
    const operations = expand({
      transaction: params.transaction,
      policy: params.policy,
      modulePolicy: params.modulePolicy,
      contract,
      calldata: params.transaction.innerData,
      parentOperation: params.transaction.operation,
      depth: 1,
      pathPrefix: "",
      contracts,
      limits,
      state
    });
    return {
      recognized: true,
      complete: true,
      contract,
      operations,
      depthIssues: state.depthIssues,
      totalPayloadBytes: state.totalPayloadBytes
    };
  } catch (error: unknown) {
    const failure = error instanceof MultiSendDecodeError
      ? error
      : new MultiSendDecodeError("MALFORMED_CALLDATA", String(error), undefined, false, { cause: error });
    return { recognized: true, complete: false, contract, failure, operations: [], depthIssues: [] };
  }
}

function expand(params: {
  transaction: SafeTransaction;
  policy: SafeMultisigConfig;
  modulePolicy?: SafeModulePolicyConfig;
  contract: MultiSendContractConfig;
  calldata: Hex;
  parentOperation: SafeOperation;
  depth: number;
  pathPrefix: string;
  contracts: readonly MultiSendContractConfig[];
  limits: MultiSendLimits;
  state: { totalPayloadBytes: number; totalOperations: number; depthIssues: MultiSendDepthIssue[] };
}): AnalyzedSafeSubOperation[] {
  const payload = decodeMultiSendCalldata(params.calldata);
  const payloadBytes = hexByteLength(payload);
  params.state.totalPayloadBytes += payloadBytes;
  if (params.state.totalPayloadBytes > params.limits.maxTotalPayloadBytes) {
    throw new MultiSendDecodeError(
      "TOTAL_PAYLOAD_LIMIT",
      `Decoded MultiSend payload bytes ${params.state.totalPayloadBytes} exceed limit ${params.limits.maxTotalPayloadBytes}.`,
      undefined,
      true
    );
  }
  const parsed = parseMultiSendPayload(payload, params.limits);
  if (params.state.totalOperations + parsed.length > params.limits.maxSuboperations) {
    throw new MultiSendDecodeError(
      "SUBOPERATION_COUNT_LIMIT",
      `Decoded suboperation count would exceed limit ${params.limits.maxSuboperations}.`,
      undefined,
      true
    );
  }
  params.state.totalOperations += parsed.length;
  const flattened: AnalyzedSafeSubOperation[] = [];

  for (const item of parsed) {
    const path = params.pathPrefix === "" ? String(item.index) : `${params.pathPrefix}.${item.index}`;
    const operation: SafeSubOperation = {
      ...item,
      path,
      depth: params.depth,
      safeAddress: params.transaction.safeAddress,
      outerTransactionHash: params.transaction.outerTransactionHash,
      blockNumber: params.transaction.blockNumber,
      multiSendAddress: params.contract.address,
      multiSendMode: params.contract.mode,
      parentOperation: params.parentOperation
    };
    const action = classifySafeAction(item.target, item.data, item.value);
    const evaluation = evaluateSubOperationPolicy(operation, action, params.policy, params.modulePolicy);
    flattened.push({ ...operation, action, evaluation });

    const nestedContract = findMultiSendContract(params.contracts, item.target);
    if (nestedContract === undefined || item.selector.toLowerCase() !== MULTISEND_SELECTOR.toLowerCase()) continue;
    const childDepth = params.depth + 1;
    if (childDepth > params.limits.maxDepth) {
      params.state.depthIssues.push({ path, target: item.target, attemptedDepth: childDepth, maxDepth: params.limits.maxDepth });
      continue;
    }
    flattened.push(...expand({
      ...params,
      contract: nestedContract,
      calldata: item.data,
      parentOperation: item.operation,
      depth: childDepth,
      pathPrefix: path
    }));
  }
  return flattened;
}

function evaluateSubOperationPolicy(
  operation: SafeSubOperation,
  action: ReturnType<typeof classifySafeAction>,
  policy: SafeMultisigConfig,
  modulePolicy?: SafeModulePolicyConfig
): SafePolicyEvaluation {
  const transaction: SafeTransaction = {
    safeAddress: operation.safeAddress,
    outerTransactionHash: operation.outerTransactionHash,
    blockNumber: operation.blockNumber,
    innerTarget: operation.target,
    innerValue: operation.value,
    innerData: operation.data,
    innerSelector: operation.selector,
    operation: operation.operation,
    safeTxGas: 0n,
    baseGas: 0n,
    gasPrice: 0n,
    gasToken: operation.safeAddress,
    refundReceiver: operation.safeAddress
  };
  const safeEvaluation = evaluateSafePolicy(transaction, action, policy);
  const evaluation = modulePolicy === undefined
    ? safeEvaluation
    : intersectSafePolicyEvaluations(safeEvaluation, evaluateSafeModulePolicy(transaction, action, modulePolicy));
  if (operation.multiSendMode !== "CALL_ONLY" || operation.operation !== "DELEGATECALL") return evaluation;
  const violation = {
    kind: "multisend-mode" as const,
    reason: "CALL_ONLY MultiSend forbids internal DELEGATECALL.",
    expected: "CALL",
    observed: operation.operation
  };
  return { ...evaluation, compliant: false, violations: [...evaluation.violations, violation] };
}

function findMultiSendContract(
  contracts: readonly MultiSendContractConfig[],
  address: Address
): MultiSendContractConfig | undefined {
  return contracts.find((contract) => contract.address.toLowerCase() === address.toLowerCase());
}

function stripHexPrefix(value: Hex): string { return value.slice(2); }
function hexByteLength(value: Hex): number { return (value.length - 2) / 2; }
function readHex(hex: string, byteOffset: number, byteLength: number): string {
  return hex.slice(byteOffset * 2, (byteOffset + byteLength) * 2);
}
