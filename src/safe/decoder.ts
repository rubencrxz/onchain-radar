import {
  decodeFunctionData,
  getAddress,
  parseAbi,
  toFunctionSelector,
  type Address,
  type Hex
} from "viem";
import type { RpcTransaction } from "../rpc.js";
import type { SafeDecodeResult, SafeOperation } from "./types.js";

export const SAFE_EXEC_TRANSACTION_SIGNATURE =
  "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";
export const SAFE_EXEC_TRANSACTION_SELECTOR = toFunctionSelector(SAFE_EXEC_TRANSACTION_SIGNATURE);

export const SAFE_EXEC_TRANSACTION_ABI = parseAbi([
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) returns (bool success)"
]);

export function decodeSafeExecTransaction(params: {
  safeAddress: Address;
  transaction: RpcTransaction;
}): SafeDecodeResult {
  const outerSelector = selectorOf(params.transaction.input);
  const common = {
    safeAddress: getAddress(params.safeAddress),
    outerTransactionHash: params.transaction.hash,
    blockNumber: params.transaction.blockNumber
  };

  if (outerSelector.toLowerCase() !== SAFE_EXEC_TRANSACTION_SELECTOR.toLowerCase()) {
    return {
      decoded: false,
      ...common,
      failureKind: "UNSUPPORTED_OUTER_SELECTOR",
      outerSelector,
      error: `Outer selector ${outerSelector} is not the supported Safe execTransaction selector.`
    };
  }

  try {
    const decoded = decodeFunctionData({ abi: SAFE_EXEC_TRANSACTION_ABI, data: params.transaction.input });
    const [to, value, data, operationValue, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver] = decoded.args;
    const operation = normalizeOperation(operationValue);
    if (operation === undefined) {
      return {
        decoded: false,
        ...common,
        failureKind: "UNSUPPORTED_OPERATION",
        outerSelector,
        error: `Safe operation ${operationValue.toString()} is not CALL (0) or DELEGATECALL (1).`
      };
    }

    return {
      decoded: true,
      transaction: {
        ...common,
        innerTarget: getAddress(to),
        innerValue: value,
        innerData: data,
        innerSelector: selectorOf(data),
        operation,
        safeTxGas,
        baseGas,
        gasPrice,
        gasToken: getAddress(gasToken),
        refundReceiver: getAddress(refundReceiver)
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

export function selectorOf(data: Hex): Hex {
  return (data.length >= 10 ? data.slice(0, 10) : "0x") as Hex;
}

function normalizeOperation(value: number): SafeOperation | undefined {
  if (value === 0) return "CALL";
  if (value === 1) return "DELEGATECALL";
  return undefined;
}
