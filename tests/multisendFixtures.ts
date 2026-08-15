import { concatHex, encodeFunctionData, getAddress, numberToHex, size, type Address, type Hex } from "viem";
import type { AdministrativeMonitoringConfig, MultiSendMode, SafeOperation } from "../src/safe/types.js";
import { MULTISEND_ABI, MULTISEND_SELECTOR } from "../src/safe/multisend.js";
import { SAFE_ACTION_SELECTORS } from "../src/safe/actions.js";
import {
  IMPLEMENTATION,
  SAFE,
  TARGET,
  UNKNOWN_TARGET,
  execTransactionInput,
  safePolicy
} from "./safeFixtures.js";

export const MULTISEND = getAddress("0x7000000000000000000000000000000000000007");
export const NESTED_MULTISEND = getAddress("0x8000000000000000000000000000000000000008");

export function packSuboperation(params: {
  operation?: SafeOperation | number;
  target?: Address;
  value?: bigint;
  data?: Hex;
} = {}): Hex {
  const operation = typeof params.operation === "number"
    ? params.operation
    : params.operation === "DELEGATECALL" ? 1 : 0;
  const data = params.data ?? "0x";
  return concatHex([
    numberToHex(operation, { size: 1 }),
    params.target ?? TARGET,
    numberToHex(params.value ?? 0n, { size: 32 }),
    numberToHex(BigInt(size(data)), { size: 32 }),
    data
  ]);
}

export function multiSendData(operations: readonly Hex[]): Hex {
  return encodeFunctionData({
    abi: MULTISEND_ABI,
    functionName: "multiSend",
    args: [concatHex(operations)]
  });
}

export function multiSendExecInput(operations: readonly Hex[], options: {
  multiSend?: Address;
  outerOperation?: SafeOperation;
} = {}): Hex {
  return execTransactionInput({
    target: options.multiSend ?? MULTISEND,
    data: multiSendData(operations),
    operation: options.outerOperation ?? "DELEGATECALL"
  });
}

export function administrativeMultiSendConfig(mode: MultiSendMode = "MULTISEND"): AdministrativeMonitoringConfig {
  return {
    multisigs: [safePolicy({
      allowedTargets: [MULTISEND, NESTED_MULTISEND, TARGET],
      allowedSelectors: [
        MULTISEND_SELECTOR,
        SAFE_ACTION_SELECTORS["upgradeTo(address)"]!,
        SAFE_ACTION_SELECTORS["transfer(address,uint256)"]!,
        SAFE_ACTION_SELECTORS["approve(address,uint256)"]!
      ],
      allowedOperations: ["CALL", "DELEGATECALL"],
      maxNativeValueWei: 10n
    })],
    multisendContracts: [
      { name: "Safe MultiSend", address: MULTISEND, mode },
      { name: "Nested MultiSend", address: NESTED_MULTISEND, mode: "MULTISEND" }
    ],
    multisendLimits: {
      maxDepth: 2,
      maxSuboperations: 20,
      maxTotalPayloadBytes: 10_000,
      maxSuboperationDataBytes: 2_000
    }
  };
}

export { IMPLEMENTATION, SAFE, TARGET, UNKNOWN_TARGET };
