import {
  encodeAbiParameters,
  getAddress,
  isAddress,
  keccak256,
  toHex,
  type Address,
  type Hex
} from "viem";
import type { RpcClient } from "../rpc.js";
import type { SafeOperation } from "./types.js";

export const ZODIAC_ROLES_V2_MASTERCOPY_2_1 = getAddress(
  "0x9646fDAD06d3e24444381f44362a3B0eB343D337"
);
export const ZODIAC_ROLES_V2_LAYOUT = Object.freeze({ rolesSlot: 4n, unwrappersSlot: 6n });
export const ZODIAC_MULTI_SEND_UNWRAPPER_2_1 = getAddress(
  "0x93B7fCbc63ED8a3a24B59e1C3e6649D50B7427c0"
);

export type ZodiacClearance = "NONE" | "TARGET" | "FUNCTION";
export type ZodiacExecutionOptions = "NONE" | "SEND" | "DELEGATECALL" | "BOTH";

export type ZodiacConditionDescriptor = {
  index: number;
  parent: number;
  parameterType: string;
  operator: string;
  comparisonHash?: Hex;
};

export type ZodiacFunctionPermission = {
  selector: Hex;
  configured: boolean;
  wildcard: boolean;
  executionOptions: ZodiacExecutionOptions;
  conditionCount: number;
  conditionPointer?: Address;
  conditions: ZodiacConditionDescriptor[];
};

export type ZodiacRolePermissionObservation =
  | {
      status: "unsupported";
      moduleAddress: Address;
      blockNumber: bigint;
      reason: string;
    }
  | {
      status: "observed";
      moduleAddress: Address;
      mastercopy: Address;
      blockNumber: bigint;
      roleKey: Hex;
      target: Address;
      clearance: ZodiacClearance;
      targetExecutionOptions: ZodiacExecutionOptions;
      functionPermission: ZodiacFunctionPermission;
    };

export type ZodiacStructuralAuthorization = {
  targetAllowed: boolean;
  selectorAllowed: boolean;
  operationAllowed: boolean;
  nativeValueAllowed: boolean;
  structurallyAllowed: boolean;
  conditionEvaluation: "not-applicable" | "wildcard" | "scoped-not-evaluated";
  fullyVerified: boolean;
};

const MINIMAL_PROXY_PREFIX = "363d3d373d3d3d363d73";
const MINIMAL_PROXY_SUFFIX = "5af43d82803e903d91602b57fd5bf3";
const PARAMETER_TYPES = ["NONE", "STATIC", "DYNAMIC", "TUPLE", "ARRAY", "CALLDATA", "ABI_ENCODED"];
const OPERATORS = [
  "PASS", "AND", "OR", "NOR", "PLACEHOLDER_04", "MATCHES", "ARRAY_SOME", "ARRAY_EVERY",
  "ARRAY_SUBSET", "PLACEHOLDER_09", "PLACEHOLDER_10", "PLACEHOLDER_11", "PLACEHOLDER_12",
  "PLACEHOLDER_13", "PLACEHOLDER_14", "EQUAL_TO_AVATAR", "EQUAL_TO", "GREATER_THAN",
  "LESS_THAN", "SIGNED_INT_GREATER_THAN", "SIGNED_INT_LESS_THAN", "BITMASK", "CUSTOM",
  "PLACEHOLDER_23", "PLACEHOLDER_24", "PLACEHOLDER_25", "PLACEHOLDER_26", "PLACEHOLDER_27",
  "WITHIN_ALLOWANCE", "ETHER_WITHIN_ALLOWANCE", "CALL_WITHIN_ALLOWANCE", "PLACEHOLDER_31"
];

export async function readZodiacRolePermission(params: {
  rpc: RpcClient;
  moduleAddress: Address;
  roleKey: Hex;
  target: Address;
  selector: Hex;
  blockNumber: bigint;
  maxConditionNodes?: number;
  maxConditionBytes?: number;
}): Promise<ZodiacRolePermissionObservation> {
  const moduleAddress = getAddress(params.moduleAddress);
  const target = getAddress(params.target);
  if (!/^0x[0-9a-fA-F]{64}$/.test(params.roleKey)) throw new Error("Zodiac roleKey must be exactly 32 bytes.");
  if (!/^0x[0-9a-fA-F]{8}$/.test(params.selector)) throw new Error("Zodiac selector must be exactly four bytes.");
  if (params.blockNumber < 0n) throw new Error("Zodiac permission blockNumber must be non-negative.");
  if (params.rpc.getCode === undefined) {
    return { status: "unsupported", moduleAddress, blockNumber: params.blockNumber, reason: "RPC client does not expose bounded eth_getCode introspection." };
  }

  const proxyCode = await params.rpc.getCode({ address: moduleAddress, blockNumber: params.blockNumber });
  const mastercopy = extractMinimalProxyMastercopy(proxyCode);
  if (mastercopy === undefined) {
    return { status: "unsupported", moduleAddress, blockNumber: params.blockNumber, reason: "Module is not the supported canonical EIP-1167 Zodiac Roles proxy form." };
  }
  if (mastercopy.toLowerCase() !== ZODIAC_ROLES_V2_MASTERCOPY_2_1.toLowerCase()) {
    return { status: "unsupported", moduleAddress, blockNumber: params.blockNumber, reason: `Unsupported Zodiac Roles mastercopy ${mastercopy}; storage layout was not assumed.` };
  }

  const targetWord = await readWord(params.rpc, moduleAddress, zodiacRoleTargetSlot(params.roleKey, target), params.blockNumber);
  const clearance = decodeClearance(Number(targetWord & 0xffn));
  const targetExecutionOptions = decodeExecutionOptions(Number((targetWord >> 8n) & 0xffn));
  const functionWord = await readWord(
    params.rpc,
    moduleAddress,
    zodiacRoleFunctionSlot(params.roleKey, target, params.selector),
    params.blockNumber
  );
  const functionPermission = await decodeFunctionPermission({
    rpc: params.rpc,
    selector: params.selector,
    header: functionWord,
    blockNumber: params.blockNumber,
    maxConditionNodes: params.maxConditionNodes ?? 256,
    maxConditionBytes: params.maxConditionBytes ?? 65_536
  });
  return {
    status: "observed",
    moduleAddress,
    mastercopy,
    blockNumber: params.blockNumber,
    roleKey: params.roleKey,
    target,
    clearance,
    targetExecutionOptions,
    functionPermission
  };
}

export async function readZodiacTransactionUnwrapper(params: {
  rpc: RpcClient;
  moduleAddress: Address;
  target: Address;
  selector: Hex;
  blockNumber: bigint;
}): Promise<Address> {
  const word = await readWord(
    params.rpc,
    getAddress(params.moduleAddress),
    zodiacUnwrapperSlot(getAddress(params.target), params.selector),
    params.blockNumber
  );
  return getAddress(`0x${toHex(word, { size: 32 }).slice(-40)}`);
}

export function assessZodiacStructuralAuthorization(
  observation: Extract<ZodiacRolePermissionObservation, { status: "observed" }>,
  operation: SafeOperation,
  value: bigint
): ZodiacStructuralAuthorization {
  const targetAllowed = observation.clearance !== "NONE";
  const selectorAllowed = observation.clearance === "TARGET" ||
    (observation.clearance === "FUNCTION" && observation.functionPermission.configured);
  const options = observation.clearance === "TARGET"
    ? observation.targetExecutionOptions
    : observation.functionPermission.executionOptions;
  const operationAllowed = operation === "CALL" || options === "DELEGATECALL" || options === "BOTH";
  const nativeValueAllowed = value === 0n || options === "SEND" || options === "BOTH";
  const conditionEvaluation = observation.clearance !== "FUNCTION"
    ? "not-applicable"
    : observation.functionPermission.wildcard
      ? "wildcard"
      : "scoped-not-evaluated";
  const structurallyAllowed = targetAllowed && selectorAllowed && operationAllowed && nativeValueAllowed;
  return {
    targetAllowed,
    selectorAllowed,
    operationAllowed,
    nativeValueAllowed,
    structurallyAllowed,
    conditionEvaluation,
    fullyVerified: structurallyAllowed && conditionEvaluation !== "scoped-not-evaluated"
  };
}

export function hashAbiEncodedAddress(address: Address): Hex {
  return keccak256(encodeAbiParameters([{ type: "address" }], [getAddress(address)]));
}

export function decodeRoleKeyAscii(roleKey: Hex): string | undefined {
  if (!/^0x[0-9a-fA-F]{64}$/.test(roleKey)) return undefined;
  const bytes = roleKey.slice(2).match(/.{2}/g) ?? [];
  const end = bytes.findIndex((value) => value === "00");
  const content = bytes.slice(0, end === -1 ? bytes.length : end);
  if (content.length === 0 || content.some((value) => Number.parseInt(value, 16) < 0x20 || Number.parseInt(value, 16) > 0x7e)) return undefined;
  return String.fromCharCode(...content.map((value) => Number.parseInt(value, 16)));
}

export function extractMinimalProxyMastercopy(code: Hex | undefined): Address | undefined {
  if (code === undefined) return undefined;
  const raw = code.slice(2).toLowerCase();
  if (raw.length !== 90 || !raw.startsWith(MINIMAL_PROXY_PREFIX) || !raw.endsWith(MINIMAL_PROXY_SUFFIX)) return undefined;
  const address = `0x${raw.slice(MINIMAL_PROXY_PREFIX.length, MINIMAL_PROXY_PREFIX.length + 40)}`;
  return isAddress(address) ? getAddress(address) : undefined;
}

export function zodiacRoleTargetSlot(roleKey: Hex, target: Address): Hex {
  const roleBase = roleStorageBase(roleKey);
  return keccak256(encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [getAddress(target), roleBase + 1n]));
}

export function zodiacRoleFunctionSlot(roleKey: Hex, target: Address, selector: Hex): Hex {
  const roleBase = roleStorageBase(roleKey);
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }],
    [zodiacPermissionKey(getAddress(target), selector), roleBase + 2n]
  ));
}

export function zodiacUnwrapperSlot(target: Address, selector: Hex): Hex {
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }],
    [zodiacPermissionKey(getAddress(target), selector), ZODIAC_ROLES_V2_LAYOUT.unwrappersSlot]
  ));
}

function roleStorageBase(roleKey: Hex): bigint {
  return BigInt(keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }],
    [roleKey, ZODIAC_ROLES_V2_LAYOUT.rolesSlot]
  )));
}

function zodiacPermissionKey(target: Address, selector: Hex): Hex {
  if (!/^0x[0-9a-fA-F]{8}$/.test(selector)) throw new Error("Zodiac selector must be exactly four bytes.");
  return `0x${target.slice(2).toLowerCase()}${selector.slice(2).toLowerCase()}${"0".repeat(16)}` as Hex;
}

async function readWord(rpc: RpcClient, address: Address, slot: Hex, blockNumber: bigint): Promise<bigint> {
  const value = await rpc.getStorageAt({ address, slot, blockNumber });
  return value === undefined ? 0n : BigInt(value);
}

async function decodeFunctionPermission(params: {
  rpc: RpcClient;
  selector: Hex;
  header: bigint;
  blockNumber: bigint;
  maxConditionNodes: number;
  maxConditionBytes: number;
}): Promise<ZodiacFunctionPermission> {
  if (!Number.isSafeInteger(params.maxConditionNodes) || params.maxConditionNodes <= 0 ||
      !Number.isSafeInteger(params.maxConditionBytes) || params.maxConditionBytes <= 0) {
    throw new Error("Zodiac permission introspection limits must be positive safe integers.");
  }
  if (params.header === 0n) {
    return { selector: params.selector, configured: false, wildcard: false, executionOptions: "NONE", conditionCount: 0, conditions: [] };
  }
  const count = Number((params.header >> 240n) & 0xffffn);
  const executionOptions = decodeExecutionOptions(Number((params.header >> 224n) & 0xffn));
  const wildcard = ((params.header >> 216n) & 1n) === 1n;
  if (count > params.maxConditionNodes) throw new Error(`Zodiac condition count ${count} exceeds introspection limit ${params.maxConditionNodes}.`);
  if (wildcard) {
    if (count !== 0) throw new Error("Zodiac wildcard permission has a non-zero condition count.");
    return { selector: params.selector, configured: true, wildcard: true, executionOptions, conditionCount: 0, conditions: [] };
  }
  const pointer = getAddress(`0x${toHex(params.header, { size: 32 }).slice(-40)}`);
  if (pointer === getAddress("0x0000000000000000000000000000000000000000") || params.rpc.getCode === undefined) {
    throw new Error("Scoped Zodiac permission is missing readable condition bytecode.");
  }
  const code = await params.rpc.getCode({ address: pointer, blockNumber: params.blockNumber });
  if (code === undefined || !code.startsWith("0x00")) throw new Error(`Zodiac condition pointer ${pointer} has invalid code.`);
  const byteLength = (code.length - 2) / 2;
  if (byteLength > params.maxConditionBytes) throw new Error(`Zodiac condition bytecode ${byteLength} exceeds introspection limit ${params.maxConditionBytes}.`);
  const raw = code.slice(4);
  if (raw.length < count * 4) throw new Error("Zodiac condition descriptor body is truncated.");
  let comparisonOffset = count * 4;
  const conditions: ZodiacConditionDescriptor[] = [];
  for (let index = 0; index < count; index++) {
    const bits = Number.parseInt(raw.slice(index * 4, index * 4 + 4), 16);
    const operatorIndex = bits & 0x1f;
    const parameterTypeIndex = (bits >> 5) & 0x07;
    const descriptor: ZodiacConditionDescriptor = {
      index,
      parent: (bits >> 8) & 0xff,
      parameterType: PARAMETER_TYPES[parameterTypeIndex] ?? `UNKNOWN_${parameterTypeIndex}`,
      operator: OPERATORS[operatorIndex] ?? `UNKNOWN_${operatorIndex}`
    };
    if (operatorIndex >= 16) {
      if (comparisonOffset + 64 > raw.length) throw new Error("Zodiac condition comparison body is truncated.");
      descriptor.comparisonHash = `0x${raw.slice(comparisonOffset, comparisonOffset + 64)}` as Hex;
      comparisonOffset += 64;
    }
    conditions.push(descriptor);
  }
  if (comparisonOffset !== raw.length) throw new Error("Zodiac condition bytecode contains unconsumed trailing bytes.");
  return { selector: params.selector, configured: true, wildcard: false, executionOptions, conditionCount: count, conditionPointer: pointer, conditions };
}

function decodeClearance(value: number): ZodiacClearance {
  if (value === 0) return "NONE";
  if (value === 1) return "TARGET";
  if (value === 2) return "FUNCTION";
  throw new Error(`Unsupported Zodiac clearance ${value}.`);
}

function decodeExecutionOptions(value: number): ZodiacExecutionOptions {
  if (value === 0) return "NONE";
  if (value === 1) return "SEND";
  if (value === 2) return "DELEGATECALL";
  if (value === 3) return "BOTH";
  throw new Error(`Unsupported Zodiac execution options ${value}.`);
}
