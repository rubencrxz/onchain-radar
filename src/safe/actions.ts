import {
  decodeFunctionData,
  getAddress,
  parseAbiItem,
  toFunctionSelector,
  type AbiFunction,
  type Address,
  type Hex
} from "viem";
import { selectorOf } from "./decoder.js";
import type {
  ClassifiedSafeAction,
  SafeActionCategory,
  SafeMultisigConfig,
  SafeSemanticCategory
} from "./types.js";

type ActionDefinition = {
  signature: string;
  abi: AbiFunction;
  category: SafeActionCategory;
  semanticCategory: SafeSemanticCategory;
};

const ACTION_SIGNATURES: ReadonlyArray<[string, SafeActionCategory, SafeSemanticCategory]> = [
  ["upgradeTo(address)", "upgrade", "PROTOCOL_ADMINISTRATION"],
  ["upgradeToAndCall(address,bytes)", "upgrade", "PROTOCOL_ADMINISTRATION"],
  ["changeAdmin(address)", "administration", "PROTOCOL_ADMINISTRATION"],
  ["upgrade(address,address)", "upgrade", "PROTOCOL_ADMINISTRATION"],
  ["upgradeAndCall(address,address,bytes)", "upgrade", "PROTOCOL_ADMINISTRATION"],
  ["changeProxyAdmin(address,address)", "administration", "PROTOCOL_ADMINISTRATION"],
  ["transferOwnership(address)", "administration", "PROTOCOL_ADMINISTRATION"],
  ["grantRole(bytes32,address)", "access-control", "PROTOCOL_ADMINISTRATION"],
  ["revokeRole(bytes32,address)", "access-control", "PROTOCOL_ADMINISTRATION"],
  ["pause()", "administration", "PROTOCOL_ADMINISTRATION"],
  ["unpause()", "administration", "PROTOCOL_ADMINISTRATION"],
  ["enableModule(address)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["disableModule(address,address)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["addOwnerWithThreshold(address,uint256)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["removeOwner(address,address,uint256)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["swapOwner(address,address,address)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["changeThreshold(uint256)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["setGuard(address)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["setFallbackHandler(address)", "safe-management", "ADMINISTRATIVE_CONTROL"],
  ["transfer(address,uint256)", "asset", "FINANCIAL_OPERATION"],
  ["approve(address,uint256)", "asset", "FINANCIAL_OPERATION"],
  ["deposit()", "asset", "FINANCIAL_OPERATION"],
  ["withdraw(uint256)", "asset", "FINANCIAL_OPERATION"]
];

const DEFINITIONS = new Map<Hex, ActionDefinition>(
  ACTION_SIGNATURES.map(([signature, category, semanticCategory]) => {
    const functionName = signature.slice(0, signature.indexOf("("));
    const parameterNames = parameterNamesFor(signature);
    const types = signature.slice(signature.indexOf("(") + 1, -1);
    const namedInputs = types === "" ? "" : types.split(",").map((type, index) => `${type} ${parameterNames[index]}`).join(", ");
    const abi = parseAbiItem(`function ${functionName}(${namedInputs})`) as AbiFunction;
    return [toFunctionSelector(signature), { signature, abi, category, semanticCategory }];
  })
);

export const SAFE_ACTION_SELECTORS = Object.freeze(
  Object.fromEntries([...DEFINITIONS].map(([selector, definition]) => [definition.signature, selector])) as Record<string, Hex>
);

export function classifySafeAction(target: Address, data: Hex, nativeValue = 0n): ClassifiedSafeAction {
  const selector = selectorOf(data);
  if (selector === "0x" && nativeValue > 0n) {
    return {
      known: true,
      selector,
      functionName: "nativeTransfer",
      functionSignature: "nativeTransfer()",
      category: "asset",
      semanticCategory: "FINANCIAL_OPERATION",
      parameters: { amountWei: nativeValue.toString() },
      effectTarget: getAddress(target)
    };
  }
  const definition = DEFINITIONS.get(selector.toLowerCase() as Hex);
  if (definition === undefined) {
    return {
      known: false,
      selector,
      functionName: "unknown",
      functionSignature: "unknown",
      semanticCategory: "UNKNOWN_OPERATION",
      parameters: {},
      effectTarget: getAddress(target)
    };
  }

  try {
    const decoded = decodeFunctionData({ abi: [definition.abi], data });
    const parameters = Object.fromEntries(
      definition.abi.inputs.map((input, index) => [input.name || `arg${index}`, toJsonSafe(decoded.args[index])])
    );
    const functionName = definition.abi.name;
    const effectTarget = readEffectTarget(functionName, target, decoded.args);
    const expectedImplementation = readExpectedImplementation(functionName, decoded.args);
    const expectedAdmin = readExpectedAdmin(functionName, decoded.args);
    return {
      known: true,
      selector,
      functionName,
      functionSignature: definition.signature,
      category: definition.category,
      semanticCategory: definition.semanticCategory,
      parameters,
      effectTarget,
      ...(expectedImplementation === undefined ? {} : { expectedImplementation }),
      ...(expectedAdmin === undefined ? {} : { expectedAdmin })
    };
  } catch {
    return {
      known: false,
      selector,
      functionName: "unknown",
      functionSignature: "unknown",
      semanticCategory: "UNKNOWN_OPERATION",
      parameters: {},
      effectTarget: getAddress(target)
    };
  }
}

export function isAdministrativeSafeAction(action: ClassifiedSafeAction): boolean {
  return action.semanticCategory === "ADMINISTRATIVE_CONTROL" ||
    action.semanticCategory === "PROTOCOL_ADMINISTRATION";
}

export function isMaterialFinancialAction(
  action: ClassifiedSafeAction,
  target: Address,
  nativeValue: bigint,
  policy: SafeMultisigConfig
): boolean {
  if (action.semanticCategory !== "FINANCIAL_OPERATION") return false;
  if (nativeValue > policy.financialOperationPolicy.maxNativeValueWei) return true;
  if (policy.financialOperationPolicy.notableTokenTargets.some((address) => address.toLowerCase() === target.toLowerCase())) {
    return true;
  }
  if (!action.known) return false;
  if (action.functionName === "transfer") return policy.financialOperationPolicy.emitAllowedTransfers;
  if (action.functionName === "approve") return policy.financialOperationPolicy.emitAllowedApprovals;
  return nativeValue > 0n;
}

function readEffectTarget(functionName: string, target: Address, args: readonly unknown[]): Address {
  if (["upgrade", "upgradeAndCall", "changeProxyAdmin"].includes(functionName) && isAddressValue(args[0])) {
    return getAddress(args[0]);
  }
  return getAddress(target);
}

function readExpectedImplementation(functionName: string, args: readonly unknown[]): Address | undefined {
  const index = functionName === "upgradeTo" || functionName === "upgradeToAndCall" ? 0 :
    functionName === "upgrade" || functionName === "upgradeAndCall" ? 1 : -1;
  return index >= 0 && isAddressValue(args[index]) ? getAddress(args[index]) : undefined;
}

function readExpectedAdmin(functionName: string, args: readonly unknown[]): Address | undefined {
  const index = functionName === "changeAdmin" ? 0 : functionName === "changeProxyAdmin" ? 1 : -1;
  return index >= 0 && isAddressValue(args[index]) ? getAddress(args[index]) : undefined;
}

function isAddressValue(value: unknown): value is Address {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function toJsonSafe(value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(toJsonSafe);
  return value;
}

function parameterNamesFor(signature: string): string[] {
  const names: Record<string, string[]> = {
    "upgradeTo(address)": ["newImplementation"],
    "upgradeToAndCall(address,bytes)": ["newImplementation", "data"],
    "changeAdmin(address)": ["newAdmin"],
    "upgrade(address,address)": ["proxy", "implementation"],
    "upgradeAndCall(address,address,bytes)": ["proxy", "implementation", "data"],
    "changeProxyAdmin(address,address)": ["proxy", "newAdmin"],
    "transferOwnership(address)": ["newOwner"],
    "grantRole(bytes32,address)": ["role", "account"],
    "revokeRole(bytes32,address)": ["role", "account"],
    "enableModule(address)": ["module"],
    "disableModule(address,address)": ["prevModule", "module"],
    "addOwnerWithThreshold(address,uint256)": ["owner", "threshold"],
    "removeOwner(address,address,uint256)": ["prevOwner", "owner", "threshold"],
    "swapOwner(address,address,address)": ["prevOwner", "oldOwner", "newOwner"],
    "changeThreshold(uint256)": ["threshold"],
    "setGuard(address)": ["guard"],
    "setFallbackHandler(address)": ["handler"],
    "transfer(address,uint256)": ["to", "amount"],
    "approve(address,uint256)": ["spender", "amount"],
    "withdraw(uint256)": ["amount"]
  };
  return names[signature] ?? [];
}
