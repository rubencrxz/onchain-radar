import type { Address, Hex } from "viem";

export type SafeOperation = "CALL" | "DELEGATECALL";
export type SafeCriticality = "standard" | "high" | "critical";
export type MultiSendMode = "MULTISEND" | "CALL_ONLY";
export type MultiSendAlertDetail = "all" | "sensitive-only" | "violations-only";
export type SafeSemanticCategory =
  | "ADMINISTRATIVE_CONTROL"
  | "PROTOCOL_ADMINISTRATION"
  | "FINANCIAL_OPERATION"
  | "UNKNOWN_OPERATION";

export type MultiSendContractConfig = {
  name: string;
  address: Address;
  mode: MultiSendMode;
};

export type MultiSendLimits = {
  maxDepth: number;
  maxSuboperations: number;
  maxTotalPayloadBytes: number;
  maxSuboperationDataBytes: number;
};

export const DEFAULT_MULTISEND_LIMITS: Readonly<MultiSendLimits> = Object.freeze({
  maxDepth: 2,
  maxSuboperations: 256,
  maxTotalPayloadBytes: 1_048_576,
  maxSuboperationDataBytes: 262_144
});

export type SafeMultisigConfig = {
  name: string;
  address: Address;
  criticality: SafeCriticality;
  allowedTargets: Address[];
  allowedSelectors: Hex[];
  allowedOperations: SafeOperation[];
  allowedImplementations: Address[];
  maxNativeValueWei: bigint;
  allowedOwners: Address[];
  minimumThreshold?: number;
  allowedThresholds: number[];
  allowedModules: Address[];
  allowedGuards: Address[];
  allowedFallbackHandlers: Address[];
  multisendAlertDetail: MultiSendAlertDetail;
  financialOperationPolicy: FinancialOperationPolicy;
  modulePolicies: SafeModulePolicyConfig[];
};

export type FinancialOperationPolicy = {
  emitAllowedTransfers: boolean;
  emitAllowedApprovals: boolean;
  maxNativeValueWei: bigint;
  notableTokenTargets: Address[];
};

export type SafeModulePolicyConfig = {
  name: string;
  address: Address;
  allowedTargets: Address[];
  allowedSelectors: Hex[];
  allowedOperations: SafeOperation[];
  allowedImplementations: Address[];
  maxNativeValueWei: bigint;
  adapter?: ZodiacRolesV2AdapterConfig;
};

export type ZodiacRolesV2AdapterConfig = {
  type: "ZODIAC_ROLES_V2";
  managerSafes: Address[];
};

export type AdministrativeMonitoringConfig = {
  multisigs: SafeMultisigConfig[];
  multisendContracts?: MultiSendContractConfig[];
  multisendLimits?: MultiSendLimits;
};

export type SafeSubOperation = {
  index: number;
  path: string;
  depth: number;
  operation: SafeOperation;
  target: Address;
  value: bigint;
  data: Hex;
  selector: Hex;
  safeAddress: Address;
  outerTransactionHash: Hex;
  blockNumber: bigint;
  multiSendAddress: Address;
  multiSendMode: MultiSendMode;
  parentOperation: SafeOperation;
};

export type AnalyzedSafeSubOperation = SafeSubOperation & {
  action: ClassifiedSafeAction;
  evaluation: SafePolicyEvaluation;
};

export type SafeTransaction = {
  safeAddress: Address;
  outerTransactionHash: Hex;
  blockNumber: bigint;
  innerTarget: Address;
  innerValue: bigint;
  innerData: Hex;
  innerSelector: Hex;
  operation: SafeOperation;
  safeTxGas: bigint;
  baseGas: bigint;
  gasPrice: bigint;
  gasToken: Address;
  refundReceiver: Address;
};

export type SafeModuleEntrypoint =
  | "execTransactionFromModule"
  | "execTransactionFromModuleReturnData"
  | "execTransactionWithRole"
  | "execTransactionWithRoleReturnData";

export type ZodiacRolesExecutionContext = {
  adapterType: "ZODIAC_ROLES_V2";
  roleKey: Hex;
  shouldRevert: boolean;
  wrapperPath: string;
  wrapperDepth: number;
  managerSafe?: Address;
};

export type SafeModuleTransaction = {
  moduleAddress: Address;
  moduleName?: string;
  entrypoint: SafeModuleEntrypoint;
  outerTarget: Address | null;
  eventLogIndex?: number;
  zodiacRoles?: ZodiacRolesExecutionContext;
  transaction: SafeTransaction;
};

export type SafeModuleDecodeFailureKind =
  | "UNSUPPORTED_OUTER_SELECTOR"
  | "MALFORMED_CALLDATA"
  | "UNSUPPORTED_OPERATION"
  | "AMBIGUOUS_MULTIPLE_MODULE_EXECUTIONS"
  | "ZODIAC_WRAPPER_NOT_FOUND"
  | "ZODIAC_WRAPPER_AMBIGUOUS"
  | "ZODIAC_UNSUPPORTED_SELECTOR";

export type SafeModuleDecodeResult =
  | { decoded: true; moduleTransaction: SafeModuleTransaction }
  | {
      decoded: false;
      safeAddress: Address;
      moduleAddress: Address;
      outerTransactionHash: Hex;
      blockNumber: bigint;
      outerTarget: Address | null;
      eventLogIndex?: number;
      failureKind: SafeModuleDecodeFailureKind;
      outerSelector: Hex;
      error: string;
    };

export type SafeDecodeFailureKind = "UNSUPPORTED_OUTER_SELECTOR" | "MALFORMED_CALLDATA" | "UNSUPPORTED_OPERATION";

export type SafeDecodeResult =
  | { decoded: true; transaction: SafeTransaction }
  | {
      decoded: false;
      safeAddress: Address;
      outerTransactionHash: Hex;
      blockNumber: bigint;
      failureKind: SafeDecodeFailureKind;
      outerSelector: Hex;
      error: string;
    };

export type SafeActionCategory = "upgrade" | "administration" | "access-control" | "safe-management" | "asset";

export type ClassifiedSafeAction = {
  known: true;
  selector: Hex;
  functionName: string;
  functionSignature: string;
  category: SafeActionCategory;
  semanticCategory: SafeSemanticCategory;
  parameters: Record<string, unknown>;
  effectTarget: Address;
  expectedImplementation?: Address;
  expectedAdmin?: Address;
} | {
  known: false;
  selector: Hex;
  functionName: "unknown";
  functionSignature: "unknown";
  semanticCategory: "UNKNOWN_OPERATION";
  parameters: Record<string, never>;
  effectTarget: Address;
};

export type SafePolicyViolationKind =
  | "target"
  | "selector"
  | "operation"
  | "implementation"
  | "native-value"
  | "multisend-mode"
  | "owner"
  | "threshold"
  | "module"
  | "guard"
  | "fallback-handler";

export type SafePolicyViolation = {
  kind: SafePolicyViolationKind;
  reason: string;
  expected: unknown;
  observed: unknown;
  scope?: "safe" | "module";
};

export type SafePolicyEvaluation = {
  compliant: boolean;
  targetAllowed: boolean;
  selectorAllowed: boolean;
  operationAllowed: boolean;
  implementationAllowed?: boolean;
  nativeValueAllowed: boolean;
  violations: SafePolicyViolation[];
};
