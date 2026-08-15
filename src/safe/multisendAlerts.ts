import type { Alert, AlertSeverity } from "../alerts.js";
import type { Address, Hex } from "viem";
import type { SafeExecutionOutcome } from "./alerts.js";
import type { MultiSendExpansionResult } from "./multisend.js";
import type {
  AnalyzedSafeSubOperation,
  MultiSendContractConfig,
  SafeMultisigConfig,
  SafePolicyViolation,
  SafeTransaction
} from "./types.js";
import { isAdministrativeSafeAction, isMaterialFinancialAction } from "./actions.js";

type MultiSendAlertContext = {
  chain: "ethereum";
  policy: SafeMultisigConfig;
  transaction: SafeTransaction;
  expansion: Extract<MultiSendExpansionResult, { recognized: true }>;
  outcome: SafeExecutionOutcome;
  createdAt: string;
  moduleContext?: {
    address: string;
    name?: string;
    maxNativeValueWei: bigint;
    zodiacRoles?: { roleKey: Hex; shouldRevert: boolean; wrapperPath: string; managerSafe?: Address };
  };
};

export function createMultiSendAlerts(params: MultiSendAlertContext): Alert[] {
  if (!params.expansion.complete) return [createFailureAlert(params)];

  const operations = params.expansion.operations;
  const perOperationViolationCount = operations.reduce((count, operation) => count + operation.evaluation.violations.length, 0);
  const totalValue = operations.reduce((sum, operation) => sum + operation.value, 0n);
  const effectiveMaxNativeValueWei = params.moduleContext === undefined
    ? params.policy.maxNativeValueWei
    : params.moduleContext.maxNativeValueWei < params.policy.maxNativeValueWei
      ? params.moduleContext.maxNativeValueWei
      : params.policy.maxNativeValueWei;
  const aggregateValueViolation = totalValue > effectiveMaxNativeValueWei;
  const violationCount = perOperationViolationCount + (aggregateValueViolation ? 1 : 0);
  const sensitiveCount = operations.filter((operation) => isAdministrativeSafeAction(operation.action)).length;
  const financialCount = operations.filter((operation) => operation.action.semanticCategory === "FINANCIAL_OPERATION").length;
  const unknownCount = operations.filter((operation) => operation.action.semanticCategory === "UNKNOWN_OPERATION").length;
  const delegatecallCount = operations.filter((operation) => operation.operation === "DELEGATECALL").length;
  const alerts: Alert[] = [createBaseAlert({
    ...params,
    ruleId: "SAFE_MULTISEND_EXECUTED",
    ruleName: "Safe MultiSend Executed",
    severity: violationCount === 0 ? "INFO" : hasCriticalViolation(operations, params.policy) ? "CRITICAL" : "WARNING",
    summary: `Safe ${params.policy.name} executed ${operations.length} decoded MultiSend suboperation(s); ${violationCount} policy violation(s) observed.`,
    data: params.transaction.innerData,
    identitySuffix: "summary",
    metadata: {
      multiSend: {
        ...summaryMetadata(params.expansion.contract, operations, sensitiveCount, violationCount, totalValue, delegatecallCount, params),
        financialOperationCount: financialCount,
        unknownOperationCount: unknownCount,
        alertDetail: params.policy.multisendAlertDetail
      }
    }
  })];

  for (const operation of operations) alerts.push(...createSuboperationAlerts(params, operation));
  for (const issue of params.expansion.depthIssues) {
    alerts.push(createBaseAlert({
      ...params,
      ruleId: "SAFE_MULTISEND_DEPTH_EXCEEDED",
      ruleName: "Safe MultiSend Depth Exceeded",
      severity: "CRITICAL",
      summary: `Nested MultiSend at path ${issue.path} would exceed configured depth ${issue.maxDepth}; deeper calldata was not interpreted.`,
      data: "0x",
      identitySuffix: `${issue.path}:${issue.target}`,
      metadata: { multiSend: { contract: params.expansion.contract, issue } }
    }));
  }

  if (violationCount > 0) {
    const violations = operations
      .filter((operation) => operation.evaluation.violations.length > 0)
      .map((operation) => operationViolationMetadata(operation));
    if (aggregateValueViolation) {
      violations.push({
        suboperationIndex: "aggregate",
        suboperationPath: "batch",
        target: params.expansion.contract.address,
        selector: params.transaction.innerSelector,
        operation: params.transaction.operation,
        violations: [{
          kind: "native-value",
          reason: "Aggregate native value across decoded suboperations exceeds maxNativeValueWei.",
          expected: effectiveMaxNativeValueWei.toString(),
          observed: totalValue.toString()
        }]
      });
    }
    alerts.push(createBaseAlert({
      ...params,
      ruleId: "SAFE_MULTISEND_POLICY_VIOLATION",
      ruleName: "Safe MultiSend Policy Violation",
      severity: hasCriticalViolation(operations, params.policy) ? "CRITICAL" : "WARNING",
      summary: `MultiSend batch contains ${violationCount} explicit policy violation(s) across ${violations.length} operation scope(s).`,
      data: params.transaction.innerData,
      identitySuffix: `policy:${operations.map((operation) => operation.path).join(".")}`,
      metadata: { multiSend: { contract: params.expansion.contract, violations, totalNativeValueWei: totalValue.toString() } }
    }));
  }

  const components = batchRiskComponents(operations);
  if (components.length >= 2 && components.some((component) => component.kind === "upgrade" || component.kind === "delegatecall" || component.kind === "safe-management")) {
    alerts.push(createBaseAlert({
      ...params,
      ruleId: "SAFE_BATCH_ADMINISTRATIVE_ANOMALY",
      ruleName: "Safe Batch Administrative Anomaly",
      severity: components.some((component) => component.kind === "upgrade" || component.kind === "delegatecall") ? "CRITICAL" : "WARNING",
      summary: `MultiSend batch combines ${components.length} independently sensitive administrative or asset actions.`,
      data: params.transaction.innerData,
      identitySuffix: `anomaly:${components.map((component) => component.path).join(".")}`,
      metadata: { multiSend: { contract: params.expansion.contract, componentSignals: components } }
    }));
  }
  return alerts;
}

function createSuboperationAlerts(params: MultiSendAlertContext, operation: AnalyzedSafeSubOperation): Alert[] {
  const alerts: Alert[] = [];
  const severity: AlertSeverity = operation.evaluation.compliant
    ? isAdministrativeSafeAction(operation.action) ? "WARNING" : "INFO"
    : isCriticalOperation(operation, params.policy) ? "CRITICAL" : "WARNING";
  if (shouldEmitSubcall(params, operation)) {
    alerts.push(createSubcallAlert(params, operation, "SAFE_MULTISEND_SUBCALL", "Safe MultiSend Subcall", severity,
      `MultiSend suboperation ${operation.path} executes ${operation.operation} to ${operation.target} with selector ${operation.selector}.`));
  }

  if (operation.operation === "DELEGATECALL") {
    alerts.push(createSubcallAlert(params, operation, "SAFE_NESTED_DELEGATECALL", "Safe Nested Delegatecall",
      operation.evaluation.operationAllowed && operation.evaluation.targetAllowed && operation.multiSendMode === "MULTISEND"
        ? "WARNING"
        : params.policy.criticality === "critical" ? "CRITICAL" : "WARNING",
      `MultiSend suboperation ${operation.path} performs DELEGATECALL to ${operation.target}.`));
  }
  if (!operation.action.known && operation.selector !== "0x") {
    alerts.push(createSubcallAlert(params, operation, "SAFE_UNKNOWN_SELECTOR", "Safe Unknown Selector",
      operation.evaluation.selectorAllowed ? "INFO" : "WARNING",
      `MultiSend suboperation ${operation.path} uses unclassified selector ${operation.selector}; this does not establish malicious intent.`));
  }
  if (operation.action.known && isAdministrativeSafeAction(operation.action)) {
    alerts.push(createSubcallAlert(params, operation, "SAFE_SENSITIVE_ADMIN_ACTION", "Safe Sensitive Action", "WARNING",
      `MultiSend suboperation ${operation.path} executes classified action ${operation.action.functionSignature}.`));
  }
  if (operation.evaluation.implementationAllowed === false) {
    alerts.push(createSubcallAlert(params, operation, "SAFE_UNKNOWN_IMPLEMENTATION_UPGRADE", "Safe Unknown Implementation Upgrade", "CRITICAL",
      `MultiSend suboperation ${operation.path} references non-allowlisted implementation ${operation.action.known ? operation.action.expectedImplementation : "unknown"}.`));
  }
  return alerts;
}

function shouldEmitSubcall(params: MultiSendAlertContext, operation: AnalyzedSafeSubOperation): boolean {
  if (params.policy.multisendAlertDetail === "all") return true;
  if (params.policy.multisendAlertDetail === "violations-only") return !operation.evaluation.compliant;
  return isAdministrativeSafeAction(operation.action) ||
    operation.action.semanticCategory === "UNKNOWN_OPERATION" ||
    operation.operation === "DELEGATECALL" ||
    !operation.evaluation.compliant ||
    isMaterialFinancialAction(operation.action, operation.target, operation.value, params.policy);
}

function createSubcallAlert(
  params: MultiSendAlertContext,
  operation: AnalyzedSafeSubOperation,
  ruleId: string,
  ruleName: string,
  severity: AlertSeverity,
  summary: string
): Alert {
  return createBaseAlert({
    ...params,
    ruleId,
    ruleName,
    severity,
    summary,
    data: operation.data,
    identitySuffix: [operation.multiSendAddress, operation.path, operation.target, operation.selector, operation.operation].join(":"),
    metadata: {
      multiSend: {
        contract: params.expansion.contract,
        suboperation: suboperationMetadata(operation),
        action: operation.action,
        policy: operation.evaluation
      }
    }
  });
}

function createFailureAlert(params: MultiSendAlertContext): Alert {
  const failure = params.expansion.complete ? undefined : params.expansion.failure;
  if (failure === undefined) throw new Error("Expected incomplete MultiSend expansion.");
  const ruleId = failure.validButOverLimit ? "SAFE_MULTISEND_LIMIT_EXCEEDED" : "SAFE_MULTISEND_MALFORMED";
  return createBaseAlert({
    ...params,
    ruleId,
    ruleName: failure.validButOverLimit ? "Safe MultiSend Defensive Limit Exceeded" : "Safe MultiSend Malformed Payload",
    severity: "CRITICAL",
    summary: `Configured MultiSend transaction could not be interpreted completely: ${failure.kind}. No partial suboperations were accepted.`,
    data: params.transaction.innerData,
    identitySuffix: `${failure.kind}:${failure.offsetBytes ?? "unknown"}`,
    metadata: {
      multiSend: {
        contract: params.expansion.contract,
        decodeStatus: failure.validButOverLimit ? "valid-over-limit" : "malformed",
        failureKind: failure.kind,
        failureMessage: failure.message,
        offsetBytes: failure.offsetBytes ?? null,
        partialInterpretationAccepted: false
      }
    }
  });
}

function createBaseAlert(params: MultiSendAlertContext & {
  ruleId: string;
  ruleName: string;
  severity: AlertSeverity;
  summary: string;
  data: string;
  identitySuffix: string;
  metadata: Record<string, unknown>;
}): Alert {
  return {
    id: [params.chain, params.ruleId, params.transaction.safeAddress, params.transaction.outerTransactionHash,
      ...(params.moduleContext === undefined ? [] : ["module", params.moduleContext.address]),
      params.expansion.contract.address, params.identitySuffix].join(":"),
    chain: params.chain,
    ruleId: params.ruleId,
    ruleName: params.ruleName,
    severity: params.severity,
    eventSignature: params.moduleContext === undefined
      ? "Safe.execTransaction+MultiSend.multiSend"
      : "Safe.execTransactionFromModule+MultiSend.multiSend",
    blockNumber: params.transaction.blockNumber.toString(),
    transactionHash: params.transaction.outerTransactionHash,
    address: params.transaction.safeAddress,
    topics: [],
    data: params.data,
    summary: params.summary,
    metadata: {
      source: "safe-multisend-analysis",
      safeAddress: params.transaction.safeAddress,
      outerTransactionHash: params.transaction.outerTransactionHash,
      executionOutcome: params.outcome,
      ...(params.moduleContext === undefined ? {} : {
        executionPath: "MODULE",
        module: {
          ...params.moduleContext,
          maxNativeValueWei: params.moduleContext.maxNativeValueWei.toString()
        }
      }),
      ...params.metadata
    },
    createdAt: params.createdAt
  };
}

function summaryMetadata(
  contract: MultiSendContractConfig,
  operations: readonly AnalyzedSafeSubOperation[],
  sensitiveCount: number,
  violationCount: number,
  totalValue: bigint,
  delegatecallCount: number,
  params: MultiSendAlertContext
): Record<string, unknown> {
  return {
    contract,
    mode: contract.mode,
    suboperationCount: operations.length,
    sensitiveActionCount: sensitiveCount,
    violationCount,
    totalNativeValueWei: totalValue.toString(),
    delegatecallCount,
    totalPayloadBytes: params.expansion.complete ? params.expansion.totalPayloadBytes : 0,
    depthFirstOrder: operations.map((operation) => operation.path),
    complete: params.expansion.complete && params.expansion.depthIssues.length === 0,
    depthLimited: params.expansion.complete && params.expansion.depthIssues.length > 0
  };
}

function suboperationMetadata(operation: AnalyzedSafeSubOperation): Record<string, unknown> {
  return {
    index: operation.index,
    path: operation.path,
    depth: operation.depth,
    operation: operation.operation,
    target: operation.target,
    valueWei: operation.value.toString(),
    data: operation.data,
    selector: operation.selector,
    multiSendAddress: operation.multiSendAddress,
    multiSendMode: operation.multiSendMode,
    parentOperation: operation.parentOperation
  };
}

function operationViolationMetadata(operation: AnalyzedSafeSubOperation): {
  suboperationIndex: number | string;
  suboperationPath: string;
  target: string;
  selector: string;
  operation: string;
  violations: SafePolicyViolation[];
} {
  return {
    suboperationIndex: operation.index,
    suboperationPath: operation.path,
    target: operation.target,
    selector: operation.selector,
    operation: operation.operation,
    violations: operation.evaluation.violations
  };
}

function isCriticalOperation(operation: AnalyzedSafeSubOperation, policy: SafeMultisigConfig): boolean {
  return operation.evaluation.implementationAllowed === false ||
    operation.evaluation.violations.some((violation) =>
      (violation.kind === "threshold" && violation.reason.includes("below minimumThreshold")) ||
      (["module", "guard", "fallback-handler"].includes(violation.kind) && policy.criticality === "critical")
    ) ||
    (operation.operation === "DELEGATECALL" && (!operation.evaluation.operationAllowed || !operation.evaluation.targetAllowed || operation.multiSendMode === "CALL_ONLY"));
}

function hasCriticalViolation(operations: readonly AnalyzedSafeSubOperation[], policy: SafeMultisigConfig): boolean {
  return operations.some((operation) => isCriticalOperation(operation, policy));
}

function batchRiskComponents(operations: readonly AnalyzedSafeSubOperation[]): Array<Record<string, unknown> & { kind: string; path: string }> {
  const components: Array<Record<string, unknown> & { kind: string; path: string }> = [];
  for (const operation of operations) {
    if (operation.operation === "DELEGATECALL") components.push({ kind: "delegatecall", path: operation.path, target: operation.target });
    if (!operation.action.known) continue;
    const name = operation.action.functionName;
    if (["upgradeTo", "upgradeToAndCall", "upgrade", "upgradeAndCall"].includes(name)) {
      components.push({ kind: "upgrade", path: operation.path, target: operation.action.effectTarget, implementation: operation.action.expectedImplementation ?? null });
    } else if (name === "approve") {
      components.push({ kind: "approval", path: operation.path, target: operation.target, parameters: operation.action.parameters });
    } else if (name === "transfer") {
      components.push({ kind: "asset-transfer", path: operation.path, target: operation.target, parameters: operation.action.parameters });
    } else if (operation.action.semanticCategory === "ADMINISTRATIVE_CONTROL") {
      components.push({ kind: "safe-management", path: operation.path, action: name, parameters: operation.action.parameters });
    } else if (operation.action.semanticCategory === "PROTOCOL_ADMINISTRATION") {
      components.push({ kind: "protocol-administration", path: operation.path, action: name, parameters: operation.action.parameters });
    }
  }
  return components;
}
