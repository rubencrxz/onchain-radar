import type { Alert, AlertSeverity } from "../alerts.js";
import type {
  ClassifiedSafeAction,
  SafeDecodeResult,
  SafeMultisigConfig,
  SafePolicyEvaluation,
  SafeTransaction
} from "./types.js";
import { isAdministrativeSafeAction } from "./actions.js";

export type SafeExecutionOutcome = "success" | "failure" | "unknown";

export function createSafeMonitoringAlerts(params: {
  chain: "ethereum";
  policy: SafeMultisigConfig;
  transaction: SafeTransaction;
  action: ClassifiedSafeAction;
  evaluation: SafePolicyEvaluation;
  outcome: SafeExecutionOutcome;
  createdAt: string;
}): Alert[] {
  const { transaction, action, evaluation } = params;
  const alerts: Alert[] = [];
  alerts.push(createAlert(params, "SAFE_TRANSACTION_EXECUTED", "Safe Transaction Executed", evaluation.compliant ? "INFO" : "WARNING",
    evaluation.compliant
      ? `Safe ${params.policy.name} executed a policy-compliant ${transaction.operation} to ${transaction.innerTarget}.`
      : `Safe ${params.policy.name} executed ${transaction.operation} to ${transaction.innerTarget} with policy violations.`));

  if (!evaluation.targetAllowed) {
    alerts.push(createAlert(params, "SAFE_UNKNOWN_TARGET", "Safe Unknown Target", transaction.operation === "DELEGATECALL" ? "CRITICAL" : "WARNING",
      `Safe called target ${transaction.innerTarget}, which is not in allowedTargets.`));
  }
  if (transaction.operation === "DELEGATECALL") {
    alerts.push(createAlert(params, "SAFE_DELEGATECALL_EXECUTED", "Safe Delegatecall Executed", evaluation.operationAllowed && evaluation.targetAllowed ? "WARNING" : "CRITICAL",
      `Safe executed DELEGATECALL to ${transaction.innerTarget} with selector ${transaction.innerSelector}.`));
  }
  if (!action.known) {
    alerts.push(createAlert(params, "SAFE_UNKNOWN_SELECTOR", "Safe Unknown Selector", evaluation.selectorAllowed ? "INFO" : "WARNING",
      `Safe inner selector ${transaction.innerSelector} is not classified; this does not establish malicious intent.`));
  }
  if (action.known && isAdministrativeSafeAction(action)) {
    alerts.push(createAlert(params, "SAFE_SENSITIVE_ADMIN_ACTION", "Safe Sensitive Action", "WARNING",
      `Safe executed classified action ${action.functionSignature} on ${transaction.innerTarget}.`));
  }
  if (!evaluation.nativeValueAllowed) {
    alerts.push(createAlert(params, "SAFE_NATIVE_VALUE_ANOMALY", "Safe Native Value Anomaly", "WARNING",
      `Safe native value ${transaction.innerValue.toString()} wei exceeds configured maximum ${params.policy.maxNativeValueWei.toString()} wei.`));
  }
  if (evaluation.implementationAllowed === false) {
    alerts.push(createAlert(params, "SAFE_UNKNOWN_IMPLEMENTATION_UPGRADE", "Safe Unknown Implementation Upgrade", "CRITICAL",
      `Safe upgrade action references implementation ${action.known ? action.expectedImplementation : "unknown"}, which is not allowlisted.`));
  }
  if (!evaluation.compliant) {
    const critical = evaluation.violations.some((violation) =>
      violation.kind === "implementation" ||
      (violation.kind === "threshold" && violation.reason.includes("below minimumThreshold")) ||
      (["module", "guard", "fallback-handler"].includes(violation.kind) && params.policy.criticality === "critical")
    ) ||
      (!evaluation.operationAllowed && transaction.operation === "DELEGATECALL");
    alerts.push(createAlert(params, "SAFE_POLICY_VIOLATION", "Safe Policy Violation", critical ? "CRITICAL" : "WARNING",
      `Safe operation violated policy: ${evaluation.violations.map((violation) => violation.kind).join(", ")}.`));
  }
  return alerts;
}

export function createUndecodedSafeAlert(params: {
  chain: "ethereum";
  policy: SafeMultisigConfig;
  result: Exclude<SafeDecodeResult, { decoded: true }>;
  outcome: SafeExecutionOutcome;
  createdAt: string;
}): Alert {
  return {
    id: [params.chain, "SAFE_TRANSACTION_UNDECODED", params.result.safeAddress, params.result.outerTransactionHash, params.result.outerSelector, params.result.failureKind].join(":"),
    chain: params.chain,
    ruleId: "SAFE_TRANSACTION_UNDECODED",
    ruleName: "Safe Transaction Could Not Be Reconstructed",
    severity: params.result.failureKind === "UNSUPPORTED_OUTER_SELECTOR" ? "WARNING" : "CRITICAL",
    eventSignature: "Safe.execTransaction",
    blockNumber: params.result.blockNumber.toString(),
    transactionHash: params.result.outerTransactionHash,
    address: params.result.safeAddress,
    topics: [],
    data: params.result.outerSelector,
    summary: `Transaction associated with Safe ${params.policy.name} could not be decoded: ${params.result.failureKind}.`,
    metadata: {
      source: "eth_getTransactionByHash",
      safe: {
        name: params.policy.name,
        address: params.result.safeAddress,
        criticality: params.policy.criticality,
        outerSelector: params.result.outerSelector,
        decodeStatus: params.result.failureKind,
        decodeError: params.result.error,
        executionOutcome: params.outcome
      }
    },
    createdAt: params.createdAt
  };
}

function createAlert(
  params: {
    chain: "ethereum";
    policy: SafeMultisigConfig;
    transaction: SafeTransaction;
    action: ClassifiedSafeAction;
    evaluation: SafePolicyEvaluation;
    outcome: SafeExecutionOutcome;
    createdAt: string;
  },
  ruleId: string,
  ruleName: string,
  severity: AlertSeverity,
  summary: string
): Alert {
  const { transaction, action, evaluation } = params;
  return {
    id: [params.chain, ruleId, transaction.safeAddress, transaction.outerTransactionHash, transaction.innerTarget, transaction.innerSelector, transaction.operation].join(":"),
    chain: params.chain,
    ruleId,
    ruleName,
    severity,
    eventSignature: "Safe.execTransaction",
    blockNumber: transaction.blockNumber.toString(),
    transactionHash: transaction.outerTransactionHash,
    address: transaction.safeAddress,
    topics: [],
    data: transaction.innerData,
    summary,
    metadata: {
      source: "eth_getTransactionByHash",
      safe: {
        name: params.policy.name,
        address: transaction.safeAddress,
        criticality: params.policy.criticality,
        outerTransactionHash: transaction.outerTransactionHash,
        innerTarget: transaction.innerTarget,
        innerValueWei: transaction.innerValue.toString(),
        innerData: transaction.innerData,
        innerSelector: transaction.innerSelector,
        operation: transaction.operation,
        safeTxGas: transaction.safeTxGas.toString(),
        baseGas: transaction.baseGas.toString(),
        gasPrice: transaction.gasPrice.toString(),
        gasToken: transaction.gasToken,
        refundReceiver: transaction.refundReceiver,
        executionOutcome: params.outcome,
        action: {
          known: action.known,
          functionName: action.functionName,
          functionSignature: action.functionSignature,
          ...(action.known ? { category: action.category } : {}),
          semanticCategory: action.semanticCategory,
          parameters: action.parameters,
          effectTarget: action.effectTarget,
          ...(action.known && action.expectedImplementation !== undefined ? { expectedImplementation: action.expectedImplementation } : {}),
          ...(action.known && action.expectedAdmin !== undefined ? { expectedAdmin: action.expectedAdmin } : {})
        },
        policy: {
          compliant: evaluation.compliant,
          targetAllowed: evaluation.targetAllowed,
          selectorAllowed: evaluation.selectorAllowed,
          operationAllowed: evaluation.operationAllowed,
          implementationAllowed: evaluation.implementationAllowed ?? null,
          nativeValueAllowed: evaluation.nativeValueAllowed,
          violations: evaluation.violations
        }
      }
    },
    createdAt: params.createdAt
  };
}
