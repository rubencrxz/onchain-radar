import type { Alert, AlertSeverity } from "../alerts.js";
import type { ClassifiedSafeAction, SafeModuleDecodeResult, SafeModulePolicyConfig, SafeMultisigConfig, SafePolicyEvaluation } from "./types.js";

export type SafeModuleEnabledObservation = {
  beforeBlock: string;
  afterBlock: string;
  enabledBefore: boolean;
  enabledAfter: boolean;
  enabledAtExecution: boolean;
};

export function createSafeModuleExecutionAlerts(params: {
  chain: "ethereum";
  safePolicy: SafeMultisigConfig;
  modulePolicy?: SafeModulePolicyConfig;
  result: SafeModuleDecodeResult;
  action?: ClassifiedSafeAction;
  safeEvaluation?: SafePolicyEvaluation;
  moduleEvaluation?: SafePolicyEvaluation;
  effectiveEvaluation?: SafePolicyEvaluation;
  enabled: SafeModuleEnabledObservation;
  outcome: "success" | "failure";
  createdAt: string;
}): Alert[] {
  const alerts: Alert[] = [];
  const moduleAddress = params.result.decoded
    ? params.result.moduleTransaction.moduleAddress
    : params.result.moduleAddress;
  const knownModule = params.modulePolicy !== undefined;
  if (!knownModule) {
    alerts.push(createAlert(params, "SAFE_MODULE_UNKNOWN", "Safe Unknown Executing Module",
      params.safePolicy.criticality === "critical" ? "CRITICAL" : "WARNING",
      `Safe ${params.safePolicy.name} emitted a module execution from unconfigured module ${moduleAddress}.`, "unknown-module"));
  }
  if (!params.enabled.enabledAtExecution) {
    alerts.push(createAlert(params, "SAFE_MODULE_DISABLED_EXECUTOR", "Safe Disabled Module Execution",
      params.safePolicy.criticality === "standard" ? "WARNING" : "CRITICAL",
      `Module ${moduleAddress} was not enabled in either the pre-block or post-block Safe state.`, "disabled-module"));
  }
  if (!params.result.decoded) {
    alerts.push(createAlert(params, "SAFE_MODULE_TRANSACTION_UNDECODED", "Safe Module Transaction Undecoded", "WARNING",
      `Module execution could not be reconstructed from outer calldata: ${params.result.failureKind}.`, params.result.failureKind));
    return alerts;
  }

  const transaction = params.result.moduleTransaction.transaction;
  const evaluation = params.effectiveEvaluation;
  if (evaluation === undefined || params.action === undefined || params.safeEvaluation === undefined) {
    throw new Error("Decoded Safe module transaction requires action and policy evaluations.");
  }
  alerts.push(createAlert(params, "SAFE_MODULE_TRANSACTION_EXECUTED", "Safe Module Transaction Executed",
    evaluation.compliant && knownModule && params.enabled.enabledAtExecution ? "INFO" : "WARNING",
    `Module ${moduleAddress} executed ${transaction.operation} to ${transaction.innerTarget} with selector ${transaction.innerSelector}.`, "execution"));
  if (!evaluation.targetAllowed) {
    alerts.push(createAlert(params, "SAFE_MODULE_UNKNOWN_TARGET", "Safe Module Prohibited Target", transaction.operation === "DELEGATECALL" ? "CRITICAL" : "WARNING",
      `Module execution target ${transaction.innerTarget} is not allowed by the intersected Safe/module policy.`, "target"));
  }
  if (!evaluation.selectorAllowed) {
    alerts.push(createAlert(params, "SAFE_MODULE_UNKNOWN_SELECTOR", "Safe Module Prohibited Selector", "WARNING",
      `Module execution selector ${transaction.innerSelector} is not allowed by the intersected Safe/module policy.`, "selector"));
  }
  if (transaction.operation === "DELEGATECALL") {
    alerts.push(createAlert(params, "SAFE_MODULE_DELEGATECALL", "Safe Module Delegatecall",
      evaluation.operationAllowed && evaluation.targetAllowed ? "WARNING" : "CRITICAL",
      `Module ${moduleAddress} executed DELEGATECALL to ${transaction.innerTarget}.`, "delegatecall"));
  }
  if (evaluation.implementationAllowed === false) {
    alerts.push(createAlert(params, "SAFE_MODULE_UNKNOWN_IMPLEMENTATION_UPGRADE", "Safe Module Unknown Implementation Upgrade", "CRITICAL",
      `Module execution references an implementation outside the intersected allowlists.`, "implementation"));
  }
  const extraViolations = [
    ...evaluation.violations,
    ...(params.enabled.enabledAtExecution ? [] : [{ kind: "module", scope: "safe", reason: "Module was not enabled in observed Safe state.", expected: true, observed: false }])
  ];
  if (extraViolations.length > 0) {
    const critical = extraViolations.some((violation) => violation.kind === "implementation" || violation.kind === "operation" || violation.reason.includes("not enabled"));
    alerts.push(createAlert(params, "SAFE_MODULE_POLICY_VIOLATION", "Safe Module Policy Violation", critical ? "CRITICAL" : "WARNING",
      `Module execution violates ${extraViolations.length} explicit Safe/module policy condition(s).`, "policy", { violations: extraViolations }));
  }
  return alerts;
}

function createAlert(
  params: Parameters<typeof createSafeModuleExecutionAlerts>[0],
  ruleId: string,
  ruleName: string,
  severity: AlertSeverity,
  summary: string,
  suffix: string,
  extraMetadata: Record<string, unknown> = {}
): Alert {
  const decoded = params.result.decoded ? params.result.moduleTransaction : undefined;
  const moduleAddress = decoded?.moduleAddress ?? (params.result.decoded ? undefined : params.result.moduleAddress);
  if (moduleAddress === undefined) throw new Error("Safe module alert is missing module address.");
  const transactionHash = decoded?.transaction.outerTransactionHash ?? (params.result.decoded ? "unknown" : params.result.outerTransactionHash);
  const blockNumber = decoded?.transaction.blockNumber ?? (params.result.decoded ? undefined : params.result.blockNumber);
  if (blockNumber === undefined) throw new Error("Safe module alert is missing block number.");
  const eventLogIndex = decoded?.eventLogIndex ?? (params.result.decoded ? undefined : params.result.eventLogIndex);
  const inner = decoded?.transaction;
  return {
    id: [params.chain, ruleId, params.safePolicy.address, moduleAddress, transactionHash,
      eventLogIndex ?? "unknown", inner?.innerTarget ?? "unknown", inner?.innerSelector ?? "0x", inner?.operation ?? "unknown", suffix].join(":"),
    chain: params.chain,
    ruleId,
    ruleName,
    severity,
    eventSignature: "Safe.execTransactionFromModule",
    blockNumber: blockNumber.toString(),
    transactionHash,
    ...(eventLogIndex === undefined ? {} : { logIndex: eventLogIndex }),
    address: params.safePolicy.address,
    topics: [],
    data: inner?.innerData ?? "0x",
    summary,
    metadata: {
      source: "safe-module-analysis",
      safeAddress: params.safePolicy.address,
      safeName: params.safePolicy.name,
      moduleAddress,
      moduleName: params.modulePolicy?.name ?? null,
      executionOutcome: params.outcome,
      enabledState: params.enabled,
      decodeStatus: params.result.decoded ? "decoded" : "undecoded",
      ...(params.result.decoded ? {
        entrypoint: params.result.moduleTransaction.entrypoint,
        outerTarget: params.result.moduleTransaction.outerTarget,
        ...(params.result.moduleTransaction.zodiacRoles === undefined
          ? {}
          : { zodiacRoles: params.result.moduleTransaction.zodiacRoles }),
        transaction: {
          target: inner?.innerTarget,
          valueWei: inner?.innerValue.toString(),
          data: inner?.innerData,
          selector: inner?.innerSelector,
          operation: inner?.operation
        },
        action: params.action,
        policy: {
          safe: params.safeEvaluation,
          module: params.moduleEvaluation ?? null,
          effective: params.effectiveEvaluation
        }
      } : {
        outerTarget: params.result.outerTarget,
        outerSelector: params.result.outerSelector,
        failureKind: params.result.failureKind,
        decodeError: params.result.error
      }),
      ...extraMetadata
    },
    createdAt: params.createdAt
  };
}
