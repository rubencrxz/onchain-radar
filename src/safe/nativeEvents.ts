import { getAddress, isAddress, type Address } from "viem";
import type { Alert, AlertSeverity } from "../alerts.js";
import type { AdministrativeMonitoringConfig, SafeMultisigConfig } from "./types.js";

export const SAFE_NATIVE_ADMIN_EVENT_SIGNATURES = [
  "AddedOwner(address)",
  "RemovedOwner(address)",
  "ChangedThreshold(uint256)",
  "EnabledModule(address)",
  "DisabledModule(address)",
  "ChangedGuard(address)",
  "ChangedFallbackHandler(address)"
] as const;

export const SAFE_NATIVE_ADMIN_RULE_IDS = new Set([
  "SAFE_OWNER_ADDED",
  "SAFE_OWNER_REMOVED",
  "SAFE_THRESHOLD_CHANGED",
  "SAFE_MODULE_ENABLED",
  "SAFE_MODULE_DISABLED",
  "SAFE_GUARD_CHANGED",
  "SAFE_FALLBACK_HANDLER_CHANGED"
]);

export function refineSafeNativeEventAlerts(
  alerts: readonly Alert[],
  config: AdministrativeMonitoringConfig
): Alert[] {
  const policies = new Map(config.multisigs.map((policy) => [policy.address.toLowerCase(), policy]));
  return alerts.map((alert) => {
    if (!SAFE_NATIVE_ADMIN_RULE_IDS.has(alert.ruleId)) return alert;
    const policy = policies.get(alert.address.toLowerCase());
    if (policy === undefined) return alert;
    const evaluation = evaluateNativeEvent(alert, policy);
    return {
      ...alert,
      severity: evaluation.severity,
      metadata: {
        ...alert.metadata,
        safeNativeEvent: {
          semanticCategory: "ADMINISTRATIVE_CONTROL",
          safeAddress: policy.address,
          safeName: policy.name,
          criticality: policy.criticality,
          severityReason: evaluation.severityReason,
          observedValue: evaluation.observedValue,
          expectedPolicy: evaluation.expectedPolicy,
          policyMatched: evaluation.policyMatched
        }
      }
    };
  });
}

type NativeEventEvaluation = {
  severity: AlertSeverity;
  severityReason: string;
  observedValue: unknown;
  expectedPolicy: unknown;
  policyMatched: boolean;
};

function evaluateNativeEvent(alert: Alert, policy: SafeMultisigConfig): NativeEventEvaluation {
  const decoded = asRecord(alert.metadata.decoded);
  if (alert.ruleId === "SAFE_OWNER_ADDED" || alert.ruleId === "SAFE_OWNER_REMOVED") {
    return addressEvaluation(decoded?.owner, policy.allowedOwners, "owner", policy, false);
  }
  if (alert.ruleId === "SAFE_MODULE_ENABLED" || alert.ruleId === "SAFE_MODULE_DISABLED") {
    return addressEvaluation(
      decoded?.module,
      policy.allowedModules,
      "module",
      policy,
      alert.ruleId === "SAFE_MODULE_ENABLED"
    );
  }
  if (alert.ruleId === "SAFE_GUARD_CHANGED") {
    return addressEvaluation(decoded?.guard, policy.allowedGuards, "guard", policy, true);
  }
  if (alert.ruleId === "SAFE_FALLBACK_HANDLER_CHANGED") {
    return addressEvaluation(decoded?.handler, policy.allowedFallbackHandlers, "fallback handler", policy, true);
  }
  const observedText = decoded?.threshold;
  const threshold = typeof observedText === "string" && /^\d+$/.test(observedText) ? Number(observedText) : undefined;
  const expectedPolicy = {
    minimumThreshold: policy.minimumThreshold ?? null,
    allowedThresholds: policy.allowedThresholds
  };
  if (threshold === undefined || !Number.isSafeInteger(threshold)) {
    return {
      severity: "WARNING",
      severityReason: "Threshold event could not be evaluated against policy.",
      observedValue: observedText ?? null,
      expectedPolicy,
      policyMatched: false
    };
  }
  if (policy.minimumThreshold !== undefined && threshold < policy.minimumThreshold) {
    return {
      severity: "CRITICAL",
      severityReason: `Observed threshold ${threshold} is below configured minimum ${policy.minimumThreshold}.`,
      observedValue: threshold,
      expectedPolicy,
      policyMatched: false
    };
  }
  const matched = policy.allowedThresholds.includes(threshold);
  return {
    severity: matched ? "INFO" : "WARNING",
    severityReason: matched
      ? `Observed threshold ${threshold} is explicitly allowlisted.`
      : `Observed threshold ${threshold} is not in allowedThresholds.`,
    observedValue: threshold,
    expectedPolicy,
    policyMatched: matched
  };
}

function addressEvaluation(
  observed: unknown,
  allowed: readonly Address[],
  label: string,
  policy: SafeMultisigConfig,
  criticalWhenUnknown: boolean
): NativeEventEvaluation {
  const expectedPolicy = allowed;
  const normalized = typeof observed === "string" && isAddress(observed) ? getAddress(observed) : undefined;
  const matched = normalized !== undefined && allowed.some((address) => address.toLowerCase() === normalized.toLowerCase());
  const critical = !matched && criticalWhenUnknown && policy.criticality === "critical";
  return {
    severity: matched ? "INFO" : critical ? "CRITICAL" : "WARNING",
    severityReason: matched
      ? `Observed ${label} is explicitly allowlisted.`
      : normalized === undefined
        ? `Observed ${label} could not be decoded for policy evaluation.`
        : `Observed ${label} ${normalized} is not allowlisted${critical ? " for a critical Safe" : ""}.`,
    observedValue: normalized ?? observed ?? null,
    expectedPolicy,
    policyMatched: matched
  };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}
