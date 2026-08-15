import type { SafeModulePolicyConfig, SafeMultisigConfig, SafePolicyEvaluation, SafePolicyViolation, SafeTransaction, ClassifiedSafeAction } from "./types.js";

export function evaluateSafePolicy(
  transaction: SafeTransaction,
  action: ClassifiedSafeAction,
  policy: SafeMultisigConfig
): SafePolicyEvaluation {
  const targetAllowed = includesAddress(policy.allowedTargets, transaction.innerTarget);
  const selectorAllowed = policy.allowedSelectors.some((selector) => selector.toLowerCase() === transaction.innerSelector.toLowerCase());
  const operationAllowed = policy.allowedOperations.includes(transaction.operation);
  const nativeValueAllowed = transaction.innerValue <= policy.maxNativeValueWei;
  const implementationAllowed = action.known && action.expectedImplementation !== undefined
    ? includesAddress(policy.allowedImplementations, action.expectedImplementation)
    : undefined;
  const violations: SafePolicyViolation[] = [];

  if (!targetAllowed) violations.push({ kind: "target", reason: "Inner target is not in allowedTargets.", expected: policy.allowedTargets, observed: transaction.innerTarget });
  if (!selectorAllowed) violations.push({ kind: "selector", reason: "Inner selector is not in allowedSelectors.", expected: policy.allowedSelectors, observed: transaction.innerSelector });
  if (!operationAllowed) violations.push({ kind: "operation", reason: "Safe operation is not in allowedOperations.", expected: policy.allowedOperations, observed: transaction.operation });
  if (!nativeValueAllowed) violations.push({ kind: "native-value", reason: "Native value exceeds maxNativeValueWei.", expected: policy.maxNativeValueWei.toString(), observed: transaction.innerValue.toString() });
  if (implementationAllowed === false) violations.push({ kind: "implementation", reason: "Decoded implementation is not in allowedImplementations.", expected: policy.allowedImplementations, observed: action.known ? action.expectedImplementation : undefined });
  if (action.known) evaluateAdministrativeControlPolicy(action, policy, violations);

  return {
    compliant: violations.length === 0,
    targetAllowed,
    selectorAllowed,
    operationAllowed,
    ...(implementationAllowed === undefined ? {} : { implementationAllowed }),
    nativeValueAllowed,
    violations
  };
}

export function evaluateSafeModulePolicy(
  transaction: SafeTransaction,
  action: ClassifiedSafeAction,
  policy: SafeModulePolicyConfig
): SafePolicyEvaluation {
  const targetAllowed = includesAddress(policy.allowedTargets, transaction.innerTarget);
  const selectorAllowed = policy.allowedSelectors.some((selector) => selector.toLowerCase() === transaction.innerSelector.toLowerCase());
  const operationAllowed = policy.allowedOperations.includes(transaction.operation);
  const nativeValueAllowed = transaction.innerValue <= policy.maxNativeValueWei;
  const implementationAllowed = action.known && action.expectedImplementation !== undefined
    ? includesAddress(policy.allowedImplementations, action.expectedImplementation)
    : undefined;
  const violations: SafePolicyViolation[] = [];
  if (!targetAllowed) violations.push(moduleViolation("target", "Target is not allowed by module policy.", policy.allowedTargets, transaction.innerTarget));
  if (!selectorAllowed) violations.push(moduleViolation("selector", "Selector is not allowed by module policy.", policy.allowedSelectors, transaction.innerSelector));
  if (!operationAllowed) violations.push(moduleViolation("operation", "Operation is not allowed by module policy.", policy.allowedOperations, transaction.operation));
  if (!nativeValueAllowed) violations.push(moduleViolation("native-value", "Native value exceeds module maxNativeValueWei.", policy.maxNativeValueWei.toString(), transaction.innerValue.toString()));
  if (implementationAllowed === false) {
    violations.push(moduleViolation("implementation", "Implementation is not allowed by module policy.", policy.allowedImplementations, action.known ? action.expectedImplementation : undefined));
  }
  return {
    compliant: violations.length === 0,
    targetAllowed,
    selectorAllowed,
    operationAllowed,
    ...(implementationAllowed === undefined ? {} : { implementationAllowed }),
    nativeValueAllowed,
    violations
  };
}

export function intersectSafePolicyEvaluations(
  safeEvaluation: SafePolicyEvaluation,
  moduleEvaluation: SafePolicyEvaluation
): SafePolicyEvaluation {
  const safeViolations = safeEvaluation.violations.map((violation) => ({ ...violation, scope: violation.scope ?? "safe" as const }));
  const implementationAllowed = safeEvaluation.implementationAllowed === undefined && moduleEvaluation.implementationAllowed === undefined
    ? undefined
    : safeEvaluation.implementationAllowed !== false && moduleEvaluation.implementationAllowed !== false;
  return {
    compliant: safeEvaluation.compliant && moduleEvaluation.compliant,
    targetAllowed: safeEvaluation.targetAllowed && moduleEvaluation.targetAllowed,
    selectorAllowed: safeEvaluation.selectorAllowed && moduleEvaluation.selectorAllowed,
    operationAllowed: safeEvaluation.operationAllowed && moduleEvaluation.operationAllowed,
    ...(implementationAllowed === undefined ? {} : { implementationAllowed }),
    nativeValueAllowed: safeEvaluation.nativeValueAllowed && moduleEvaluation.nativeValueAllowed,
    violations: [...safeViolations, ...moduleEvaluation.violations]
  };
}

function moduleViolation(
  kind: SafePolicyViolation["kind"],
  reason: string,
  expected: unknown,
  observed: unknown
): SafePolicyViolation {
  return { kind, reason, expected, observed, scope: "module" };
}

function evaluateAdministrativeControlPolicy(
  action: Extract<ClassifiedSafeAction, { known: true }>,
  policy: SafeMultisigConfig,
  violations: SafePolicyViolation[]
): void {
  const name = action.functionName;
  const owner = name === "addOwnerWithThreshold" ? action.parameters.owner :
    name === "swapOwner" ? action.parameters.newOwner : undefined;
  if (typeof owner === "string" && policy.allowedOwners.length > 0 && !includesAddress(policy.allowedOwners, owner)) {
    violations.push({ kind: "owner", reason: "Resulting Safe owner is not in allowedOwners.", expected: policy.allowedOwners, observed: owner });
  }
  const threshold = readPositiveInteger(action.parameters.threshold);
  if (threshold !== undefined) {
    if (policy.minimumThreshold !== undefined && threshold < policy.minimumThreshold) {
      violations.push({ kind: "threshold", reason: "Resulting threshold is below minimumThreshold.", expected: policy.minimumThreshold, observed: threshold });
    } else if (policy.allowedThresholds.length > 0 && !policy.allowedThresholds.includes(threshold)) {
      violations.push({ kind: "threshold", reason: "Resulting threshold is not in allowedThresholds.", expected: policy.allowedThresholds, observed: threshold });
    }
  }
  const addressPolicies: Array<[string, unknown, readonly string[], SafePolicyViolation["kind"]]> = [
    ["enableModule", action.parameters.module, policy.allowedModules, "module"],
    ["setGuard", action.parameters.guard, policy.allowedGuards, "guard"],
    ["setFallbackHandler", action.parameters.handler, policy.allowedFallbackHandlers, "fallback-handler"]
  ];
  for (const [functionName, observed, allowed, kind] of addressPolicies) {
    if (name === functionName && typeof observed === "string" && !includesAddress(allowed, observed)) {
      violations.push({ kind, reason: `Decoded ${kind} is not allowlisted.`, expected: allowed, observed });
    }
  }
}

function readPositiveInteger(value: unknown): number | undefined {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function includesAddress(values: readonly string[], candidate: string): boolean {
  return values.some((value) => value.toLowerCase() === candidate.toLowerCase());
}
