import { getAddress, isAddress, type Address } from "viem";
import type { Alert } from "../alerts.js";
import type { AnalyzedSafeSubOperation, ClassifiedSafeAction, SafeTransaction } from "./types.js";

const EFFECT_RULES = new Set([
  "PROXY_UPGRADED",
  "PROXY_IMPLEMENTATION_SLOT_CHANGED",
  "PROXY_ADMIN_CHANGED",
  "PROXY_ADMIN_SLOT_CHANGED",
  "OWNERSHIP_TRANSFERRED",
  "ROLE_GRANTED",
  "ROLE_REVOKED",
  "PAUSED",
  "UNPAUSED",
  "SAFE_OWNER_ADDED",
  "SAFE_OWNER_REMOVED",
  "SAFE_THRESHOLD_CHANGED",
  "SAFE_MODULE_ENABLED",
  "SAFE_MODULE_DISABLED",
  "SAFE_GUARD_CHANGED",
  "SAFE_FALLBACK_HANDLER_CHANGED",
  "LARGE_ASSET_TRANSFER"
]);

export function correlateSafeAdministrativeEffects(params: {
  chain: "ethereum";
  transaction: SafeTransaction;
  action: ClassifiedSafeAction;
  administrativeAlerts: readonly Alert[];
  slotAlerts: readonly Alert[];
  createdAt: string;
}): Alert[] {
  if (!params.action.known) return [];
  const action = params.action;
  if (action.semanticCategory === "ADMINISTRATIVE_CONTROL") {
    return [correlateNativeControlAction({ ...params, action })];
  }
  const expectedRules = expectedRuleIds(action.functionName);
  if (expectedRules.length === 0) return [];

  const eventEffects = params.administrativeAlerts.filter((alert) =>
    expectedRules.includes(alert.ruleId) &&
    alert.transactionHash.toLowerCase() === params.transaction.outerTransactionHash.toLowerCase() &&
    sameAddress(alert.address, action.effectTarget)
  );
  const slotEffects = params.slotAlerts.filter((alert) =>
    expectedRules.includes(alert.ruleId) &&
    alert.blockNumber === params.transaction.blockNumber.toString() &&
    sameAddress(alert.address, action.effectTarget)
  );
  const effects = [...eventEffects, ...slotEffects];
  if (effects.length === 0) return [];

  const comparisons = effects.map((alert) => compareEffect(action, alert));
  const divergences = comparisons.filter((comparison) => comparison.matches === false);
  const ruleId = divergences.length === 0
    ? "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED"
    : "SAFE_ADMINISTRATIVE_EFFECT_INCONSISTENCY";
  const severity = divergences.length === 0 ? "INFO" : "CRITICAL";
  const status = divergences.length === 0 ? "confirmed" : "inconsistent";

  return [{
    id: [params.chain, ruleId, params.transaction.safeAddress, params.transaction.outerTransactionHash, params.action.effectTarget, params.transaction.innerSelector].join(":"),
    chain: params.chain,
    ruleId,
    ruleName: divergences.length === 0 ? "Safe Administrative Effect Confirmed" : "Safe Administrative Effect Inconsistency",
    severity,
    eventSignature: "Safe.execTransaction+administrative-effects",
    blockNumber: params.transaction.blockNumber.toString(),
    transactionHash: params.transaction.outerTransactionHash,
    address: params.transaction.safeAddress,
    topics: [],
    data: params.transaction.innerData,
    summary: divergences.length === 0
      ? `Safe action ${params.action.functionSignature} is confirmed by ${effects.length} observable administrative effect(s).`
      : `Safe action ${params.action.functionSignature} diverges from ${divergences.length} observable administrative effect(s).`,
    metadata: {
      source: "safe-administrative-correlation",
      safeCorrelation: {
        status,
        safeAddress: params.transaction.safeAddress,
        target: params.action.effectTarget,
        intention: {
          function: params.action.functionSignature,
          parameters: params.action.parameters,
          expectedImplementation: params.action.expectedImplementation ?? null,
          expectedAdmin: params.action.expectedAdmin ?? null
        },
        componentAlertIds: effects.map((alert) => alert.id),
        componentRuleIds: effects.map((alert) => alert.ruleId),
        comparisons,
        divergences
      }
    },
    createdAt: params.createdAt
  }];
}

export function expectedRuleIds(functionName: string): string[] {
  if (["upgradeTo", "upgradeToAndCall", "upgrade", "upgradeAndCall"].includes(functionName)) {
    return ["PROXY_UPGRADED", "PROXY_IMPLEMENTATION_SLOT_CHANGED"];
  }
  if (["changeAdmin", "changeProxyAdmin"].includes(functionName)) return ["PROXY_ADMIN_CHANGED", "PROXY_ADMIN_SLOT_CHANGED"];
  if (functionName === "transferOwnership") return ["OWNERSHIP_TRANSFERRED"];
  if (functionName === "grantRole") return ["ROLE_GRANTED"];
  if (functionName === "revokeRole") return ["ROLE_REVOKED"];
  if (functionName === "pause") return ["PAUSED"];
  if (functionName === "unpause") return ["UNPAUSED"];
  if (functionName === "transfer") return ["LARGE_ASSET_TRANSFER"];
  if (functionName === "swapOwner") return ["SAFE_OWNER_REMOVED", "SAFE_OWNER_ADDED"];
  if (functionName === "addOwnerWithThreshold") return ["SAFE_OWNER_ADDED", "SAFE_THRESHOLD_CHANGED"];
  if (functionName === "removeOwner") return ["SAFE_OWNER_REMOVED", "SAFE_THRESHOLD_CHANGED"];
  if (functionName === "changeThreshold") return ["SAFE_THRESHOLD_CHANGED"];
  if (functionName === "enableModule") return ["SAFE_MODULE_ENABLED"];
  if (functionName === "disableModule") return ["SAFE_MODULE_DISABLED"];
  if (functionName === "setGuard") return ["SAFE_GUARD_CHANGED"];
  if (functionName === "setFallbackHandler") return ["SAFE_FALLBACK_HANDLER_CHANGED"];
  return [];
}

export function correlateMultiSendAdministrativeEffects(params: {
  chain: "ethereum";
  transaction: SafeTransaction;
  operations: readonly AnalyzedSafeSubOperation[];
  administrativeAlerts: readonly Alert[];
  slotAlerts: readonly Alert[];
  createdAt: string;
}): Alert[] {
  const candidates = params.operations.filter((operation) =>
    operation.action.known && expectedRuleIds(operation.action.functionName).length > 0
  );
  if (candidates.length === 0) return [];

  const effects = [...params.administrativeAlerts, ...params.slotAlerts].filter((alert) => EFFECT_RULES.has(alert.ruleId));
  const candidatePathsByEffect = new Map<string, string[]>();
  for (const effect of effects) {
    const exactPaths = candidates
      .filter((operation) => operationCouldExplainEffect(operation, effect, params.transaction))
      .map((operation) => operation.path);
    const paths = exactPaths.length > 0
      ? exactPaths
      : candidates
        .filter((operation) => operationSharesEffectScope(operation, effect, params.transaction))
        .map((operation) => operation.path);
    if (paths.length > 0) candidatePathsByEffect.set(effect.id, paths);
  }

  const ambiguousEffects = effects.filter((effect) => (candidatePathsByEffect.get(effect.id)?.length ?? 0) > 1);
  const alerts: Alert[] = [];
  if (ambiguousEffects.length > 0) {
    const candidatePaths = [...new Set(ambiguousEffects.flatMap((effect) => candidatePathsByEffect.get(effect.id) ?? []))].sort(comparePaths);
    alerts.push({
      id: [params.chain, "SAFE_ADMINISTRATIVE_EFFECT_AMBIGUOUS", params.transaction.safeAddress,
        params.transaction.outerTransactionHash, candidatePaths.join(".")].join(":"),
      chain: params.chain,
      ruleId: "SAFE_ADMINISTRATIVE_EFFECT_AMBIGUOUS",
      ruleName: "Safe Administrative Effect Attribution Ambiguous",
      severity: "WARNING",
      eventSignature: "Safe.execTransaction+MultiSend+administrative-effects",
      blockNumber: params.transaction.blockNumber.toString(),
      transactionHash: params.transaction.outerTransactionHash,
      address: params.transaction.safeAddress,
      topics: [],
      data: params.transaction.innerData,
      summary: `${ambiguousEffects.length} administrative effect(s) can be explained by more than one MultiSend suboperation; no unique attribution was asserted.`,
      metadata: {
        source: "safe-multisend-correlation",
        correlationStatus: "ambiguous",
        candidateSuboperations: candidatePaths,
        effects: ambiguousEffects.map((effect) => ({
          alertId: effect.id,
          ruleId: effect.ruleId,
          candidateSuboperations: candidatePathsByEffect.get(effect.id)
        }))
      },
      createdAt: params.createdAt
    });
  }

  const ambiguousIds = new Set(ambiguousEffects.map((effect) => effect.id));
  for (const operation of candidates) {
    if (!operation.action.known) continue;
    const applicableAdministrative = params.administrativeAlerts.filter((alert) =>
      !ambiguousIds.has(alert.id) && candidatePathsByEffect.get(alert.id)?.includes(operation.path)
    );
    const applicableSlots = params.slotAlerts.filter((alert) =>
      !ambiguousIds.has(alert.id) && candidatePathsByEffect.get(alert.id)?.includes(operation.path)
    );
    const syntheticTransaction = transactionForSuboperation(params.transaction, operation);
    const correlated = correlateSafeAdministrativeEffects({
      chain: params.chain,
      transaction: syntheticTransaction,
      action: operation.action,
      administrativeAlerts: applicableAdministrative,
      slotAlerts: applicableSlots,
      createdAt: params.createdAt
    });
    for (const alert of correlated) {
      const correlation = asRecord(alert.metadata.safeCorrelation) ?? {};
      alerts.push({
        ...alert,
        id: [params.chain, alert.ruleId, params.transaction.safeAddress, params.transaction.outerTransactionHash,
          operation.multiSendAddress, operation.path, operation.target, operation.selector, operation.operation].join(":"),
        eventSignature: "Safe.execTransaction+MultiSend+administrative-effects",
        data: operation.data,
        summary: `${alert.summary} Attributed to MultiSend suboperation ${operation.path}.`,
        metadata: {
          ...alert.metadata,
          source: "safe-multisend-correlation",
          correlationStatus: readCorrelationStatus(alert),
          candidateSuboperations: [operation.path],
          safeCorrelation: { ...correlation, suboperationPath: operation.path, suboperationIndex: operation.index }
        }
      });
    }
  }
  return alerts;
}

function operationCouldExplainEffect(
  operation: AnalyzedSafeSubOperation,
  alert: Alert,
  transaction: SafeTransaction
): boolean {
  if (!operationSharesEffectScope(operation, alert, transaction) || !operation.action.known) return false;
  const expected = expectedValue(operation.action, alert.ruleId);
  const observed = observedValue(alert);
  return expected === undefined || observed === undefined || normalizeComparable(expected) === normalizeComparable(observed);
}

function operationSharesEffectScope(
  operation: AnalyzedSafeSubOperation,
  alert: Alert,
  transaction: SafeTransaction
): boolean {
  if (!operation.action.known || !expectedRuleIds(operation.action.functionName).includes(alert.ruleId)) return false;
  if (!sameAddress(alert.address, operation.action.effectTarget)) return false;
  const isSlot = alert.ruleId === "PROXY_IMPLEMENTATION_SLOT_CHANGED" || alert.ruleId === "PROXY_ADMIN_SLOT_CHANGED";
  return isSlot
    ? alert.blockNumber === transaction.blockNumber.toString()
    : alert.transactionHash.toLowerCase() === transaction.outerTransactionHash.toLowerCase();
}

function transactionForSuboperation(transaction: SafeTransaction, operation: AnalyzedSafeSubOperation): SafeTransaction {
  return {
    ...transaction,
    innerTarget: operation.target,
    innerValue: operation.value,
    innerData: operation.data,
    innerSelector: operation.selector,
    operation: operation.operation
  };
}

function comparePaths(left: string, right: string): number {
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    if (a[index] === undefined) return -1;
    if (b[index] === undefined) return 1;
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  }
  return 0;
}

function compareEffect(action: Extract<ClassifiedSafeAction, { known: true }>, alert: Alert): Record<string, unknown> {
  const observed = observedValue(alert);
  const expected = expectedValue(action, alert.ruleId);
  return {
    alertId: alert.id,
    ruleId: alert.ruleId,
    expected: expected ?? null,
    observed: observed ?? null,
    matches: expected === undefined || observed === undefined ? true : normalizeComparable(expected) === normalizeComparable(observed)
  };
}

function expectedValue(action: Extract<ClassifiedSafeAction, { known: true }>, ruleId: string): unknown {
  if (ruleId === "PROXY_UPGRADED" || ruleId === "PROXY_IMPLEMENTATION_SLOT_CHANGED") return action.expectedImplementation;
  if (ruleId === "PROXY_ADMIN_CHANGED" || ruleId === "PROXY_ADMIN_SLOT_CHANGED") return action.expectedAdmin;
  if (ruleId === "OWNERSHIP_TRANSFERRED") return action.parameters.newOwner;
  if (ruleId === "ROLE_GRANTED" || ruleId === "ROLE_REVOKED") return `${String(action.parameters.role)}:${String(action.parameters.account)}`;
  if (ruleId === "LARGE_ASSET_TRANSFER") return `${String(action.parameters.to)}:${String(action.parameters.amount)}`;
  if (ruleId === "SAFE_OWNER_ADDED") return action.functionName === "swapOwner" ? action.parameters.newOwner : action.parameters.owner;
  if (ruleId === "SAFE_OWNER_REMOVED") return action.parameters.oldOwner ?? action.parameters.owner;
  if (ruleId === "SAFE_THRESHOLD_CHANGED") return action.parameters.threshold;
  if (ruleId === "SAFE_MODULE_ENABLED" || ruleId === "SAFE_MODULE_DISABLED") return action.parameters.module;
  if (ruleId === "SAFE_GUARD_CHANGED") return action.parameters.guard;
  if (ruleId === "SAFE_FALLBACK_HANDLER_CHANGED") return action.parameters.handler;
  return undefined;
}

function observedValue(alert: Alert): unknown {
  if (alert.ruleId === "PROXY_IMPLEMENTATION_SLOT_CHANGED" || alert.ruleId === "PROXY_ADMIN_SLOT_CHANGED") {
    const eip1967 = asRecord(alert.metadata.eip1967);
    return eip1967?.newAddress;
  }
  const decoded = asRecord(alert.metadata.decoded);
  if (alert.ruleId === "PROXY_UPGRADED") return decoded?.implementation;
  if (alert.ruleId === "PROXY_ADMIN_CHANGED") return decoded?.newAdmin;
  if (alert.ruleId === "OWNERSHIP_TRANSFERRED") return decoded?.newOwner;
  if (alert.ruleId === "ROLE_GRANTED" || alert.ruleId === "ROLE_REVOKED") return `${String(decoded?.role)}:${String(decoded?.account)}`;
  if (alert.ruleId === "LARGE_ASSET_TRANSFER") return `${String(alert.metadata.to)}:${String(alert.metadata.value)}`;
  if (alert.ruleId === "SAFE_OWNER_ADDED" || alert.ruleId === "SAFE_OWNER_REMOVED") return decoded?.owner;
  if (alert.ruleId === "SAFE_THRESHOLD_CHANGED") return decoded?.threshold;
  if (alert.ruleId === "SAFE_MODULE_ENABLED" || alert.ruleId === "SAFE_MODULE_DISABLED") return decoded?.module;
  if (alert.ruleId === "SAFE_GUARD_CHANGED") return decoded?.guard;
  if (alert.ruleId === "SAFE_FALLBACK_HANDLER_CHANGED") return decoded?.handler;
  return undefined;
}

function correlateNativeControlAction(params: {
  chain: "ethereum";
  transaction: SafeTransaction;
  action: Extract<ClassifiedSafeAction, { known: true }>;
  administrativeAlerts: readonly Alert[];
  slotAlerts: readonly Alert[];
  createdAt: string;
}): Alert {
  const expectations = nativeExpectations(params.action);
  const effects = params.administrativeAlerts.filter((alert) =>
    expectations.some((expectation) => expectation.ruleId === alert.ruleId) &&
    alert.transactionHash.toLowerCase() === params.transaction.outerTransactionHash.toLowerCase() &&
    sameAddress(alert.address, params.transaction.safeAddress)
  );
  const comparisons = expectations.map((expectation) => {
    const candidates = effects.filter((effect) => effect.ruleId === expectation.ruleId);
    const exact = candidates.filter((effect) => {
      const observed = observedValue(effect);
      return observed !== undefined && normalizeComparable(observed) === normalizeComparable(expectation.expected);
    });
    return {
      ruleId: expectation.ruleId,
      expected: expectation.expected,
      optional: expectation.optional,
      observed: candidates.map((effect) => observedValue(effect) ?? null),
      componentAlertIds: exact.map((effect) => effect.id),
      matches: exact.length === 1,
      ambiguous: exact.length > 1,
      missing: exact.length === 0 && candidates.length === 0
    };
  });
  const required = comparisons.filter((comparison) => !comparison.optional);
  const status = comparisons.some((comparison) => comparison.ambiguous)
    ? "ambiguous"
    : comparisons.some((comparison) => !comparison.matches && !comparison.missing)
      ? "inconsistent"
      : required.some((comparison) => comparison.missing)
        ? "unobserved"
        : "confirmed";
  const ruleId = status === "confirmed" ? "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED" :
    status === "ambiguous" ? "SAFE_ADMINISTRATIVE_EFFECT_AMBIGUOUS" :
    status === "inconsistent" ? "SAFE_ADMINISTRATIVE_EFFECT_INCONSISTENCY" :
    "SAFE_ADMINISTRATIVE_EFFECT_UNOBSERVED";
  const severity = status === "confirmed" ? "INFO" : status === "inconsistent" ? "CRITICAL" : "WARNING";
  return {
    id: [params.chain, ruleId, params.transaction.safeAddress, params.transaction.outerTransactionHash,
      params.action.effectTarget, params.transaction.innerSelector].join(":"),
    chain: params.chain,
    ruleId,
    ruleName: `Safe Administrative Effect ${status[0]!.toUpperCase()}${status.slice(1)}`,
    severity,
    eventSignature: "Safe.execTransaction+Safe-native-administrative-effects",
    blockNumber: params.transaction.blockNumber.toString(),
    transactionHash: params.transaction.outerTransactionHash,
    address: params.transaction.safeAddress,
    topics: [],
    data: params.transaction.innerData,
    summary: `Safe control action ${params.action.functionSignature} has correlation status ${status}.`,
    metadata: {
      source: "safe-native-administrative-correlation",
      correlationStatus: status,
      candidateSuboperations: [],
      safeCorrelation: {
        status,
        category: params.action.semanticCategory,
        safeAddress: params.transaction.safeAddress,
        target: params.action.effectTarget,
        intention: { function: params.action.functionSignature, parameters: params.action.parameters },
        eventsObserved: effects.map((effect) => ({ alertId: effect.id, ruleId: effect.ruleId, value: observedValue(effect) ?? null })),
        comparisons,
        stateBefore: null,
        stateAfter: null
      }
    },
    createdAt: params.createdAt
  };
}

function nativeExpectations(action: Extract<ClassifiedSafeAction, { known: true }>): Array<{
  ruleId: string;
  expected: unknown;
  optional: boolean;
}> {
  return expectedRuleIds(action.functionName).map((ruleId) => ({
    ruleId,
    expected: expectedValue(action, ruleId),
    optional: ruleId === "SAFE_THRESHOLD_CHANGED" && action.functionName !== "changeThreshold"
  }));
}

function normalizeComparable(value: unknown): string {
  if (typeof value === "string" && isAddress(value)) return getAddress(value).toLowerCase();
  return String(value).toLowerCase();
}

function sameAddress(left: string, right: Address): boolean {
  return isAddress(left) && getAddress(left).toLowerCase() === getAddress(right).toLowerCase();
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function readCorrelationStatus(alert: Alert): "confirmed" | "inconsistent" | "ambiguous" | "unobserved" {
  const direct = alert.metadata.correlationStatus;
  if (["confirmed", "inconsistent", "ambiguous", "unobserved"].includes(String(direct))) {
    return direct as "confirmed" | "inconsistent" | "ambiguous" | "unobserved";
  }
  const nested = asRecord(alert.metadata.safeCorrelation)?.status;
  return ["confirmed", "inconsistent", "ambiguous", "unobserved"].includes(String(nested))
    ? nested as "confirmed" | "inconsistent" | "ambiguous" | "unobserved"
    : "unobserved";
}
