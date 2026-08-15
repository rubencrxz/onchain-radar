import type { Address, Hex } from "viem";
import type { Alert, RawLogForAlert } from "../alerts.js";
import type { AdministrativeMonitoringConfig, AnalyzedSafeSubOperation, SafeDecodeResult, SafePolicyEvaluation, SafeTransaction } from "./types.js";
import type { RpcClient, RpcTransaction, RpcTransactionReceipt } from "../rpc.js";
import { buildEventTopicMap } from "../events.js";
import { deduplicateAlerts } from "../processor.js";
import { classifySafeAction } from "./actions.js";
import { createSafeMonitoringAlerts, createUndecodedSafeAlert, type SafeExecutionOutcome } from "./alerts.js";
import { correlateMultiSendAdministrativeEffects, correlateSafeAdministrativeEffects } from "./correlation.js";
import { decodeSafeExecTransaction, selectorOf } from "./decoder.js";
import { analyzeMultiSendTransaction } from "./multisend.js";
import { createMultiSendAlerts } from "./multisendAlerts.js";
import { SAFE_NATIVE_ADMIN_EVENT_SIGNATURES } from "./nativeEvents.js";
import { observeSafeActionState, type SafeStateObservation } from "./state.js";
import {
  decodeSafeModuleExecutionEvent,
  decodeSafeModuleTransaction,
  SAFE_MODULE_EXECUTION_EVENT_SIGNATURES
} from "./module.js";
import { createSafeModuleExecutionAlerts, type SafeModuleEnabledObservation } from "./moduleAlerts.js";
import { evaluateSafeModulePolicy, evaluateSafePolicy, intersectSafePolicyEvaluations } from "./policy.js";
import { decodeConfiguredZodiacRolesTransaction } from "./zodiacRoles.js";

export const SAFE_EXECUTION_EVENT_SIGNATURES = [
  "ExecutionSuccess(bytes32,uint256)",
  "ExecutionFailure(bytes32,uint256)",
  ...SAFE_MODULE_EXECUTION_EVENT_SIGNATURES
] as const;

export const SAFE_MONITORING_EVENT_SIGNATURES = [
  ...SAFE_EXECUTION_EVENT_SIGNATURES,
  ...SAFE_NATIVE_ADMIN_EVENT_SIGNATURES
] as const;

export type SafeAnalysisResult = {
  alerts: Alert[];
  outerTransactionAlerts: Alert[];
  multisendAlerts: Alert[];
  transactionAlerts: Alert[];
  correlationAlerts: Alert[];
  reconstructedCount: number;
  undecodedCount: number;
  correlationCount: number;
  multiSendContexts: Array<{ transaction: SafeTransaction; operations: AnalyzedSafeSubOperation[] }>;
  moduleExecutionCount: number;
};

export async function analyzeSafeTransactions(params: {
  rpc: RpcClient;
  chain: "ethereum";
  config: AdministrativeMonitoringConfig;
  executionLogs: readonly RawLogForAlert[];
  administrativeAlerts: readonly Alert[];
  slotAlerts: readonly Alert[];
  clock: () => string;
}): Promise<SafeAnalysisResult> {
  const policies = new Map(params.config.multisigs.map((safe) => [safe.address.toLowerCase(), safe]));
  const logs = uniqueExecutionLogs(params.executionLogs)
    .filter((log) => policies.has(log.address.toLowerCase()))
    .sort(compareLogs);
  const outerAlerts: Alert[] = [];
  const multisendAlerts: Alert[] = [];
  const correlations: Alert[] = [];
  let reconstructedCount = 0;
  let undecodedCount = 0;
  let moduleExecutionCount = 0;
  const multiSendContexts: Array<{ transaction: SafeTransaction; operations: AnalyzedSafeSubOperation[] }> = [];
  const moduleEventsPerTransaction = countModuleEventsByTransaction(logs);
  const moduleEventsPerTransactionAndModule = countModuleEventsByTransactionAndModule(logs);
  const seenModuleEvents = new Map<string, number>();

  for (const log of logs) {
    if (log.transactionHash === null || log.blockNumber === null) {
      throw new Error("Safe execution log is missing transactionHash or blockNumber.");
    }
    const policy = policies.get(log.address.toLowerCase());
    if (policy === undefined) continue;
    const transaction = await getTransaction(params.rpc, log.transactionHash);
    const receipt = await getReceipt(params.rpc, log.transactionHash);
    validateRpcTransactionPair(log, transaction, receipt);
    const moduleEvent = decodeSafeModuleExecutionEvent(log);
    if (moduleEvent !== undefined) {
      moduleExecutionCount += 1;
      const modulePolicy = policy.modulePolicies.find((candidate) => candidate.address.toLowerCase() === moduleEvent.moduleAddress.toLowerCase());
      const enabled = await observeExecutingModule(params.rpc, policy.address, moduleEvent.moduleAddress, transaction.blockNumber);
      const moduleKey = transactionModuleKey(log.transactionHash, moduleEvent.moduleAddress);
      const moduleEventIndex = seenModuleEvents.get(moduleKey) ?? 0;
      seenModuleEvents.set(moduleKey, moduleEventIndex + 1);
      const directModule = decodeSafeModuleTransaction({
        safeAddress: policy.address,
        moduleAddress: moduleEvent.moduleAddress,
        modulePolicy,
        transaction,
        eventLogIndex: log.logIndex === null || log.logIndex === undefined ? undefined : Number(BigInt(log.logIndex)),
        executionEventsInTransaction: moduleEventsPerTransaction.get(log.transactionHash.toLowerCase()) ?? 1
      });
      const decodedModule = directModule.decoded || modulePolicy?.adapter?.type !== "ZODIAC_ROLES_V2"
        ? directModule
        : decodeConfiguredZodiacRolesTransaction({
            safeAddress: policy.address,
            moduleAddress: moduleEvent.moduleAddress,
            modulePolicy,
            transaction,
            config: params.config,
            eventLogIndex: log.logIndex === null || log.logIndex === undefined
              ? undefined
              : Number(BigInt(log.logIndex)),
            moduleEventIndex,
            moduleEventsInTransaction: moduleEventsPerTransactionAndModule.get(moduleKey) ?? 1
          });
      if (!decodedModule.decoded) {
        undecodedCount += 1;
        outerAlerts.push(...createSafeModuleExecutionAlerts({
          chain: params.chain, safePolicy: policy, modulePolicy, result: decodedModule,
          enabled, outcome: moduleEvent.outcome, createdAt: params.clock()
        }));
        continue;
      }
      reconstructedCount += 1;
      const moduleTransaction = decodedModule.moduleTransaction.transaction;
      const action = classifySafeAction(moduleTransaction.innerTarget, moduleTransaction.innerData, moduleTransaction.innerValue);
      const safeEvaluation = evaluateSafePolicy(moduleTransaction, action, policy);
      const moduleEvaluation = modulePolicy === undefined ? undefined : evaluateSafeModulePolicy(moduleTransaction, action, modulePolicy);
      const intersectedEvaluation = moduleEvaluation === undefined
        ? withMissingModulePolicy(safeEvaluation, moduleEvent.moduleAddress, policy)
        : intersectSafePolicyEvaluations(safeEvaluation, moduleEvaluation);
      const effectiveEvaluation = withSafeModuleAllowance(intersectedEvaluation, moduleEvent.moduleAddress, policy);
      outerAlerts.push(...createSafeModuleExecutionAlerts({
        chain: params.chain, safePolicy: policy, modulePolicy, result: decodedModule, action,
        safeEvaluation, moduleEvaluation, effectiveEvaluation, enabled,
        outcome: moduleEvent.outcome, createdAt: params.clock()
      }));
      const expansion = analyzeMultiSendTransaction({ transaction: moduleTransaction, policy, config: params.config, modulePolicy });
      if (expansion.recognized) {
        multisendAlerts.push(...createMultiSendAlerts({
          chain: params.chain, policy, transaction: moduleTransaction, expansion,
          outcome: moduleEvent.outcome, createdAt: params.clock(),
          moduleContext: {
            address: moduleEvent.moduleAddress,
            ...(modulePolicy === undefined ? {} : { name: modulePolicy.name }),
            maxNativeValueWei: modulePolicy?.maxNativeValueWei ?? 0n,
            ...(decodedModule.moduleTransaction.zodiacRoles === undefined
              ? {}
              : { zodiacRoles: decodedModule.moduleTransaction.zodiacRoles })
          }
        }));
        if (expansion.complete) {
          multiSendContexts.push({ transaction: moduleTransaction, operations: expansion.operations });
          const moduleCorrelations = correlateMultiSendAdministrativeEffects({
            chain: params.chain, transaction: moduleTransaction, operations: expansion.operations,
            administrativeAlerts: params.administrativeAlerts, slotAlerts: params.slotAlerts, createdAt: params.clock()
          });
          correlations.push(...tagModuleCorrelations(
            await enrichMultiSendCorrelationsWithState(params.rpc, moduleTransaction, expansion.operations, moduleCorrelations),
            moduleEvent.moduleAddress,
            decodedModule.moduleTransaction.eventLogIndex,
            decodedModule.moduleTransaction.zodiacRoles
          ));
        }
      } else {
        const direct = correlateSafeAdministrativeEffects({
          chain: params.chain, transaction: moduleTransaction, action,
          administrativeAlerts: params.administrativeAlerts, slotAlerts: params.slotAlerts, createdAt: params.clock()
        });
        const state = await observeSafeActionState({ rpc: params.rpc, transaction: moduleTransaction, action });
        correlations.push(...tagModuleCorrelations(
          direct.map((alert) => attachStateObservation(alert, state)),
          moduleEvent.moduleAddress,
          decodedModule.moduleTransaction.eventLogIndex,
          decodedModule.moduleTransaction.zodiacRoles
        ));
      }
      continue;
    }
    const outcome = executionOutcome(log, receipt);
    const decoded = decodeOrDescribeUnsupportedEntrypoint(policy.address, transaction);

    if (!decoded.decoded) {
      undecodedCount += 1;
      outerAlerts.push(createUndecodedSafeAlert({
        chain: params.chain,
        policy,
        result: decoded,
        outcome,
        createdAt: params.clock()
      }));
      continue;
    }

    reconstructedCount += 1;
    const action = classifySafeAction(decoded.transaction.innerTarget, decoded.transaction.innerData, decoded.transaction.innerValue);
    const evaluation = evaluateSafePolicy(decoded.transaction, action, policy);
    const outerMonitoringAlerts = createSafeMonitoringAlerts({
      chain: params.chain,
      policy,
      transaction: decoded.transaction,
      action,
      evaluation,
      outcome,
      createdAt: params.clock()
    });
    const expansion = analyzeMultiSendTransaction({ transaction: decoded.transaction, policy, config: params.config });
    outerAlerts.push(...(expansion.recognized
      ? outerMonitoringAlerts.filter((alert) => alert.ruleId !== "SAFE_UNKNOWN_SELECTOR")
      : outerMonitoringAlerts));
    if (expansion.recognized) {
      multisendAlerts.push(...createMultiSendAlerts({
        chain: params.chain,
        policy,
        transaction: decoded.transaction,
        expansion,
        outcome,
        createdAt: params.clock()
      }));
      if (expansion.complete) {
        multiSendContexts.push({ transaction: decoded.transaction, operations: expansion.operations });
        const multiCorrelations = correlateMultiSendAdministrativeEffects({
          chain: params.chain,
          transaction: decoded.transaction,
          operations: expansion.operations,
          administrativeAlerts: params.administrativeAlerts,
          slotAlerts: params.slotAlerts,
          createdAt: params.clock()
        });
        correlations.push(...await enrichMultiSendCorrelationsWithState(
          params.rpc,
          decoded.transaction,
          expansion.operations,
          multiCorrelations
        ));
      }
    } else {
      const directCorrelations = correlateSafeAdministrativeEffects({
        chain: params.chain,
        transaction: decoded.transaction,
        action,
        administrativeAlerts: params.administrativeAlerts,
        slotAlerts: params.slotAlerts,
        createdAt: params.clock()
      });
      const state = await observeSafeActionState({ rpc: params.rpc, transaction: decoded.transaction, action });
      correlations.push(...directCorrelations.map((alert) => attachStateObservation(alert, state)));
    }
  }

  const deduplicatedOuter = deduplicateAlerts(outerAlerts);
  const deduplicatedMultiSend = deduplicateAlerts(multisendAlerts);
  return {
    alerts: deduplicateAlerts([...deduplicatedOuter, ...deduplicatedMultiSend, ...correlations]),
    outerTransactionAlerts: deduplicatedOuter,
    multisendAlerts: deduplicatedMultiSend,
    transactionAlerts: deduplicateAlerts([...deduplicatedOuter, ...deduplicatedMultiSend]),
    correlationAlerts: deduplicateAlerts(correlations),
    reconstructedCount,
    undecodedCount,
    correlationCount: correlations.length,
    multiSendContexts,
    moduleExecutionCount
  };
}

async function observeExecutingModule(
  rpc: RpcClient,
  safe: Address,
  module: Address,
  blockNumber: bigint
): Promise<SafeModuleEnabledObservation> {
  if (rpc.isSafeModuleEnabled === undefined) {
    throw new Error("RPC client does not implement isModuleEnabled required for Safe module execution analysis.");
  }
  const beforeBlock = blockNumber === 0n ? 0n : blockNumber - 1n;
  const enabledBefore = await rpc.isSafeModuleEnabled({ safe, module, blockNumber: beforeBlock });
  const enabledAfter = blockNumber === beforeBlock
    ? enabledBefore
    : await rpc.isSafeModuleEnabled({ safe, module, blockNumber });
  return {
    beforeBlock: beforeBlock.toString(),
    afterBlock: blockNumber.toString(),
    enabledBefore,
    enabledAfter,
    enabledAtExecution: enabledBefore || enabledAfter
  };
}

function withMissingModulePolicy(
  evaluation: SafePolicyEvaluation,
  moduleAddress: Address,
  policy: AdministrativeMonitoringConfig["multisigs"][number]
): SafePolicyEvaluation {
  return {
    ...evaluation,
    compliant: false,
    violations: [
      ...evaluation.violations.map((violation) => ({ ...violation, scope: "safe" as const })),
      {
        kind: "module",
        scope: "module",
        reason: "No module-specific policy is configured.",
        expected: policy.modulePolicies.map((module) => module.address),
        observed: moduleAddress
      }
    ]
  };
}

function withSafeModuleAllowance(
  evaluation: SafePolicyEvaluation,
  moduleAddress: Address,
  policy: AdministrativeMonitoringConfig["multisigs"][number]
): SafePolicyEvaluation {
  if (policy.allowedModules.some((module) => module.toLowerCase() === moduleAddress.toLowerCase())) return evaluation;
  return {
    ...evaluation,
    compliant: false,
    violations: [...evaluation.violations, {
      kind: "module",
      scope: "safe",
      reason: "Executing module is not in the Safe allowedModules policy.",
      expected: policy.allowedModules,
      observed: moduleAddress
    }]
  };
}

function tagModuleCorrelations(
  alerts: readonly Alert[],
  moduleAddress: Address,
  eventLogIndex?: number,
  zodiacRoles?: { roleKey: Hex; shouldRevert: boolean; wrapperPath: string; managerSafe?: Address }
): Alert[] {
  return alerts.map((alert) => ({
    ...alert,
    id: [alert.id, "module", moduleAddress, eventLogIndex ?? "unknown"].join(":"),
    eventSignature: `Safe.execTransactionFromModule+${alert.eventSignature}`,
    metadata: {
      ...alert.metadata,
      executionPath: "MODULE",
      moduleAddress,
      moduleExecutionLogIndex: eventLogIndex ?? null,
      ...(zodiacRoles === undefined ? {} : { zodiacRoles })
    }
  }));
}

function countModuleEventsByTransaction(logs: readonly RawLogForAlert[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const log of logs) {
    if (log.transactionHash === null || decodeSafeModuleExecutionEvent(log) === undefined) continue;
    const key = log.transactionHash.toLowerCase();
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function countModuleEventsByTransactionAndModule(logs: readonly RawLogForAlert[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const log of logs) {
    if (log.transactionHash === null) continue;
    const event = decodeSafeModuleExecutionEvent(log);
    if (event === undefined) continue;
    const key = transactionModuleKey(log.transactionHash, event.moduleAddress);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function transactionModuleKey(transactionHash: Hex, moduleAddress: Address): string {
  return `${transactionHash.toLowerCase()}:${moduleAddress.toLowerCase()}`;
}

async function enrichMultiSendCorrelationsWithState(
  rpc: RpcClient,
  transaction: SafeTransaction,
  operations: readonly AnalyzedSafeSubOperation[],
  alerts: readonly Alert[]
): Promise<Alert[]> {
  let enriched = [...alerts];
  for (const operation of operations) {
    if (!operation.action.known || operation.action.semanticCategory !== "ADMINISTRATIVE_CONTROL") continue;
    const synthetic: SafeTransaction = {
      ...transaction,
      innerTarget: operation.target,
      innerValue: operation.value,
      innerData: operation.data,
      innerSelector: operation.selector,
      operation: operation.operation
    };
    const state = await observeSafeActionState({ rpc, transaction: synthetic, action: operation.action });
    if (state === undefined) continue;
    enriched = enriched.map((alert) => correlationPath(alert) === operation.path ? attachStateObservation(alert, state) : alert);
  }
  return enriched;
}

function attachStateObservation(alert: Alert, state: SafeStateObservation | undefined): Alert {
  if (state === undefined) return alert;
  const safeCorrelation = asRecord(alert.metadata.safeCorrelation) ?? {};
  return {
    ...alert,
    metadata: {
      ...alert.metadata,
      safeCorrelation: {
        ...safeCorrelation,
        stateBefore: { blockNumber: state.beforeBlock, ...state.before },
        stateAfter: { blockNumber: state.afterBlock, ...state.after }
      }
    }
  };
}

function correlationPath(alert: Alert): string | undefined {
  const value = asRecord(alert.metadata.safeCorrelation)?.suboperationPath;
  return typeof value === "string" ? value : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function decodeOrDescribeUnsupportedEntrypoint(safeAddress: Address, transaction: RpcTransaction): SafeDecodeResult {
  if (transaction.to === null || transaction.to.toLowerCase() !== safeAddress.toLowerCase()) {
    return {
      decoded: false,
      safeAddress,
      outerTransactionHash: transaction.hash,
      blockNumber: transaction.blockNumber,
      failureKind: "UNSUPPORTED_OUTER_SELECTOR",
      outerSelector: selectorOf(transaction.input),
      error: `Execution event was emitted by the configured Safe, but the outer transaction target was ${transaction.to ?? "contract creation"}; module and nested entrypoints are not decoded in this increment.`
    };
  }
  return decodeSafeExecTransaction({ safeAddress, transaction });
}

async function getTransaction(rpc: RpcClient, transactionHash: Hex): Promise<RpcTransaction> {
  if (rpc.getTransaction === undefined) throw new Error("RPC client does not implement eth_getTransactionByHash required by administrativeMonitoring.");
  return rpc.getTransaction(transactionHash);
}

async function getReceipt(rpc: RpcClient, transactionHash: Hex): Promise<RpcTransactionReceipt> {
  if (rpc.getTransactionReceipt === undefined) throw new Error("RPC client does not implement eth_getTransactionReceipt required by administrativeMonitoring.");
  return rpc.getTransactionReceipt(transactionHash);
}

function validateRpcTransactionPair(log: RawLogForAlert, transaction: RpcTransaction, receipt: RpcTransactionReceipt): void {
  if (transaction.hash.toLowerCase() !== receipt.transactionHash.toLowerCase() ||
      transaction.hash.toLowerCase() !== log.transactionHash?.toLowerCase()) {
    throw new Error(`RPC transaction/receipt hash mismatch for ${transaction.hash}.`);
  }
  if (transaction.blockNumber !== receipt.blockNumber || transaction.blockNumber !== BigInt(log.blockNumber ?? "0x0")) {
    throw new Error(`RPC transaction/receipt block mismatch for ${transaction.hash}.`);
  }
}

function executionOutcome(log: RawLogForAlert, receipt: RpcTransactionReceipt): SafeExecutionOutcome {
  const topicMap = buildEventTopicMap([...SAFE_EXECUTION_EVENT_SIGNATURES]);
  const signature = log.topics[0] === undefined ? undefined : topicMap.get(log.topics[0]);
  if (signature === SAFE_EXECUTION_EVENT_SIGNATURES[0]) return "success";
  if (signature === SAFE_EXECUTION_EVENT_SIGNATURES[1]) return "failure";
  return receipt.status === "success" ? "unknown" : "failure";
}

function uniqueExecutionLogs(logs: readonly RawLogForAlert[]): RawLogForAlert[] {
  const seen = new Set<string>();
  return logs.filter((log) => {
    const moduleExecution = decodeSafeModuleExecutionEvent(log) !== undefined;
    const key = moduleExecution
      ? `${log.address.toLowerCase()}:${log.transactionHash ?? "unknown"}:${log.logIndex ?? "unknown"}`
      : `${log.address.toLowerCase()}:${log.transactionHash ?? "unknown"}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function compareLogs(left: RawLogForAlert, right: RawLogForAlert): number {
  return compareNullableHex(left.blockNumber, right.blockNumber) ||
    compareNullableHex(left.transactionIndex, right.transactionIndex) ||
    compareNullableHex(left.logIndex, right.logIndex);
}

function compareNullableHex(left: Hex | null | undefined, right: Hex | null | undefined): number {
  const a = left === null || left === undefined ? 0n : BigInt(left);
  const b = right === null || right === undefined ? 0n : BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}
