import type { Alert } from "./alerts.js";
import type { MonitorConfig, ProxySlotMonitorConfig } from "./config.js";
import { analyzeEconomicActivity } from "./economic/analyzer.js";
import { ERC20_TRANSFER_TOPIC } from "./economic/transfers.js";
import {
  createEip1967SlotChangeAlertFromValues,
  EIP1967_ADMIN_SLOT,
  EIP1967_IMPLEMENTATION_SLOT,
  type Eip1967SlotKind
} from "./eip1967.js";
import { buildEventTopicMap } from "./events.js";
import { deduplicateAlerts, processLogs, type ProcessorClock, type UnprocessedLog } from "./processor.js";
import { chunkBlockRange, type BlockRange } from "./ranges.js";
import type { RpcClient } from "./rpc.js";
import { refineAlertsSeverity } from "./severity.js";
import type { AlertSink } from "./sinks.js";
import {
  analyzeSafeTransactions,
  SAFE_EXECUTION_EVENT_SIGNATURES,
  SAFE_MONITORING_EVENT_SIGNATURES
} from "./safe/analyzer.js";
import { correlateMultiSendAdministrativeEffects } from "./safe/correlation.js";
import { refineSafeNativeEventAlerts } from "./safe/nativeEvents.js";

export type HistoricalScanResult = {
  alerts: Alert[];
  unprocessedLogs: UnprocessedLog[];
  detectedLogCount: number;
  eventAlertCount: number;
  slotAlertCount: number;
  economicTransferCount: number;
  economicAlertCount: number;
  safeTransactionCount: number;
  safeLeafOperationCount: number;
  safeAlertCount: number;
  safeCorrelationCount: number;
};

export type HistoricalScanHooks = {
  onChunkStart?: (range: BlockRange) => void;
  onStoragePhaseStart?: (proxyCount: number) => void;
  onStoragePhaseComplete?: (alertCount: number) => void;
  onEconomicPhaseStart?: (assetCount: number) => void;
  onEconomicPhaseComplete?: (movementCount: number, alertCount: number) => void;
  onSafePhaseStart?: (multisigCount: number) => void;
  onSafePhaseComplete?: (transactionCount: number, alertCount: number, correlationCount: number) => void;
  onUnprocessedLog?: (unprocessed: UnprocessedLog) => void;
};

export async function executeHistoricalScan(params: {
  rpc: RpcClient;
  config: MonitorConfig;
  startBlock: bigint;
  endBlock: bigint;
  maxBlockRange: bigint;
  clock: ProcessorClock;
  sinks: readonly AlertSink[];
  hooks?: HistoricalScanHooks;
}): Promise<HistoricalScanResult> {
  const topicMap = buildEventTopicMap(params.config.eventSignatures);
  const topics = [...topicMap.keys()];
  const ranges = chunkBlockRange(params.startBlock, params.endBlock, params.maxBlockRange);
  const eventAlerts: Alert[] = [];
  const unprocessedLogs: UnprocessedLog[] = [];
  const economicLogs: import("./alerts.js").RawLogForAlert[] = [];
  const safeExecutionLogs: import("./alerts.js").RawLogForAlert[] = [];
  const safeTopicMap = buildEventTopicMap([...SAFE_MONITORING_EVENT_SIGNATURES]);
  const safeTopics = [...safeTopicMap.keys()];
  const safeExecutionTopicMap = buildEventTopicMap([...SAFE_EXECUTION_EVENT_SIGNATURES]);
  const safeMonitoring = params.config.administrativeMonitoring;
  const safeEventsCoveredByMainQuery = safeMonitoring !== undefined &&
    SAFE_MONITORING_EVENT_SIGNATURES.every((signature) => params.config.eventSignatures.includes(signature)) &&
    safeMonitoring.multisigs.every((safe) =>
      params.config.monitoredAddresses.some((address) => address.toLowerCase() === safe.address.toLowerCase())
    );
  let detectedLogCount = 0;

  for (const range of ranges) {
    params.hooks?.onChunkStart?.(range);
    const logs = await params.rpc.getLogs({
      addresses: params.config.monitoredAddresses,
      topics,
      fromBlock: range.fromBlock,
      toBlock: range.toBlock
    });
    detectedLogCount += logs.length;

    const processed = processLogs({
      chain: params.config.chain,
      logs,
      topicMap,
      allowlists: params.config.allowlists,
      clock: params.clock
    });
    eventAlerts.push(...processed.alerts);
    unprocessedLogs.push(...processed.unprocessedLogs);

    if (safeMonitoring !== undefined) {
      const logsForSafeAnalysis = safeEventsCoveredByMainQuery
        ? logs.filter((log) =>
            safeMonitoring.multisigs.some((safe) => safe.address.toLowerCase() === log.address.toLowerCase()) &&
            log.topics[0] !== undefined && safeTopicMap.has(log.topics[0])
          )
        : await params.rpc.getLogs({
            addresses: safeMonitoring.multisigs.map((safe) => safe.address),
            topics: safeTopics,
            fromBlock: range.fromBlock,
            toBlock: range.toBlock
          });
      if (!safeEventsCoveredByMainQuery) detectedLogCount += logsForSafeAnalysis.length;
      safeExecutionLogs.push(...logsForSafeAnalysis.filter((log) =>
        log.topics[0] !== undefined && safeExecutionTopicMap.has(log.topics[0])
      ));
      const processedSafeEvents = processLogs({
        chain: params.config.chain,
        logs: logsForSafeAnalysis,
        topicMap: safeTopicMap,
        allowlists: params.config.allowlists,
        clock: params.clock
      });
      eventAlerts.push(...refineSafeNativeEventAlerts(processedSafeEvents.alerts, safeMonitoring));
      unprocessedLogs.push(...processedSafeEvents.unprocessedLogs);
    }

    if (params.config.economicMonitoring !== undefined) {
      const logsForEconomicAnalysis = await params.rpc.getLogs({
        addresses: params.config.economicMonitoring.assets.map((asset) => asset.tokenAddress),
        topics: [ERC20_TRANSFER_TOPIC],
        fromBlock: range.fromBlock,
        toBlock: range.toBlock
      });
      detectedLogCount += logsForEconomicAnalysis.length;
      economicLogs.push(...logsForEconomicAnalysis);
    }
  }

  const proxies =
    params.config.proxySlotMonitoring?.enabled === true ? params.config.proxySlotMonitoring.proxies : [];
  params.hooks?.onStoragePhaseStart?.(proxies.length);
  const slotAlerts = await readConfiguredProxySlotAlerts({
    rpc: params.rpc,
    proxies,
    startBlock: params.startBlock,
    endBlock: params.endBlock,
    chain: params.config.chain,
    clock: params.clock
  });
  params.hooks?.onStoragePhaseComplete?.(slotAlerts.length);

  const uniqueEventAlerts = deduplicateAlerts(
    safeMonitoring === undefined ? eventAlerts : refineSafeNativeEventAlerts(eventAlerts, safeMonitoring)
  );
  const refinedSlotAlerts = refineAlertsSeverity(slotAlerts, params.config.allowlists);
  params.hooks?.onSafePhaseStart?.(safeMonitoring?.multisigs.length ?? 0);
  const safeResult = safeMonitoring === undefined
    ? undefined
    : await analyzeSafeTransactions({
        rpc: params.rpc,
        chain: params.config.chain,
        config: safeMonitoring,
        executionLogs: safeExecutionLogs,
        administrativeAlerts: uniqueEventAlerts,
        slotAlerts: refinedSlotAlerts,
        clock: params.clock
      });
  params.hooks?.onSafePhaseComplete?.(
    safeResult?.reconstructedCount ?? 0,
    safeResult?.transactionAlerts.length ?? 0,
    safeResult?.correlationCount ?? 0
  );
  params.hooks?.onEconomicPhaseStart?.(params.config.economicMonitoring?.assets.length ?? 0);
  const economicResult =
    params.config.economicMonitoring === undefined
      ? undefined
      : await analyzeEconomicActivity({
          rpc: params.rpc,
          config: params.config.economicMonitoring,
          logs: economicLogs,
          startBlock: params.startBlock,
          endBlock: params.endBlock,
          clock: params.clock
        });
  params.hooks?.onEconomicPhaseComplete?.(
    economicResult?.movements.length ?? 0,
    economicResult?.alerts.length ?? 0
  );
  const safeEconomicCorrelations = safeResult === undefined || economicResult === undefined
    ? []
    : safeResult.multiSendContexts.flatMap((context) => correlateMultiSendAdministrativeEffects({
        chain: params.config.chain,
        transaction: context.transaction,
        operations: context.operations,
        administrativeAlerts: economicResult.alerts,
        slotAlerts: [],
        createdAt: params.clock()
      }));
  const alerts = deduplicateAlerts([
    ...uniqueEventAlerts,
    ...(safeResult?.outerTransactionAlerts ?? []),
    ...(safeResult?.multisendAlerts ?? []),
    ...refinedSlotAlerts,
    ...(safeResult?.correlationAlerts ?? []),
    ...safeEconomicCorrelations,
    ...(economicResult?.alerts ?? [])
  ]);
  const result: HistoricalScanResult = {
    alerts,
    unprocessedLogs,
    detectedLogCount,
    eventAlertCount: uniqueEventAlerts.length,
    slotAlertCount: refinedSlotAlerts.length,
    economicTransferCount: economicResult?.movements.length ?? 0,
    economicAlertCount: economicResult?.alerts.length ?? 0,
    safeTransactionCount: safeResult?.reconstructedCount ?? 0,
    safeLeafOperationCount: safeResult === undefined ? 0 : countSafeLeafOperations(safeResult),
    safeAlertCount: safeResult?.transactionAlerts.length ?? 0,
    safeCorrelationCount: (safeResult?.correlationCount ?? 0) + safeEconomicCorrelations.length
  };

  for (const unprocessed of unprocessedLogs) {
    params.hooks?.onUnprocessedLog?.(unprocessed);
  }

  for (const sink of params.sinks) {
    await sink.write(alerts);
  }

  return result;
}

function countSafeLeafOperations(result: Awaited<ReturnType<typeof analyzeSafeTransactions>>): number {
  const multiSendLeafCount = result.multiSendContexts.reduce((total, context) => {
    const paths = new Set(context.operations.map((operation) => operation.path));
    return total + context.operations.filter((operation) =>
      ![...paths].some((candidate) => candidate.startsWith(`${operation.path}.`))).length;
  }, 0);
  return result.reconstructedCount - result.multiSendContexts.length + multiSendLeafCount;
}

async function readConfiguredProxySlotAlerts(params: {
  rpc: RpcClient;
  proxies: readonly ProxySlotMonitorConfig[];
  startBlock: bigint;
  endBlock: bigint;
  chain: "ethereum";
  clock: ProcessorClock;
}): Promise<Alert[]> {
  const beforeBlock = params.startBlock === 0n ? 0n : params.startBlock - 1n;
  const alerts: Alert[] = [];

  for (const proxy of params.proxies) {
    if (proxy.checkImplementationSlot) {
      const alert = await readSlotChangeAlert({
        ...params,
        proxy,
        beforeBlock,
        slotKind: "implementation",
        slot: EIP1967_IMPLEMENTATION_SLOT
      });
      if (alert !== undefined) {
        alerts.push(alert);
      }
    }

    if (proxy.checkAdminSlot) {
      const alert = await readSlotChangeAlert({
        ...params,
        proxy,
        beforeBlock,
        slotKind: "admin",
        slot: EIP1967_ADMIN_SLOT
      });
      if (alert !== undefined) {
        alerts.push(alert);
      }
    }
  }

  return alerts;
}

async function readSlotChangeAlert(params: {
  rpc: RpcClient;
  proxy: ProxySlotMonitorConfig;
  beforeBlock: bigint;
  endBlock: bigint;
  chain: "ethereum";
  clock: ProcessorClock;
  slotKind: Eip1967SlotKind;
  slot: `0x${string}`;
}): Promise<Alert | undefined> {
  const beforeValue = await params.rpc.getStorageAt({
    address: params.proxy.address,
    slot: params.slot,
    blockNumber: params.beforeBlock
  });
  const afterValue = await params.rpc.getStorageAt({
    address: params.proxy.address,
    slot: params.slot,
    blockNumber: params.endBlock
  });

  return createEip1967SlotChangeAlertFromValues({
    chain: params.chain,
    proxy: params.proxy,
    slotKind: params.slotKind,
    slot: params.slot,
    beforeBlock: params.beforeBlock,
    afterBlock: params.endBlock,
    beforeValue,
    afterValue,
    createdAt: params.clock()
  });
}
