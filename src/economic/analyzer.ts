import type { RawLogForAlert } from "../alerts.js";
import { deduplicateAlerts, type ProcessorClock } from "../processor.js";
import type { RpcClient } from "../rpc.js";
import { observeEconomicBalances } from "./balances.js";
import { runEconomicDetectors } from "./detectors.js";
import { extractAssetMovements } from "./transfers.js";
import type { EconomicAnalysisResult, EconomicMonitoringConfig } from "./types.js";

export async function analyzeEconomicActivity(params: {
  rpc: RpcClient;
  config: EconomicMonitoringConfig;
  logs: readonly RawLogForAlert[];
  startBlock: bigint;
  endBlock: bigint;
  clock: ProcessorClock;
}): Promise<EconomicAnalysisResult> {
  const movements = extractAssetMovements(params.logs, params.config);
  const balanceObservations = await observeEconomicBalances({
    rpc: params.rpc,
    config: params.config,
    movements,
    startBlock: params.startBlock,
    endBlock: params.endBlock
  });
  const anomalies = runEconomicDetectors({
    config: params.config,
    movements,
    observations: balanceObservations,
    startBlock: params.startBlock,
    endBlock: params.endBlock,
    clock: params.clock
  });

  return {
    movements,
    balanceObservations,
    anomalies,
    alerts: deduplicateAlerts(anomalies.map((anomaly) => anomaly.alert))
  };
}
