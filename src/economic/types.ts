import type { Address, Hex } from "viem";
import type { Alert } from "../alerts.js";

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

export type CriticalContractRole =
  | "vault"
  | "lending-pool"
  | "liquidity-pool"
  | "bridge"
  | "treasury"
  | "collateral"
  | "other";

export type CriticalContractConfig = {
  name: string;
  address: Address;
  role: CriticalContractRole;
};

export type EconomicThresholds = {
  largeTransferAbsolute: bigint;
  singleBlockOutflowAbsolute: bigint;
  singleBlockOutflowPercent: number;
  windowOutflowPercent: number;
  concentrationPercent: number;
  criticalOutflowPercent?: number;
  criticalDrawdownPercent?: number;
};

export type MonitoredAssetConfig = {
  name: string;
  tokenAddress: Address;
  decimals: number;
  criticalContracts: CriticalContractConfig[];
  thresholds: EconomicThresholds;
  windowBlocks: number;
};

export type EconomicMonitoringConfig = {
  assets: MonitoredAssetConfig[];
};

export type AssetMovementDirection =
  | "critical-inflow"
  | "critical-outflow"
  | "critical-to-critical"
  | "external-to-external"
  | "mint"
  | "burn";

export type AssetMovement = {
  asset: MonitoredAssetConfig;
  tokenAddress: Address;
  from: Address;
  to: Address;
  value: bigint;
  direction: AssetMovementDirection;
  blockNumber: bigint;
  transactionHash: Hex | "unknown";
  transactionIndex?: number;
  logIndex: number;
  topics: readonly Hex[];
  data: Hex;
};

export type BalanceObservation = {
  asset: MonitoredAssetConfig;
  criticalContract: CriticalContractConfig;
  blockNumber: bigint;
  balance: bigint;
};

export type EconomicWindow = {
  fromBlock: bigint;
  toBlock: bigint;
  windowBlocks: number;
};

export type EconomicSignalKind =
  | "large-transfer"
  | "critical-outflow"
  | "liquidity-drawdown"
  | "outflow-concentration"
  | "large-mint"
  | "correlated-anomaly";

export type EconomicAnomalyResult = {
  kind: EconomicSignalKind;
  asset: MonitoredAssetConfig;
  criticalContract?: CriticalContractConfig;
  window: EconomicWindow;
  alert: Alert;
  componentAlertIds?: readonly string[];
};

export type EconomicAnalysisResult = {
  movements: AssetMovement[];
  balanceObservations: BalanceObservation[];
  anomalies: EconomicAnomalyResult[];
  alerts: Alert[];
};
