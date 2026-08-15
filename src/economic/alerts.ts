import type { Alert, AlertSeverity } from "../alerts.js";
import type { AssetMovement, CriticalContractConfig, EconomicWindow, MonitoredAssetConfig } from "./types.js";

export function createMovementAlert(params: {
  ruleId: "LARGE_ASSET_TRANSFER" | "LARGE_TOKEN_MINT";
  ruleName: string;
  severity: AlertSeverity;
  severityReason: string;
  summary: string;
  movement: AssetMovement;
  threshold: Record<string, unknown>;
  observedValue: Record<string, unknown>;
  referenceValue: Record<string, unknown> | null;
  createdAt: string;
}): Alert {
  const movement = params.movement;
  return {
    id: [
      "ethereum",
      params.ruleId,
      movement.tokenAddress,
      movement.blockNumber.toString(),
      movement.transactionHash,
      movement.logIndex.toString()
    ].join(":"),
    chain: "ethereum",
    ruleId: params.ruleId,
    ruleName: params.ruleName,
    severity: params.severity,
    eventSignature: "Transfer(address,address,uint256)",
    blockNumber: movement.blockNumber.toString(),
    transactionHash: movement.transactionHash,
    logIndex: movement.logIndex,
    address: movement.tokenAddress,
    topics: [...movement.topics],
    data: movement.data,
    summary: params.summary,
    metadata: {
      source: "economic-transfer-analysis",
      asset: assetMetadata(movement.asset),
      direction: movement.direction,
      from: movement.from,
      to: movement.to,
      value: movement.value.toString(),
      severityReason: params.severityReason,
      threshold: params.threshold,
      observedValue: params.observedValue,
      referenceValue: params.referenceValue
    },
    createdAt: params.createdAt
  };
}

export function createAggregateEconomicAlert(params: {
  ruleId: string;
  ruleName: string;
  severity: AlertSeverity;
  severityReason: string;
  summary: string;
  asset: MonitoredAssetConfig;
  criticalContract: CriticalContractConfig;
  window: EconomicWindow;
  idParts?: readonly string[];
  eventSignature: string;
  threshold: Record<string, unknown>;
  observedValue: Record<string, unknown>;
  referenceValue: Record<string, unknown> | null;
  details?: Record<string, unknown>;
  createdAt: string;
}): Alert {
  return {
    id: [
      "ethereum",
      params.ruleId,
      params.asset.tokenAddress,
      params.criticalContract.address,
      params.window.fromBlock.toString(),
      params.window.toBlock.toString(),
      ...(params.idParts ?? [])
    ].join(":"),
    chain: "ethereum",
    ruleId: params.ruleId,
    ruleName: params.ruleName,
    severity: params.severity,
    eventSignature: params.eventSignature,
    blockNumber: params.window.toBlock.toString(),
    transactionHash: "economic-analysis",
    address: params.asset.tokenAddress,
    topics: [],
    data: "0x",
    summary: params.summary,
    metadata: {
      source: "economic-balance-analysis",
      asset: assetMetadata(params.asset),
      criticalContract: {
        name: params.criticalContract.name,
        address: params.criticalContract.address,
        role: params.criticalContract.role
      },
      window: {
        fromBlock: params.window.fromBlock.toString(),
        toBlock: params.window.toBlock.toString(),
        windowBlocks: params.window.windowBlocks
      },
      severityReason: params.severityReason,
      threshold: params.threshold,
      observedValue: params.observedValue,
      referenceValue: params.referenceValue,
      ...(params.details ?? {})
    },
    createdAt: params.createdAt
  };
}

export function formatAssetAmount(value: bigint, decimals: number): string {
  if (decimals === 0) {
    return value.toString();
  }

  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const fraction = (value % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction === "" ? whole.toString() : `${whole.toString()}.${fraction}`;
}

export function formatPercentage(numerator: bigint, denominator: bigint): string | null {
  if (denominator === 0n) {
    return null;
  }

  const hundredths = (numerator * 10_000n) / denominator;
  return `${(hundredths / 100n).toString()}.${(hundredths % 100n).toString().padStart(2, "0")}%`;
}

function assetMetadata(asset: MonitoredAssetConfig): Record<string, unknown> {
  return {
    name: asset.name,
    tokenAddress: asset.tokenAddress,
    decimals: asset.decimals
  };
}
