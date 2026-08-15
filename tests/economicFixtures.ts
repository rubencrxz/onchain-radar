import { encodeAbiParameters, getAddress, type Address, type Hex } from "viem";
import type { RawLogForAlert } from "../src/alerts.js";
import type { MonitorConfig } from "../src/config.js";
import { ERC20_TRANSFER_TOPIC } from "../src/economic/transfers.js";
import type {
  AssetMovement,
  BalanceObservation,
  CriticalContractConfig,
  EconomicMonitoringConfig,
  MonitoredAssetConfig
} from "../src/economic/types.js";
import { emptyAllowlists } from "./fixtures.js";

export const ECON_TOKEN = getAddress("0x1000000000000000000000000000000000000001");
export const ECON_TOKEN_B = getAddress("0x1000000000000000000000000000000000000002");
export const ECON_VAULT = getAddress("0x2000000000000000000000000000000000000001");
export const ECON_VAULT_B = getAddress("0x2000000000000000000000000000000000000002");
export const ECON_USER_A = getAddress("0x3000000000000000000000000000000000000001");
export const ECON_USER_B = getAddress("0x3000000000000000000000000000000000000002");
export const ECON_USER_C = getAddress("0x3000000000000000000000000000000000000003");

export function economicAsset(overrides: Partial<MonitoredAssetConfig> = {}): MonitoredAssetConfig {
  return {
    name: "Synthetic Restaked Asset",
    tokenAddress: ECON_TOKEN,
    decimals: 0,
    criticalContracts: [{ name: "Synthetic Vault", address: ECON_VAULT, role: "vault" }],
    thresholds: {
      largeTransferAbsolute: 100n,
      singleBlockOutflowAbsolute: 500n,
      singleBlockOutflowPercent: 10,
      windowOutflowPercent: 20,
      concentrationPercent: 60,
      criticalOutflowPercent: 50,
      criticalDrawdownPercent: 50
    },
    windowBlocks: 20,
    ...overrides
  };
}

export function economicConfig(assets: MonitoredAssetConfig[] = [economicAsset()]): EconomicMonitoringConfig {
  return { assets };
}

export function monitorConfigWithEconomic(economicMonitoring?: EconomicMonitoringConfig): MonitorConfig {
  return {
    chain: "ethereum",
    monitoredAddresses: [],
    knownMultisigs: [],
    eventSignatures: ["PayloadExecuted(uint40)"],
    allowlists: emptyAllowlists(),
    ...(economicMonitoring === undefined ? {} : { economicMonitoring })
  };
}

export function transferLog(params: {
  token?: Address;
  from: Address;
  to: Address;
  value: bigint;
  blockNumber?: bigint;
  transactionOrdinal?: number;
  transactionIndex?: number;
  logIndex?: number;
}): RawLogForAlert {
  const blockNumber = params.blockNumber ?? 100n;
  const transactionOrdinal = params.transactionOrdinal ?? 1;
  const logIndex = params.logIndex ?? 0;
  return {
    blockNumber: toQuantityHex(blockNumber),
    transactionHash: `0x${transactionOrdinal.toString(16).padStart(64, "0")}` as Hex,
    ...(params.transactionIndex === undefined
      ? {}
      : { transactionIndex: toQuantityHex(BigInt(params.transactionIndex)) }),
    logIndex: toQuantityHex(BigInt(logIndex)),
    address: params.token ?? ECON_TOKEN,
    topics: [
      ERC20_TRANSFER_TOPIC,
      encodeAbiParameters([{ type: "address" }], [params.from]),
      encodeAbiParameters([{ type: "address" }], [params.to])
    ],
    data: encodeAbiParameters([{ type: "uint256" }], [params.value])
  };
}

export function movement(params: {
  from: Address;
  to: Address;
  value: bigint;
  blockNumber?: bigint;
  asset?: MonitoredAssetConfig;
  logIndex?: number;
}): AssetMovement {
  const asset = params.asset ?? economicAsset();
  const criticalAddresses = new Set(asset.criticalContracts.map((contract) => contract.address.toLowerCase()));
  const fromCritical = criticalAddresses.has(params.from.toLowerCase());
  const toCritical = criticalAddresses.has(params.to.toLowerCase());
  const direction =
    params.from === "0x0000000000000000000000000000000000000000"
      ? "mint"
      : params.to === "0x0000000000000000000000000000000000000000"
        ? "burn"
        : fromCritical && toCritical
          ? "critical-to-critical"
          : fromCritical
            ? "critical-outflow"
            : toCritical
              ? "critical-inflow"
              : "external-to-external";
  const log = transferLog({
    token: asset.tokenAddress,
    from: params.from,
    to: params.to,
    value: params.value,
    blockNumber: params.blockNumber,
    logIndex: params.logIndex
  });

  return {
    asset,
    tokenAddress: asset.tokenAddress,
    from: params.from,
    to: params.to,
    value: params.value,
    direction,
    blockNumber: params.blockNumber ?? 100n,
    transactionHash: log.transactionHash ?? "unknown",
    logIndex: params.logIndex ?? 0,
    topics: log.topics,
    data: log.data
  };
}

export function observation(params: {
  balance: bigint;
  blockNumber: bigint;
  asset?: MonitoredAssetConfig;
  criticalContract?: CriticalContractConfig;
}): BalanceObservation {
  const asset = params.asset ?? economicAsset();
  return {
    asset,
    criticalContract: params.criticalContract ?? asset.criticalContracts[0]!,
    blockNumber: params.blockNumber,
    balance: params.balance
  };
}

function toQuantityHex(value: bigint): Hex {
  return `0x${value.toString(16)}` as Hex;
}
