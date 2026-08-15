import { decodeAbiParameters, getAddress, keccak256, stringToHex, type Address, type Hex } from "viem";
import type { RawLogForAlert } from "../alerts.js";
import {
  ZERO_ADDRESS,
  type AssetMovement,
  type AssetMovementDirection,
  type EconomicMonitoringConfig,
  type MonitoredAssetConfig
} from "./types.js";

export const ERC20_TRANSFER_SIGNATURE = "Transfer(address,address,uint256)";
export const ERC20_TRANSFER_TOPIC = keccak256(stringToHex(ERC20_TRANSFER_SIGNATURE));

export class EconomicTransferDecodeError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "EconomicTransferDecodeError";
  }
}

export function extractAssetMovements(
  logs: readonly RawLogForAlert[],
  config: EconomicMonitoringConfig
): AssetMovement[] {
  const assetsByToken = new Map(config.assets.map((asset) => [asset.tokenAddress.toLowerCase(), asset]));
  const movements: AssetMovement[] = [];

  for (const log of logs) {
    const asset = assetsByToken.get(log.address.toLowerCase());
    if (asset === undefined || log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC.toLowerCase()) {
      continue;
    }

    movements.push(decodeTransfer(log, asset));
  }

  const ordered = movements.sort(compareMovements);
  const seen = new Set<string>();

  return ordered.filter((movement) => {
    const key = [
      movement.tokenAddress.toLowerCase(),
      movement.blockNumber.toString(),
      movement.transactionHash.toLowerCase(),
      movement.logIndex.toString()
    ].join(":");
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function decodeTransfer(log: RawLogForAlert, asset: MonitoredAssetConfig): AssetMovement {
  if (log.blockNumber === null) {
    throw new EconomicTransferDecodeError(`Configured token ${asset.tokenAddress} returned a Transfer without blockNumber.`);
  }

  if (log.topics.length !== 3 || log.topics[1] === undefined || log.topics[2] === undefined) {
    throw new EconomicTransferDecodeError(
      `Malformed Transfer for configured token ${asset.tokenAddress} at block ${BigInt(log.blockNumber).toString()}: expected 3 topics.`
    );
  }

  try {
    const from = topicToAddress(log.topics[1]);
    const to = topicToAddress(log.topics[2]);
    const [value] = decodeAbiParameters([{ type: "uint256" }], log.data);
    const transactionIndex = parseOptionalIndex(log.transactionIndex, "transaction index");
    const logIndex = log.logIndex === undefined || log.logIndex === null ? 0 : Number(BigInt(log.logIndex));

    if (!Number.isSafeInteger(logIndex) || logIndex < 0) {
      throw new Error("invalid log index");
    }

    return {
      asset,
      tokenAddress: getAddress(log.address),
      from,
      to,
      value,
      direction: classifyDirection(from, to, asset),
      blockNumber: BigInt(log.blockNumber),
      transactionHash: log.transactionHash ?? "unknown",
      ...(transactionIndex === undefined ? {} : { transactionIndex }),
      logIndex,
      topics: [...log.topics],
      data: log.data
    };
  } catch (error: unknown) {
    throw new EconomicTransferDecodeError(
      `Malformed Transfer for configured token ${asset.tokenAddress} at block ${BigInt(log.blockNumber).toString()}.`,
      { cause: error }
    );
  }
}

function topicToAddress(topic: Hex): Address {
  if (!/^0x[0-9a-fA-F]{64}$/.test(topic)) {
    throw new Error("invalid indexed address topic");
  }

  return getAddress(`0x${topic.slice(-40)}`);
}

function classifyDirection(from: Address, to: Address, asset: MonitoredAssetConfig): AssetMovementDirection {
  if (sameAddress(from, ZERO_ADDRESS)) {
    return "mint";
  }

  if (sameAddress(to, ZERO_ADDRESS)) {
    return "burn";
  }

  const fromCritical = asset.criticalContracts.some((contract) => sameAddress(contract.address, from));
  const toCritical = asset.criticalContracts.some((contract) => sameAddress(contract.address, to));

  if (fromCritical && toCritical) {
    return "critical-to-critical";
  }

  if (fromCritical) {
    return "critical-outflow";
  }

  if (toCritical) {
    return "critical-inflow";
  }

  return "external-to-external";
}

function compareMovements(left: AssetMovement, right: AssetMovement): number {
  if (left.blockNumber !== right.blockNumber) {
    return left.blockNumber < right.blockNumber ? -1 : 1;
  }

  const transactionComparison = compareTransactionPosition(left, right);
  if (transactionComparison !== 0) {
    return transactionComparison;
  }

  return left.logIndex - right.logIndex;
}

function compareTransactionPosition(left: AssetMovement, right: AssetMovement): number {
  if (
    left.transactionIndex !== undefined &&
    right.transactionIndex !== undefined &&
    left.transactionIndex !== right.transactionIndex
  ) {
    return left.transactionIndex - right.transactionIndex;
  }

  return compareStrings(left.transactionHash, right.transactionHash);
}

function parseOptionalIndex(value: Hex | null | undefined, name: string): number | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  const parsed = Number(BigInt(value));
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`invalid ${name}`);
  }

  return parsed;
}

function sameAddress(left: Address, right: Address): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
