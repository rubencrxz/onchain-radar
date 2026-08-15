import type { Address, Hex } from "viem";
import { decodeConfiguredEventLog } from "./decoders.js";
import type { RuleDefinition } from "./rules.js";

export type AlertSeverity = "INFO" | "WARNING" | "CRITICAL";

export type Alert = {
  id: string;
  chain: "ethereum";
  ruleId: string;
  ruleName: string;
  severity: AlertSeverity;
  eventSignature: string;
  blockNumber: string;
  transactionHash: string;
  logIndex?: number;
  address: string;
  topics: string[];
  data: string;
  summary: string;
  metadata: Record<string, unknown>;
  createdAt: string;
};

export type RawLogForAlert = {
  blockNumber: Hex | null;
  transactionHash: Hex | null;
  transactionIndex?: Hex | null;
  logIndex?: Hex | null;
  address: Address;
  topics: readonly Hex[];
  data: Hex;
};

export function createAlertFromLog(params: {
  chain: "ethereum";
  log: RawLogForAlert;
  eventSignature: string;
  rule: RuleDefinition;
  createdAt?: string;
}): Alert {
  const blockNumber = formatBlockNumberForJson(params.log.blockNumber);
  const transactionHash = params.log.transactionHash ?? "unknown";
  const logIndex = formatLogIndex(params.log.logIndex);
  const decodeResult = decodeConfiguredEventLog(params.eventSignature, params.log);
  const decodedMetadata =
    decodeResult.decoded === undefined
      ? { decodeError: decodeResult.decodeError }
      : {
          decoded: decodeResult.decoded
        };

  return {
    id: buildAlertId({
      chain: params.chain,
      ruleId: params.rule.ruleId,
      blockNumber,
      transactionHash,
      logIndex
    }),
    chain: params.chain,
    ruleId: params.rule.ruleId,
    ruleName: params.rule.ruleName,
    severity: params.rule.defaultSeverity,
    eventSignature: params.eventSignature,
    blockNumber,
    transactionHash,
    ...(logIndex === undefined ? {} : { logIndex }),
    address: params.log.address,
    topics: [...params.log.topics],
    data: params.log.data,
    summary: params.rule.summary(params.log.address, decodeResult.decoded),
    metadata: {
      source: "eth_getLogs",
      blockNumberHex: params.log.blockNumber,
      logIndexHex: params.log.logIndex ?? null,
      rawTopics: [...params.log.topics],
      rawData: params.log.data,
      ...decodedMetadata
    },
    createdAt: params.createdAt ?? new Date().toISOString()
  };
}

export function buildAlertId(params: {
  chain: "ethereum";
  ruleId: string;
  blockNumber: string;
  transactionHash: string;
  logIndex?: number;
}): string {
  return [params.chain, params.ruleId, params.blockNumber, params.transactionHash, params.logIndex ?? "unknown"].join(":");
}

function formatBlockNumberForJson(blockNumber: Hex | null): string {
  if (blockNumber === null) {
    return "unknown";
  }

  return BigInt(blockNumber).toString();
}

function formatLogIndex(logIndex: Hex | null | undefined): number | undefined {
  if (logIndex === null || logIndex === undefined) {
    return undefined;
  }

  return Number(BigInt(logIndex));
}
