import { buildAlertsFilePath } from "./alertWriter.js";
import type { RawLogForAlert } from "./alerts.js";
import { loadMonitorConfig } from "./config.js";
import { loadScanEnv } from "./env.js";
import { executeHistoricalScan } from "./historicalScanner.js";
import { countAlertsByRuleId } from "./rules.js";
import {
  createViemRpcProvider,
  PolicyRpcClient,
  type RpcOperationContext,
  type RpcPolicyEvent
} from "./rpc.js";
import { JsonlAlertSink, TerminalAlertSink } from "./sinks.js";

async function main(): Promise<void> {
  const env = loadScanEnv();
  const config = loadMonitorConfig();
  const outputFilePath = buildAlertsFilePath(config.chain, env.startBlock, env.endBlock);
  const provider = createViemRpcProvider(env.rpcUrl, env.rpcPolicy.timeoutMs);
  const rpc = new PolicyRpcClient(provider, env.rpcPolicy, { logger: printRpcPolicyEvent });

  console.log("Ethereum Security Monitor - Phase 3 Minimal Rule Engine");
  console.log(`Chain: ${config.chain}`);
  console.log(`Block range: ${env.startBlock.toString()} -> ${env.endBlock.toString()}`);
  console.log(`Chunk size: ${env.rpcPolicy.maxBlockRange.toString()} blocks`);
  console.log(`RPC timeout: ${env.rpcPolicy.timeoutMs.toString()} ms`);
  console.log(`RPC max retries: ${env.rpcPolicy.maxRetries.toString()}`);
  console.log("RPC concurrency: 1 (sequential)");
  console.log(`Configured event signatures: ${config.eventSignatures.length}`);
  console.log(`Monitored addresses: ${config.monitoredAddresses.length === 0 ? "all" : config.monitoredAddresses.length}`);
  console.log(`Known multisigs: ${config.knownMultisigs.length}`);
  console.log(`Safe administrative policies: ${config.administrativeMonitoring?.multisigs.length ?? 0}`);
  console.log(`Economic assets: ${config.economicMonitoring?.assets.length ?? 0}`);
  console.log("");

  const result = await executeHistoricalScan({
    rpc,
    config,
    startBlock: env.startBlock,
    endBlock: env.endBlock,
    maxBlockRange: env.rpcPolicy.maxBlockRange,
    clock: () => new Date().toISOString(),
    sinks: [new TerminalAlertSink(), new JsonlAlertSink(outputFilePath)],
    hooks: {
      onChunkStart: (range) => {
        console.log(`Scanning blocks ${range.fromBlock.toString()} -> ${range.toBlock.toString()}...`);
      },
      onStoragePhaseStart: (proxyCount) => {
        if (proxyCount === 0) {
          console.log("EIP-1967 slot monitoring disabled or no proxies configured.");
        } else {
          console.log(`Checking EIP-1967 slots for ${proxyCount} configured proxy/proxies...`);
        }
      },
      onStoragePhaseComplete: (alertCount) => {
        if (alertCount === 0 && config.proxySlotMonitoring?.enabled === true) {
          console.log("EIP-1967 checks completed with zero changes.");
        }
      },
      onEconomicPhaseStart: (assetCount) => {
        if (assetCount > 0) {
          console.log(`Analyzing economic movements and balances for ${assetCount} configured asset(s)...`);
        }
      },
      onEconomicPhaseComplete: (movementCount, alertCount) => {
        if (config.economicMonitoring !== undefined) {
          console.log(`Economic analysis completed: ${movementCount} movement(s), ${alertCount} alert(s).`);
        }
      },
      onSafePhaseStart: (multisigCount) => {
        if (multisigCount > 0) console.log(`Reconstructing executions for ${multisigCount} configured Safe(s)...`);
      },
      onSafePhaseComplete: (transactionCount, alertCount, correlationCount) => {
        if (config.administrativeMonitoring !== undefined) {
          console.log(`Safe analysis completed: ${transactionCount} reconstructed transaction(s), ${alertCount} transaction alert(s), ${correlationCount} correlation(s).`);
        }
      },
      onUnprocessedLog: (unprocessed) => printRawLog(unprocessed.log, unprocessed.matchedEventSignature)
    }
  });
  const alerts = result.alerts;
  const countsByRule = countAlertsByRuleId(alerts.map((alert) => alert.ruleId));

  console.log("");
  console.log("Scan complete.");
  console.log(`  Logs detected: ${result.detectedLogCount}`);
  console.log(`  Event alerts written: ${result.eventAlertCount}`);
  console.log(`  EIP-1967 slot alerts written: ${result.slotAlertCount}`);
  console.log(`  Economic transfers analyzed: ${result.economicTransferCount}`);
  console.log(`  Economic alerts written: ${result.economicAlertCount}`);
  console.log(`  Safe transactions reconstructed: ${result.safeTransactionCount}`);
  console.log(`  Safe alerts written: ${result.safeAlertCount + result.safeCorrelationCount}`);
  console.log(`  Total alerts written: ${alerts.length}`);
  console.log("  Count by ruleId:");

  if (countsByRule.size === 0) {
    console.log("    none");
  } else {
    for (const [ruleId, count] of countsByRule.entries()) {
      console.log(`    ${ruleId}: ${count}`);
    }
  }

  console.log(`  Output file: ${outputFilePath}`);
}

function printRpcPolicyEvent(event: RpcPolicyEvent): void {
  if (event.type === "retry") {
    console.log(
      `RPC retry: operation=${event.operation}, ${formatRpcContext(event.context)}, classification=${event.classification}, reason=${event.reason}, attempt=${event.failedAttempt}/${event.maxAttempts}, nextDelayMs=${event.delayMs}.`
    );
    return;
  }

  if (event.type === "exhausted") {
    console.error(
      `RPC retries exhausted: operation=${event.operation}, ${formatRpcContext(event.context)}, classification=${event.classification}, reason=${event.reason}, attempts=${event.attempts}.`
    );
    return;
  }

  console.log(
    `RPC range split: blocks ${event.fromBlock.toString()}-${event.toBlock.toString()} -> ${event.fromBlock.toString()}-${event.leftToBlock.toString()} and ${event.rightFromBlock.toString()}-${event.toBlock.toString()} (depth ${event.depth}).`
  );
}

function formatRpcContext(context: RpcOperationContext): string {
  if (context.operation === "eth_getLogs") {
    return `blocks=${context.fromBlock.toString()}-${context.toBlock.toString()}`;
  }

  if (context.operation === "eth_call") {
    return `token=${context.token}, holder=${context.holder}, block=${context.blockNumber.toString()}, method=${context.method}`;
  }

  if (context.operation === "eth_getStorageAt") return `address=${context.address}, slot=${context.slot}, block=${context.blockNumber.toString()}`;
  if (context.operation === "eth_getBlockByNumber") return `block=${context.blockNumber.toString()}`;
  if ("transactionHash" in context) {
    return `transaction=${context.transactionHash}`;
  }
  return "latest block";
}

function printRawLog(log: RawLogForAlert, matchedEventSignature: string): void {
  console.log("Detected event");
  console.log(`  blockNumber: ${formatBlockNumber(log.blockNumber)}`);
  console.log(`  transactionHash: ${log.transactionHash ?? "unknown"}`);
  console.log(`  address: ${log.address}`);
  console.log(`  matchedEventSignature: ${matchedEventSignature}`);
  console.log(`  topics: ${JSON.stringify(log.topics)}`);
  console.log(`  data: ${log.data}`);
  console.log("");
}

function formatBlockNumber(blockNumber: RawLogForAlert["blockNumber"]): string {
  if (blockNumber === null) {
    return "unknown";
  }

  return `${BigInt(blockNumber).toString()} (${blockNumber})`;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Scanner failed: ${message}`);
  process.exitCode = 1;
});
