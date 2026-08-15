import "dotenv/config";
import { loadMonitorConfig } from "./config.js";
import { loadLiveEnv } from "./env.js";
import { runLiveCycle } from "./liveScanner.js";
import { createViemRpcProvider, PolicyRpcClient, type RpcPolicyEvent } from "./rpc.js";
import { AppendJsonlAlertSink, TerminalAlertSink } from "./sinks.js";

let stopping = false;
async function main(): Promise<void> {
  const env = loadLiveEnv();
  const config = loadMonitorConfig();
  const rpc = new PolicyRpcClient(createViemRpcProvider(env.rpcUrl, env.rpcPolicy.timeoutMs), env.rpcPolicy, { logger: logRpcEvent });
  const sinks = [new TerminalAlertSink(), new AppendJsonlAlertSink(env.alertOutputPath)];
  const stop = () => { stopping = true; console.log("Shutdown requested; no new live cycle will start."); };
  process.once("SIGINT", stop); process.once("SIGTERM", stop);
  console.log(`Live monitor started: confirmations=${env.confirmations}, maxBlocksPerCycle=${env.maxBlocksPerCycle.toString()}.`);
  do {
    const summary = await runLiveCycle({ rpc, config, confirmations: env.confirmations, maxBlocksPerCycle: env.maxBlocksPerCycle, checkpointPath: env.checkpointPath, journalPath: env.alertJournalPath, ...(env.startBlock === undefined ? {} : { startBlock: env.startBlock }), sinks });
    console.log(`Live cycle: confirmedHead=${summary.confirmedHead.toString()}, emitted=${summary.alertsEmitted}, lastProcessed=${summary.lastProcessedBlock?.toString() ?? "none"}.`);
    if (stopping) break;
    await new Promise<void>((resolve) => setTimeout(resolve, env.pollIntervalMs));
  } while (!stopping);
}

function logRpcEvent(event: RpcPolicyEvent): void {
  if (event.type === "retry") console.log(`RPC retry: ${event.operation}, attempt=${event.failedAttempt}/${event.maxAttempts}, delayMs=${event.delayMs}.`);
  else if (event.type === "exhausted") console.error(`RPC exhausted: ${event.operation}, attempts=${event.attempts}.`);
  else console.log(`RPC split: ${event.fromBlock.toString()}-${event.toBlock.toString()}.`);
}

main().catch((error: unknown) => { console.error(`Live monitor failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
