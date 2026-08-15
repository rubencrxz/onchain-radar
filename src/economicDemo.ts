import { encodeAbiParameters, getAddress, type Address, type Hex } from "viem";
import { analyzeEconomicActivity } from "./economic/analyzer.js";
import { ERC20_TRANSFER_TOPIC } from "./economic/transfers.js";
import { ZERO_ADDRESS, type EconomicMonitoringConfig } from "./economic/types.js";
import type { RpcClient } from "./rpc.js";

const TOKEN = getAddress("0x1000000000000000000000000000000000000001");
const VAULT = getAddress("0x2000000000000000000000000000000000000001");
const RECIPIENT_A = getAddress("0x3000000000000000000000000000000000000001");
const RECIPIENT_B = getAddress("0x3000000000000000000000000000000000000002");
const FIXED_TIME = "2026-07-31T00:00:00.000Z";

const config: EconomicMonitoringConfig = {
  assets: [
    {
      name: "Synthetic Restaked Asset",
      tokenAddress: TOKEN,
      decimals: 0,
      criticalContracts: [{ name: "Synthetic Integrated Vault", address: VAULT, role: "vault" }],
      thresholds: {
        largeTransferAbsolute: 100n,
        singleBlockOutflowAbsolute: 500n,
        singleBlockOutflowPercent: 10,
        windowOutflowPercent: 20,
        concentrationPercent: 60,
        criticalOutflowPercent: 50,
        criticalDrawdownPercent: 50
      },
      windowBlocks: 20
    }
  ]
};

const balances = new Map<bigint, bigint>([
  [99n, 1_000n],
  [104n, 1_000n],
  [105n, 300n],
  [110n, 300n]
]);

const rpc: RpcClient = {
  async getLogs() {
    return [];
  },
  async getStorageAt() {
    return undefined;
  },
  async getErc20Balance(request) {
    const balance = balances.get(request.blockNumber);
    if (balance === undefined) {
      throw new Error(`Synthetic fixture has no balance for block ${request.blockNumber.toString()}.`);
    }
    return balance;
  }
};

async function main(): Promise<void> {
  const result = await analyzeEconomicActivity({
    rpc,
    config,
    logs: [
      transferLog(ZERO_ADDRESS, RECIPIENT_A, 200n, 102n, 0),
      transferLog(VAULT, RECIPIENT_A, 600n, 105n, 0),
      transferLog(VAULT, RECIPIENT_B, 100n, 105n, 1)
    ],
    startBlock: 100n,
    endBlock: 110n,
    clock: () => FIXED_TIME
  });

  console.log("Synthetic fixture only - this does not reproduce or prove a historical exploit.");
  console.log(`Movements: ${result.movements.length.toString()}`);
  console.log(`Balance observations: ${result.balanceObservations.length.toString()}`);
  for (const alert of result.alerts) {
    console.log(`[${alert.severity}] ${alert.ruleId}: ${alert.summary}`);
  }
}

function transferLog(from: Address, to: Address, value: bigint, blockNumber: bigint, logIndex: number) {
  return {
    blockNumber: `0x${blockNumber.toString(16)}` as Hex,
    transactionHash: `0x${(blockNumber * 10n + BigInt(logIndex)).toString(16).padStart(64, "0")}` as Hex,
    logIndex: `0x${logIndex.toString(16)}` as Hex,
    address: TOKEN,
    topics: [
      ERC20_TRANSFER_TOPIC,
      encodeAbiParameters([{ type: "address" }], [from]),
      encodeAbiParameters([{ type: "address" }], [to])
    ],
    data: encodeAbiParameters([{ type: "uint256" }], [value])
  } as const;
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
