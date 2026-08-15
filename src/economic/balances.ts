import type { RpcClient } from "../rpc.js";
import type {
  AssetMovement,
  BalanceObservation,
  CriticalContractConfig,
  EconomicMonitoringConfig,
  MonitoredAssetConfig
} from "./types.js";

export async function observeEconomicBalances(params: {
  rpc: RpcClient;
  config: EconomicMonitoringConfig;
  movements: readonly AssetMovement[];
  startBlock: bigint;
  endBlock: bigint;
}): Promise<BalanceObservation[]> {
  const observations: BalanceObservation[] = [];
  const initialBlock = params.startBlock === 0n ? 0n : params.startBlock - 1n;

  for (const asset of params.config.assets) {
    const assetMovements = params.movements.filter((movement) => sameAddress(movement.tokenAddress, asset.tokenAddress));

    for (const criticalContract of asset.criticalContracts) {
      const blocks = requiredObservationBlocks({
        asset,
        criticalContract,
        movements: assetMovements,
        startBlock: params.startBlock,
        endBlock: params.endBlock,
        initialBlock
      });

      for (const blockNumber of blocks) {
        const balance = await params.rpc.getErc20Balance({
          token: asset.tokenAddress,
          holder: criticalContract.address,
          blockNumber
        });
        observations.push({ asset, criticalContract, blockNumber, balance });
      }
    }
  }

  return observations;
}

function requiredObservationBlocks(params: {
  asset: MonitoredAssetConfig;
  criticalContract: CriticalContractConfig;
  movements: readonly AssetMovement[];
  startBlock: bigint;
  endBlock: bigint;
  initialBlock: bigint;
}): bigint[] {
  const blocks = new Set<bigint>([params.initialBlock, params.endBlock]);
  const windowSize = BigInt(params.asset.windowBlocks);

  for (let block = params.initialBlock + windowSize; block < params.endBlock; block += windowSize) {
    blocks.add(block);
  }

  for (const movement of params.movements) {
    if (
      sameAddress(movement.from, params.criticalContract.address) ||
      sameAddress(movement.to, params.criticalContract.address)
    ) {
      blocks.add(movement.blockNumber);
      blocks.add(movement.blockNumber === 0n ? 0n : movement.blockNumber - 1n);
    }
  }

  return [...blocks].sort(compareBigInts);
}

function compareBigInts(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}
