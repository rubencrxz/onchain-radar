export const MAX_BLOCK_RANGE = 2_000n;

export type BlockRange = {
  fromBlock: bigint;
  toBlock: bigint;
};

export function chunkBlockRange(startBlock: bigint, endBlock: bigint, maxRange = MAX_BLOCK_RANGE): BlockRange[] {
  if (startBlock > endBlock) {
    throw new Error("START_BLOCK must be less than or equal to END_BLOCK.");
  }

  if (maxRange <= 0n) {
    throw new Error("MAX_BLOCK_RANGE must be greater than zero.");
  }

  const chunks: BlockRange[] = [];
  let current = startBlock;

  while (current <= endBlock) {
    const toBlock = minBigInt(current + maxRange - 1n, endBlock);
    chunks.push({ fromBlock: current, toBlock });
    current = toBlock + 1n;
  }

  return chunks;
}

function minBigInt(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}
