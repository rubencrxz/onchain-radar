export type LiveRange = { fromBlock: bigint; toBlock: bigint };

export class LiveCursorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LiveCursorError";
  }
}

export function confirmedHead(latestBlock: bigint, confirmations: number): bigint {
  if (latestBlock < 0n || !Number.isSafeInteger(confirmations) || confirmations < 0) {
    throw new LiveCursorError("Latest block and confirmations must be non-negative.");
  }
  return latestBlock >= BigInt(confirmations) ? latestBlock - BigInt(confirmations) : 0n;
}

export function nextLiveRange(
  lastProcessedBlock: bigint,
  latestBlock: bigint,
  confirmations: number,
  maxBlocksPerCycle: bigint
): LiveRange | undefined {
  if (lastProcessedBlock < -1n) throw new LiveCursorError("lastProcessedBlock must be at least -1.");
  if (maxBlocksPerCycle <= 0n) throw new LiveCursorError("maxBlocksPerCycle must be positive.");
  const head = confirmedHead(latestBlock, confirmations);
  if (latestBlock < lastProcessedBlock) throw new LiveCursorError("Latest block is below the checkpoint.");
  if (head <= lastProcessedBlock) return undefined;
  return { fromBlock: lastProcessedBlock + 1n, toBlock: head < lastProcessedBlock + maxBlocksPerCycle ? head : lastProcessedBlock + maxBlocksPerCycle };
}
