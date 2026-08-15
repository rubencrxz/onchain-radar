import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Hex } from "viem";

export type Checkpoint = {
  version: 1;
  chain: "ethereum";
  chainId: 1;
  lastProcessedBlock: bigint;
  lastProcessedBlockHash: Hex;
  updatedAt: string;
};

export class CheckpointError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CheckpointError";
  }
}

export class CanonicalityError extends CheckpointError {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalityError";
  }
}

export function loadCheckpoint(filePath: string, expectedChain: "ethereum" = "ethereum"): Checkpoint | undefined {
  const path = resolve(filePath);
  if (!existsSync(path)) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new CheckpointError(`Cannot parse checkpoint ${path}.`, { cause: error });
  }
  if (!isRecord(value) || value.version !== 1 || value.chain !== expectedChain || value.chainId !== 1) {
    throw new CheckpointError(`Invalid or incompatible checkpoint ${path}.`);
  }
  if (typeof value.lastProcessedBlock !== "string" || !/^-?\d+$/.test(value.lastProcessedBlock) || BigInt(value.lastProcessedBlock) < -1n) {
    throw new CheckpointError("Checkpoint lastProcessedBlock must be a decimal string at least -1.");
  }
  if (typeof value.lastProcessedBlockHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value.lastProcessedBlockHash)) {
    throw new CheckpointError("Checkpoint lastProcessedBlockHash must be a 32-byte hex value.");
  }
  if (typeof value.updatedAt !== "string" || value.updatedAt.length === 0) {
    throw new CheckpointError("Checkpoint updatedAt must be a non-empty string.");
  }
  return {
    version: 1,
    chain: "ethereum",
    chainId: 1,
    lastProcessedBlock: BigInt(value.lastProcessedBlock),
    lastProcessedBlockHash: value.lastProcessedBlockHash as Hex,
    updatedAt: value.updatedAt
  };
}

export function writeCheckpoint(filePath: string, checkpoint: Checkpoint): void {
  if (checkpoint.lastProcessedBlock < -1n) throw new CheckpointError("Checkpoint block cannot be below -1.");
  const path = resolve(filePath);
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${Date.now().toString(36)}`;
  const contents = JSON.stringify({ ...checkpoint, lastProcessedBlock: checkpoint.lastProcessedBlock.toString() }, null, 2) + "\n";
  try {
    writeFileSync(temporary, contents, { encoding: "utf8", flag: "wx" });
    renameSync(temporary, path);
  } catch (error) {
    throw new CheckpointError(`Cannot atomically write checkpoint ${path}.`, { cause: error });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
