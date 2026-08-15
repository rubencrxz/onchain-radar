import { createPublicClient, http, numberToHex, type Address, type Hex } from "viem";
import { mainnet } from "viem/chains";
import type { RawLogForAlert } from "./alerts.js";

export const DEFAULT_RPC_TIMEOUT_MS = 15_000;
export const DEFAULT_RPC_MAX_RETRIES = 3;
export const DEFAULT_RPC_RETRY_BASE_DELAY_MS = 500;
export const DEFAULT_RPC_RETRY_MAX_DELAY_MS = 5_000;
export const DEFAULT_RPC_MAX_BLOCK_RANGE = 2_000n;
export const DEFAULT_RPC_MAX_SPLIT_DEPTH = 20;

export type RpcPolicyConfig = {
  timeoutMs: number;
  maxRetries: number;
  retryBaseDelayMs: number;
  retryMaxDelayMs: number;
  maxBlockRange: bigint;
  maxSplitDepth: number;
};

export type RpcLogRequest = {
  addresses: readonly Address[];
  topics: readonly Hex[];
  fromBlock: bigint;
  toBlock: bigint;
};

export type RpcStorageRequest = {
  address: Address;
  slot: Hex;
  blockNumber: bigint;
};

export type RpcCodeRequest = {
  address: Address;
  blockNumber: bigint;
};

export type RpcErc20BalanceRequest = {
  token: Address;
  holder: Address;
  blockNumber: bigint;
};

export type RpcSafeThresholdRequest = { safe: Address; blockNumber: bigint };
export type RpcSafeOwnerRequest = { safe: Address; owner: Address; blockNumber: bigint };
export type RpcSafeModuleRequest = { safe: Address; module: Address; blockNumber: bigint };

export type RpcTransaction = {
  hash: Hex;
  to: Address | null;
  input: Hex;
  value: bigint;
  blockNumber: bigint;
};

export type RpcTransactionReceipt = {
  transactionHash: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  status: "success" | "reverted";
  logs: RawLogForAlert[];
};

export interface RawRpcProvider {
  getLogs(request: RpcLogRequest): Promise<RawLogForAlert[]>;
  getStorageAt(request: RpcStorageRequest): Promise<Hex | undefined>;
  getCode?(request: RpcCodeRequest): Promise<Hex | undefined>;
  getErc20Balance(request: RpcErc20BalanceRequest): Promise<bigint>;
  getBlockNumber?(): Promise<bigint>;
  getBlock?(blockNumber: bigint): Promise<RpcBlock>;
  getTransaction?(transactionHash: Hex): Promise<RpcTransaction>;
  getTransactionReceipt?(transactionHash: Hex): Promise<RpcTransactionReceipt>;
  getSafeThreshold?(request: RpcSafeThresholdRequest): Promise<bigint>;
  isSafeOwner?(request: RpcSafeOwnerRequest): Promise<boolean>;
  isSafeModuleEnabled?(request: RpcSafeModuleRequest): Promise<boolean>;
}

export interface RpcClient {
  readonly supportsSafeStateReads?: boolean;
  getLogs(request: RpcLogRequest): Promise<RawLogForAlert[]>;
  getStorageAt(request: RpcStorageRequest): Promise<Hex | undefined>;
  getCode?(request: RpcCodeRequest): Promise<Hex | undefined>;
  getErc20Balance(request: RpcErc20BalanceRequest): Promise<bigint>;
  getBlockNumber?(): Promise<bigint>;
  getBlock?(blockNumber: bigint): Promise<RpcBlock>;
  getTransaction?(transactionHash: Hex): Promise<RpcTransaction>;
  getTransactionReceipt?(transactionHash: Hex): Promise<RpcTransactionReceipt>;
  getSafeThreshold?(request: RpcSafeThresholdRequest): Promise<bigint>;
  isSafeOwner?(request: RpcSafeOwnerRequest): Promise<boolean>;
  isSafeModuleEnabled?(request: RpcSafeModuleRequest): Promise<boolean>;
}

export type LiveRpcClient = RpcClient & { getBlockNumber(): Promise<bigint>; getBlock(blockNumber: bigint): Promise<RpcBlock> };

export type RpcBlock = {
  number: bigint;
  hash: Hex;
  parentHash: Hex;
  timestamp: bigint;
};

export type RpcOperation =
  | "eth_getLogs"
  | "eth_getStorageAt"
  | "eth_getCode"
  | "eth_call"
  | "eth_blockNumber"
  | "eth_getBlockByNumber"
  | "eth_getTransactionByHash"
  | "eth_getTransactionReceipt";
export type RpcErrorClassification = "timeout" | "rate-limit" | "transient" | "permanent" | "range-too-large";

export type RpcOperationContext =
  | {
      operation: "eth_getLogs";
      fromBlock: bigint;
      toBlock: bigint;
    }
  | {
      operation: "eth_getStorageAt";
      address: Address;
      slot: Hex;
      blockNumber: bigint;
    }
  | {
      operation: "eth_getCode";
      address: Address;
      blockNumber: bigint;
    }
  | {
      operation: "eth_call";
      method: "balanceOf" | "getThreshold" | "isOwner" | "isModuleEnabled";
      token?: Address;
      holder?: Address;
      safe?: Address;
      subject?: Address;
      blockNumber: bigint;
    }
  | {
      operation: "eth_blockNumber";
    }
  | {
      operation: "eth_getBlockByNumber";
      blockNumber: bigint;
    }
  | {
      operation: "eth_getTransactionByHash" | "eth_getTransactionReceipt";
      transactionHash: Hex;
    };

export type RpcPolicyEvent =
  | {
      type: "retry";
      operation: RpcOperation;
      context: RpcOperationContext;
      classification: RpcErrorClassification;
      reason: string;
      failedAttempt: number;
      maxAttempts: number;
      delayMs: number;
    }
  | {
      type: "exhausted";
      operation: RpcOperation;
      context: RpcOperationContext;
      classification: RpcErrorClassification;
      reason: string;
      attempts: number;
    }
  | {
      type: "split";
      operation: "eth_getLogs";
      fromBlock: bigint;
      toBlock: bigint;
      leftToBlock: bigint;
      rightFromBlock: bigint;
      depth: number;
    };

export type RpcPolicyLogger = (event: RpcPolicyEvent) => void;
export type Sleep = (milliseconds: number) => Promise<void>;
export type RunWithTimeout = <T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  createTimeoutError: () => RpcTimeoutError
) => Promise<T>;

export class RpcPolicyConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RpcPolicyConfigError";
  }
}

export class RpcClassifiedError extends Error {
  constructor(
    message: string,
    readonly operation: RpcOperation,
    readonly context: RpcOperationContext,
    readonly classification: RpcErrorClassification,
    readonly retryable: boolean,
    options?: { cause?: unknown }
  ) {
    super(message, options);
    this.name = "RpcClassifiedError";
  }
}

export class RpcTimeoutError extends RpcClassifiedError {
  constructor(operation: RpcOperation, context: RpcOperationContext, cause?: unknown) {
    super(`RPC timeout during ${operation} (${formatRpcContext(context)}).`, operation, context, "timeout", true, { cause });
    this.name = "RpcTimeoutError";
  }
}

export class RpcRateLimitError extends RpcClassifiedError {
  constructor(operation: RpcOperation, context: RpcOperationContext, cause?: unknown) {
    super(`RPC rate limit during ${operation} (${formatRpcContext(context)}).`, operation, context, "rate-limit", true, {
      cause
    });
    this.name = "RpcRateLimitError";
  }
}

export class RpcTransientError extends RpcClassifiedError {
  constructor(operation: RpcOperation, context: RpcOperationContext, cause?: unknown) {
    super(`Transient RPC failure during ${operation} (${formatRpcContext(context)}).`, operation, context, "transient", true, {
      cause
    });
    this.name = "RpcTransientError";
  }
}

export class RpcPermanentError extends RpcClassifiedError {
  constructor(operation: RpcOperation, context: RpcOperationContext, cause?: unknown) {
    super(`Permanent RPC failure during ${operation} (${formatRpcContext(context)}).`, operation, context, "permanent", false, {
      cause
    });
    this.name = "RpcPermanentError";
  }
}

export class RpcRangeTooLargeError extends RpcClassifiedError {
  constructor(operation: "eth_getLogs", context: RpcOperationContext, cause?: unknown, detail?: string) {
    super(
      `RPC log range rejected during ${operation} (${formatRpcContext(context)}). ${
        detail ?? "The range will be split when possible; otherwise reduce RPC_MAX_BLOCK_RANGE."
      }`,
      operation,
      context,
      "range-too-large",
      false,
      { cause }
    );
    this.name = "RpcRangeTooLargeError";
  }
}

export class RpcRetriesExhaustedError extends Error {
  readonly operation: RpcOperation;
  readonly context: RpcOperationContext;
  readonly classification: RpcErrorClassification;

  constructor(readonly attempts: number, classifiedCause: RpcClassifiedError) {
    super(
      `RPC retries exhausted after ${attempts} attempt(s) during ${classifiedCause.operation} (${formatRpcContext(
        classifiedCause.context
      )}); classification=${classifiedCause.classification}.`,
      { cause: classifiedCause }
    );
    this.name = "RpcRetriesExhaustedError";
    this.operation = classifiedCause.operation;
    this.context = classifiedCause.context;
    this.classification = classifiedCause.classification;
  }
}

export function validateRpcPolicyConfig(config: RpcPolicyConfig): RpcPolicyConfig {
  requirePositiveInteger(config.timeoutMs, "RPC_TIMEOUT_MS");
  requireNonNegativeInteger(config.maxRetries, "RPC_MAX_RETRIES");
  requirePositiveInteger(config.retryBaseDelayMs, "RPC_RETRY_BASE_DELAY_MS");
  requirePositiveInteger(config.retryMaxDelayMs, "RPC_RETRY_MAX_DELAY_MS");
  requireNonNegativeInteger(config.maxSplitDepth, "RPC_MAX_SPLIT_DEPTH");

  if (config.retryMaxDelayMs < config.retryBaseDelayMs) {
    throw new RpcPolicyConfigError("RPC_RETRY_MAX_DELAY_MS must be greater than or equal to RPC_RETRY_BASE_DELAY_MS.");
  }

  if (config.maxBlockRange <= 0n) {
    throw new RpcPolicyConfigError("RPC_MAX_BLOCK_RANGE must be a positive integer.");
  }

  return { ...config };
}

export const systemSleep: Sleep = async (milliseconds) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });

export const runWithSystemTimeout: RunWithTimeout = async (operation, timeoutMs, createTimeoutError) =>
  new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        reject(createTimeoutError());
      }
    }, timeoutMs);

    Promise.resolve()
      .then(operation)
      .then(
        (value) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve(value);
          }
        },
        (error: unknown) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            reject(error);
          }
        }
      );
  });

export class PolicyRpcClient implements RpcClient {
  readonly supportsSafeStateReads: boolean;
  private readonly config: RpcPolicyConfig;
  private readonly sleep: Sleep;
  private readonly runWithTimeout: RunWithTimeout;
  private readonly logger?: RpcPolicyLogger;
  private readonly balanceCache = new Map<string, Promise<bigint>>();
  private readonly codeCache = new Map<string, Promise<Hex | undefined>>();
  private readonly transactionCache = new Map<string, Promise<RpcTransaction>>();
  private readonly receiptCache = new Map<string, Promise<RpcTransactionReceipt>>();
  private readonly safeStateCache = new Map<string, Promise<bigint | boolean>>();

  constructor(
    private readonly provider: RawRpcProvider,
    config: RpcPolicyConfig,
    dependencies: {
      sleep?: Sleep;
      runWithTimeout?: RunWithTimeout;
      logger?: RpcPolicyLogger;
    } = {}
  ) {
    this.config = validateRpcPolicyConfig(config);
    this.sleep = dependencies.sleep ?? systemSleep;
    this.runWithTimeout = dependencies.runWithTimeout ?? runWithSystemTimeout;
    this.logger = dependencies.logger;
    this.supportsSafeStateReads = provider.getSafeThreshold !== undefined &&
      provider.isSafeOwner !== undefined && provider.isSafeModuleEnabled !== undefined;
  }

  async getLogs(request: RpcLogRequest): Promise<RawLogForAlert[]> {
    validateLogRequest(request, this.config.maxBlockRange);
    return this.getLogsWithAdaptiveSplit(request, 0);
  }

  async getStorageAt(request: RpcStorageRequest): Promise<Hex | undefined> {
    const context: RpcOperationContext = { operation: "eth_getStorageAt", ...request };
    return this.executeWithPolicy("eth_getStorageAt", context, () => this.provider.getStorageAt(request));
  }

  async getCode(request: RpcCodeRequest): Promise<Hex | undefined> {
    if (request.blockNumber < 0n) throw new RpcPolicyConfigError("Code blockNumber must be non-negative.");
    const key = [request.address.toLowerCase(), request.blockNumber.toString()].join(":");
    const cached = this.codeCache.get(key);
    if (cached !== undefined) return cached;
    const context: RpcOperationContext = { operation: "eth_getCode", ...request };
    const pending = this.executeWithPolicy("eth_getCode", context, () => {
      if (this.provider.getCode === undefined) throw new RpcPermanentError("eth_getCode", context);
      return this.provider.getCode(request);
    });
    this.codeCache.set(key, pending);
    try { return await pending; } catch (error) { this.codeCache.delete(key); throw error; }
  }

  async getErc20Balance(request: RpcErc20BalanceRequest): Promise<bigint> {
    if (request.blockNumber < 0n) {
      throw new RpcPolicyConfigError("ERC-20 balanceOf blockNumber must be non-negative.");
    }

    const cacheKey = [request.token.toLowerCase(), request.holder.toLowerCase(), request.blockNumber.toString()].join(":");
    const cached = this.balanceCache.get(cacheKey);
    if (cached !== undefined) {
      return cached;
    }

    const context: RpcOperationContext = { operation: "eth_call", method: "balanceOf", ...request };
    const pending = this.executeWithPolicy("eth_call", context, () => this.provider.getErc20Balance(request));
    this.balanceCache.set(cacheKey, pending);

    try {
      return await pending;
    } catch (error: unknown) {
      this.balanceCache.delete(cacheKey);
      throw error;
    }
  }

  async getBlockNumber(): Promise<bigint> {
    return this.executeWithPolicy("eth_blockNumber", { operation: "eth_blockNumber" }, () => {
      if (this.provider.getBlockNumber === undefined) throw new RpcPermanentError("eth_blockNumber", { operation: "eth_blockNumber" });
      return this.provider.getBlockNumber();
    });
  }

  async getBlock(blockNumber: bigint): Promise<RpcBlock> {
    if (blockNumber < 0n) throw new RpcPolicyConfigError("Block number must be non-negative.");
    return this.executeWithPolicy("eth_getBlockByNumber", { operation: "eth_getBlockByNumber", blockNumber }, () =>
      {
        if (this.provider.getBlock === undefined) throw new RpcPermanentError("eth_getBlockByNumber", { operation: "eth_getBlockByNumber", blockNumber });
        return this.provider.getBlock(blockNumber);
      }
    );
  }

  async getTransaction(transactionHash: Hex): Promise<RpcTransaction> {
    return this.getCachedTransactionValue(
      this.transactionCache,
      transactionHash,
      "eth_getTransactionByHash",
      () => {
        if (this.provider.getTransaction === undefined) {
          throw new RpcPermanentError("eth_getTransactionByHash", { operation: "eth_getTransactionByHash", transactionHash });
        }
        return this.provider.getTransaction(transactionHash);
      }
    );
  }

  async getTransactionReceipt(transactionHash: Hex): Promise<RpcTransactionReceipt> {
    return this.getCachedTransactionValue(
      this.receiptCache,
      transactionHash,
      "eth_getTransactionReceipt",
      () => {
        if (this.provider.getTransactionReceipt === undefined) {
          throw new RpcPermanentError("eth_getTransactionReceipt", { operation: "eth_getTransactionReceipt", transactionHash });
        }
        return this.provider.getTransactionReceipt(transactionHash);
      }
    );
  }

  async getSafeThreshold(request: RpcSafeThresholdRequest): Promise<bigint> {
    return this.getCachedSafeState(
      ["threshold", request.safe, request.blockNumber.toString()].join(":"),
      { operation: "eth_call", method: "getThreshold", safe: request.safe, blockNumber: request.blockNumber },
      () => {
        if (this.provider.getSafeThreshold === undefined) throw new RpcPermanentError("eth_call", { operation: "eth_call", method: "getThreshold", safe: request.safe, blockNumber: request.blockNumber });
        return this.provider.getSafeThreshold(request);
      }
    ) as Promise<bigint>;
  }

  async isSafeOwner(request: RpcSafeOwnerRequest): Promise<boolean> {
    return this.getCachedSafeState(
      ["owner", request.safe, request.owner, request.blockNumber.toString()].join(":"),
      { operation: "eth_call", method: "isOwner", safe: request.safe, subject: request.owner, blockNumber: request.blockNumber },
      () => {
        if (this.provider.isSafeOwner === undefined) throw new RpcPermanentError("eth_call", { operation: "eth_call", method: "isOwner", safe: request.safe, subject: request.owner, blockNumber: request.blockNumber });
        return this.provider.isSafeOwner(request);
      }
    ) as Promise<boolean>;
  }

  async isSafeModuleEnabled(request: RpcSafeModuleRequest): Promise<boolean> {
    return this.getCachedSafeState(
      ["module", request.safe, request.module, request.blockNumber.toString()].join(":"),
      { operation: "eth_call", method: "isModuleEnabled", safe: request.safe, subject: request.module, blockNumber: request.blockNumber },
      () => {
        if (this.provider.isSafeModuleEnabled === undefined) throw new RpcPermanentError("eth_call", { operation: "eth_call", method: "isModuleEnabled", safe: request.safe, subject: request.module, blockNumber: request.blockNumber });
        return this.provider.isSafeModuleEnabled(request);
      }
    ) as Promise<boolean>;
  }

  private async getCachedSafeState<T extends bigint | boolean>(
    cacheKey: string,
    context: RpcOperationContext,
    execute: () => Promise<T>
  ): Promise<T> {
    const key = cacheKey.toLowerCase();
    const cached = this.safeStateCache.get(key);
    if (cached !== undefined) return cached as Promise<T>;
    const pending = this.executeWithPolicy("eth_call", context, execute);
    this.safeStateCache.set(key, pending);
    try { return await pending; } catch (error) { this.safeStateCache.delete(key); throw error; }
  }

  private async getCachedTransactionValue<T>(
    cache: Map<string, Promise<T>>,
    transactionHash: Hex,
    operation: "eth_getTransactionByHash" | "eth_getTransactionReceipt",
    execute: () => Promise<T>
  ): Promise<T> {
    const key = transactionHash.toLowerCase();
    const cached = cache.get(key);
    if (cached !== undefined) return cached;
    const context: RpcOperationContext = { operation, transactionHash };
    const pending = this.executeWithPolicy(operation, context, execute);
    cache.set(key, pending);
    try {
      return await pending;
    } catch (error: unknown) {
      cache.delete(key);
      throw error;
    }
  }

  private async getLogsWithAdaptiveSplit(request: RpcLogRequest, depth: number): Promise<RawLogForAlert[]> {
    const context: RpcOperationContext = {
      operation: "eth_getLogs",
      fromBlock: request.fromBlock,
      toBlock: request.toBlock
    };

    try {
      return await this.executeWithPolicy("eth_getLogs", context, () => this.provider.getLogs(request));
    } catch (error: unknown) {
      if (!(error instanceof RpcRangeTooLargeError)) {
        throw error;
      }

      if (request.fromBlock === request.toBlock) {
        throw new RpcRangeTooLargeError("eth_getLogs", context, error, "The provider rejected a single-block query.");
      }

      if (depth >= this.config.maxSplitDepth) {
        throw new RpcRangeTooLargeError(
          "eth_getLogs",
          context,
          error,
          `Adaptive split depth ${this.config.maxSplitDepth} was exhausted; reduce RPC_MAX_BLOCK_RANGE.`
        );
      }

      const middle = (request.fromBlock + request.toBlock) / 2n;
      this.logger?.({
        type: "split",
        operation: "eth_getLogs",
        fromBlock: request.fromBlock,
        toBlock: request.toBlock,
        leftToBlock: middle,
        rightFromBlock: middle + 1n,
        depth: depth + 1
      });

      const left = await this.getLogsWithAdaptiveSplit({ ...request, toBlock: middle }, depth + 1);
      const right = await this.getLogsWithAdaptiveSplit({ ...request, fromBlock: middle + 1n }, depth + 1);
      return [...left, ...right];
    }
  }

  private async executeWithPolicy<T>(
    operation: RpcOperation,
    context: RpcOperationContext,
    execute: () => Promise<T>
  ): Promise<T> {
    const maxAttempts = this.config.maxRetries + 1;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        return await this.runWithTimeout(execute, this.config.timeoutMs, () => new RpcTimeoutError(operation, context));
      } catch (error: unknown) {
        const classified = classifyRpcError(error, operation, context);

        if (!classified.retryable) {
          throw classified;
        }

        if (attempt === maxAttempts) {
          this.logger?.({
            type: "exhausted",
            operation,
            context,
            classification: classified.classification,
            reason: summarizeRpcFailure(classified),
            attempts: attempt
          });
          throw new RpcRetriesExhaustedError(attempt, classified);
        }

        const delayMs = calculateBackoffDelay(attempt - 1, this.config.retryBaseDelayMs, this.config.retryMaxDelayMs);
        this.logger?.({
          type: "retry",
          operation,
          context,
          classification: classified.classification,
          reason: summarizeRpcFailure(classified),
          failedAttempt: attempt,
          maxAttempts,
          delayMs
        });
        await this.sleep(delayMs);
      }
    }

    throw new Error("Unreachable RPC retry state.");
  }
}

export function createViemRpcProvider(rpcUrl: string, timeoutMs: number): RawRpcProvider {
  const client = createPublicClient({
    chain: mainnet,
    transport: http(rpcUrl, { retryCount: 0, timeout: timeoutMs })
  });

  return {
    async getLogs(request) {
      return (await client.request({
        method: "eth_getLogs",
        params: [
          {
            address: request.addresses.length > 0 ? [...request.addresses] : undefined,
            fromBlock: numberToHex(request.fromBlock),
            toBlock: numberToHex(request.toBlock),
            topics: [[...request.topics]]
          }
        ]
      })) as RawLogForAlert[];
    },
    async getStorageAt(request) {
      return client.getStorageAt(request);
    },
    async getCode(request) {
      return client.getCode({ address: request.address, blockNumber: request.blockNumber });
    },
    async getErc20Balance(request) {
      return client.readContract({
        address: request.token,
        abi: ERC20_BALANCE_OF_ABI,
        functionName: "balanceOf",
        args: [request.holder],
        blockNumber: request.blockNumber
      });
    },
    async getBlockNumber() {
      return client.getBlockNumber();
    },
    async getBlock(blockNumber) {
      const block = await client.getBlock({ blockNumber });
      if (block.number === null || block.hash === null) throw new Error(`RPC returned incomplete block ${blockNumber.toString()}.`);
      return { number: block.number, hash: block.hash, parentHash: block.parentHash, timestamp: block.timestamp };
    },
    async getTransaction(transactionHash) {
      const transaction = await client.getTransaction({ hash: transactionHash });
      if (transaction.blockNumber === null) throw new Error(`RPC returned pending transaction ${transactionHash}.`);
      return {
        hash: transaction.hash,
        to: transaction.to,
        input: transaction.input,
        value: transaction.value,
        blockNumber: transaction.blockNumber
      };
    },
    async getTransactionReceipt(transactionHash) {
      const receipt = await client.getTransactionReceipt({ hash: transactionHash });
      return {
        transactionHash: receipt.transactionHash,
        blockNumber: receipt.blockNumber,
        blockHash: receipt.blockHash,
        status: receipt.status,
        logs: receipt.logs.map((log) => ({
          blockNumber: log.blockNumber === null ? null : numberToHex(log.blockNumber),
          transactionHash: log.transactionHash,
          transactionIndex: log.transactionIndex === null ? null : numberToHex(log.transactionIndex),
          logIndex: log.logIndex === null ? null : numberToHex(log.logIndex),
          address: log.address,
          topics: log.topics,
          data: log.data
        }))
      };
    },
    async getSafeThreshold(request) {
      return client.readContract({ address: request.safe, abi: SAFE_STATE_ABI, functionName: "getThreshold", blockNumber: request.blockNumber });
    },
    async isSafeOwner(request) {
      return client.readContract({ address: request.safe, abi: SAFE_STATE_ABI, functionName: "isOwner", args: [request.owner], blockNumber: request.blockNumber });
    },
    async isSafeModuleEnabled(request) {
      return client.readContract({ address: request.safe, abi: SAFE_STATE_ABI, functionName: "isModuleEnabled", args: [request.module], blockNumber: request.blockNumber });
    }
  };
}

export function calculateBackoffDelay(retryIndex: number, baseDelayMs: number, maxDelayMs: number): number {
  return Math.min(maxDelayMs, baseDelayMs * 2 ** retryIndex);
}

export function classifyRpcError(
  error: unknown,
  operation: RpcOperation,
  context: RpcOperationContext
): RpcClassifiedError {
  if (error instanceof RpcClassifiedError) {
    return error;
  }

  const message = readErrorMessage(error).toLowerCase();
  const status = readNumericProperty(error, ["status", "statusCode"]);
  const code = readNumericProperty(error, ["code"]);
  const name = readStringProperty(error, "name").toLowerCase();

  if (operation === "eth_getLogs" && (status === 413 || isRangeTooLargeMessage(message))) {
    return new RpcRangeTooLargeError(operation, context, error);
  }

  if (
    status === 429 ||
    includesAny(message, ["rate limit", "rate-limit", "too many requests", "request limit", "limit exceeded"])
  ) {
    return new RpcRateLimitError(operation, context, error);
  }

  if (
    status === 408 ||
    name === "timeouterror" ||
    name === "aborterror" ||
    code === -32070 ||
    includesAny(message, ["timeout", "timed out", "etimedout"])
  ) {
    return new RpcTimeoutError(operation, context, error);
  }

  if (
    (status !== undefined && status >= 500 && status <= 599) ||
    includesAny(message, [
      "econnreset",
      "econnrefused",
      "eai_again",
      "fetch failed",
      "failed to fetch",
      "network error",
      "socket hang up",
      "disconnected",
      "temporarily unavailable",
      "service unavailable",
      "gateway timeout",
      "internal server error",
      "server error"
    ])
  ) {
    return new RpcTransientError(operation, context, error);
  }

  if (
    code === -32600 ||
    code === -32601 ||
    code === -32602 ||
    code === -32700 ||
    includesAny(message, ["invalid params", "invalid argument", "invalid address", "parse error", "method not found"])
  ) {
    return new RpcPermanentError(operation, context, error);
  }

  return new RpcPermanentError(operation, context, error);
}

function validateLogRequest(request: RpcLogRequest, maxBlockRange: bigint): void {
  if (request.fromBlock > request.toBlock) {
    throw new RpcPolicyConfigError("eth_getLogs fromBlock must be less than or equal to toBlock.");
  }

  const size = request.toBlock - request.fromBlock + 1n;
  if (size > maxBlockRange) {
    throw new RpcPolicyConfigError(
      `eth_getLogs range ${request.fromBlock.toString()}-${request.toBlock.toString()} contains ${size.toString()} blocks, exceeding RPC_MAX_BLOCK_RANGE=${maxBlockRange.toString()}.`
    );
  }
}

function requirePositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RpcPolicyConfigError(`${name} must be a positive integer.`);
  }
}

function requireNonNegativeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RpcPolicyConfigError(`${name} must be a non-negative integer.`);
  }
}

function formatRpcContext(context: RpcOperationContext): string {
  if (context.operation === "eth_getLogs") {
    return `blocks ${context.fromBlock.toString()}-${context.toBlock.toString()}`;
  }

  if (context.operation === "eth_getStorageAt") {
    return `address ${context.address}, slot ${context.slot}, block ${context.blockNumber.toString()}`;
  }

  if (context.operation === "eth_getCode") {
    return `address ${context.address}, block ${context.blockNumber.toString()}`;
  }

  if (context.operation === "eth_blockNumber") return "latest block";
  if (context.operation === "eth_getBlockByNumber") return `block ${context.blockNumber.toString()}`;
  if ("transactionHash" in context) {
    return `transaction ${context.transactionHash}`;
  }
  if (context.method === "balanceOf") {
    return `token ${context.token}, holder ${context.holder}, block ${context.blockNumber.toString()}, method balanceOf`;
  }
  return `Safe ${context.safe}, subject ${context.subject ?? "n/a"}, block ${context.blockNumber.toString()}, method ${context.method}`;
}

const ERC20_BALANCE_OF_ABI = [
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }]
  }
] as const;

const SAFE_STATE_ABI = [
  { type: "function", name: "getThreshold", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "uint256" }] },
  { type: "function", name: "isOwner", stateMutability: "view", inputs: [{ name: "owner", type: "address" }], outputs: [{ name: "", type: "bool" }] },
  { type: "function", name: "isModuleEnabled", stateMutability: "view", inputs: [{ name: "module", type: "address" }], outputs: [{ name: "", type: "bool" }] }
] as const;

function isRangeTooLargeMessage(message: string): boolean {
  return includesAny(message, [
    "range too large",
    "block range is too wide",
    "block range too wide",
    "too many results",
    "query returned more than",
    "response size exceeded",
    "log response size exceeded",
    "please limit the query"
  ]);
}

function includesAny(value: string, candidates: readonly string[]): boolean {
  return candidates.some((candidate) => value.includes(candidate));
}

function readErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === "string") {
    return error;
  }

  return "";
}

function summarizeRpcFailure(error: RpcClassifiedError): string {
  if (error.classification === "timeout") {
    return "request timeout";
  }

  if (error.classification === "rate-limit") {
    return "provider rate limit";
  }

  const status = readNumericProperty(error.cause, ["status", "statusCode"]);
  if (status !== undefined) {
    return `HTTP ${status.toString()}`;
  }

  return error.classification === "transient" ? "temporary transport/provider failure" : "permanent provider failure";
}

function readNumericProperty(error: unknown, keys: readonly string[]): number | undefined {
  let current: unknown = error;

  for (let depth = 0; depth < 4 && isRecord(current); depth += 1) {
    for (const key of keys) {
      if (typeof current[key] === "number") {
        return current[key];
      }
    }
    current = current.cause;
  }

  return undefined;
}

function readStringProperty(error: unknown, key: string): string {
  return isRecord(error) && typeof error[key] === "string" ? error[key] : "";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
