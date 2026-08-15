import { decodeEventLog, parseAbiItem, type AbiEvent, type Hex } from "viem";

export type RawLogForDecode = {
  topics: readonly Hex[];
  data: Hex;
};

export type EventDecodeResult =
  | {
      decoded: Record<string, unknown>;
      decodeError?: undefined;
    }
  | {
      decoded?: undefined;
      decodeError: string;
    };

const EVENT_ABI_ITEMS = new Map<string, AbiEvent>([
  [
    "OwnershipTransferred(address,address)",
    parseAbiItem("event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)") as AbiEvent
  ],
  [
    "RoleGranted(bytes32,address,address)",
    parseAbiItem("event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)") as AbiEvent
  ],
  [
    "RoleRevoked(bytes32,address,address)",
    parseAbiItem("event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)") as AbiEvent
  ],
  ["Paused(address)", parseAbiItem("event Paused(address account)") as AbiEvent],
  ["Unpaused(address)", parseAbiItem("event Unpaused(address account)") as AbiEvent],
  ["Upgraded(address)", parseAbiItem("event Upgraded(address indexed implementation)") as AbiEvent],
  ["AdminChanged(address,address)", parseAbiItem("event AdminChanged(address previousAdmin, address newAdmin)") as AbiEvent],
  ["ExecutionSuccess(bytes32,uint256)", parseAbiItem("event ExecutionSuccess(bytes32 txHash, uint256 payment)") as AbiEvent],
  ["ExecutionFailure(bytes32,uint256)", parseAbiItem("event ExecutionFailure(bytes32 txHash, uint256 payment)") as AbiEvent],
  ["ExecutionFromModuleSuccess(address)", parseAbiItem("event ExecutionFromModuleSuccess(address indexed module)") as AbiEvent],
  ["ExecutionFromModuleFailure(address)", parseAbiItem("event ExecutionFromModuleFailure(address indexed module)") as AbiEvent],
  ["AddedOwner(address)", parseAbiItem("event AddedOwner(address owner)") as AbiEvent],
  ["RemovedOwner(address)", parseAbiItem("event RemovedOwner(address owner)") as AbiEvent],
  ["ChangedThreshold(uint256)", parseAbiItem("event ChangedThreshold(uint256 threshold)") as AbiEvent],
  ["EnabledModule(address)", parseAbiItem("event EnabledModule(address module)") as AbiEvent],
  ["DisabledModule(address)", parseAbiItem("event DisabledModule(address module)") as AbiEvent],
  ["ChangedGuard(address)", parseAbiItem("event ChangedGuard(address guard)") as AbiEvent],
  ["ChangedFallbackHandler(address)", parseAbiItem("event ChangedFallbackHandler(address handler)") as AbiEvent],
  ["PayloadExecuted(uint40)", parseAbiItem("event PayloadExecuted(uint40 payloadId)") as AbiEvent]
]);

export function decodeConfiguredEventLog(eventSignature: string, log: RawLogForDecode): EventDecodeResult {
  const abiItem = EVENT_ABI_ITEMS.get(eventSignature);

  if (abiItem === undefined) {
    return { decodeError: `No decoder configured for event signature: ${eventSignature}` };
  }

  try {
    const decoded = decodeEventLog({
      abi: [abiItem],
      data: log.data,
      topics: [...log.topics] as [] | [Hex, ...Hex[]]
    });

    return {
      decoded: toJsonSafeRecord(decoded.args)
    };
  } catch (error: unknown) {
    return {
      decodeError: error instanceof Error ? error.message : String(error)
    };
  }
}

function toJsonSafeRecord(value: unknown): Record<string, unknown> {
  const converted = toJsonSafe(value);

  if (isPlainRecord(converted)) {
    return converted;
  }

  return { value: converted };
}

function toJsonSafe(value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }

  if (Array.isArray(value)) {
    return value.map((item) => toJsonSafe(item));
  }

  if (isPlainRecord(value)) {
    const converted: Record<string, unknown> = {};

    for (const [key, item] of Object.entries(value)) {
      converted[key] = toJsonSafe(item);
    }

    return converted;
  }

  return value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
