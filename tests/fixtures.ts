import { encodeAbiParameters, type Address, type Hex } from "viem";
import type { RawLogForAlert } from "../src/alerts.js";
import type { AllowlistConfig } from "../src/config.js";
import { buildEventTopicMap, type EventTopicMap } from "../src/events.js";

export const FIXED_CREATED_AT = "2026-07-03T00:00:00.000Z";
export const ADDRESS_A = "0x1111111111111111111111111111111111111111" as Address;
export const ADDRESS_B = "0x2222222222222222222222222222222222222222" as Address;
export const ADDRESS_C = "0x3333333333333333333333333333333333333333" as Address;
export const AAVE_PAYLOADS_CONTROLLER = "0xdAbad81aF85554E9ae636395611C58F7eC1aAEc5" as Address;
export const AAVE_POOL = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2" as Address;
export const AAVE_POOL_IMPLEMENTATION = "0x728a138A4823392C2EFA55e028d434F526fE03CF" as Address;
export const SAMPLE_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;
export const SAMPLE_SAFE_TX_HASH = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as Hex;

export const EVENT_SIGNATURES = [
  "OwnershipTransferred(address,address)",
  "RoleGranted(bytes32,address,address)",
  "RoleRevoked(bytes32,address,address)",
  "Paused(address)",
  "Unpaused(address)",
  "Upgraded(address)",
  "AdminChanged(address,address)",
  "ExecutionSuccess(bytes32,uint256)",
  "ExecutionFailure(bytes32,uint256)",
  "PayloadExecuted(uint40)"
] as const;

export const EXPECTED_RULE_IDS = [
  "OWNERSHIP_TRANSFERRED",
  "ROLE_GRANTED",
  "ROLE_REVOKED",
  "PAUSED",
  "UNPAUSED",
  "PROXY_UPGRADED",
  "PROXY_ADMIN_CHANGED",
  "SAFE_EXECUTION_SUCCESS",
  "SAFE_EXECUTION_FAILURE",
  "GOVERNANCE_PAYLOAD_EXECUTED"
] as const;

export function emptyAllowlists(): AllowlistConfig {
  return {
    knownActors: [],
    knownAdmins: [],
    knownImplementations: [],
    knownGovernanceContracts: [],
    knownProxyAddresses: []
  };
}

export function buildFixtureTopicMap(signatures: readonly string[] = EVENT_SIGNATURES): EventTopicMap {
  return buildEventTopicMap([...signatures]);
}

export function buildSyntheticEventLogs(topicMap = buildFixtureTopicMap()): RawLogForAlert[] {
  const entries: Array<{ topics: Hex[]; data: Hex }> = [
    {
      topics: [
        requireTopic(topicMap, EVENT_SIGNATURES[0]),
        addressToTopic(ADDRESS_A),
        addressToTopic(ADDRESS_B)
      ],
      data: "0x"
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[1]), SAMPLE_ROLE, addressToTopic(ADDRESS_B), addressToTopic(ADDRESS_C)],
      data: "0x"
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[2]), SAMPLE_ROLE, addressToTopic(ADDRESS_B), addressToTopic(ADDRESS_C)],
      data: "0x"
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[3])],
      data: encodeAbiParameters([{ type: "address", name: "account" }], [ADDRESS_A])
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[4])],
      data: encodeAbiParameters([{ type: "address", name: "account" }], [ADDRESS_A])
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[5]), addressToTopic(ADDRESS_B)],
      data: "0x"
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[6])],
      data: encodeAbiParameters(
        [
          { type: "address", name: "previousAdmin" },
          { type: "address", name: "newAdmin" }
        ],
        [ADDRESS_A, ADDRESS_B]
      )
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[7])],
      data: encodeAbiParameters(
        [
          { type: "bytes32", name: "txHash" },
          { type: "uint256", name: "payment" }
        ],
        [SAMPLE_SAFE_TX_HASH, 123n]
      )
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[8])],
      data: encodeAbiParameters(
        [
          { type: "bytes32", name: "txHash" },
          { type: "uint256", name: "payment" }
        ],
        [SAMPLE_SAFE_TX_HASH, 456n]
      )
    },
    {
      topics: [requireTopic(topicMap, EVENT_SIGNATURES[9])],
      data: encodeAbiParameters([{ type: "uint40", name: "payloadId" }], [453])
    }
  ];

  return entries.map((entry, index) => ({
    blockNumber: "0x64",
    transactionHash: `0x${(index + 1).toString(16).padStart(64, "0")}` as Hex,
    logIndex: `0x${index.toString(16)}` as Hex,
    address: ADDRESS_A,
    topics: entry.topics,
    data: entry.data
  }));
}

export function requireTopic(topicMap: EventTopicMap, signature: string): Hex {
  const topic = [...topicMap.entries()].find(([, mappedSignature]) => mappedSignature === signature)?.[0];

  if (topic === undefined) {
    throw new Error(`Missing topic for ${signature}.`);
  }

  return topic;
}

export function addressToTopic(address: Address): Hex {
  return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}` as Hex;
}

export function addressToStorageWord(address: Address): Hex {
  return `0x${"0".repeat(24)}${address.slice(2).toLowerCase()}` as Hex;
}
