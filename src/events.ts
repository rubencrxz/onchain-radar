import { keccak256, stringToBytes, type Hex } from "viem";

export type EventTopicMap = Map<Hex, string>;

export function buildEventTopicMap(eventSignatures: string[]): EventTopicMap {
  const topics = new Map<Hex, string>();

  for (const signature of eventSignatures) {
    topics.set(eventSignatureToTopic0(signature), signature);
  }

  return topics;
}

export function eventSignatureToTopic0(signature: string): Hex {
  return keccak256(stringToBytes(signature));
}
