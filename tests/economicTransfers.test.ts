import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { getAddress } from "viem";
import { extractAssetMovements } from "../src/economic/transfers.js";
import { ZERO_ADDRESS } from "../src/economic/types.js";
import {
  ECON_TOKEN_B,
  ECON_USER_A,
  ECON_USER_B,
  ECON_VAULT,
  economicConfig,
  transferLog
} from "./economicFixtures.js";

describe("configured ERC-20 Transfer extraction", () => {
  test("classifies inflow, outflow, mint, burn and external transfer", () => {
    const logs = [
      transferLog({ from: ECON_USER_A, to: ECON_VAULT, value: 1n, logIndex: 0 }),
      transferLog({ from: ECON_VAULT, to: ECON_USER_A, value: 2n, logIndex: 1 }),
      transferLog({ from: ZERO_ADDRESS, to: ECON_USER_A, value: 3n, logIndex: 2 }),
      transferLog({ from: ECON_USER_A, to: ZERO_ADDRESS, value: 4n, logIndex: 3 }),
      transferLog({ from: ECON_USER_A, to: ECON_USER_B, value: 5n, logIndex: 4 })
    ];

    assert.deepEqual(
      extractAssetMovements(logs, economicConfig()).map((item) => item.direction),
      ["critical-inflow", "critical-outflow", "mint", "burn", "external-to-external"]
    );
  });

  test("ignores Transfer logs emitted by an unconfigured token", () => {
    const logs = [transferLog({ token: ECON_TOKEN_B, from: ECON_USER_A, to: ECON_USER_B, value: 1000n })];
    assert.deepEqual(extractAssetMovements(logs, economicConfig()), []);
  });

  test("normalizes addresses and preserves bigint, transaction hash and log index", () => {
    const log = transferLog({ from: ECON_USER_A, to: ECON_USER_B, value: 2n ** 200n, logIndex: 7 });
    const movement = extractAssetMovements([log], economicConfig())[0]!;
    assert.equal(movement.from, getAddress(ECON_USER_A));
    assert.equal(movement.value, 2n ** 200n);
    assert.equal(movement.transactionHash, log.transactionHash);
    assert.equal(movement.logIndex, 7);
  });

  test("orders by block, transaction position and log index deterministically", () => {
    const logs = [
      transferLog({ from: ECON_USER_A, to: ECON_USER_B, value: 3n, blockNumber: 11n, transactionOrdinal: 1, logIndex: 0 }),
      transferLog({ from: ECON_USER_A, to: ECON_USER_B, value: 2n, blockNumber: 10n, transactionOrdinal: 2, logIndex: 0 }),
      transferLog({ from: ECON_USER_A, to: ECON_USER_B, value: 1n, blockNumber: 10n, transactionOrdinal: 1, logIndex: 2 }),
      transferLog({ from: ECON_USER_A, to: ECON_USER_B, value: 0n, blockNumber: 10n, transactionOrdinal: 1, logIndex: 1 })
    ];
    assert.deepEqual(extractAssetMovements(logs, economicConfig()).map((item) => item.value), [0n, 1n, 2n, 3n]);
  });

  test("uses on-chain transactionIndex before transaction hash when RPC logs provide it", () => {
    const firstOnChain = transferLog({
      from: ECON_USER_A,
      to: ECON_USER_B,
      value: 1n,
      transactionOrdinal: 2,
      transactionIndex: 1
    });
    const secondOnChain = transferLog({
      from: ECON_USER_A,
      to: ECON_USER_B,
      value: 2n,
      transactionOrdinal: 1,
      transactionIndex: 2
    });

    const movements = extractAssetMovements([secondOnChain, firstOnChain], economicConfig());

    assert.deepEqual(movements.map((movement) => movement.value), [1n, 2n]);
    assert.deepEqual(movements.map((movement) => movement.transactionIndex), [1, 2]);
  });

  test("deduplicates the same token-block-transaction-log identity before aggregation", () => {
    const log = transferLog({ from: ECON_VAULT, to: ECON_USER_A, value: 1000n, logIndex: 7 });
    assert.equal(extractAssetMovements([log, log], economicConfig()).length, 1);
  });
});
