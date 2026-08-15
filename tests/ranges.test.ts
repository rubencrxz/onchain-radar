import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { chunkBlockRange } from "../src/ranges.js";

describe("chunkBlockRange", () => {
  test("keeps a range smaller than one chunk", () => {
    assert.deepEqual(chunkBlockRange(10n, 12n, 5n), [{ fromBlock: 10n, toBlock: 12n }]);
  });

  test("keeps a range exactly equal to one chunk", () => {
    assert.deepEqual(chunkBlockRange(10n, 14n, 5n), [{ fromBlock: 10n, toBlock: 14n }]);
  });

  test("splits a larger inclusive range", () => {
    assert.deepEqual(chunkBlockRange(10n, 22n, 5n), [
      { fromBlock: 10n, toBlock: 14n },
      { fromBlock: 15n, toBlock: 19n },
      { fromBlock: 20n, toBlock: 22n }
    ]);
  });

  test("handles a single block", () => {
    assert.deepEqual(chunkBlockRange(42n, 42n, 1n), [{ fromBlock: 42n, toBlock: 42n }]);
  });

  test("rejects an inverted range", () => {
    assert.throws(() => chunkBlockRange(2n, 1n, 1n), /less than or equal/);
  });

  test("rejects a zero or negative chunk", () => {
    assert.throws(() => chunkBlockRange(1n, 2n, 0n), /greater than zero/);
    assert.throws(() => chunkBlockRange(1n, 2n, -1n), /greater than zero/);
  });

  test("creates no gaps and no overlaps", () => {
    const chunks = chunkBlockRange(100n, 137n, 7n);
    assert.equal(chunks[0]?.fromBlock, 100n);
    assert.equal(chunks.at(-1)?.toBlock, 137n);

    for (let index = 1; index < chunks.length; index += 1) {
      assert.equal(chunks[index]?.fromBlock, chunks[index - 1]!.toBlock + 1n);
    }
  });

  test("never creates a chunk larger than the configured maximum", () => {
    const chunks = chunkBlockRange(0n, 100n, 9n);
    for (const chunk of chunks) {
      assert.ok(chunk.toBlock - chunk.fromBlock + 1n <= 9n);
    }
  });
});
