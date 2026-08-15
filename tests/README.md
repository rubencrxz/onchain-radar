# Tests

The formal offline regression suite lives here and uses Node's built-in test runner.

Initial test coverage should focus on:

- deterministic rule fixtures;
- alert schema validation;
- severity classification;
- event signature decoding;
- proxy upgrade detection fixtures;
- multisig activity detection fixtures;
- historical case checks where practical.

Run it with:

```bash
npm test
```

The suite compiles TypeScript into the ignored `dist-tests/` directory and does not require RPC access. Simulated providers cover timeout, retries, capped backoff, classification, chunking, adaptive split, centralized storage/balance reads, cache behavior, ordering, and fail-closed output. Economic fixtures cover config validation, Transfer extraction, strict threshold boundaries, outflow aggregation, drawdown, concentration, minting, correlation, stable IDs, and compatibility when economic monitoring is absent. Safe fixtures cover direct execution plus strict MultiSend parsing, bounded nesting, per-suboperation policy, ambiguous correlation, historical/live integration, checkpoint pinning on incomplete required analysis, and restart deduplication. `npm run smoke` remains a separate fast compatibility check.
