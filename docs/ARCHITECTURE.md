# Architecture

This document describes the public architecture: reusable processing, bounded RPC, economic anomalies, confirmed live cursor, Safe/MultiSend/native-event/module monitoring, and the opt-in Zodiac Roles v2 adapter. Optional sections preserve the core behavior when omitted.

## Text Diagram

```text
                         .env + validated config
                                   |
                                   v
                        bounded PolicyRpcClient
                 timeout / retry / backoff / split / cache
                                   |
                    +--------------+--------------+
                    |                             |
                    v                             v
        historical range runner           confirmed live runner
          sequential chunks          cursor + canonical hash + lookback
                    |                             |
                    +--------------+--------------+
                                   v
           logs + transactions/receipts + storage + state/balances
                                   |
              +--------------------+--------------------+
              |                    |                    |
              v                    v                    v
       event processor         EIP-1967 diff      economic analyzer
              |             historical boundary   Transfer normalization
              |                or per block       balance observations
              v                                     pure detectors
  Safe execution analyzer                              |
  direct execTransaction                               |
  configured MultiSend                                 |
  native Safe events                                   |
  enabled modules                                      |
  configured Zodiac Roles adapter                      |
  policy + effect correlation                          |
              +--------------------+--------------------+
                                   v
                         ordered/deduplicated Alert[]
                                   |
                  +----------------+----------------+
                  |                                 |
                  v                                 v
             terminal sink                    JSONL sink
                                             historical overwrite
                                             live append + journal
                                                        |
                                                        v
                                              atomic live checkpoint
```

Historical and live modes share all detector and policy modules. Live execution adds scheduling, confirmed-block bounds, bounded economic lookback, durable ID filtering, and checkpoint effects; it does not fork or duplicate detection logic.

## Components

### Environment Loader

File: `src/env.ts`

Reads:

- `ETH_RPC_URL`;
- `START_BLOCK`;
- `END_BLOCK`;
- `RPC_TIMEOUT_MS`;
- `RPC_MAX_RETRIES`;
- `RPC_RETRY_BASE_DELAY_MS`;
- `RPC_RETRY_MAX_DELAY_MS`;
- `RPC_MAX_BLOCK_RANGE`;
- `RPC_MAX_SPLIT_DEPTH`.

It validates required values and constructs a complete `RpcPolicyConfig` before any request is made. Logic modules do not read `process.env`.

### Config Loader

File: `src/config.ts`

Reads `config/monitor.config.json` and validates:

- `chain`;
- `monitoredAddresses`;
- `knownMultisigs`;
- `eventSignatures`;
- `proxySlotMonitoring`;
- optional `economicMonitoring`;
- optional `administrativeMonitoring.multisigs`;
- optional `administrativeMonitoring.multisendContracts` and `multisendLimits`;
- Safe policy allowlists for owners, thresholds, modules, guards and fallback handlers, plus `multisendAlertDetail` and minimal financial-operation policy;
- `allowlists`.

Economic quantities are validated decimal strings and become `bigint`; addresses are checksummed, percentage thresholds are constrained to `(0, 100]` with two-decimal precision, roles are enumerated, and window sizes are positive integers. Existing configurations remain valid without the optional section.

### Event Signature Hashing

File: `src/events.ts`

Converts configured event signatures into topic0 hashes and keeps a reverse lookup from topic0 to signature.

### Historical Log Scanner

Files: `src/scan.ts`, `src/historicalScanner.ts`

`src/scan.ts` loads inputs, creates the provider/policy, supplies operational callbacks, and renders final counts. `executeHistoricalScan` owns deterministic sequential orchestration across configured administrative/economic ranges, EIP-1967 reads, and economic balance analysis.

Inputs:

- block range from `.env`;
- address filters from config;
- event topic filters from config.

The runner calls no alert sink until every log chunk, storage read, and ERC-20 balance call has succeeded. A failed operation therefore cannot create a final JSONL file that appears complete.

### Centralized RPC Policy

File: `src/rpc.ts`

The layer has two small boundaries:

- `RawRpcProvider`: raw `getLogs`, `getStorageAt`, and ERC-20 `balanceOf` operations; production uses a `viem` adapter with transport retries disabled.
- `PolicyRpcClient`: validates requests and applies explicit timeout, error classification, bounded retries, exponential backoff, and adaptive log-range splitting.

Defaults:

- timeout: `15000 ms` per attempt;
- retries: `3` after the initial attempt;
- backoff: `500 ms`, exponential, capped at `5000 ms`;
- maximum configured chunk: `2000` inclusive blocks;
- adaptive split depth: `20`.

Timeout, 429, 5xx, network/disconnect, and recognized temporary errors are retryable. Invalid RPC parameters, parsing failures, and unknown deterministic failures are permanent. Final errors retain `cause`, attempt count, operation, classification, and safe range/storage context. Retry/exhaustion logs use sanitized reason categories or HTTP status only; raw provider messages and the RPC URL are not logged.

Oversized or excessive-result log queries are split deterministically into left and right halves. Splitting does not apply to unrelated errors and stops at one block or the configured depth. No jitter is used. All requests, including storage and balance reads, are intentionally sequential with concurrency `1` to preserve ordering and avoid request amplification. Successful `balanceOf` calls are cached in memory by normalized token, holder, and block; failed promises are evicted.

Safe transaction and receipt reads use policy-wrapped `eth_getTransactionByHash` and `eth_getTransactionReceipt`. Successful results are cached in memory by transaction hash; failed promises are evicted.

### Safe Administrative Pipeline

Files: `src/safe/types.ts`, `decoder.ts`, `module.ts`, `zodiacRoles.ts`, `actions.ts`, `policy.ts`, `alerts.ts`, `multisend.ts`, `multisendAlerts.ts`, `correlation.ts`, `analyzer.ts`

Configured Safe execution logs identify unique outer transactions. The analyzer fetches transaction and receipt, decodes direct standard `execTransaction`, discards the signatures blob, classifies the inner selector with a local ABI catalogue, and evaluates target, selector, operation, implementation and native value against explicit policy.

The same log pass decodes native Safe owner, threshold, module, guard and fallback-handler events. `src/safe/nativeEvents.ts` refines their severity against the emitting Safe policy. `src/safe/state.ts` optionally obtains threshold and targeted owner/module membership before and after a block through cached policy RPC calls.

`ExecutionFromModuleSuccess/Failure` takes a separate explicit branch in the shared analyzer. `src/safe/module.ts` identifies the indexed executor and decodes standard module entrypoints only when outer calldata makes them observable. `moduleAlerts.ts` applies the intersection of Safe-wide and per-module policy. `isModuleEnabled` is checked before/after the block through the existing policy RPC cache.

An optional per-module `ZODIAC_ROLES_V2` adapter in `src/safe/zodiacRoles.ts` recognizes only its configured Roles address and Manager Safes. It unwraps exact Safe `execTransaction`, bounded configured Manager MultiSend, and exact `execTransactionWithRole` calldata, then returns the same normalized `SafeTransaction` consumed by policy, downstream MultiSend and correlation. Multiple calls are assigned by deterministic payload/log order only when counts match; unknown or ambiguous wrappers remain undecoded.

If the decoded target is an explicitly configured MultiSend contract and the selector is exactly `multiSend(bytes)`, a strict binary parser consumes every record before accepting the expansion. Suboperations are flattened in deterministic depth-first path order and reuse the same action classifier and Safe policy. The batching contract allowlist never authorizes internal targets. `CALL_ONLY` prohibits internal delegatecall independently of the Safe-wide operation list. Default limits are depth 2, 256 operations, 1 MiB aggregate packed payload and 256 KiB calldata per suboperation.

Event effects require the same transaction hash and affected target. EIP-1967 effects require the same target and processed block because a storage observation has no transaction identity. Matching values yield `SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED`; disagreement yields `SAFE_ADMINISTRATIVE_EFFECT_INCONSISTENCY`. The optional path performs no transaction/receipt calls when `administrativeMonitoring` is absent.

MultiSend correlations also carry the logical path. If multiple suboperations can explain one event/storage effect, the analyzer emits an ambiguous correlation with all candidate paths instead of selecting one.

The shared action catalogue assigns `ADMINISTRATIVE_CONTROL`, `PROTOCOL_ADMINISTRATION`, `FINANCIAL_OPERATION`, or `UNKNOWN_OPERATION`. Financial transfers and approvals no longer create `SAFE_SENSITIVE_ADMIN_ACTION`. Individual subcall emission is controlled by `all`, default `sensitive-only`, or `violations-only`; the batch summary always remains.

### Reusable Log Processor

File: `src/processor.ts`

`processLogs` receives already-fetched logs, the configured topic map, chain, allowlists, and an explicit clock dependency. Production supplies the current ISO time and tests supply a fixed clock, so `createdAt` keeps its v0.1 meaning without hidden time access inside the processor. It deterministically:

- identifies the configured event signature;
- maps it to the existing rule;
- delegates decoding and alert construction;
- applies existing severity refinement;
- preserves input order;
- removes duplicate alert IDs within the returned batch while preserving the first occurrence;
- returns alerts plus unprocessed logs.

An unknown topic or a configured signature without a structured rule remains an unprocessed log. The historical entrypoint prints it in the same raw format as v0.1. A malformed log for a supported rule still produces an alert with `metadata.decodeError`, matching v0.1.

### Decoder Layer

File: `src/decoders.ts`

Decodes supported event logs into JSON-safe fields.

Examples:

- `Upgraded(address)` -> `implementation`;
- `PayloadExecuted(uint40)` -> `payloadId`;
- `RoleGranted(bytes32,address,address)` -> `role`, `account`, `sender`.

Decode failures do not crash the scanner. Raw topics and data are preserved.

### Rule Mapper

File: `src/rules.ts`

Maps event signatures to:

- rule ID;
- rule name;
- default severity;
- summary builder.

This is intentionally simple and deterministic.

### EIP-1967 Slot Checker

File: `src/eip1967.ts`

The historical runner obtains configured proxy storage through `RpcClient` for:

- implementation slot;
- admin slot.

It compares values between:

- `START_BLOCK - 1`;
- `END_BLOCK`.

`src/eip1967.ts` contains only pure observation normalization, comparison, and zero-or-one alert creation. Severity refinement remains separate. The comparison still uses only `START_BLOCK - 1` and `END_BLOCK`; per-block observations and reorg handling are not implemented.

### Severity Refinement

File: `src/severity.ts`

Applies simple allowlist-based refinement after alert creation.

Current behavior:

- unknown new implementation -> `CRITICAL`;
- known new implementation -> `WARNING`;
- unknown new admin -> `CRITICAL`;
- known new admin -> `WARNING`;
- known governance payload emitter -> `INFO`;
- unknown governance payload emitter -> `WARNING`;
- proxy upgrade events remain `WARNING` but record whether the proxy was allowlisted.

Every refined alert includes `metadata.severityReason`.

### Economic Anomaly Pipeline

Files: `src/economic/types.ts`, `transfers.ts`, `balances.ts`, `detectors.ts`, `alerts.ts`, `analyzer.ts`

The optional path is separate from `processLogs`:

```text
configured token Transfer logs
  -> normalized, ordered, deduplicated AssetMovement[]
  -> cached historical balanceOf observations
  -> pure threshold detectors
  -> one explicit drawdown + concentration correlation
  -> economic Alert[]
```

Only `Transfer(address,address,uint256)` logs emitted by configured token addresses are decoded. Movements are ordered by block, canonical `transactionIndex` when available, then log index; transaction hash is the deterministic fallback when the index is unavailable. They are deduplicated by token/block/transaction/log identity.

Balance semantics are explicit:

- scan initial: `START_BLOCK - 1`, clamped to zero;
- prior balance for a block outflow: `block - 1`, clamped to zero;
- end-of-block observations: blocks involving a critical contract;
- interval observations: every configured `windowBlocks` from the initial point;
- final: `END_BLOCK`.

Drawdown selects the strongest peak-to-later-balance decline whose block distance is at most `windowBlocks`. Concentration selects the strongest rolling configured window and breaks equal-recipient ties lexicographically. All comparisons are strict and use bigint cross-products against integer basis points.

Economic alert order is large transfers, large mints, per-block critical outflows, drawdowns, concentrations, then correlations. Existing event alerts remain first and EIP-1967 alerts second. IDs exclude `createdAt`; final deduplication preserves the first ID.

### Alert Sinks

Files: `src/sinks.ts`, `src/alertWriter.ts`

The minimal `AlertSink` interface accepts an ordered alert batch. Initial adapters are:

- `TerminalAlertSink`, preserving the v0.1 terminal summary;
- `JsonlAlertSink`, preserving the historical path, one-object-per-line format, and overwrite behavior after complete scans;
- the live path, which appends one alert per line and uses the separate durable journal for alert identity.

JSONL is written to:

```text
alerts/ethereum-<START_BLOCK>-<END_BLOCK>-alerts.jsonl
```

Each line is one complete JSON alert object. This boundary is intentionally small; no plugin system or external integration is included.

### Regression Tests

Files: `tests/*.test.ts`, `tsconfig.test.json`

`npm test` uses TypeScript plus Node's built-in test runner. The compact suite is deterministic/offline and focuses on RPC policy, economics, live checkpoint/journal behavior, Safe/MultiSend/module/Zodiac paths, stable IDs, correlation, and fail-closed processing. `npm run smoke` remains a separate quick compatibility check.

### Bounded Zodiac permission evidence

File: `src/safe/zodiacPermissions.ts`

The bounded permission reader can read code and fixed Roles v2 storage through `PolicyRpcClient` after verifying a supported EIP-1167 mastercopy. It observes role target/function headers, execution options, transaction unwrappers, and bounded condition bytecode. Unsupported condition semantics remain explicit rather than being treated as authorized.

## Historical Data Flow

1. Load `.env`.
2. Load monitor config.
3. Validate the RPC policy and create the raw `viem` provider plus `PolicyRpcClient`.
4. Chunk the requested range using `RPC_MAX_BLOCK_RANGE`.
5. Fetch administrative logs and, when configured, token-specific Transfer logs sequentially through the bounded RPC policy; adaptively split only range/volume failures.
6. Delegate administrative logs to `processLogs` without changing v0.1 behavior.
7. Reconstruct configured Safe calls, expand configured MultiSend batches, and evaluate outer and per-suboperation policy.
8. Read EIP-1967 observations sequentially and build/refine pure storage-diff alerts.
9. Correlate Safe calldata with same-transaction events and same-block slot observations.
10. Normalize economic movements, obtain cached balance observations, and run pure economic detectors/correlation.
11. After complete success, send ordered event, Safe outer, MultiSend, storage, Safe-correlation and economic alerts to sinks.

Live cycles use the same steps for each confirmed block, plus bounded economic lookback. New IDs are delivered to required sinks, appended to the journal, and only then followed by an atomic checkpoint update. A canonical checkpoint hash mismatch stops processing without deleting or rolling back state.

## Design Constraints

The public release intentionally avoids:

- production deployment and automatic reorg rollback;
- database/indexer architecture and distributed exactly-once delivery;
- trace/debug APIs;
- mempool monitoring;
- automatic proxy discovery;
- opaque custom-module wrapper decoding, signature revalidation, signer-interface evidence and pre-execution simulation;
- governance proposal metadata fetching;
- AI enrichment;
- dashboard/UI.

The live foundation adds `src/live.ts`, `src/liveScanner.ts`, `src/liveCursor.ts`, `src/checkpoint.ts`, and `src/alertJournal.ts`. It processes confirmed blocks in bounded sequential cycles, evaluates EIP-1967 per block, uses bounded economic lookback, filters durable alert IDs, and commits the checkpoint after sinks and journal. The minimum canonicality policy stops on a checkpoint hash mismatch; automatic rollback remains deferred.

The Safe vertical is invoked inside the same historical runner, so live cycles inherit identical decoding, policy, IDs and correlation. The `demo:*` commands exercise synthetic inputs and do not represent signer-visible UI behavior.

Configured MultiSend expansion uses that same invocation. Its packed parser is fully offline-testable; the live journal deduplicates path-qualified IDs after overlap or restart. Synthetic demos do not establish signer intent or historical incident behavior.

Native Safe event decoding and correlation are shared by historical and live execution without a second detector path. The Safe-events demo demonstrates this offline, including journal reload. It is synthetic and does not model module execution or signer-visible intent.

Module-derived direct/MultiSend calls reuse the same classifier, parser and correlation boundaries. Their new IDs include module address and event log index; existing owner-path IDs remain byte-for-byte unchanged. The Safe-modules demo is synthetic.

Malformed, limit-exceeded, or depth-exceeded required MultiSend analysis is journaled after local sink delivery but raises before live checkpoint commit. Retries are deduplicated while the cursor remains pinned for explicit operator recovery.

The economic increment also excludes prices, oracles, DEX quotes, protocol-specific share accounting, traces, mempool data, cross-chain supply/message verification, and automated response.
