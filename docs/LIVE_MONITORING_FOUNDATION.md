# Live Monitoring Foundation

This increment adds the first bounded live execution path. It is operational groundwork, not a production deployment and not complete reorg handling.

## Flow

```text
latest block -> confirmed head -> pending range -> per-block historical pipeline
                                      -> journal filter -> terminal + append JSONL
                                      -> durable checkpoint
```

`runLiveCycle` processes only `lastProcessedBlock + 1` through `min(latest-confirmations, lastProcessedBlock + maxBlocksPerCycle)`. The outer `src/live.ts` loop only schedules cycles and handles SIGINT/SIGTERM.

## Checkpoint and initialization

`src/checkpoint.ts` writes JSON through a temporary file and rename. Blocks are decimal strings and hashes are stored for canonicality checks. A missing checkpoint starts at the confirmed head by default, so the monitor cannot accidentally scan Ethereum from genesis. `LIVE_START_BLOCK` explicitly enables bounded replay; the sentinel `-1` supports block zero.

At startup and before every cycle, the stored block hash is compared with the canonical RPC block. A mismatch raises `CanonicalityError` and stops without deleting state. Automatic rollback, fork choice and replay are deliberately deferred.

## Journal and delivery semantics

`src/alertJournal.ts` is append-only JSONL and validates every existing line on load. Alert IDs remain the primary identity. The journal records alert ID, block number/hash, transaction hash, rule ID and recording time. Replayed or overlapping batches are filtered durably.

Effects are ordered: process RPC data, filter journal IDs, deliver required sinks, append journal records, then atomically advance checkpoint. This is at-least-once delivery: a crash after a sink succeeds but before journal append may repeat a local/external delivery. The durable local journal prevents duplicates after successful recording; exactly-once distributed delivery is not claimed.

The live alert output is append-only at `LIVE_ALERT_OUTPUT_PATH`; the journal has a separate path. Historical JSONL behavior is unchanged.

## Economics and EIP-1967

Each cycle processes each target block with the existing processor and uses a bounded economic lookback equal to the largest configured `windowBlocks`. Journal filtering prevents repeated window alerts across overlapping cycles and restarts. EIP-1967 is evaluated per block as `block - 1 -> block`, so an intermediate upgrade and a later reversal are both observable. No new detector or threshold was added.

## Configuration

Defaults are `LIVE_CONFIRMATIONS=3`, `LIVE_POLL_INTERVAL_MS=12000`, `LIVE_MAX_BLOCKS_PER_CYCLE=100`, `LIVE_CHECKPOINT_PATH=state/live-checkpoint.json`, `LIVE_ALERT_JOURNAL_PATH=state/live-alert-journal.jsonl`, and `LIVE_ALERT_OUTPUT_PATH=state/live-alerts.jsonl`. Invalid values fail before the loop starts.

## Limits

The implementation does not provide automatic reorg rollback, durable economic state beyond replay/lookback, external integrations, provider failover, prices, or production monitoring guarantees. The `demo:*` commands exercise the same state and journal boundaries with deterministic synthetic inputs.
