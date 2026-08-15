# Onchain Radar

Deterministic Ethereum security monitoring with explainable alerts.

Onchain Radar turns confirmed on-chain evidence into structured, reviewable signals for protocol security teams. It combines configured event monitoring, EIP-1967 storage diffs, ERC-20 economic checks, Safe transaction analysis, MultiSend expansion, module execution, bounded Zodiac Roles v2 decoding, policy evaluation, correlation, and durable live processing.

> Onchain Radar observes executed actions. It does not infer signer intent, prove exploit intent, or provide pre-execution prevention.

## Product surface

- Historical range scanning and confirmed-block live processing.
- Bounded RPC policy with timeout, retries, adaptive range splitting, caching, and structured errors.
- Deterministic event-to-alert mapping with stable IDs, severity reasons, and JSONL output.
- EIP-1967 implementation and admin slot monitoring for explicitly configured proxies.
- Economic signals for large transfers, critical-contract outflows, drawdowns, concentration, minting, and explicit correlations.
- Safe `execTransaction` decoding and policy checks for targets, selectors, operations, implementations, value, owners, thresholds, modules, guards, and fallback handlers.
- Defensive MultiSend parsing with bounded nesting, path-qualified identities, per-suboperation policy, and effect correlation.
- Native Safe control events and observable Safe module execution.
- Opt-in Zodiac Roles v2 support for configured Manager Safe wrappers and downstream MultiSend calls.
- Atomic checkpoints, canonical block-hash checks, append-only journals, and local alert-ID deduplication for live cycles.

## Architecture

```text
validated environment + JSON policy
              |
              v
       bounded PolicyRpcClient
              |
     logs / txs / receipts / state
              |
   +----------+-----------+----------+
   |                      |          |
   v                      v          v
events + Safe         EIP-1967   economics
MultiSend/modules     slot diff  transfers/balances
Zodiac + policy
   +----------+-----------+----------+
              v
    ordered explainable Alert[]
              |
        terminal + JSONL
              |
       live journal/checkpoint
```

Historical and live execution share the same processors, detectors, policy engine, alert schema, and sinks. Live mode adds confirmation bounds, canonicality checks, durable journaling, and checkpoint ordering. See [Architecture](docs/ARCHITECTURE.md) and [Live Monitoring](docs/LIVE_MONITORING_FOUNDATION.md).

## Quick start

Requirements: Node.js and npm.

```bash
npm ci
npm test
npm run typecheck
npm run build
npm run smoke
```

Run the deterministic portfolio demo without an RPC:

```bash
npm run demo
```

Individual verticals are available as `npm run demo:economic`, `npm run demo:safe`, `npm run demo:multisend`, `npm run demo:safe-events`, `npm run demo:safe-modules`, and `npm run demo:zodiac`. They use synthetic inputs and demonstrate detector behavior, parsing boundaries, policy violations, correlations, checkpointing, and journal deduplication; they are not historical incident reproductions.

## Real-world validation

Onchain Radar was also applied to historical Ethereum activity. The compact [Real-world case studies](docs/REAL_WORLD_CASES.md) cover:

- KelpDAO & rsETH: a 116,500 rsETH adapter outflow, 99.80% drawdown, concentration, and correlated economic signals at block `24908285`.
- ENS Meta-Governance Safe MultiSend: 17/17 packed operations reconstructed, with owner and threshold effects correlated from a real Safe transaction.
- ENS Endowment & Zodiac Roles v2: Manager Safe and module envelopes followed into downstream MultiSend operations, including a visible approval-plus-delegatecall composition.

These are evidence summaries rather than runnable historical calibrations. Transaction links, blocks, addresses, representative alert output, and limitations are provided so the claims can be independently inspected on Ethereum. They do not demonstrate prevention, pre-execution detection, or exploit attribution.

## Running against Ethereum

Create a local environment file and choose a configuration:

```bash
cp .env.example .env
cp config/monitor.config.example.json config/monitor.config.json
```

Set `ETH_RPC_URL`, `START_BLOCK`, and `END_BLOCK` in `.env`. Configure monitored addresses, event signatures, proxy addresses, Safe policies, and optional economic monitoring in `config/monitor.config.json`. Then run:

```bash
npm run scan
```

The historical scanner writes `alerts/ethereum-<START_BLOCK>-<END_BLOCK>-alerts.jsonl` after a complete successful run. For bounded confirmed-block processing, configure the live variables in `.env.example` and run:

```bash
npm run live
```

Live mode is a continuous process, not a presentation command. It stops on checkpoint canonicality mismatch and does not claim automatic reorg rollback or distributed exactly-once delivery.

## Alert model

Each alert contains a stable `id`, chain and rule identity, severity, block, transaction evidence, a human-readable summary, and structured metadata. IDs do not depend on `createdAt`, so replay and local journal filtering are deterministic.

## Repository map

- `src/` — runtime, RPC policy, scanners, processors, detectors, Safe/MultiSend/module/Zodiac analyzers, sinks, and live state.
- `config/*.example.json` — generic configuration starting points.
- `tests/` — a compact regression suite for critical product behavior.
- `docs/ARCHITECTURE.md` — final component boundaries and data flow.
- `docs/LIVE_MONITORING_FOUNDATION.md` — checkpoint, journal, and delivery semantics.
- `docs/LIMITATIONS_AND_NEXT_STEPS.md` — explicit product boundary and deferred capabilities.
- `docs/THREAT_MODEL.md` — security signals covered by the prototype.
- `docs/REAL_WORLD_CASES.md` — compact historical Ethereum case studies and evidence.

## Limitations

This is a serious prototype, not a production monitoring service. It is post-execution only and requires explicit configuration for protocols, proxies, Safe policies, modules, and Zodiac wrappers. It does not provide mempool or trace and debug monitoring, automatic proxy discovery, generic custom-module decoding, prices/oracles, cross-chain verification, dashboards, external notifications, automated response, provider failover, or automatic reorg recovery.

Economic alerts are investigation signals, not proof of compromise, insolvency, exploit intent, or contagion. Safe analysis describes calldata and observed effects, not what a signer saw or intended.

See [Limitations and Next Steps](docs/LIMITATIONS_AND_NEXT_STEPS.md) for the detailed boundary.
