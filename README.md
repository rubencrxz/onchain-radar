# Onchain Radar

Deterministic monitoring and explainable alerting for Ethereum protocol security.

Onchain Radar is a TypeScript/`viem` prototype that turns confirmed on-chain evidence into structured alerts. It combines administrative events, EIP-1967 storage changes, configured ERC-20 balance anomalies, Safe transactions, MultiSend batches, native Safe control events, module execution, and a bounded Zodiac Roles v2 adapter.

This repository is a public product snapshot of the deterministic monitoring engine. It keeps the runtime, reproducible fixtures, configuration examples, and the documentation needed to evaluate the system.

> Onchain Radar observes executed on-chain actions. It does not infer what a signer saw, prove exploit intent, or promise prevention.

## Why it matters

Security teams rarely need another unexplained risk score. They need an auditable answer to questions such as:

- Did a critical vault lose most of a monitored asset?
- Which Safe, module, target, selector, operation, and implementation were actually involved?
- Did a MultiSend batch hide an unexpected inner call?
- Did emitted events and EIP-1967 storage confirm the decoded administrative action?
- Was an operation outside an explicit policy, or was the policy simply incomplete?

Onchain Radar keeps those decisions deterministic and configuration-driven. Every alert has a stable identity, an explicit rule, evidence metadata, and a human-readable severity reason.

## Demo evidence

| Case | What the prototype reconstructs | Validated result | Interpretation |
| --- | --- | --- | --- |
| KelpDAO / rsETH | ERC-20 movement, prior balance, block outflow, drawdown, concentration, correlation | 116,500 rsETH left the adapter at block `24908285`; balance fell by 99.80%; Balanced emitted 15 incident alerts versus 1 control warning | `USEFUL INCIDENT DETECTION`; the first alert is in the extraction block, not before it |
| ENS Meta-Governance Safe MultiSend | Safe `execTransaction`, exact packed suboperations, semantic classification, policy and native owner/threshold events | 17/17 suboperations parsed, 16/17 classified, 4 confirmed correlations, zero replay duplicates | `USEFUL WITH POLICY CALIBRATION` |
| ENS Endowment / Zodiac Roles v2 | Manager Safe wrapper, `execTransactionWithRole`, role key, module state, downstream MultiSend and selected on-chain permissions | 5/5 module executions and 6/6 leaf operations reconstructed; Balanced reduced from 5 to 1 CRITICAL after evidence-backed policy calibration | Authorized does not mean harmless: the remaining unlimited-approval plus delegatecall composition stays visible |

The historical claims above are backed by dedicated configs and checked-in JSONL demo fixtures. The replay commands are offline fixtures and are labelled as such.

## What is in the frozen demo

### Monitoring capabilities

- Historical range scanning and incremental confirmed-block monitoring.
- Centralized RPC policy with timeout, bounded retries/backoff, structured errors, inclusive chunking, and adaptive range splitting.
- Fail-closed historical output: no complete-looking JSONL file is committed when required RPC or processing work fails.
- Atomic live checkpoint, canonical hash validation, append-only alert journal, and durable alert-ID deduplication.
- Administrative rules for ownership, roles, pause state, governance payloads, proxy events, and EIP-1967 implementation/admin slots.
- Optional economic rules for large transfers, critical-contract outflow, liquidity drawdown, outflow concentration, extraordinary minting, and one explicit correlation.
- Safe `execTransaction` reconstruction and policy for targets, selectors, CALL/DELEGATECALL, implementations, native value, owners, threshold, modules, guard, and fallback handler.
- Configured MultiSend parsing with per-suboperation policy, bounded nesting, defensive payload limits, stable path-based identities, and ambiguity-aware correlations.
- Native Safe owner, threshold, module, guard, and fallback events.
- Observable Safe module execution with enabled-state checks and the intersection of Safe-wide and module-specific policy.
- Opt-in Zodiac Roles v2 support for exact configured wrappers, including Manager Safe envelopes and downstream MultiSend.
- Terminal and JSONL sinks with deterministic ordering.

### Detection boundary

| Detects directly | Observes only after execution | Deliberately outside this demo |
| --- | --- | --- |
| Configured event logs and decoded arguments | Safe calldata from mined transactions and receipts | Mempool or pre-execution simulation |
| EIP-1967 implementation/admin changes | Native Safe control changes after their events exist | What signers saw or intended |
| Configured ERC-20 transfers and historical `balanceOf` deterioration | KelpDAO extraction in the extraction block | Generic traces and arbitrary opaque wrappers |
| Safe/MultiSend/module/Zodiac calls exposed in bounded calldata | Policy violations and confirmed effects in a completed transaction | Automatic reorg rollback |
| Module enabled state and selected Zodiac permission evidence | Confirmed-block live delivery, subject to confirmation depth | Distributed exactly-once delivery |
| Stable alert IDs and local journal deduplication | Correlation between decoded calls, events, state, and storage | Prices, oracles, cross-chain supply, DNS/frontend, threat intelligence, or automated response |

## Architecture

```text
                         .env + validated JSON policy
                                      |
                                      v
                       centralized bounded RPC client
                    timeout / retry / backoff / splitting
                                      |
                    +-----------------+------------------+
                    |                                    |
                    v                                    v
          historical range runner              confirmed live cursor
                                                       |
                                          checkpoint + block hash check
                    |                                    |
                    +-----------------+------------------+
                                      v
             logs + tx/receipt + storage + balance/state observations
                                      |
              +-----------------------+-----------------------+
              |                       |                       |
              v                       v                       v
       admin/Safe pipeline       EIP-1967 diff        economic pipeline
   direct -> MultiSend -> module    per boundary/       Transfer -> balance
      -> Zodiac -> correlation       per block          -> anomaly/correlation
              +-----------------------+-----------------------+
                                      v
                         ordered, deduplicated Alert[]
                                      |
                  +-------------------+-------------------+
                  v                                       v
             terminal sink                          JSONL sink
                                               live journal/checkpoint
```

Historical and live runners share the RPC layer, processors, detectors, severity rules, Safe analysis, and alert schema. See [Architecture](docs/ARCHITECTURE.md) for module-level detail.

## Quick start

Prerequisites: Node.js and npm. The lockfile is committed.

```bash
npm ci
npm test
npm run smoke
npm run typecheck
npm run build
```

The formal suite, smoke test, and all replay commands are deterministic and offline.

## Reproducible offline demo

Run the complete replay set:

```bash
npm run economic:demo
npm run live:replay:kelp
npm run live:replay:safe
npm run live:replay:multisend
npm run live:replay:safe-events
npm run live:replay:safe-modules
npm run live:replay:zodiac-roles
```

The three recommended product walkthroughs are documented step by step in [Demo Walkthrough](docs/DEMO_WALKTHROUGH.md):

1. KelpDAO/rsETH extraction visibility and restart deduplication.
2. ENS Safe MultiSend parsing, policy, native effects, and noise calibration.
3. ENS Endowment/Zodiac module reconstruction and bounded permission evidence.

## Historical calibrations

Create a local environment file without exposing its contents:

```bash
cp .env.example .env
```

Set `ETH_RPC_URL` to an archive-capable Ethereum RPC. Historical calibrations require combinations of `eth_getLogs`, transaction, receipt, block, historical `eth_call`, code, and storage access.

```bash
npm run economic:calibrate
npm run safe:multisend:calibrate
npm run safe:modules:calibrate
```

These commands use isolated calibration configs. They write local artefacts only after every required profile and replay validation succeeds. Generated metrics are written under the ignored `artifacts/` directory:

- `config/economic.historical-calibration-001.json`
- `config/safe-multisend-historical-calibration-001.json`
- `config/safe-modules-historical-calibration-001.json`
- `alerts/*.jsonl` (the checked-in fixtures are reproducible reference outputs)

RPC URLs, API keys, and sensitive headers are never printed by the calibration commands.

## Historical and live runners

Copy an example configuration, then configure `.env`:

```bash
cp config/monitor.config.example.json config/monitor.config.json
npm run scan
```

The historical output path is:

```text
alerts/ethereum-<START_BLOCK>-<END_BLOCK>-alerts.jsonl
```

The live foundation is started separately:

```bash
npm run live
```

It processes only confirmed blocks, appends live alerts, records IDs in a durable journal, and atomically advances a checkpoint. Do not use `npm run live` as a presentation command unless a safe RPC/configuration and a bounded shutdown plan are prepared; it is a continuous loop, not an offline replay.

Important defaults are documented in [.env.example](.env.example): RPC timeout/retries/chunking plus live confirmations, polling interval, cycle size, checkpoint path, journal path, and live alert path.

## Alert model

Every JSONL line is one alert with:

- stable `id` independent of `createdAt`;
- `chain`, `ruleId`, `ruleName`, and `severity`;
- block, transaction, address, event signature, topics, and data;
- human-readable `summary`;
- structured `metadata`, including policy decisions, observed/reference values, and correlation state where applicable;
- `createdAt`, which records alert construction time but is not alert identity.

Representative real and synthetic examples are in [Sample Alerts](docs/SAMPLE_ALERTS.md). Existing IDs, rule IDs, JSON shape, severities, and ordering are part of the frozen compatibility surface.

## Operational guarantees and limits

- Processing is deterministic for the same canonical inputs and configuration.
- Historical execution and required live-cycle effects are fail-closed.
- Local alert identity is durable after successful journal recording.
- External/distributed exactly-once delivery is not claimed.
- A checkpoint hash mismatch stops live processing; automatic rollback is not implemented.
- Safe analysis describes the executed transaction, not signer-visible intent.
- Zodiac permission introspection is bounded to verified supported code/layout and selected condition evidence; unsupported semantics remain explicit.
- Economic anomalies are investigation signals, not proof of exploit, insolvency, or contagion.
- There is no production deployment, dashboard, external notification integration, provider quorum, or automated containment.

See [Limitations and Next Steps](docs/LIMITATIONS_AND_NEXT_STEPS.md) for the complete boundary.

## Documentation map

- [Demo Walkthrough](docs/DEMO_WALKTHROUGH.md) — presentation path and expected evidence.
- [Architecture](docs/ARCHITECTURE.md) — shared historical/live design.
- [Sample Alerts](docs/SAMPLE_ALERTS.md) — representative JSONL records.
- [Live Foundation](docs/LIVE_MONITORING_FOUNDATION.md) — cursor, checkpoint, journal, and delivery semantics.
- [Threat Model](docs/THREAT_MODEL.md) — security signals and boundaries.

## Status

Onchain Radar is a presentable security-monitoring prototype, not a production service. The frozen demo demonstrates post-execution observability, policy calibration, deterministic replay, and a credible path to operations without overstating prediction or prevention.
