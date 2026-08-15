# Limitations and Next Steps

This document defines the public product boundary: deterministic processing, bounded RPC, economics, confirmed live execution, Safe, MultiSend, native events, modules, and the bounded Zodiac Roles v2 adapter.

## Capability boundary at a glance

| Detects | Post-execution only | Outside this release |
| --- | --- | --- |
| Configured logs, balances, state and storage changes | Safe module calldata after mining | Mempool and simulation |
| Safe direct, configured MultiSend, standard module events and configured Zodiac wrappers | Policy compliance and effect correlation | Signer UI or human intent |
| Confirmed blocks with local checkpoint | KelpDAO extraction from its extraction block | Automatic reorg rollback |
| Configured ERC-20 economic anomalies | Investigation signals, not causal proof | Prices, oracles, traces and cross-chain state |
| Local stable-ID deduplication | At-least-once crash semantics around sinks | Distributed exactly-once and external integrations |

## Current Limitations

- Historical scanner remains available; bounded live mode is now available through `npm run live`.
- Live mode is not production monitoring and stops on checkpoint canonicality mismatch rather than rolling back automatically.
- No dashboard.
- No database or local indexer.
- No mempool monitoring.
- No trace API support.
- No automatic proxy discovery.
- No beacon proxy support.
- Direct Safe `execTransaction`, observable standard module entrypoints and configured MultiSend batches are decoded. Opaque custom-module wrappers, unconfigured non-standard batching, delegatecall effects beyond packed calldata and generic traces are not.
- Safe-native owner, threshold, module, guard and fallback events are decoded and correlated. Standard module execution events are also monitored, but module-specific wrapper calldata remains opaque when the outer transaction does not expose a supported Safe entrypoint; generic traces are deliberately absent.
- The bounded ENS Endowment and Zodiac adapter reconstructs 5/5 module executions and 6/6 leaf operations. Historical permission introspection supports one verified Roles v2 layout and selected executed-value hash membership; arbitrary condition semantics, unconfigured wrappers and trace-only internals remain unavailable.
- The monitor cannot determine what a Safe signer saw, whether a frontend was compromised, or whether a human signature was deceived.
- No governance proposal metadata mapping.
- No AI enrichment.
- No notification integrations.
- No automated transaction submission or response.
- No complex risk scoring.
- Protocol-specific events must be configured explicitly.
- EIP-1967 monitoring requires explicitly configured proxy addresses.
- Allowlist severity refinement is simple and depends on maintained config.
- The scanner detects observable signals but does not explain every protocol-level consequence.
- RPC requests are bounded and retried, but there is no fallback provider, quorum, or health-based provider rotation.
- Historical progress is held in memory; a failed run writes no final alert file and must be restarted from the requested range.
- Economic percentages use ERC-20 `balanceOf` and gross `Transfer` outflows only; they do not establish asset value, solvency, backing, exploit intent, or contagion impact.
- Fee-on-transfer, rebasing, callback-driven, proxy-migrated, or otherwise non-standard token accounting may diverge from observed Transfer totals.
- Balance sampling covers boundaries, configured intervals, and critical-contract movement blocks; it is not continuous state tracing.
- Outflow concentration currently has no separately configured minimum gross-volume gate. A real control window produced a WARNING for a normal 1.3119 rsETH single-recipient bridge release.

## Current Economic Monitoring

The optional `economicMonitoring` pipeline now provides large-transfer, critical outflow, balance drawdown, outflow-concentration, large-mint, and drawdown-plus-concentration alerts. It is deterministic and historical, uses no external oracles, and remains disabled for existing configs that omit the section.

The live foundation adds confirmed-block cursoring, atomic checkpoints, durable alert-ID journaling, per-block EIP-1967 comparisons, bounded economic lookback, graceful shutdown, and deterministic demos. It intentionally does not add automatic rollback, external sinks, or production deployment.

## Current RPC Robustness

Phase 2 Increment 2 adds:

- explicit per-attempt timeout;
- classified transient and permanent errors with safe operation context;
- bounded exponential retries without jitter;
- configurable inclusive chunk size;
- deterministic adaptive splitting for oversized log responses;
- sequential concurrency `1`;
- fail-closed final sinks.

This is request robustness, not infrastructure monitoring or durable recovery.

## Deferred Features

### Production Live Operations

The confirmed-block loop, atomic checkpoint and durable journal exist. Production readiness still requires automatic bounded reorg rollback, provider failover/quorum, process supervision, metrics, retention, deployment, runbooks and external-delivery semantics.

### Safe Coverage Expansion

Configured standard MultiSend and Zodiac Roles v2 Manager Safe decoding are complete for their explicit registries and limits. Generic condition evaluation, arbitrary opaque modules, signature revalidation, signer-interface evidence, frontend and DNS monitoring remain separate concerns.

### Governance Proposal Metadata Mapping

Connect payload IDs and governance execution transactions to human-readable proposal metadata and affected contracts.

### EIP-1967 Proxy Discovery

Identify likely proxy contracts automatically from verified deployments, bytecode, address books, or storage probes.

### Dashboard or Alert UI

Provide a simple review interface for recent alerts, severity, rules, and metadata.

### Notification Integration

Send alerts to Slack, Discord, email, webhook endpoints, or incident queues.

### AI-Assisted Alert Summaries

Use AI to summarize and explain deterministic alerts after detection. AI should enrich alerts, not decide whether the event occurred.

### Additional Protocol-Specific Economic Modules

Add modules for:

- price-valued liquidity imbalance;
- protocol-specific vault accounting reconciliation;
- oracle deviation;
- reserve health;
- pool utilization anomalies;
- bridge or cross-chain message risk.

## Recommended Development Order

1. Automatic bounded reorg recovery and journal reconciliation.
2. Extend bounded Zodiac condition evaluation only for explicitly supported operators and add provenance-aware permission drift checks, without auto-allowlisting observed calls.
3. Broader protocol-governance policy maintenance and additional historical controls.
4. Governance proposal metadata mapping.
5. EIP-1967 proxy discovery.
6. Dashboard and notification integrations.
7. AI-assisted summaries and additional protocol-specific economic modules.

## v0.1 Principle

The current version should remain deterministic, explainable, and config-driven. It is a monitoring prototype, not an autonomous security platform.
