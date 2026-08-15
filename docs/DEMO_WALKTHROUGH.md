# Frozen Demo Walkthrough

Demo snapshot: **2026-08-02**.

This walkthrough presents three validated verticals without changing detectors or requiring live infrastructure for the main demonstration. It separates:

- **offline replay** — deterministic fixtures stored in the repository;
- **historical calibration** — real Ethereum transactions and state read through an archive-capable RPC;
- **live foundation** — implemented confirmed-block execution, but not used as an indefinite demo command.

Never describe a fixture replay as a fresh historical RPC reproduction. The historical artefacts and methodology are the evidence for real cases.

## 1. Prepare and verify

Install exactly the locked dependency graph:

```bash
npm ci
```

Run the offline regression gate:

```bash
npm test
npm run smoke
npm run typecheck
npm run build
```

Expected outcome: every command exits `0`. None needs an RPC.

For real historical calibration only:

```bash
cp .env.example .env
```

Set `ETH_RPC_URL` to an archive-capable Ethereum endpoint. Do not print or commit the URL. The calibrations require historical logs, blocks, transactions, receipts, `eth_call`, code, and storage according to each case.

## 2. Product flow to explain

```text
historical range or confirmed live blocks
                  |
                  v
       bounded, retrying RPC policy
                  |
                  v
 logs + transactions + receipts + storage + balances
                  |
       +----------+-----------+
       |          |           |
       v          v           v
 admin/Safe    EIP-1967    economics
 direct call   slot diff   movements/balances
 MultiSend                 anomalies/correlation
 module/Zodiac
       +----------+-----------+
                  v
       ordered explainable alerts
                  |
       terminal + JSONL + live journal/checkpoint
```

The same detectors and alert schema are shared by historical and live execution. Live adds confirmed cursoring, hash validation, durable IDs, and checkpointing; it does not add different detection semantics.

## 3. Demo A — KelpDAO / rsETH

### Security question

Would a balance-and-transfer monitor have surfaced the release of 116,500 rsETH from the configured KelpDAO Ethereum adapter, and when?

### Offline replay

```bash
npm run live:replay:kelp
```

Expected key lines:

```text
KelpDAO/rsETH offline incremental replay (fixture, not live RPC)
block 24908284: no incident alerts
block 24908285: extraction alert emitted (...)
restart: checkpoint restored (simulated using durable journal fixture)
replay 24908285: 0 duplicate alerts emitted (journal format verified)
first Aave interaction: approximately 192 seconds later
```

The block may print several extraction rule IDs. The product point is that all incident signals begin at block `24908285`, and replay after restart emits zero duplicates.

### Historical evidence

```bash
npm run economic:calibrate
```

This runs Conservative, Balanced, and Sensitive profiles over one 66-block incident window and one equal-length active control window. It writes only after all runs succeed.

Balanced result:

| Metric | Result |
| --- | ---: |
| Incident range | `24908265-24908330` |
| Control range | `24902787-24902852` |
| Token transfers in incident range | 60 |
| Incident alerts | 15 |
| Control alerts | 1 WARNING |
| Adapter prior balance | 116,723.5206355 rsETH |
| Extraction | 116,500 rsETH |
| Drawdown | 99.80% |
| First signal | block `24908285` |
| First Aave interaction | +16 blocks / approximately 192 seconds |

Representative alert:

```text
CRITICAL_CONTRACT_OUTFLOW / CRITICAL
KelpDAO Ethereum RSETH_OFTAdapter sent 116500 KelpDAO rsETH across
1 transfer in block 24908285 (99.80% of prior balance).
```

Interpretation:

- Onchain Radar detected the extraction in the block where it occurred.
- It did not warn before the extraction.
- The on-chain signal preceded the first relevant Aave supply in the reconstructed sequence, but any defensive response would depend on confirmation delay, operational authority, and protocol controls.
- Verdict: `USEFUL INCIDENT DETECTION`, not exploit prevention.

Evidence:

- `config/economic.historical-calibration-001.json`
- `alerts/economic-historical-calibration-001.jsonl`
- `config/economic.historical-calibration-001.json`
- `alerts/economic-historical-calibration-001.jsonl`

## 4. Demo B — ENS Safe MultiSend

### Security question

Can Onchain Radar unpack a real Safe batch, evaluate each internal operation, separate routine treasury activity from control changes, and confirm the effects?

### Offline parser and policy replay

```bash
npm run live:replay:multisend
npm run live:replay:safe-events
```

The first replay demonstrates:

- a permitted batch;
- an unknown target;
- a prohibited nested delegatecall;
- an unknown implementation upgrade;
- a composed sensitive batch;
- a confirmed effect;
- malformed-payload rejection with no partial interpretation;
- zero duplicates after journal restoration.

The second demonstrates:

- `swapOwner` correlated with `RemovedOwner` and `AddedOwner`;
- `changeThreshold` correlated with `ChangedThreshold`;
- CRITICAL handling for an unknown module on a critical Safe;
- financial operations classified separately from administrative control;
- suppression of routine transfer subcall noise under `sensitive-only`;
- zero duplicates after restart.

Both commands use synthetic fixtures. They demonstrate behavior, not ENS history.

### Historical ENS calibration

```bash
npm run safe:multisend:calibrate
```

Real sample:

| Category | Block | Transaction | Batch |
| --- | ---: | --- | --- |
| Routine | `21746761` | `0xb7dbea…d9772` | 10 USDC contributor transfers |
| Sensitive | `25647884` | `0xd646d8…985f1` | 3 owner swaps and threshold confirmation |
| Composed | `22406922` | `0xc3ba44…5727a` | WETH deposit, approval, and CoW presignature |

Validated result:

| Metric | Result |
| --- | ---: |
| Parsed suboperations | 17/17 |
| Classified suboperations | 16/17 (94.12%) |
| Confirmed owner/threshold correlations | 4 |
| Ambiguous correlations | 0 |
| Replay duplicates | 0 |
| Recommended profile | Balanced |

The parser consumes every packed payload exactly and preserves path order. Routine ERC-20 transfers are `FINANCIAL_OPERATION`, not `SAFE_SENSITIVE_ADMIN_ACTION`. Unknown selectors remain visible instead of being labelled malicious.

Representative confirmed effect:

```text
SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED / INFO
Safe control action swapOwner(address,address,address) has correlation status
confirmed. Attributed to MultiSend suboperation 0.
```

Evidence:

- `config/safe-multisend-historical-calibration-001.json`
- `alerts/safe-multisend-historical-calibration-001.jsonl`
- `config/safe-multisend-historical-calibration-001.json`
- `alerts/safe-multisend-historical-calibration-001.jsonl`

## 5. Demo C — ENS Endowment / Zodiac Roles v2

### Security question

Can the monitor follow a Manager Safe through a configured Zodiac Roles module, recover downstream calls without traces, and distinguish missing local policy from actual role authorization?

### Offline module and adapter replay

```bash
npm run live:replay:safe-modules
npm run live:replay:zodiac-roles
```

The module replay covers enabled-state, unknown/disabled modules, delegatecall, unknown upgrade, downstream MultiSend, administrative correlation, explicit undecoded fallback, and restart deduplication.

The Zodiac replay covers direct and MultiSend Manager Safe envelopes, ordered role keys, downstream leaves, a confirmed upgrade fixture, unknown-wrapper preservation, and zero duplicates. It is synthetic and does not claim human intent.

### Historical ENS Endowment calibration

```bash
npm run safe:modules:calibrate
```

Real sample:

| Category | Block | Reconstructed operation |
| --- | ---: | --- |
| Routine | `25539670` | Aave V3 DAI withdrawal |
| Composed | `25553567` | approval plus withdrawal request |
| Delegatecall/MultiSend | `20663640` | BAL approval plus CoW settlement operation |
| Material native value | `25597124` | 1,023.8 ETH submitted to Lido stETH |

Validated reconstruction:

| Metric | Result |
| --- | ---: |
| Module executions | 5/5 |
| Leaf operations | 6/6 |
| Explicit undecoded operations | 0 |
| Stable IDs | yes |
| Replay duplicates | 0 |
| Confirmed administrative/EIP-1967 effects in sample | 0; none existed in the selected receipts/state |

For the BAL/CoW batch, bounded read-only inspection verified:

- role key `MANAGER`;
- the canonical supported Roles v2 mastercopy and storage layout;
- configured MultiSend transaction unwrapper;
- BAL `approve(address,uint256)` as CALL for the executed allowed spender hash;
- CoW `signOrder(...)` as DELEGATECALL for the executed BAL/USDC hashes and Safe receiver.

After evidence-backed policy calibration, Balanced moved from `18 alerts / 3 WARNING / 5 CRITICAL` to `16 / 2 / 1`. No observed call was auto-allowlisted and no detector or severity changed.

The remaining CRITICAL is:

```text
SAFE_BATCH_ADMINISTRATIVE_ANOMALY / CRITICAL
MultiSend batch combines an unlimited BAL approval with a delegatecall.
```

It is a sensitivity signal, not an assertion that Zodiac denied the operation or that an incident occurred.

Evidence:

- `config/safe-modules-historical-calibration-001.json`
- `alerts/safe-modules-historical-calibration-001.jsonl`
- `alerts/ens-endowment-bal-cow-zodiac-permission-calibration-001.jsonl`
- `config/safe-modules-historical-calibration-001.json`
- `alerts/safe-modules-historical-calibration-001.jsonl`
- `alerts/ens-endowment-bal-cow-zodiac-permission-calibration-001.jsonl`

## 6. Ten-minute presentation sequence

Use this path when network access is not guaranteed:

```bash
npm test
npm run live:replay:kelp
npm run live:replay:multisend
npm run live:replay:safe-events
npm run live:replay:zodiac-roles
```

Then open, in order:

1. `alerts/economic-historical-calibration-001.jsonl` — real economic alert evidence.
2. `alerts/safe-multisend-historical-calibration-001.jsonl` — real Safe batch/effect evidence.
3. `alerts/ens-endowment-bal-cow-zodiac-permission-calibration-001.jsonl` — real module/Zodiac policy-calibrated evidence.
4. [Sample Alerts](SAMPLE_ALERTS.md) — readable excerpts.
5. [Limitations](LIMITATIONS_AND_NEXT_STEPS.md) — explicit product boundary.

## 7. What not to claim

| Demonstrated | Not demonstrated |
| --- | --- |
| Same-block KelpDAO incident detection | Warning before bridge extraction |
| Post-execution Safe intent reconstruction | What Safe signers saw or intended |
| Exact configured MultiSend parsing | Generic trace reconstruction |
| Enabled module and bounded Zodiac wrapper reconstruction | Support for every Safe module or Zodiac condition tree |
| Local durable alert-ID deduplication | Distributed exactly-once delivery |
| Confirmed-block processing and hash mismatch stop | Automatic reorg rollback |
| Explainable policy violations and correlations | Automatic containment or proof of exploit |

## 8. Artefact safety

- Offline replays use temporary state and do not require RPC.
- Historical calibrations have dedicated configs and artefacts; they do not replace `config/monitor.config.json`.
- Calibration output is fail-closed and is only replaced after the full run succeeds.
- `npm run scan` overwrites its range-specific historical JSONL only after successful completion.
- `npm run live` is append-oriented and continuous; it is intentionally excluded from the default demo command sequence.

The frozen demo is a credible post-execution monitoring prototype. It is not a production service, prevention system, or substitute for protocol-specific response authority.
