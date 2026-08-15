# Real-world monitoring case studies

These are compact technical summaries of historical Ethereum analyses performed with Onchain Radar. They show how real execution paths map to observable evidence and to the product's deterministic detectors. They are portfolio evidence, not runnable calibration pipelines: development notebooks, raw provider outputs, and internal calibration files are intentionally excluded.

All three cases are post-execution analyses. “First alert” means the earliest alert constructed from the mined transaction, receipt, logs, calldata, or state observations available to the configured scanner. It does not mean a pre-execution warning, prevention, or proof of exploit intent.

## KelpDAO / rsETH adapter outflow

### What happened

At Ethereum block `24908285`, the configured KelpDAO Ethereum RSETH_OFTAdapter transferred `116,500 rsETH` to `0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b`. The adapter's observed balance fell from `116,723.5206355` rsETH at block `24908284` to `223.5206355`, a `99.80%` drawdown.

Evidence: [representative transaction](https://etherscan.io/tx/0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222), block `24908285`, token `0xA1290d69c65A6Fe4DF752f95823fae25cB99e5A7`, adapter `0x85d456B2DfF1fd8245387C0BfB64Dfb700e98Ef3`.

### Technical execution path

```text
mined ERC-20 Transfer log
        +
historical balanceOf(adapter, block-1/block)
        |
        v
Transfer normalization -> balance observations -> economic detectors
                                      |
                                      v
                         deterministic correlation alert
```

### Observable signals and product mechanisms

| Observable evidence | Onchain Radar mechanism/rule |
| --- | --- |
| ERC-20 `Transfer` of 116,500 rsETH involving a configured critical contract | Transfer normalization; `LARGE_ASSET_TRANSFER` |
| Gross outflow exceeded the configured percentage of the previous balance | `CRITICAL_CONTRACT_OUTFLOW` |
| Balance changed from 116,723.5206355 to 223.5206355 | Historical `balanceOf` sampling; `LIQUIDITY_DRAWDOWN` |
| One recipient received the complete observed outflow | `OUTFLOW_CONCENTRATION` |
| Drawdown and concentration affected the same asset/contract in one window | `ECONOMIC_SECURITY_ANOMALY` |

### Alert timing

The first signal appears in the extraction block, `24908285`, after the transfer log is mined and the relevant balance observation is available. The case does not show an earlier pre-extraction alert. The subsequent correlation is also post-execution and is derived from the same bounded historical window.

Representative output:

```text
CRITICAL_CONTRACT_OUTFLOW / CRITICAL
KelpDAO Ethereum RSETH_OFTAdapter sent 116500 KelpDAO rsETH
in block 24908285 (99.80% of prior balance).
```

### What it does not detect or prevent

The monitor does not establish why the transfer occurred, whether it was authorized, whether an off-chain or cross-chain cause existed, or whether the asset was insolvent. It does not alert before the transfer, inspect mempool intent, use prices/oracles, reconstruct generic traces, or submit a defensive transaction.

### Security takeaway

Simple Transfer monitoring becomes materially more useful when joined with historical balances, critical-contract context, recipient concentration, and deterministic correlation. The result is explainable incident visibility at execution time—not prevention.

## ENS Meta-Governance Safe MultiSend

### What happened

The ENS DAO Meta-Governance Working Group Safe executed a real transaction at block `25647884` that included owner rotation and threshold-related control changes. The representative transaction is [`0xd646d8…985f1`](https://etherscan.io/tx/0xd646d8f1171eb33a23d8259eb237c173b13b8eb8c2060ff0860e4c21745985f1). Across the selected real Safe batches, Onchain Radar parsed `17/17` packed suboperations and classified `16/17`.

### Technical execution path

```text
Safe.execTransaction(..., multiSend, ..., operation)
             |
             v
configured MultiSend packed-payload parser
             |
             v
ordered suboperations -> selector/action classification -> Safe policy
             |
             +--> receipt events: AddedOwner / RemovedOwner / ChangedThreshold
             |
             v
same-transaction administrative correlation
```

### Observable signals and product mechanisms

| Observable evidence | Onchain Radar mechanism/rule |
| --- | --- |
| Successful Safe execution event | `SAFE_EXECUTION_SUCCESS` |
| Packed MultiSend calldata and ordered inner calls | `SAFE_MULTISEND_EXECUTED`, `SAFE_MULTISEND_SUBCALL` |
| `swapOwner`/threshold control calls | Safe action classification and policy evaluation |
| `AddedOwner`, `RemovedOwner`, and `ChangedThreshold` receipt events | Native Safe event decoding |
| Decoded call and emitted/state effect agree | `SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED` |
| Target, selector, operation, owner, or threshold outside policy | Safe policy-violation rules and severity refinement |

### Alert timing

The first alerts appear after the representative transaction is mined, in block `25647884`, when its receipt/logs and calldata are available. The confirmation alert is constructed after the decoded Safe action can be correlated with the same-transaction events and state observations; it is not a pre-signature or pre-execution alert.

Representative output:

```text
SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED / INFO
Safe control action swapOwner(address,address,address) has
correlation status confirmed and is attributed to a MultiSend path.
```

### What it does not detect or prevent

The parser only expands configured MultiSend contracts within configured depth and payload limits. Unknown selectors remain unknown; arbitrary batching, generic traces, opaque custom wrappers, signer UI state, signature intent, and pre-execution simulation are outside the model. A policy match also does not prove that an action was safe in protocol context.

### Security takeaway

Multisig monitoring is stronger when it preserves the exact inner-call path and correlates calldata with emitted control effects. That turns “a Safe executed” into an auditable explanation of what changed, while keeping uncertainty explicit.

## ENS Endowment / Zodiac Roles v2

### What happened

The ENS DAO Endowment used a configured Zodiac Roles v2 module path to execute downstream calls. In the representative transaction at block `20663640`, a module-originated MultiSend contained an unlimited BAL approval and a delegatecall. Across the selected real case set, the adapter reconstructed `5/5` module executions and `6/6` leaf operations.

Evidence: [representative transaction](https://etherscan.io/tx/0x1bb8d5d64359b002aa6d5d2bfd449d5593e51568bbac0baed05c6705abf3e13e), Endowment Safe `0x4F2083f5fBede34C2714aFfb3105539775f7FE64`, Manager Safe `0xb423e0f6e7430fa29500c5cC9bd83D28c8BD8978`, Zodiac module `0x703806E61847984346d2D7DDd853049627e50A40`.

### Technical execution path

```text
Manager Safe / configured wrapper
             |
             v
Zodiac execTransactionWithRole(roleKey, ...)
             |
             v
Safe module execution event + bounded wrapper decoding
             |
             v
downstream MultiSend -> leaf calls -> module/Safe policy intersection
```

### Observable signals and product mechanisms

| Observable evidence | Onchain Radar mechanism/rule |
| --- | --- |
| Safe module execution event and enabled module state | `SAFE_MODULE_TRANSACTION_EXECUTED`, module-state checks |
| Verified Roles v2 wrapper, Manager Safe envelope, and role key | Bounded Zodiac Roles v2 adapter |
| Downstream packed calls | `SAFE_MULTISEND_EXECUTED`, `SAFE_MULTISEND_SUBCALL` |
| Unknown selector or delegatecall in a leaf | `SAFE_UNKNOWN_SELECTOR`, `SAFE_NESTED_DELEGATECALL` |
| Unlimited approval combined with delegatecall | `SAFE_BATCH_ADMINISTRATIVE_ANOMALY` |
| Supported administrative effect also visible in receipt/storage | `SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED` where applicable |

### Alert timing

For the representative transaction, the first module/MultiSend signals are constructed after the successful transaction, module event, and calldata are available at block `20663640`. The composition alert is derived from the decoded leaves in that same executed batch. It is not a warning before the module call and does not claim that the role system rejected the operation.

Representative output:

```text
SAFE_BATCH_ADMINISTRATIVE_ANOMALY / CRITICAL
MultiSend batch combines an unlimited BAL approval with a delegatecall.
```

### What it does not detect or prevent

The adapter supports explicitly verified Roles v2 layouts and configured wrappers only. It does not evaluate arbitrary Zodiac condition trees, generic module internals, trace-only calls, cross-chain consequences, or human authorization intent. A visible composition signal is not proof of compromise or malicious execution.

### Security takeaway

Security-sensitive behavior often emerges from composition—module wrapper, batch, approval, delegatecall—not from one isolated selector. Bounded recursive decoding can expose that composition without pretending to understand every custom module or authorization condition.

## Relationship to the product

The code paths exercised by these cases remain in `src/economic/`, `src/historicalScanner.ts`, `src/safe/`, `src/processor.ts`, `src/rpc.ts`, and `src/liveScanner.ts`. The synthetic `npm run demo` complements the case studies by making the same detector, parser, policy, correlation, checkpoint, and journal boundaries reproducible offline without requiring an archive RPC.
