# Source

Phase 3 implementation code lives here.

The current implementation builds on the Phase 2 Ethereum data source prototype and adds a minimal deterministic event-based alert mapper:

- TypeScript with `viem`;
- Ethereum mainnet RPC connection;
- historical block-range scanning;
- configured monitored addresses;
- configured event signatures;
- raw `eth_getLogs` fetching;
- terminal summaries for detected alerts;
- structured alert objects;
- JSONL alert output in `alerts/`.
- optional EIP-1967 implementation/admin slot diffing for explicitly configured proxies.
- simple allowlist-based severity refinement with `severityReason` metadata.
- bounded RPC timeout/retry/chunk/split policy and cached historical ERC-20 `balanceOf`.
- optional economic Transfer/balance anomaly detection and explicit correlation.

It does not implement live polling, checkpoints, reorg handling, prices/oracles, automatic proxy discovery, beacon proxy slot monitoring, Safe calldata decoding, AI enrichment, dashboard, database, mempool monitoring, or trace/debug APIs.

## Install

```bash
npm install
```

## Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Fill in:

```bash
ETH_RPC_URL=
START_BLOCK=
END_BLOCK=
```

`START_BLOCK` and `END_BLOCK` must be Ethereum block numbers. `RPC_MAX_BLOCK_RANGE` controls inclusive historical chunks and defaults to 2,000 blocks. Timeout, retries, backoff, and adaptive split depth are configured through the optional RPC variables documented in the root README and `.env.example`.

## Configure Monitor Inputs

Copy the example monitor config:

```bash
cp config/monitor.config.example.json config/monitor.config.json
```

Then edit `config/monitor.config.json`.

For the synthetic economic shape, inspect `config/economic.monitor.config.example.json`. Economic monitoring is optional and disabled when the section is absent.

For Phase 2:

- leave `monitoredAddresses` empty to scan all emitting addresses for the configured event signatures;
- add addresses to `monitoredAddresses` to restrict log fetching to specific contracts;
- add known Safe addresses to `knownMultisigs` for later multisig-oriented work;
- keep `eventSignatures` focused on the configured MVP event signatures.
- enable `proxySlotMonitoring` only when you have explicitly verified proxy addresses.
- configure `allowlists` only with addresses verified for the monitored protocol.

Example proxy slot monitoring config:

```json
{
  "proxySlotMonitoring": {
    "enabled": true,
    "proxies": [
      {
        "name": "Example Proxy",
        "address": "0x0000000000000000000000000000000000000000",
        "checkImplementationSlot": true,
        "checkAdminSlot": true
      }
    ]
  }
}
```

The scanner compares EIP-1967 implementation/admin slots at `START_BLOCK - 1` and `END_BLOCK`. If `START_BLOCK` is `0`, it uses block `0` as the before point.

Example allowlist config:

```json
{
  "allowlists": {
    "knownActors": [],
    "knownAdmins": [],
    "knownImplementations": [],
    "knownGovernanceContracts": [],
    "knownProxyAddresses": []
  }
}
```

Each allowlist entry can be an address string or an object with `name` and `address`.

## Run The Scanner

```bash
npm run scan
```

For each mapped alert, the scanner prints:

- block number;
- transaction hash;
- emitting contract address;
- matched configured event signature;
- rule ID;
- severity;
- summary.

For configured EIP-1967 proxies, it also prints slot-change alerts when implementation or admin storage changes across the scan range.

The scanner writes one structured alert object per line to:

```text
alerts/ethereum-<START_BLOCK>-<END_BLOCK>-alerts.jsonl
```

Raw topics and raw data are preserved in each alert object.

Severity refinement is intentionally small and explainable:

- unknown EIP-1967 implementation/admin slot targets can escalate to `CRITICAL`;
- known governance payload emitters remain `INFO`;
- unknown governance payload emitters become `WARNING`;
- proxy upgrade events record whether the emitting proxy is allowlisted but remain `WARNING` in v1.

Every alert includes `metadata.severityReason` after refinement.

## Current Event-Based Rules

The first Phase 3 mapper covers:

- `OwnershipTransferred(address,address)`;
- `RoleGranted(bytes32,address,address)`;
- `RoleRevoked(bytes32,address,address)`;
- `Paused(address)`;
- `Unpaused(address)`;
- `Upgraded(address)`;
- `AdminChanged(address,address)`;
- `ExecutionSuccess(bytes32,uint256)`;
- `ExecutionFailure(bytes32,uint256)`;
- `PayloadExecuted(uint40)`.

## Current Storage-Based Rules

The EIP-1967 mapper covers explicitly configured proxies only:

- `PROXY_IMPLEMENTATION_SLOT_CHANGED`;
- `PROXY_ADMIN_SLOT_CHANGED`.

Beacon proxy support and automatic proxy discovery are deferred.

## Current Economic Rules

For explicitly configured ERC-20 tokens and critical contracts:

- `LARGE_ASSET_TRANSFER`;
- `CRITICAL_CONTRACT_OUTFLOW`;
- `LIQUIDITY_DRAWDOWN`;
- `OUTFLOW_CONCENTRATION`;
- `LARGE_TOKEN_MINT`;
- `ECONOMIC_SECURITY_ANOMALY`.

Run `npm run economic:demo` for an offline synthetic example. It is not a historical exploit replay.

## Local Verification Without RPC

```bash
npm run typecheck
npm test
npm run smoke
```

The smoke check validates config loading, event signature topic hashing, and block-range chunking without requiring a real Ethereum RPC URL.
It also verifies event-to-rule mapping, EIP-1967 slot normalization/diff alerts, allowlist severity refinement, stable alert IDs, bigint-safe JSON serialization, and JSONL writing.
