# Sample Alerts

This document contains representative historical alerts plus clearly labelled synthetic replay examples. Values are shortened where appropriate; shortened excerpts are not intended to replace the canonical JSONL artefacts.

## Provenance guide

| Label | Meaning | Canonical source |
| --- | --- | --- |
| Historical | Produced from verified Ethereum RPC data during a fail-closed calibration | Dedicated fixture under `alerts/` |
| Synthetic | Produced by a deterministic offline fixture | Named `npm run ...replay...` or `npm run economic:demo` command |
| Excerpt | Fields omitted only for readability | Full record remains in the cited JSONL |

Alert IDs do not use `createdAt`. Replaying the same canonical evidence and configuration preserves identity; live journal membership prevents a successfully recorded alert from being emitted again after restart.

## Historical KelpDAO / rsETH Outflow

Source: `alerts/economic-historical-calibration-001.jsonl`, Balanced profile, block `24908285`.

```json
{
  "id": "ethereum:CRITICAL_CONTRACT_OUTFLOW:0xA129...5A7:0x85d4...8Ef3:24908285:24908285",
  "ruleId": "CRITICAL_CONTRACT_OUTFLOW",
  "severity": "CRITICAL",
  "blockNumber": "24908285",
  "transactionHash": "economic-analysis",
  "summary": "KelpDAO Ethereum RSETH_OFTAdapter sent 116500 KelpDAO rsETH across 1 transfer(s) in block 24908285 (99.80% of prior balance).",
  "metadata": {
    "severityReason": "Gross block outflow exceeded the explicitly configured critical percentage of the prior balance.",
    "observedValue": {
      "totalOutflow": "116500000000000000000000",
      "outflowPercent": "99.80%",
      "transferCount": 1
    },
    "referenceValue": {
      "previousBlock": "24908284",
      "previousBalance": "116723520635500000000000"
    }
  }
}
```

This is incident visibility in the extraction block. It is not a pre-extraction warning.

## Historical ENS Safe Effect Confirmation

Source: `alerts/safe-multisend-historical-calibration-001.jsonl`, owner rotation transaction at block `25647884`.

```json
{
  "ruleId": "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED",
  "severity": "INFO",
  "transactionHash": "0xd646d8f1171eb33a23d8259eb237c173b13b8eb8c2060ff0860e4c21745985f1",
  "summary": "Safe control action swapOwner(address,address,address) has correlation status confirmed. Attributed to MultiSend suboperation 0.",
  "metadata": {
    "correlationStatus": "confirmed",
    "candidateSuboperations": ["0"],
    "safeCorrelation": {
      "category": "ADMINISTRATIVE_CONTROL",
      "eventsObserved": [
        { "ruleId": "SAFE_OWNER_REMOVED" },
        { "ruleId": "SAFE_OWNER_ADDED" }
      ],
      "stateBefore": { "oldOwner": true, "newOwner": false },
      "stateAfter": { "oldOwner": false, "newOwner": true }
    }
  }
}
```

## Historical ENS Endowment / Zodiac Sensitive Batch

Source: `alerts/ens-endowment-bal-cow-zodiac-permission-calibration-001.jsonl`, block `20663640`.

```json
{
  "ruleId": "SAFE_BATCH_ADMINISTRATIVE_ANOMALY",
  "severity": "CRITICAL",
  "transactionHash": "0x1bb8d5d64359b002aa6d5d2bfd449d5593e51568bbac0baed05c6705abf3e13e",
  "summary": "MultiSend batch combines 2 independently sensitive administrative or asset actions.",
  "metadata": {
    "executionPath": "MODULE",
    "module": {
      "name": "ENS Endowment Zodiac Roles Modifier v2",
      "zodiacRoles": { "roleKey": "0x4d414e4147455200000000000000000000000000000000000000000000000000" }
    },
    "multiSend": {
      "componentSignals": [
        {
          "kind": "approval",
          "path": "0",
          "parameters": {
            "amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935"
          }
        },
        { "kind": "delegatecall", "path": "1" }
      ]
    }
  }
}
```

The bounded permission calibration found both leaves authorized by the selected Zodiac role. The CRITICAL remains an explicit composition-sensitivity alert, not an incident or permission-denial claim.

## Governance Payload Executed

Source:

- Aave Governance V3 payload scan;
- block range `25423360-25423459`;
- payload ID `453`.

```json
{
  "chain": "ethereum",
  "ruleId": "GOVERNANCE_PAYLOAD_EXECUTED",
  "ruleName": "Governance Payload Executed",
  "severity": "INFO",
  "eventSignature": "PayloadExecuted(uint40)",
  "blockNumber": "25423360",
  "transactionHash": "0x14c3acdb367a62c25d2a405f97a08ddae6399714032f1060167af4cc7b9d47c8",
  "address": "0xdabad81af85554e9ae636395611c58f7ec1aaec5",
  "summary": "Governance payload executed: payloadId 453.",
  "metadata": {
    "source": "eth_getLogs",
    "decoded": {
      "payloadId": 453
    }
  }
}
```

## Proxy Implementation Slot Changed

Source:

- Aave EIP-1967 upgrade detection scan;
- block range `25199939-25199939`.

```json
{
  "chain": "ethereum",
  "ruleId": "PROXY_IMPLEMENTATION_SLOT_CHANGED",
  "ruleName": "Proxy Implementation Slot Changed",
  "severity": "WARNING",
  "eventSignature": "EIP1967_IMPLEMENTATION_SLOT",
  "blockNumber": "25199939",
  "transactionHash": "storage-diff",
  "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
  "summary": "Proxy implementation slot changed for AaveV3Ethereum.POOL: 0x8147b99DF7672A21809c9093E6F6CE1a60F119Bd -> 0x728a138A4823392C2EFA55e028d434F526fE03CF.",
  "metadata": {
    "source": "eth_getStorageAt",
    "eip1967": {
      "proxyName": "AaveV3Ethereum.POOL",
      "slotKind": "implementation",
      "beforeBlock": "25199938",
      "afterBlock": "25199939",
      "previousAddress": "0x8147b99DF7672A21809c9093E6F6CE1a60F119Bd",
      "newAddress": "0x728a138A4823392C2EFA55e028d434F526fE03CF"
    },
    "severityReason": {
      "originalSeverity": "WARNING",
      "finalSeverity": "WARNING",
      "matchedAllowlist": true,
      "allowlist": "knownImplementations",
      "reason": "New implementation is in knownImplementations allowlist."
    }
  }
}
```

## Proxy Upgraded

Source:

- Aave upgrade detection scan;
- `Upgraded(address)` event emitted by the Aave Pool proxy.

```json
{
  "chain": "ethereum",
  "ruleId": "PROXY_UPGRADED",
  "ruleName": "Proxy Implementation Upgraded",
  "severity": "WARNING",
  "eventSignature": "Upgraded(address)",
  "blockNumber": "25199939",
  "transactionHash": "0xe9949c36e86fc9f481897dbac8de33d655bff20b267955a303e2e5643fbc2b35",
  "address": "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
  "summary": "Proxy upgraded to implementation 0x728a138A4823392C2EFA55e028d434F526fE03CF.",
  "metadata": {
    "source": "eth_getLogs",
    "decoded": {
      "implementation": "0x728a138A4823392C2EFA55e028d434F526fE03CF"
    },
    "severityReason": {
      "originalSeverity": "WARNING",
      "finalSeverity": "WARNING",
      "matchedAllowlist": true,
      "allowlist": "knownProxyAddresses",
      "reason": "Upgrade event emitter is in knownProxyAddresses allowlist."
    }
  }
}
```

## Role Granted

Source:

- Aave upgrade detection scan;
- `RoleGranted(bytes32,address,address)` emitted by the Aave ACL Manager.

```json
{
  "chain": "ethereum",
  "ruleId": "ROLE_GRANTED",
  "ruleName": "Ownership/Admin Changed",
  "severity": "WARNING",
  "eventSignature": "RoleGranted(bytes32,address,address)",
  "blockNumber": "25199939",
  "transactionHash": "0xe9949c36e86fc9f481897dbac8de33d655bff20b267955a303e2e5643fbc2b35",
  "address": "0xc2aacf6553d20d1e9d78e365aaba8032af9c85b0",
  "summary": "Role granted: 0x8aa855a911518ecfbe5bc3088c8f3dda7badf130faaf8ace33fdc33828e18167 to 0x13a9CC64344b02bACC5AD9Cf38B5711F1B9ec3d4 by 0x5300A1a15135EA4dc7aD5a167152C01EFc9b192A.",
  "metadata": {
    "source": "eth_getLogs",
    "decoded": {
      "role": "0x8aa855a911518ecfbe5bc3088c8f3dda7badf130faaf8ace33fdc33828e18167",
      "account": "0x13a9CC64344b02bACC5AD9Cf38B5711F1B9ec3d4",
      "sender": "0x5300A1a15135EA4dc7aD5a167152C01EFc9b192A"
    }
  }
}
```

## Synthetic Critical Contract Outflow

Source: `npm run economic:demo`. This is an offline fixture, not a historical incident replay.

```json
{
  "ruleId": "CRITICAL_CONTRACT_OUTFLOW",
  "severity": "CRITICAL",
  "eventSignature": "Transfer(address,address,uint256)",
  "blockNumber": "105",
  "transactionHash": "economic-analysis",
  "address": "0x1000000000000000000000000000000000000001",
  "summary": "Synthetic Integrated Vault sent 700 Synthetic Restaked Asset across 2 transfer(s) in block 105 (70.00% of prior balance).",
  "metadata": {
    "severityReason": "Gross block outflow exceeded the explicitly configured critical percentage of the prior balance.",
    "threshold": {
      "singleBlockOutflowAbsolute": "500",
      "singleBlockOutflowPercent": 10,
      "criticalOutflowPercent": 50
    },
    "observedValue": {
      "totalOutflow": "700",
      "outflowPercent": "70.00%",
      "transferCount": 2
    },
    "referenceValue": {
      "previousBlock": "104",
      "previousBalance": "1000"
    }
  }
}
```

## Synthetic Correlated Economic Anomaly

Source: `npm run economic:demo`. Component IDs are shortened here only for readability.

```json
{
  "ruleId": "ECONOMIC_SECURITY_ANOMALY",
  "severity": "CRITICAL",
  "eventSignature": "ECONOMIC_SIGNAL_CORRELATION",
  "blockNumber": "105",
  "transactionHash": "economic-analysis",
  "summary": "Synthetic Integrated Vault shows both rapid Synthetic Restaked Asset balance deterioration and concentrated outflow within blocks 99-105; investigate potential compromise or contagion.",
  "metadata": {
    "severityReason": "A configured balance drawdown and concentrated outflow affected the same asset and critical contract within one window.",
    "observedValue": {
      "componentSignals": [
        "LIQUIDITY_DRAWDOWN",
        "OUTFLOW_CONCENTRATION"
      ]
    },
    "referenceValue": {
      "componentAlertIds": [
        "ethereum:LIQUIDITY_DRAWDOWN:...",
        "ethereum:OUTFLOW_CONCENTRATION:..."
      ]
    }
  }
}
```

## Synthetic Safe Policy Violation

Source: `npm run live:replay:safe`. This is a synthetic fixture, not a Bybit replay.

```json
{
  "ruleId": "SAFE_POLICY_VIOLATION",
  "severity": "WARNING",
  "eventSignature": "Safe.execTransaction",
  "blockNumber": "100",
  "transactionHash": "0x...02",
  "address": "0x1000000000000000000000000000000000000001",
  "summary": "Safe operation violated policy: target.",
  "metadata": {
    "safe": {
      "innerTarget": "0x3000000000000000000000000000000000000003",
      "innerSelector": "0xa9059cbb",
      "operation": "CALL",
      "policy": {
        "compliant": false,
        "violations": [
          {
            "kind": "target",
            "reason": "Inner target is not in allowedTargets."
          }
        ]
      }
    }
  }
}
```

## Synthetic Safe Administrative Effect Confirmed

Source: `npm run live:replay:safe`. EIP-1967 target, block and implementation match decoded `upgradeTo(address)` calldata.

```json
{
  "ruleId": "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED",
  "severity": "INFO",
  "eventSignature": "Safe.execTransaction+administrative-effects",
  "blockNumber": "100",
  "transactionHash": "0x...05",
  "summary": "Safe action upgradeTo(address) is confirmed by 1 observable administrative effect(s).",
  "metadata": {
    "safeCorrelation": {
      "status": "confirmed",
      "target": "0x2000000000000000000000000000000000000002",
      "componentRuleIds": [
        "PROXY_IMPLEMENTATION_SLOT_CHANGED"
      ],
      "comparisons": [
        {
          "ruleId": "PROXY_IMPLEMENTATION_SLOT_CHANGED",
          "expected": "0x4000000000000000000000000000000000000004",
          "observed": "0x4000000000000000000000000000000000000004",
          "matches": true
        }
      ]
    }
  }
}
```

## Synthetic Safe MultiSend Policy Violation

Source: `npm run live:replay:multisend`. This is a synthetic batch, not historical or signer-intent evidence.

```json
{
  "ruleId": "SAFE_MULTISEND_POLICY_VIOLATION",
  "severity": "WARNING",
  "eventSignature": "Safe.execTransaction+MultiSend.multiSend",
  "blockNumber": "100",
  "transactionHash": "0x...02",
  "summary": "MultiSend batch contains 1 explicit policy violation(s) across 1 operation scope(s).",
  "metadata": {
    "multiSend": {
      "contract": {
        "name": "Synthetic MultiSend",
        "address": "0x7000000000000000000000000000000000000007",
        "mode": "MULTISEND"
      },
      "violations": [
        {
          "suboperationIndex": 1,
          "suboperationPath": "1",
          "target": "0x3000000000000000000000000000000000000003",
          "selector": "0xa9059cbb",
          "operation": "CALL",
          "violations": [
            {
              "kind": "target",
              "reason": "Inner target is not in allowedTargets."
            }
          ]
        }
      ]
    }
  }
}
```

## Synthetic Ambiguous MultiSend Effect

When two same-target upgrade suboperations can both explain one `Upgraded` event, the monitor does not choose one:

```json
{
  "ruleId": "SAFE_ADMINISTRATIVE_EFFECT_AMBIGUOUS",
  "severity": "WARNING",
  "metadata": {
    "correlationStatus": "ambiguous",
    "candidateSuboperations": ["0", "1"]
  }
}
```

## Synthetic Native Safe Threshold Effect

Source: `npm run live:replay:safe-events`. The fixture correlates decoded `changeThreshold(2)` with `ChangedThreshold(2)` and preserves prior/post historical state:

```json
{
  "ruleId": "SAFE_ADMINISTRATIVE_EFFECT_CONFIRMED",
  "severity": "INFO",
  "metadata": {
    "correlationStatus": "confirmed",
    "candidateSuboperations": ["1"],
    "safeCorrelation": {
      "category": "ADMINISTRATIVE_CONTROL",
      "intention": {
        "function": "changeThreshold(uint256)",
        "parameters": { "threshold": "2" }
      },
      "stateBefore": { "threshold": "3" },
      "stateAfter": { "threshold": "2" },
      "suboperationPath": "1"
    }
  }
}
```

An unknown `EnabledModule` on a critical Safe is separately CRITICAL and includes `severityReason`, `observedValue`, `expectedPolicy`, and `policyMatched: false`. This is policy evidence, not proof of compromise.

## Synthetic Safe Module Policy Violation

Source: `npm run live:replay:safe-modules`:

```json
{
  "ruleId": "SAFE_MODULE_POLICY_VIOLATION",
  "severity": "CRITICAL",
  "eventSignature": "Safe.execTransactionFromModule",
  "metadata": {
    "source": "safe-module-analysis",
    "moduleAddress": "0x3000000000000000000000000000000000000003",
    "enabledState": {
      "enabledBefore": true,
      "enabledAfter": true,
      "enabledAtExecution": true
    },
    "transaction": {
      "target": "0x6000000000000000000000000000000000000006",
      "selector": "0x3659cfe6",
      "operation": "DELEGATECALL"
    },
    "violations": [
      { "scope": "safe", "kind": "target" },
      { "scope": "module", "kind": "operation" }
    ]
  }
}
```

The fixture demonstrates explicit policy intersection. It does not establish compromise or signer intent.
