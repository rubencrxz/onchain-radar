import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  correlateEconomicAnomalies,
  detectCriticalContractOutflows,
  detectLargeMints,
  detectLargeTransfers,
  detectLiquidityDrawdowns,
  detectOutflowConcentrations
} from "../src/economic/detectors.js";
import { ZERO_ADDRESS } from "../src/economic/types.js";
import { FIXED_CREATED_AT } from "./fixtures.js";
import {
  ECON_TOKEN_B,
  ECON_USER_A,
  ECON_USER_B,
  ECON_VAULT,
  ECON_VAULT_B,
  economicAsset,
  economicConfig,
  movement,
  observation
} from "./economicFixtures.js";

const clock = () => FIXED_CREATED_AT;

describe("large economic transfers and mints", () => {
  test("uses strict absolute thresholds and distinguishes critical involvement", () => {
    const below = movement({ from: ECON_USER_A, to: ECON_USER_B, value: 99n });
    const exact = movement({ from: ECON_USER_A, to: ECON_USER_B, value: 100n, logIndex: 1 });
    const external = movement({ from: ECON_USER_A, to: ECON_USER_B, value: 101n, logIndex: 2 });
    const critical = movement({ from: ECON_VAULT, to: ECON_USER_A, value: 101n, logIndex: 3 });
    const alerts = detectLargeTransfers([below, exact, external, critical], clock).map((result) => result.alert);

    assert.deepEqual(alerts.map((alert) => alert.severity), ["INFO", "WARNING"]);
    assert.deepEqual(alerts.map((alert) => alert.ruleId), ["LARGE_ASSET_TRANSFER", "LARGE_ASSET_TRANSFER"]);
    assert.equal((alerts[0]?.metadata.observedValue as { transferAmount: string }).transferAmount, "101");
  });

  test("detects only extraordinary mints and never confuses a burn with a mint", () => {
    const normalMint = movement({ from: ZERO_ADDRESS, to: ECON_USER_A, value: 100n });
    const largeMint = movement({ from: ZERO_ADDRESS, to: ECON_USER_A, value: 101n, logIndex: 1 });
    const burn = movement({ from: ECON_USER_A, to: ZERO_ADDRESS, value: 1000n, logIndex: 2 });
    const alerts = detectLargeMints([normalMint, largeMint, burn], clock).map((result) => result.alert);

    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.ruleId, "LARGE_TOKEN_MINT");
    assert.equal(alerts[0]?.severity, "INFO");
    assert.match(alerts[0]?.summary ?? "", /does not determine whether.*backed or authorized/i);
  });

  test("keeps IDs stable independently from createdAt", () => {
    const item = movement({ from: ECON_USER_A, to: ECON_USER_B, value: 101n });
    const first = detectLargeTransfers([item], () => "2026-01-01T00:00:00.000Z")[0]!.alert;
    const second = detectLargeTransfers([item], () => "2027-01-01T00:00:00.000Z")[0]!.alert;
    assert.equal(first.id, second.id);
    assert.notEqual(first.createdAt, second.createdAt);
  });
});

describe("critical contract outflow", () => {
  test("aggregates gross outflows per block, excludes inflows and reports recipients once", () => {
    const asset = economicAsset();
    const movements = [
      movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: 400n, blockNumber: 100n }),
      movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: 200n, blockNumber: 100n, logIndex: 1 }),
      movement({ asset, from: ECON_USER_B, to: ECON_VAULT, value: 500n, blockNumber: 100n, logIndex: 2 })
    ];
    const results = detectCriticalContractOutflows({
      config: economicConfig([asset]),
      movements,
      observations: [observation({ asset, blockNumber: 99n, balance: 1000n })],
      clock
    });

    assert.equal(results.length, 1);
    const alert = results[0]!.alert;
    assert.equal(alert.severity, "CRITICAL");
    assert.deepEqual(alert.metadata.observedValue, {
      totalOutflow: "600",
      outflowPercent: "60.00%",
      transferCount: 2
    });
    assert.equal((alert.metadata.principalRecipients as unknown[]).length, 1);
  });

  test("can trigger only from prior-balance percentage and is strict at equality", () => {
    const asset = economicAsset({
      thresholds: {
        ...economicAsset().thresholds,
        singleBlockOutflowAbsolute: 10_000n,
        criticalOutflowPercent: 50
      }
    });
    const exact = movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: 100n, blockNumber: 100n });
    const above = movement({ asset, from: ECON_VAULT, to: ECON_USER_B, value: 101n, blockNumber: 101n });
    const results = detectCriticalContractOutflows({
      config: economicConfig([asset]),
      movements: [exact, above],
      observations: [
        observation({ asset, blockNumber: 99n, balance: 1000n }),
        observation({ asset, blockNumber: 100n, balance: 1000n })
      ],
      clock
    });
    assert.deepEqual(results.map((result) => result.window.toBlock), [101n]);
  });

  test("keeps multiple recipients in deterministic amount order", () => {
    const asset = economicAsset();
    const results = detectCriticalContractOutflows({
      config: economicConfig([asset]),
      movements: [
        movement({ asset, from: ECON_VAULT, to: ECON_USER_B, value: 400n }),
        movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: 200n, logIndex: 1 })
      ],
      observations: [observation({ asset, blockNumber: 99n, balance: 2000n })],
      clock
    });
    const recipients = results[0]!.alert.metadata.principalRecipients as Array<{ address: string }>;
    assert.deepEqual(recipients.map((recipient) => recipient.address), [ECON_USER_B, ECON_USER_A]);
  });
});

describe("liquidity drawdown", () => {
  test("does not alert below or exactly at threshold, but alerts above within the exact window", () => {
    const asset = economicAsset();
    const base = { config: economicConfig([asset]), clock };
    assert.equal(
      detectLiquidityDrawdowns({
        ...base,
        observations: [observation({ asset, blockNumber: 100n, balance: 1000n }), observation({ asset, blockNumber: 120n, balance: 801n })]
      }).length,
      0
    );
    assert.equal(
      detectLiquidityDrawdowns({
        ...base,
        observations: [observation({ asset, blockNumber: 100n, balance: 1000n }), observation({ asset, blockNumber: 120n, balance: 800n })]
      }).length,
      0
    );
    const above = detectLiquidityDrawdowns({
      ...base,
      observations: [observation({ asset, blockNumber: 100n, balance: 1000n }), observation({ asset, blockNumber: 120n, balance: 799n })]
    });
    assert.equal(above.length, 1);
    assert.equal(above[0]?.window.toBlock - above[0]!.window.fromBlock, 20n);
    assert.equal(above[0]?.alert.severity, "WARNING");
  });

  test("uses explicit critical drawdown threshold", () => {
    const asset = economicAsset();
    const results = detectLiquidityDrawdowns({
      config: economicConfig([asset]),
      observations: [observation({ asset, blockNumber: 100n, balance: 1000n }), observation({ asset, blockNumber: 110n, balance: 400n })],
      clock
    });
    assert.equal(results[0]?.alert.severity, "CRITICAL");
    assert.equal((results[0]?.alert.metadata.observedValue as { drawdownPercent: string }).drawdownPercent, "60.00%");
  });

  test("analyzes several contracts and assets independently", () => {
    const assetA = economicAsset({ criticalContracts: [
      { name: "Vault A", address: ECON_VAULT, role: "vault" },
      { name: "Vault B", address: ECON_VAULT_B, role: "lending-pool" }
    ] });
    const assetB = economicAsset({ name: "Asset B", tokenAddress: ECON_TOKEN_B });
    const observations = [
      observation({ asset: assetA, criticalContract: assetA.criticalContracts[0], blockNumber: 1n, balance: 1000n }),
      observation({ asset: assetA, criticalContract: assetA.criticalContracts[0], blockNumber: 2n, balance: 700n }),
      observation({ asset: assetA, criticalContract: assetA.criticalContracts[1], blockNumber: 1n, balance: 1000n }),
      observation({ asset: assetA, criticalContract: assetA.criticalContracts[1], blockNumber: 2n, balance: 700n }),
      observation({ asset: assetB, blockNumber: 1n, balance: 1000n }),
      observation({ asset: assetB, blockNumber: 2n, balance: 700n })
    ];
    assert.equal(detectLiquidityDrawdowns({ config: economicConfig([assetA, assetB]), observations, clock }).length, 3);
  });
});

describe("outflow concentration", () => {
  test("detects a dominant recipient and ignores balanced or exact-threshold distributions", () => {
    const asset = economicAsset();
    const dominant = detectOutflowConcentrations({
      config: economicConfig([asset]),
      movements: [
        movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: 61n }),
        movement({ asset, from: ECON_VAULT, to: ECON_USER_B, value: 39n, logIndex: 1 })
      ],
      startBlock: 100n,
      clock
    });
    assert.equal(dominant.length, 1);
    assert.equal((dominant[0]?.alert.metadata.observedValue as { recipient: string }).recipient, ECON_USER_A);

    const balanced = [50n, 60n].map((first, index) =>
      detectOutflowConcentrations({
        config: economicConfig([asset]),
        movements: [
          movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: first }),
          movement({ asset, from: ECON_VAULT, to: ECON_USER_B, value: 100n - first, logIndex: index + 1 })
        ],
        startBlock: 100n,
        clock
      }).length
    );
    assert.deepEqual(balanced, [0, 0]);
  });

  test("breaks equal-recipient ties by normalized address", () => {
    const asset = economicAsset({ thresholds: { ...economicAsset().thresholds, concentrationPercent: 40 } });
    const results = detectOutflowConcentrations({
      config: economicConfig([asset]),
      movements: [
        movement({ asset, from: ECON_VAULT, to: ECON_USER_B, value: 50n }),
        movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: 50n, logIndex: 1 })
      ],
      startBlock: 100n,
      clock
    });
    assert.equal((results[0]?.alert.metadata.observedValue as { recipient: string }).recipient, ECON_USER_A);
  });
});

describe("minimal economic correlation", () => {
  function componentSignals(outflowBlock = 110n) {
    const asset = economicAsset({ thresholds: { ...economicAsset().thresholds, criticalDrawdownPercent: 80 } });
    const drawdowns = detectLiquidityDrawdowns({
      config: economicConfig([asset]),
      observations: [observation({ asset, blockNumber: 100n, balance: 1000n }), observation({ asset, blockNumber: 110n, balance: 700n })],
      clock
    });
    const concentrations = detectOutflowConcentrations({
      config: economicConfig([asset]),
      movements: [
        movement({ asset, from: ECON_VAULT, to: ECON_USER_A, value: 80n, blockNumber: outflowBlock }),
        movement({ asset, from: ECON_VAULT, to: ECON_USER_B, value: 20n, blockNumber: outflowBlock, logIndex: 1 })
      ],
      startBlock: outflowBlock,
      clock
    });
    return { drawdowns, concentrations };
  }

  test("does not correlate a single signal or signals outside one window", () => {
    const within = componentSignals();
    assert.equal(correlateEconomicAnomalies(within.drawdowns, clock).length, 0);
    const outside = componentSignals(140n);
    assert.equal(correlateEconomicAnomalies([...outside.drawdowns, ...outside.concentrations], clock).length, 0);
  });

  test("creates one critical alert referencing both component alerts inside the window", () => {
    const signals = componentSignals();
    const results = correlateEconomicAnomalies([...signals.drawdowns, ...signals.concentrations], clock);
    assert.equal(results.length, 1);
    assert.equal(results[0]?.alert.ruleId, "ECONOMIC_SECURITY_ANOMALY");
    assert.equal(results[0]?.alert.severity, "CRITICAL");
    assert.deepEqual(results[0]?.componentAlertIds, [signals.drawdowns[0]?.alert.id, signals.concentrations[0]?.alert.id]);
    assert.deepEqual(results[0]?.alert.metadata.componentAlertIds, results[0]?.componentAlertIds);
  });
});
