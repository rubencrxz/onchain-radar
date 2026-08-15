import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseMonitorConfig } from "../src/config.js";
import { ECON_TOKEN, ECON_VAULT } from "./economicFixtures.js";

function rawConfig(economicMonitoring?: unknown): Record<string, unknown> {
  return {
    chain: "ethereum",
    monitoredAddresses: [],
    knownMultisigs: [],
    eventSignatures: ["PayloadExecuted(uint40)"],
    allowlists: {},
    ...(economicMonitoring === undefined ? {} : { economicMonitoring })
  };
}

function validEconomicRaw(): Record<string, unknown> {
  return {
    assets: [
      {
        name: "Synthetic Asset",
        tokenAddress: ECON_TOKEN.toLowerCase(),
        decimals: 18,
        criticalContracts: [{ name: "Synthetic Vault", address: ECON_VAULT.toLowerCase(), role: "vault" }],
        thresholds: {
          largeTransferAbsolute: "1000",
          singleBlockOutflowAbsolute: "5000",
          singleBlockOutflowPercent: 10,
          windowOutflowPercent: 20,
          concentrationPercent: 60,
          criticalOutflowPercent: 50,
          criticalDrawdownPercent: 55
        },
        windowBlocks: 20
      }
    ]
  };
}

describe("economic monitoring configuration", () => {
  test("keeps the section optional and preserves existing config behavior", () => {
    assert.equal(parseMonitorConfig(rawConfig()).economicMonitoring, undefined);
  });

  test("parses bigint thresholds and normalizes addresses", () => {
    const raw = validEconomicRaw();
    (((raw.assets as Record<string, unknown>[])[0]!).thresholds as Record<string, unknown>).concentrationPercent = 60.29;
    const config = parseMonitorConfig(rawConfig(raw));
    const asset = config.economicMonitoring?.assets[0];
    assert.equal(asset?.tokenAddress, ECON_TOKEN);
    assert.equal(asset?.criticalContracts[0]?.address, ECON_VAULT);
    assert.equal(asset?.thresholds.largeTransferAbsolute, 1000n);
    assert.equal(asset?.thresholds.concentrationPercent, 60.29);
    assert.equal(asset?.windowBlocks, 20);
  });

  test("rejects invalid addresses and decimals", () => {
    const invalidAddress = validEconomicRaw();
    ((invalidAddress.assets as Record<string, unknown>[])[0]!).tokenAddress = "invalid";
    assert.throws(() => parseMonitorConfig(rawConfig(invalidAddress)), /invalid Ethereum address/);

    const invalidDecimals = validEconomicRaw();
    ((invalidDecimals.assets as Record<string, unknown>[])[0]!).decimals = -1;
    assert.throws(() => parseMonitorConfig(rawConfig(invalidDecimals)), /decimals/);
  });

  test("rejects invalid percentages, bigint quantities and windows", () => {
    const invalidPercent = validEconomicRaw();
    (((invalidPercent.assets as Record<string, unknown>[])[0]!).thresholds as Record<string, unknown>).concentrationPercent = 101;
    assert.throws(() => parseMonitorConfig(rawConfig(invalidPercent)), /at most 100/);

    const invalidBigInt = validEconomicRaw();
    (((invalidBigInt.assets as Record<string, unknown>[])[0]!).thresholds as Record<string, unknown>).largeTransferAbsolute = "1.5";
    assert.throws(() => parseMonitorConfig(rawConfig(invalidBigInt)), /base-10 integer string/);

    const invalidWindow = validEconomicRaw();
    ((invalidWindow.assets as Record<string, unknown>[])[0]!).windowBlocks = 0;
    assert.throws(() => parseMonitorConfig(rawConfig(invalidWindow)), /positive integer/);
  });
});
