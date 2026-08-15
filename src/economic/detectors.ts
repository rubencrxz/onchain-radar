import type { AlertSeverity } from "../alerts.js";
import { createAggregateEconomicAlert, createMovementAlert, formatAssetAmount, formatPercentage } from "./alerts.js";
import type {
  AssetMovement,
  BalanceObservation,
  CriticalContractConfig,
  EconomicAnomalyResult,
  EconomicMonitoringConfig,
  EconomicWindow,
  MonitoredAssetConfig
} from "./types.js";

type Clock = () => string;

export function runEconomicDetectors(params: {
  config: EconomicMonitoringConfig;
  movements: readonly AssetMovement[];
  observations: readonly BalanceObservation[];
  startBlock: bigint;
  endBlock: bigint;
  clock: Clock;
}): EconomicAnomalyResult[] {
  const direct = [
    ...detectLargeTransfers(params.movements, params.clock),
    ...detectLargeMints(params.movements, params.clock),
    ...detectCriticalContractOutflows(params),
    ...detectLiquidityDrawdowns(params),
    ...detectOutflowConcentrations(params)
  ];

  return [...direct, ...correlateEconomicAnomalies(direct, params.clock)];
}

export function detectLargeTransfers(
  movements: readonly AssetMovement[],
  clock: Clock
): EconomicAnomalyResult[] {
  return movements
    .filter((movement) => movement.value > movement.asset.thresholds.largeTransferAbsolute)
    .map((movement) => {
      const critical = movement.direction.includes("critical");
      const severity: AlertSeverity = critical ? "WARNING" : "INFO";
      const window = singleBlockWindow(movement.blockNumber);
      const alert = createMovementAlert({
        ruleId: "LARGE_ASSET_TRANSFER",
        ruleName: "Large Asset Transfer",
        severity,
        severityReason: critical
          ? "The configured large-transfer threshold was exceeded and a critical contract was involved."
          : "The configured large-transfer threshold was exceeded without a critical contract outflow.",
        summary: `Large ${movement.asset.name} transfer observed (${formatAssetAmount(
          movement.value,
          movement.asset.decimals
        )}): ${movement.from} -> ${movement.to}; direction=${movement.direction}.`,
        movement,
        threshold: { largeTransferAbsolute: movement.asset.thresholds.largeTransferAbsolute.toString() },
        observedValue: { transferAmount: movement.value.toString(), direction: movement.direction },
        referenceValue: null,
        createdAt: clock()
      });

      return { kind: "large-transfer", asset: movement.asset, window, alert };
    });
}

export function detectLargeMints(movements: readonly AssetMovement[], clock: Clock): EconomicAnomalyResult[] {
  return movements
    .filter(
      (movement) => movement.direction === "mint" && movement.value > movement.asset.thresholds.largeTransferAbsolute
    )
    .map((movement) => {
      const window = singleBlockWindow(movement.blockNumber);
      const alert = createMovementAlert({
        ruleId: "LARGE_TOKEN_MINT",
        ruleName: "Large Token Mint",
        severity: "INFO",
        severityReason:
          "An ERC-20 mint exceeded the configured absolute threshold; issuance cause and backing require investigation.",
        summary: `Extraordinary ${movement.asset.name} issuance observed: ${formatAssetAmount(
          movement.value,
          movement.asset.decimals
        )} minted to ${movement.to}. This signal does not determine whether the issuance is backed or authorized.`,
        movement,
        threshold: { largeTransferAbsolute: movement.asset.thresholds.largeTransferAbsolute.toString() },
        observedValue: { mintedAmount: movement.value.toString() },
        referenceValue: { mintSource: movement.from },
        createdAt: clock()
      });

      return { kind: "large-mint", asset: movement.asset, window, alert };
    });
}

export function detectCriticalContractOutflows(params: {
  config: EconomicMonitoringConfig;
  movements: readonly AssetMovement[];
  observations: readonly BalanceObservation[];
  clock: Clock;
}): EconomicAnomalyResult[] {
  const anomalies: EconomicAnomalyResult[] = [];

  for (const asset of params.config.assets) {
    for (const criticalContract of asset.criticalContracts) {
      const outflows = params.movements.filter(
        (movement) =>
          sameAddress(movement.tokenAddress, asset.tokenAddress) &&
          sameAddress(movement.from, criticalContract.address)
      );
      const byBlock = groupByBlock(outflows);

      for (const [blockNumber, blockMovements] of byBlock) {
        const totalOutflow = sumValues(blockMovements);
        const previousBlock = blockNumber === 0n ? 0n : blockNumber - 1n;
        const referenceBalance = findBalance(params.observations, asset, criticalContract, previousBlock);
        const exceedsAbsolute = totalOutflow > asset.thresholds.singleBlockOutflowAbsolute;
        const exceedsConfiguredPercent =
          referenceBalance !== undefined &&
          exceedsPercent(totalOutflow, referenceBalance, asset.thresholds.singleBlockOutflowPercent);

        if (!exceedsAbsolute && !exceedsConfiguredPercent) {
          continue;
        }

        const criticalPercent = asset.thresholds.criticalOutflowPercent;
        const isCritical =
          criticalPercent !== undefined &&
          referenceBalance !== undefined &&
          exceedsPercent(totalOutflow, referenceBalance, criticalPercent);
        const recipients = aggregateRecipients(blockMovements);
        const window = singleBlockWindow(blockNumber);
        const severity: AlertSeverity = isCritical ? "CRITICAL" : "WARNING";
        const percentage = referenceBalance === undefined ? null : formatPercentage(totalOutflow, referenceBalance);
        const alert = createAggregateEconomicAlert({
          ruleId: "CRITICAL_CONTRACT_OUTFLOW",
          ruleName: "Critical Contract Outflow",
          severity,
          severityReason: isCritical
            ? "Gross block outflow exceeded the explicitly configured critical percentage of the prior balance."
            : "Gross block outflow exceeded an absolute or percentage warning threshold.",
          summary: `${criticalContract.name} sent ${formatAssetAmount(totalOutflow, asset.decimals)} ${
            asset.name
          } across ${blockMovements.length.toString()} transfer(s) in block ${blockNumber.toString()}${
            percentage === null ? "" : ` (${percentage} of prior balance)`
          }.`,
          asset,
          criticalContract,
          window,
          eventSignature: "Transfer(address,address,uint256)",
          threshold: {
            singleBlockOutflowAbsolute: asset.thresholds.singleBlockOutflowAbsolute.toString(),
            singleBlockOutflowPercent: asset.thresholds.singleBlockOutflowPercent,
            criticalOutflowPercent: criticalPercent ?? null
          },
          observedValue: {
            totalOutflow: totalOutflow.toString(),
            outflowPercent: percentage,
            transferCount: blockMovements.length
          },
          referenceValue: {
            previousBlock: previousBlock.toString(),
            previousBalance: referenceBalance?.toString() ?? null
          },
          details: {
            principalRecipients: recipients.slice(0, 5).map((recipient) => ({
              address: recipient.address,
              amount: recipient.amount.toString(),
              outflowPercent: formatPercentage(recipient.amount, totalOutflow)
            }))
          },
          createdAt: params.clock()
        });

        anomalies.push({ kind: "critical-outflow", asset, criticalContract, window, alert });
      }
    }
  }

  return anomalies;
}

export function detectLiquidityDrawdowns(params: {
  config: EconomicMonitoringConfig;
  observations: readonly BalanceObservation[];
  clock: Clock;
}): EconomicAnomalyResult[] {
  const anomalies: EconomicAnomalyResult[] = [];

  for (const asset of params.config.assets) {
    for (const criticalContract of asset.criticalContracts) {
      const observations = params.observations
        .filter(
          (observation) =>
            sameAddress(observation.asset.tokenAddress, asset.tokenAddress) &&
            sameAddress(observation.criticalContract.address, criticalContract.address)
        )
        .sort((left, right) => compareBigInts(left.blockNumber, right.blockNumber));
      let best: DrawdownCandidate | undefined;

      for (let startIndex = 0; startIndex < observations.length; startIndex += 1) {
        for (let endIndex = startIndex + 1; endIndex < observations.length; endIndex += 1) {
          const initial = observations[startIndex]!;
          const final = observations[endIndex]!;
          if (final.blockNumber - initial.blockNumber > BigInt(asset.windowBlocks)) {
            break;
          }
          if (initial.balance === 0n || final.balance >= initial.balance) {
            continue;
          }

          const drop = initial.balance - final.balance;
          if (!exceedsPercent(drop, initial.balance, asset.thresholds.windowOutflowPercent)) {
            continue;
          }

          const candidate = { initial, final, drop };
          if (best === undefined || isStrongerDrawdown(candidate, best)) {
            best = candidate;
          }
        }
      }

      if (best === undefined) {
        continue;
      }

      const criticalPercent = asset.thresholds.criticalDrawdownPercent;
      const isCritical =
        criticalPercent !== undefined && exceedsPercent(best.drop, best.initial.balance, criticalPercent);
      const severity: AlertSeverity = isCritical ? "CRITICAL" : "WARNING";
      const percentage = formatPercentage(best.drop, best.initial.balance)!;
      const window = {
        fromBlock: best.initial.blockNumber,
        toBlock: best.final.blockNumber,
        windowBlocks: asset.windowBlocks
      };
      const alert = createAggregateEconomicAlert({
        ruleId: "LIQUIDITY_DRAWDOWN",
        ruleName: "Liquidity Drawdown",
        severity,
        severityReason: isCritical
          ? "Balance drawdown exceeded the explicitly configured critical percentage within the configured window."
          : "Balance drawdown exceeded the configured warning percentage within the configured window.",
        summary: `${criticalContract.name} ${asset.name} balance fell from ${formatAssetAmount(
          best.initial.balance,
          asset.decimals
        )} to ${formatAssetAmount(best.final.balance, asset.decimals)} (${percentage}) across blocks ${
          best.initial.blockNumber
        }-${best.final.blockNumber}.`,
        asset,
        criticalContract,
        window,
        eventSignature: "ERC20_BALANCE_OBSERVATION",
        threshold: {
          windowOutflowPercent: asset.thresholds.windowOutflowPercent,
          criticalDrawdownPercent: criticalPercent ?? null
        },
        observedValue: {
          drawdownAmount: best.drop.toString(),
          drawdownPercent: percentage,
          finalBalance: best.final.balance.toString()
        },
        referenceValue: {
          initialBalance: best.initial.balance.toString(),
          initialBlock: best.initial.blockNumber.toString()
        },
        createdAt: params.clock()
      });

      anomalies.push({ kind: "liquidity-drawdown", asset, criticalContract, window, alert });
    }
  }

  return anomalies;
}

export function detectOutflowConcentrations(params: {
  config: EconomicMonitoringConfig;
  movements: readonly AssetMovement[];
  startBlock: bigint;
  clock: Clock;
}): EconomicAnomalyResult[] {
  const anomalies: EconomicAnomalyResult[] = [];

  for (const asset of params.config.assets) {
    for (const criticalContract of asset.criticalContracts) {
      const outflows = params.movements.filter(
        (movement) =>
          sameAddress(movement.tokenAddress, asset.tokenAddress) &&
          sameAddress(movement.from, criticalContract.address)
      );
      const endBlocks = [...new Set(outflows.map((movement) => movement.blockNumber))].sort(compareBigInts);
      let best: ConcentrationCandidate | undefined;

      for (const toBlock of endBlocks) {
        const candidateStart = toBlock - BigInt(asset.windowBlocks) + 1n;
        const fromBlock = candidateStart > params.startBlock ? candidateStart : params.startBlock;
        const windowMovements = outflows.filter(
          (movement) => movement.blockNumber >= fromBlock && movement.blockNumber <= toBlock
        );
        const totalOutflow = sumValues(windowMovements);
        const dominant = aggregateRecipients(windowMovements)[0];
        if (
          dominant === undefined ||
          !exceedsPercent(dominant.amount, totalOutflow, asset.thresholds.concentrationPercent)
        ) {
          continue;
        }

        const candidate = { fromBlock, toBlock, totalOutflow, dominant, movementCount: windowMovements.length };
        if (best === undefined || isStrongerConcentration(candidate, best)) {
          best = candidate;
        }
      }

      if (best === undefined) {
        continue;
      }

      const percentage = formatPercentage(best.dominant.amount, best.totalOutflow)!;
      const window = { fromBlock: best.fromBlock, toBlock: best.toBlock, windowBlocks: asset.windowBlocks };
      const alert = createAggregateEconomicAlert({
        ruleId: "OUTFLOW_CONCENTRATION",
        ruleName: "Outflow Concentration",
        severity: "WARNING",
        severityReason: "One recipient exceeded the configured share of gross outflows within the analysis window.",
        summary: `${best.dominant.address} received ${percentage} of ${criticalContract.name}'s ${asset.name} outflows (${formatAssetAmount(
          best.dominant.amount,
          asset.decimals
        )} of ${formatAssetAmount(best.totalOutflow, asset.decimals)}) across blocks ${best.fromBlock}-${best.toBlock}.`,
        asset,
        criticalContract,
        window,
        idParts: [best.dominant.address],
        eventSignature: "Transfer(address,address,uint256)",
        threshold: { concentrationPercent: asset.thresholds.concentrationPercent },
        observedValue: {
          recipient: best.dominant.address,
          recipientAmount: best.dominant.amount.toString(),
          concentrationPercent: percentage,
          totalOutflow: best.totalOutflow.toString(),
          transferCount: best.movementCount
        },
        referenceValue: { grossWindowOutflow: best.totalOutflow.toString() },
        createdAt: params.clock()
      });

      anomalies.push({ kind: "outflow-concentration", asset, criticalContract, window, alert });
    }
  }

  return anomalies;
}

export function correlateEconomicAnomalies(
  anomalies: readonly EconomicAnomalyResult[],
  clock: Clock
): EconomicAnomalyResult[] {
  const drawdowns = anomalies.filter((anomaly) => anomaly.kind === "liquidity-drawdown");
  const concentrations = anomalies.filter((anomaly) => anomaly.kind === "outflow-concentration");
  const correlated: EconomicAnomalyResult[] = [];

  for (const drawdown of drawdowns) {
    const concentration = concentrations.find(
      (candidate) =>
        sameAddress(candidate.asset.tokenAddress, drawdown.asset.tokenAddress) &&
        candidate.criticalContract !== undefined &&
        drawdown.criticalContract !== undefined &&
        sameAddress(candidate.criticalContract.address, drawdown.criticalContract.address) &&
        windowsFitWithin(
          drawdown.window,
          candidate.window,
          drawdown.asset.windowBlocks
        )
    );

    if (concentration === undefined || drawdown.criticalContract === undefined) {
      continue;
    }

    const window = {
      fromBlock: minBigInt(drawdown.window.fromBlock, concentration.window.fromBlock),
      toBlock: maxBigInt(drawdown.window.toBlock, concentration.window.toBlock),
      windowBlocks: drawdown.asset.windowBlocks
    };
    const componentAlertIds = [drawdown.alert.id, concentration.alert.id];
    const alert = createAggregateEconomicAlert({
      ruleId: "ECONOMIC_SECURITY_ANOMALY",
      ruleName: "Correlated Economic Security Anomaly",
      severity: "CRITICAL",
      severityReason:
        "A configured balance drawdown and concentrated outflow affected the same asset and critical contract within one window.",
      summary: `${drawdown.criticalContract.name} shows both rapid ${drawdown.asset.name} balance deterioration and concentrated outflow within blocks ${window.fromBlock}-${window.toBlock}; investigate potential compromise or contagion.`,
      asset: drawdown.asset,
      criticalContract: drawdown.criticalContract,
      window,
      eventSignature: "ECONOMIC_SIGNAL_CORRELATION",
      threshold: {
        windowOutflowPercent: drawdown.asset.thresholds.windowOutflowPercent,
        concentrationPercent: drawdown.asset.thresholds.concentrationPercent
      },
      observedValue: { componentSignals: ["LIQUIDITY_DRAWDOWN", "OUTFLOW_CONCENTRATION"] },
      referenceValue: { componentAlertIds },
      details: { componentAlertIds },
      createdAt: clock()
    });

    correlated.push({
      kind: "correlated-anomaly",
      asset: drawdown.asset,
      criticalContract: drawdown.criticalContract,
      window,
      alert,
      componentAlertIds
    });
  }

  return correlated;
}

type DrawdownCandidate = {
  initial: BalanceObservation;
  final: BalanceObservation;
  drop: bigint;
};

type RecipientTotal = { address: string; amount: bigint };
type ConcentrationCandidate = {
  fromBlock: bigint;
  toBlock: bigint;
  totalOutflow: bigint;
  dominant: RecipientTotal;
  movementCount: number;
};

function singleBlockWindow(blockNumber: bigint): EconomicWindow {
  return { fromBlock: blockNumber, toBlock: blockNumber, windowBlocks: 1 };
}

function groupByBlock(movements: readonly AssetMovement[]): Map<bigint, AssetMovement[]> {
  const grouped = new Map<bigint, AssetMovement[]>();
  for (const movement of movements) {
    const current = grouped.get(movement.blockNumber) ?? [];
    current.push(movement);
    grouped.set(movement.blockNumber, current);
  }
  return grouped;
}

function aggregateRecipients(movements: readonly AssetMovement[]): RecipientTotal[] {
  const totals = new Map<string, RecipientTotal>();
  for (const movement of movements) {
    const key = movement.to.toLowerCase();
    const existing = totals.get(key);
    totals.set(key, { address: movement.to, amount: (existing?.amount ?? 0n) + movement.value });
  }

  return [...totals.values()].sort((left, right) => {
    if (left.amount !== right.amount) {
      return left.amount > right.amount ? -1 : 1;
    }
    return compareStrings(left.address.toLowerCase(), right.address.toLowerCase());
  });
}

function findBalance(
  observations: readonly BalanceObservation[],
  asset: MonitoredAssetConfig,
  contract: CriticalContractConfig,
  blockNumber: bigint
): bigint | undefined {
  return observations.find(
    (observation) =>
      observation.blockNumber === blockNumber &&
      sameAddress(observation.asset.tokenAddress, asset.tokenAddress) &&
      sameAddress(observation.criticalContract.address, contract.address)
  )?.balance;
}

function exceedsPercent(value: bigint, reference: bigint, percentage: number): boolean {
  return reference > 0n && value * 10_000n > reference * percentageToBasisPoints(percentage);
}

function percentageToBasisPoints(percentage: number): bigint {
  return BigInt(Math.round(percentage * 100));
}

function sumValues(movements: readonly AssetMovement[]): bigint {
  return movements.reduce((sum, movement) => sum + movement.value, 0n);
}

function isStrongerDrawdown(candidate: DrawdownCandidate, current: DrawdownCandidate): boolean {
  const ratioComparison = compareRatios(
    candidate.drop,
    candidate.initial.balance,
    current.drop,
    current.initial.balance
  );
  if (ratioComparison !== 0) {
    return ratioComparison > 0;
  }
  if (candidate.drop !== current.drop) {
    return candidate.drop > current.drop;
  }
  return candidate.initial.blockNumber < current.initial.blockNumber;
}

function isStrongerConcentration(candidate: ConcentrationCandidate, current: ConcentrationCandidate): boolean {
  const ratioComparison = compareRatios(
    candidate.dominant.amount,
    candidate.totalOutflow,
    current.dominant.amount,
    current.totalOutflow
  );
  if (ratioComparison !== 0) {
    return ratioComparison > 0;
  }
  if (candidate.totalOutflow !== current.totalOutflow) {
    return candidate.totalOutflow > current.totalOutflow;
  }
  return candidate.toBlock < current.toBlock;
}

function compareRatios(leftNumerator: bigint, leftDenominator: bigint, rightNumerator: bigint, rightDenominator: bigint): number {
  const left = leftNumerator * rightDenominator;
  const right = rightNumerator * leftDenominator;
  return left < right ? -1 : left > right ? 1 : 0;
}

function windowsFitWithin(left: EconomicWindow, right: EconomicWindow, windowBlocks: number): boolean {
  const fromBlock = minBigInt(left.fromBlock, right.fromBlock);
  const toBlock = maxBigInt(left.toBlock, right.toBlock);
  return toBlock - fromBlock <= BigInt(windowBlocks);
}

function compareBigInts(left: bigint, right: bigint): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function minBigInt(left: bigint, right: bigint): bigint {
  return left < right ? left : right;
}

function maxBigInt(left: bigint, right: bigint): bigint {
  return left > right ? left : right;
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
