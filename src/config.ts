import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { getAddress, isAddress, type Address } from "viem";
import type {
  CriticalContractConfig,
  CriticalContractRole,
  EconomicMonitoringConfig,
  EconomicThresholds,
  MonitoredAssetConfig
} from "./economic/types.js";
import type {
  AdministrativeMonitoringConfig,
  MultiSendContractConfig,
  MultiSendLimits,
  MultiSendAlertDetail,
  MultiSendMode,
  SafeCriticality,
  SafeModulePolicyConfig,
  SafeMultisigConfig,
  SafeOperation
} from "./safe/types.js";
import { DEFAULT_MULTISEND_LIMITS } from "./safe/types.js";

export type MonitorConfig = {
  chain: "ethereum";
  monitoredAddresses: Address[];
  knownMultisigs: Address[];
  eventSignatures: string[];
  proxySlotMonitoring?: ProxySlotMonitoringConfig;
  economicMonitoring?: EconomicMonitoringConfig;
  administrativeMonitoring?: AdministrativeMonitoringConfig;
  allowlists: AllowlistConfig;
};

export type AllowlistConfig = {
  knownActors: AllowlistEntry[];
  knownAdmins: AllowlistEntry[];
  knownImplementations: AllowlistEntry[];
  knownGovernanceContracts: AllowlistEntry[];
  knownProxyAddresses: AllowlistEntry[];
};

export type AllowlistEntry = {
  name?: string;
  address: Address;
};

export type ProxySlotMonitoringConfig = {
  enabled: boolean;
  proxies: ProxySlotMonitorConfig[];
};

export type ProxySlotMonitorConfig = {
  name?: string;
  address: Address;
  checkImplementationSlot: boolean;
  checkAdminSlot: boolean;
};

const CONFIG_PATH = resolve("config/monitor.config.json");

type RawMonitorConfig = {
  chain?: unknown;
  monitoredAddresses?: unknown;
  knownMultisigs?: unknown;
  eventSignatures?: unknown;
  proxySlotMonitoring?: unknown;
  economicMonitoring?: unknown;
  administrativeMonitoring?: unknown;
  allowlists?: unknown;
};

export function loadMonitorConfig(): MonitorConfig {
  if (!existsSync(CONFIG_PATH)) {
    throw new Error(
      "Missing config/monitor.config.json. Copy config/monitor.config.example.json to config/monitor.config.json and adjust it."
    );
  }

  return parseMonitorConfig(JSON.parse(readFileSync(CONFIG_PATH, "utf8")));
}

export function parseMonitorConfig(value: unknown): MonitorConfig {
  if (!isRecord(value)) {
    throw new Error("Monitor config must be a JSON object.");
  }

  const raw = value as RawMonitorConfig;

  if (raw.chain !== "ethereum") {
    throw new Error('Config field "chain" must be "ethereum".');
  }

  return {
    chain: "ethereum",
    monitoredAddresses: parseAddresses(raw.monitoredAddresses, "monitoredAddresses"),
    knownMultisigs: parseAddresses(raw.knownMultisigs, "knownMultisigs"),
    eventSignatures: parseEventSignatures(raw.eventSignatures),
    proxySlotMonitoring: parseProxySlotMonitoring(raw.proxySlotMonitoring),
    economicMonitoring: parseEconomicMonitoring(raw.economicMonitoring),
    administrativeMonitoring: parseAdministrativeMonitoring(raw.administrativeMonitoring),
    allowlists: parseAllowlists(raw.allowlists)
  };
}

const SAFE_CRITICALITIES = new Set<SafeCriticality>(["standard", "high", "critical"]);
const SAFE_OPERATIONS = new Set<SafeOperation>(["CALL", "DELEGATECALL"]);
const MULTISEND_MODES = new Set<MultiSendMode>(["MULTISEND", "CALL_ONLY"]);
const MULTISEND_ALERT_DETAILS = new Set<MultiSendAlertDetail>(["all", "sensitive-only", "violations-only"]);

function parseAdministrativeMonitoring(value: unknown): AdministrativeMonitoringConfig | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value) || !Array.isArray(value.multisigs) || value.multisigs.length === 0) {
    throw new Error('Config field "administrativeMonitoring.multisigs" must be a non-empty array when provided.');
  }

  const multisigs = value.multisigs.map((multisig, index) => parseSafeMultisig(multisig, index));
  assertNoDuplicateStrings(
    multisigs.map((multisig) => multisig.address.toLowerCase()),
    "administrativeMonitoring.multisigs",
    "Safe addresses"
  );
  const multisendContracts = value.multisendContracts === undefined
    ? []
    : parseMultiSendContracts(value.multisendContracts);
  const multisendLimits = value.multisendLimits === undefined
    ? { ...DEFAULT_MULTISEND_LIMITS }
    : parseMultiSendLimits(value.multisendLimits);
  return { multisigs, multisendContracts, multisendLimits };
}

function parseMultiSendContracts(value: unknown): MultiSendContractConfig[] {
  if (!Array.isArray(value)) {
    throw new Error('Config field "administrativeMonitoring.multisendContracts" must be an array.');
  }
  const contracts = value.map((contract, index) => {
    const field = `administrativeMonitoring.multisendContracts[${index}]`;
    if (!isRecord(contract)) throw new Error(`Config field "${field}" must be an object.`);
    if (typeof contract.mode !== "string" || !MULTISEND_MODES.has(contract.mode as MultiSendMode)) {
      throw new Error(`Config field "${field}.mode" must be MULTISEND or CALL_ONLY.`);
    }
    return {
      name: parseNonEmptyString(contract.name, `${field}.name`),
      address: parseNormalizedAddress(contract.address, `${field}.address`),
      mode: contract.mode as MultiSendMode
    };
  });
  assertNoDuplicateStrings(
    contracts.map((contract) => contract.address.toLowerCase()),
    "administrativeMonitoring.multisendContracts",
    "MultiSend addresses"
  );
  return contracts;
}

function parseMultiSendLimits(value: unknown): MultiSendLimits {
  const field = "administrativeMonitoring.multisendLimits";
  if (!isRecord(value)) throw new Error(`Config field "${field}" must be an object.`);
  return {
    maxDepth: parsePositiveSafeInteger(value.maxDepth, `${field}.maxDepth`),
    maxSuboperations: parsePositiveSafeInteger(value.maxSuboperations, `${field}.maxSuboperations`),
    maxTotalPayloadBytes: parsePositiveSafeInteger(value.maxTotalPayloadBytes, `${field}.maxTotalPayloadBytes`),
    maxSuboperationDataBytes: parsePositiveSafeInteger(
      value.maxSuboperationDataBytes,
      `${field}.maxSuboperationDataBytes`
    )
  };
}

function parsePositiveSafeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new Error(`Config field "${field}" must be a positive safe integer.`);
  }
  return value as number;
}

function parseSafeMultisig(value: unknown, index: number): SafeMultisigConfig {
  const field = `administrativeMonitoring.multisigs[${index}]`;
  if (!isRecord(value)) throw new Error(`Config field "${field}" must be an object.`);
  if (typeof value.criticality !== "string" || !SAFE_CRITICALITIES.has(value.criticality as SafeCriticality)) {
    throw new Error(`Config field "${field}.criticality" must be standard, high, or critical.`);
  }
  if (!Array.isArray(value.allowedTargets)) throw new Error(`Config field "${field}.allowedTargets" must be an array.`);
  if (!Array.isArray(value.allowedSelectors)) throw new Error(`Config field "${field}.allowedSelectors" must be an array.`);
  if (!Array.isArray(value.allowedOperations)) throw new Error(`Config field "${field}.allowedOperations" must be an array.`);
  if (!Array.isArray(value.allowedImplementations)) {
    throw new Error(`Config field "${field}.allowedImplementations" must be an array.`);
  }

  const allowedTargets = value.allowedTargets.map((target, targetIndex) =>
    parseNormalizedAddress(target, `${field}.allowedTargets[${targetIndex}]`)
  );
  const allowedSelectors = value.allowedSelectors.map((selector, selectorIndex) =>
    parseSelector(selector, `${field}.allowedSelectors[${selectorIndex}]`)
  );
  const allowedOperations = value.allowedOperations.map((operation, operationIndex) => {
    if (typeof operation !== "string" || !SAFE_OPERATIONS.has(operation as SafeOperation)) {
      throw new Error(`Config field "${field}.allowedOperations[${operationIndex}]" must be CALL or DELEGATECALL.`);
    }
    return operation as SafeOperation;
  });
  const allowedImplementations = value.allowedImplementations.map((implementation, implementationIndex) =>
    parseNormalizedAddress(implementation, `${field}.allowedImplementations[${implementationIndex}]`)
  );
  const allowedOwners = parseOptionalAddressArray(value.allowedOwners, `${field}.allowedOwners`);
  const allowedModules = parseOptionalAddressArray(value.allowedModules, `${field}.allowedModules`);
  const allowedGuards = parseOptionalAddressArray(value.allowedGuards, `${field}.allowedGuards`);
  const allowedFallbackHandlers = parseOptionalAddressArray(
    value.allowedFallbackHandlers,
    `${field}.allowedFallbackHandlers`
  );
  const minimumThreshold = value.minimumThreshold === undefined
    ? undefined
    : parsePositiveSafeInteger(value.minimumThreshold, `${field}.minimumThreshold`);
  const allowedThresholds = value.allowedThresholds === undefined
    ? []
    : parsePositiveIntegerArray(value.allowedThresholds, `${field}.allowedThresholds`);
  if (minimumThreshold !== undefined && allowedThresholds.some((threshold) => threshold < minimumThreshold)) {
    throw new Error(`Config field "${field}.allowedThresholds" cannot contain values below minimumThreshold.`);
  }
  const multisendAlertDetail = value.multisendAlertDetail === undefined
    ? "sensitive-only"
    : parseMultiSendAlertDetail(value.multisendAlertDetail, `${field}.multisendAlertDetail`);
  const financialOperationPolicy = parseFinancialOperationPolicy(
    value.financialOperationPolicy,
    `${field}.financialOperationPolicy`
  );
  const modulePolicies = parseSafeModulePolicies(value.modulePolicies, `${field}.modulePolicies`);

  assertNoDuplicateStrings(allowedTargets.map((item) => item.toLowerCase()), `${field}.allowedTargets`, "targets");
  assertNoDuplicateStrings(allowedSelectors, `${field}.allowedSelectors`, "selectors");
  assertNoDuplicateStrings(allowedOperations, `${field}.allowedOperations`, "operations");
  assertNoDuplicateStrings(
    allowedImplementations.map((item) => item.toLowerCase()),
    `${field}.allowedImplementations`,
    "implementations"
  );

  return {
    name: parseNonEmptyString(value.name, `${field}.name`),
    address: parseNormalizedAddress(value.address, `${field}.address`),
    criticality: value.criticality as SafeCriticality,
    allowedTargets,
    allowedSelectors,
    allowedOperations,
    allowedImplementations,
    maxNativeValueWei: parseNonNegativeBigInt(value.maxNativeValueWei, `${field}.maxNativeValueWei`),
    allowedOwners,
    ...(minimumThreshold === undefined ? {} : { minimumThreshold }),
    allowedThresholds,
    allowedModules,
    allowedGuards,
    allowedFallbackHandlers,
    multisendAlertDetail,
    financialOperationPolicy,
    modulePolicies
  };
}

function parseSafeModulePolicies(value: unknown, field: string): SafeModulePolicyConfig[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`Config field "${field}" must be an array.`);
  const policies = value.map((entry, index) => {
    const itemField = `${field}[${index}]`;
    if (!isRecord(entry)) throw new Error(`Config field "${itemField}" must be an object.`);
    if (!Array.isArray(entry.allowedTargets) || !Array.isArray(entry.allowedSelectors) ||
        !Array.isArray(entry.allowedOperations) || !Array.isArray(entry.allowedImplementations)) {
      throw new Error(`Config field "${itemField}" requires allowedTargets, allowedSelectors, allowedOperations, and allowedImplementations arrays.`);
    }
    const allowedTargets = entry.allowedTargets.map((target, targetIndex) =>
      parseNormalizedAddress(target, `${itemField}.allowedTargets[${targetIndex}]`));
    const allowedSelectors = entry.allowedSelectors.map((selector, selectorIndex) =>
      parseSelector(selector, `${itemField}.allowedSelectors[${selectorIndex}]`));
    const allowedOperations = entry.allowedOperations.map((operation, operationIndex) => {
      if (typeof operation !== "string" || !SAFE_OPERATIONS.has(operation as SafeOperation)) {
        throw new Error(`Config field "${itemField}.allowedOperations[${operationIndex}]" must be CALL or DELEGATECALL.`);
      }
      return operation as SafeOperation;
    });
    const allowedImplementations = entry.allowedImplementations.map((implementation, implementationIndex) =>
      parseNormalizedAddress(implementation, `${itemField}.allowedImplementations[${implementationIndex}]`));
    const adapter = parseSafeModuleAdapter(entry.adapter, `${itemField}.adapter`);
    assertNoDuplicateStrings(allowedTargets.map((address) => address.toLowerCase()), `${itemField}.allowedTargets`, "targets");
    assertNoDuplicateStrings(allowedSelectors, `${itemField}.allowedSelectors`, "selectors");
    assertNoDuplicateStrings(allowedOperations, `${itemField}.allowedOperations`, "operations");
    assertNoDuplicateStrings(allowedImplementations.map((address) => address.toLowerCase()), `${itemField}.allowedImplementations`, "implementations");
    return {
      name: parseNonEmptyString(entry.name, `${itemField}.name`),
      address: parseNormalizedAddress(entry.address, `${itemField}.address`),
      allowedTargets,
      allowedSelectors,
      allowedOperations,
      allowedImplementations,
      maxNativeValueWei: parseNonNegativeBigInt(entry.maxNativeValueWei, `${itemField}.maxNativeValueWei`),
      ...(adapter === undefined ? {} : { adapter })
    };
  });
  assertNoDuplicateStrings(policies.map((policy) => policy.address.toLowerCase()), field, "module addresses");
  return policies;
}

function parseSafeModuleAdapter(value: unknown, field: string): SafeModulePolicyConfig["adapter"] {
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new Error(`Config field "${field}" must be an object.`);
  if (value.type !== "ZODIAC_ROLES_V2") {
    throw new Error(`Config field "${field}.type" must be ZODIAC_ROLES_V2.`);
  }
  if (!Array.isArray(value.managerSafes)) {
    throw new Error(`Config field "${field}.managerSafes" must be an array.`);
  }
  const managerSafes = value.managerSafes.map((address, index) =>
    parseNormalizedAddress(address, `${field}.managerSafes[${index}]`));
  assertNoDuplicateStrings(managerSafes.map((address) => address.toLowerCase()), `${field}.managerSafes`, "manager Safe addresses");
  return { type: "ZODIAC_ROLES_V2", managerSafes };
}

function parseOptionalAddressArray(value: unknown, field: string): Address[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`Config field "${field}" must be an array.`);
  const addresses = value.map((entry, index) => parseNormalizedAddress(entry, `${field}[${index}]`));
  assertNoDuplicateStrings(addresses.map((address) => address.toLowerCase()), field, "addresses");
  return addresses;
}

function parsePositiveIntegerArray(value: unknown, field: string): number[] {
  if (!Array.isArray(value)) throw new Error(`Config field "${field}" must be an array.`);
  const values = value.map((entry, index) => parsePositiveSafeInteger(entry, `${field}[${index}]`));
  assertNoDuplicateStrings(values.map(String), field, "thresholds");
  return values;
}

function parseMultiSendAlertDetail(value: unknown, field: string): MultiSendAlertDetail {
  if (typeof value !== "string" || !MULTISEND_ALERT_DETAILS.has(value as MultiSendAlertDetail)) {
    throw new Error(`Config field "${field}" must be all, sensitive-only, or violations-only.`);
  }
  return value as MultiSendAlertDetail;
}

function parseFinancialOperationPolicy(value: unknown, field: string): SafeMultisigConfig["financialOperationPolicy"] {
  if (value === undefined) {
    return {
      emitAllowedTransfers: false,
      emitAllowedApprovals: false,
      maxNativeValueWei: 0n,
      notableTokenTargets: []
    };
  }
  if (!isRecord(value)) throw new Error(`Config field "${field}" must be an object.`);
  return {
    emitAllowedTransfers: parseOptionalBoolean(value.emitAllowedTransfers, `${field}.emitAllowedTransfers`, false),
    emitAllowedApprovals: parseOptionalBoolean(value.emitAllowedApprovals, `${field}.emitAllowedApprovals`, false),
    maxNativeValueWei: value.maxNativeValueWei === undefined
      ? 0n
      : parseNonNegativeBigInt(value.maxNativeValueWei, `${field}.maxNativeValueWei`),
    notableTokenTargets: parseOptionalAddressArray(value.notableTokenTargets, `${field}.notableTokenTargets`)
  };
}

function parseOptionalBoolean(value: unknown, field: string, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  if (typeof value !== "boolean") throw new Error(`Config field "${field}" must be a boolean.`);
  return value;
}

function parseSelector(value: unknown, field: string): `0x${string}` {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{8}$/.test(value)) {
    throw new Error(`Config field "${field}" must be a four-byte hex selector.`);
  }
  return value.toLowerCase() as `0x${string}`;
}

function parseNonNegativeBigInt(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw new Error(`Config field "${field}" must be a non-negative base-10 integer string.`);
  }
  return BigInt(value);
}

function assertNoDuplicateStrings(values: readonly string[], field: string, label: string): void {
  if (new Set(values).size !== values.length) throw new Error(`Config field "${field}" contains duplicate ${label}.`);
}

const CRITICAL_CONTRACT_ROLES = new Set<CriticalContractRole>([
  "vault",
  "lending-pool",
  "liquidity-pool",
  "bridge",
  "treasury",
  "collateral",
  "other"
]);

function parseEconomicMonitoring(value: unknown): EconomicMonitoringConfig | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value) || !Array.isArray(value.assets) || value.assets.length === 0) {
    throw new Error('Config field "economicMonitoring.assets" must be a non-empty array when provided.');
  }

  const assets = value.assets.map((asset, index) => parseMonitoredAsset(asset, index));
  const tokenAddresses = new Set(assets.map((asset) => asset.tokenAddress.toLowerCase()));

  if (tokenAddresses.size !== assets.length) {
    throw new Error('Config field "economicMonitoring.assets" contains duplicate token addresses.');
  }

  return { assets };
}

function parseMonitoredAsset(value: unknown, index: number): MonitoredAssetConfig {
  const field = `economicMonitoring.assets[${index}]`;
  if (!isRecord(value)) {
    throw new Error(`Config field "${field}" must be an object.`);
  }

  const name = parseNonEmptyString(value.name, `${field}.name`);
  const tokenAddress = parseNormalizedAddress(value.tokenAddress, `${field}.tokenAddress`);

  if (!Number.isSafeInteger(value.decimals) || (value.decimals as number) < 0 || (value.decimals as number) > 255) {
    throw new Error(`Config field "${field}.decimals" must be an integer between 0 and 255.`);
  }

  if (!Array.isArray(value.criticalContracts) || value.criticalContracts.length === 0) {
    throw new Error(`Config field "${field}.criticalContracts" must be a non-empty array.`);
  }

  const criticalContracts = value.criticalContracts.map((contract, contractIndex) =>
    parseCriticalContract(contract, `${field}.criticalContracts[${contractIndex}]`)
  );
  const criticalAddresses = new Set(criticalContracts.map((contract) => contract.address.toLowerCase()));

  if (criticalAddresses.size !== criticalContracts.length) {
    throw new Error(`Config field "${field}.criticalContracts" contains duplicate addresses.`);
  }

  if (!Number.isSafeInteger(value.windowBlocks) || (value.windowBlocks as number) <= 0) {
    throw new Error(`Config field "${field}.windowBlocks" must be a positive integer.`);
  }

  return {
    name,
    tokenAddress,
    decimals: value.decimals as number,
    criticalContracts,
    thresholds: parseEconomicThresholds(value.thresholds, `${field}.thresholds`),
    windowBlocks: value.windowBlocks as number
  };
}

function parseCriticalContract(value: unknown, field: string): CriticalContractConfig {
  if (!isRecord(value)) {
    throw new Error(`Config field "${field}" must be an object.`);
  }

  if (typeof value.role !== "string" || !CRITICAL_CONTRACT_ROLES.has(value.role as CriticalContractRole)) {
    throw new Error(`Config field "${field}.role" is not a supported critical contract role.`);
  }

  return {
    name: parseNonEmptyString(value.name, `${field}.name`),
    address: parseNormalizedAddress(value.address, `${field}.address`),
    role: value.role as CriticalContractRole
  };
}

function parseEconomicThresholds(value: unknown, field: string): EconomicThresholds {
  if (!isRecord(value)) {
    throw new Error(`Config field "${field}" must be an object.`);
  }

  const thresholds: EconomicThresholds = {
    largeTransferAbsolute: parsePositiveBigInt(value.largeTransferAbsolute, `${field}.largeTransferAbsolute`),
    singleBlockOutflowAbsolute: parsePositiveBigInt(
      value.singleBlockOutflowAbsolute,
      `${field}.singleBlockOutflowAbsolute`
    ),
    singleBlockOutflowPercent: parsePercentage(value.singleBlockOutflowPercent, `${field}.singleBlockOutflowPercent`),
    windowOutflowPercent: parsePercentage(value.windowOutflowPercent, `${field}.windowOutflowPercent`),
    concentrationPercent: parsePercentage(value.concentrationPercent, `${field}.concentrationPercent`),
    ...(value.criticalOutflowPercent === undefined
      ? {}
      : { criticalOutflowPercent: parsePercentage(value.criticalOutflowPercent, `${field}.criticalOutflowPercent`) }),
    ...(value.criticalDrawdownPercent === undefined
      ? {}
      : { criticalDrawdownPercent: parsePercentage(value.criticalDrawdownPercent, `${field}.criticalDrawdownPercent`) })
  };

  if (
    thresholds.criticalOutflowPercent !== undefined &&
    thresholds.criticalOutflowPercent <= thresholds.singleBlockOutflowPercent
  ) {
    throw new Error(`Config field "${field}.criticalOutflowPercent" must exceed singleBlockOutflowPercent.`);
  }

  if (
    thresholds.criticalDrawdownPercent !== undefined &&
    thresholds.criticalDrawdownPercent <= thresholds.windowOutflowPercent
  ) {
    throw new Error(`Config field "${field}.criticalDrawdownPercent" must exceed windowOutflowPercent.`);
  }

  return thresholds;
}

function parsePositiveBigInt(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw new Error(`Config field "${field}" must be a positive base-10 integer string.`);
  }

  const parsed = BigInt(value);
  if (parsed <= 0n) {
    throw new Error(`Config field "${field}" must be greater than zero.`);
  }

  return parsed;
}

function parsePercentage(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0 || value > 100) {
    throw new Error(`Config field "${field}" must be a number greater than 0 and at most 100.`);
  }

  const scaled = value * 100;
  if (Math.abs(scaled - Math.round(scaled)) > 1e-9) {
    throw new Error(`Config field "${field}" supports at most two decimal places.`);
  }

  return value;
}

function parseNormalizedAddress(value: unknown, field: string): Address {
  if (typeof value !== "string" || !isAddress(value)) {
    throw new Error(`Config field "${field}" contains an invalid Ethereum address.`);
  }

  return getAddress(value);
}

function parseNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`Config field "${field}" must be a non-empty string.`);
  }

  return value.trim();
}

function parseAddresses(value: unknown, fieldName: string): Address[] {
  if (!Array.isArray(value)) {
    throw new Error(`Config field "${fieldName}" must be an array.`);
  }

  return value.map((address) => {
    if (typeof address !== "string" || !isAddress(address)) {
      throw new Error(`Config field "${fieldName}" contains an invalid Ethereum address: ${String(address)}`);
    }

    return address;
  });
}

function parseEventSignatures(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new Error('Config field "eventSignatures" must be an array.');
  }

  const signatures = value.map((signature) => {
    if (typeof signature !== "string" || signature.trim() === "") {
      throw new Error(`Config field "eventSignatures" contains an invalid signature: ${String(signature)}`);
    }

    return signature.trim();
  });

  if (signatures.length === 0) {
    throw new Error('Config field "eventSignatures" must contain at least one event signature.');
  }

  return signatures;
}

function parseProxySlotMonitoring(value: unknown): ProxySlotMonitoringConfig | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (!isRecord(value)) {
    throw new Error('Config field "proxySlotMonitoring" must be an object when provided.');
  }

  if (typeof value.enabled !== "boolean") {
    throw new Error('Config field "proxySlotMonitoring.enabled" must be a boolean.');
  }

  if (!Array.isArray(value.proxies)) {
    throw new Error('Config field "proxySlotMonitoring.proxies" must be an array.');
  }

  return {
    enabled: value.enabled,
    proxies: value.proxies.map((proxy, index) => parseProxySlotMonitor(proxy, index))
  };
}

function parseProxySlotMonitor(value: unknown, index: number): ProxySlotMonitorConfig {
  if (!isRecord(value)) {
    throw new Error(`Config field "proxySlotMonitoring.proxies[${index}]" must be an object.`);
  }

  if (value.name !== undefined && (typeof value.name !== "string" || value.name.trim() === "")) {
    throw new Error(`Config field "proxySlotMonitoring.proxies[${index}].name" must be a non-empty string when provided.`);
  }

  if (typeof value.address !== "string" || !isAddress(value.address)) {
    throw new Error(`Config field "proxySlotMonitoring.proxies[${index}].address" contains an invalid Ethereum address.`);
  }

  if (typeof value.checkImplementationSlot !== "boolean") {
    throw new Error(`Config field "proxySlotMonitoring.proxies[${index}].checkImplementationSlot" must be a boolean.`);
  }

  if (typeof value.checkAdminSlot !== "boolean") {
    throw new Error(`Config field "proxySlotMonitoring.proxies[${index}].checkAdminSlot" must be a boolean.`);
  }

  return {
    ...(value.name === undefined ? {} : { name: value.name.trim() }),
    address: value.address,
    checkImplementationSlot: value.checkImplementationSlot,
    checkAdminSlot: value.checkAdminSlot
  };
}

function parseAllowlists(value: unknown): AllowlistConfig {
  if (value === undefined) {
    return {
      knownActors: [],
      knownAdmins: [],
      knownImplementations: [],
      knownGovernanceContracts: [],
      knownProxyAddresses: []
    };
  }

  if (!isRecord(value)) {
    throw new Error('Config field "allowlists" must be an object when provided.');
  }

  return {
    knownActors: parseAllowlistEntries(value.knownActors, "allowlists.knownActors"),
    knownAdmins: parseAllowlistEntries(value.knownAdmins, "allowlists.knownAdmins"),
    knownImplementations: parseAllowlistEntries(value.knownImplementations, "allowlists.knownImplementations"),
    knownGovernanceContracts: parseAllowlistEntries(value.knownGovernanceContracts, "allowlists.knownGovernanceContracts"),
    knownProxyAddresses: parseAllowlistEntries(value.knownProxyAddresses, "allowlists.knownProxyAddresses")
  };
}

function parseAllowlistEntries(value: unknown, fieldName: string): AllowlistEntry[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error(`Config field "${fieldName}" must be an array when provided.`);
  }

  return value.map((entry, index) => parseAllowlistEntry(entry, `${fieldName}[${index}]`));
}

function parseAllowlistEntry(value: unknown, fieldName: string): AllowlistEntry {
  if (typeof value === "string") {
    if (!isAddress(value)) {
      throw new Error(`Config field "${fieldName}" contains an invalid Ethereum address.`);
    }

    return { address: value };
  }

  if (!isRecord(value)) {
    throw new Error(`Config field "${fieldName}" must be an address string or object.`);
  }

  if (value.name !== undefined && (typeof value.name !== "string" || value.name.trim() === "")) {
    throw new Error(`Config field "${fieldName}.name" must be a non-empty string when provided.`);
  }

  if (typeof value.address !== "string" || !isAddress(value.address)) {
    throw new Error(`Config field "${fieldName}.address" contains an invalid Ethereum address.`);
  }

  return {
    ...(value.name === undefined ? {} : { name: value.name.trim() }),
    address: value.address
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
