import { getAddress, isAddress, type Address } from "viem";
import type { Alert, AlertSeverity } from "./alerts.js";
import type { AllowlistConfig, AllowlistEntry } from "./config.js";

export type SeverityReason = {
  originalSeverity: AlertSeverity;
  finalSeverity: AlertSeverity;
  matchedAllowlist: boolean;
  allowlist?: keyof AllowlistConfig;
  matchedAddress?: string;
  matchedName?: string;
  reason: string;
};

export function refineAlertSeverity(alert: Alert, allowlists: AllowlistConfig): Alert {
  const originalSeverity = alert.severity;
  const decision = decideSeverity(alert, allowlists);

  return {
    ...alert,
    severity: decision.finalSeverity,
    metadata: {
      ...alert.metadata,
      severityReason: {
        originalSeverity,
        ...decision
      }
    }
  };
}

export function refineAlertsSeverity(alerts: Alert[], allowlists: AllowlistConfig): Alert[] {
  return alerts.map((alert) => refineAlertSeverity(alert, allowlists));
}

function decideSeverity(
  alert: Alert,
  allowlists: AllowlistConfig
): Omit<SeverityReason, "originalSeverity"> {
  if (alert.ruleId === "PROXY_IMPLEMENTATION_SLOT_CHANGED") {
    const newAddress = readEip1967Address(alert, "newAddress");
    const match = findAllowlistMatch(newAddress, allowlists.knownImplementations);

    if (match !== undefined) {
      return {
        finalSeverity: "WARNING",
        matchedAllowlist: true,
        allowlist: "knownImplementations",
        matchedAddress: match.address,
        matchedName: match.name,
        reason: "New implementation is in knownImplementations allowlist."
      };
    }

    return {
      finalSeverity: "CRITICAL",
      matchedAllowlist: false,
      allowlist: "knownImplementations",
      ...(newAddress === undefined ? {} : { matchedAddress: newAddress }),
      reason:
        newAddress === undefined
          ? "New implementation address was not available for allowlist matching."
          : "New implementation is not in knownImplementations allowlist."
    };
  }

  if (alert.ruleId === "PROXY_ADMIN_SLOT_CHANGED") {
    const newAddress = readEip1967Address(alert, "newAddress");
    const match = findAllowlistMatch(newAddress, allowlists.knownAdmins);

    if (match !== undefined) {
      return {
        finalSeverity: "WARNING",
        matchedAllowlist: true,
        allowlist: "knownAdmins",
        matchedAddress: match.address,
        matchedName: match.name,
        reason: "New proxy admin is in knownAdmins allowlist."
      };
    }

    return {
      finalSeverity: "CRITICAL",
      matchedAllowlist: false,
      allowlist: "knownAdmins",
      ...(newAddress === undefined ? {} : { matchedAddress: newAddress }),
      reason:
        newAddress === undefined
          ? "New proxy admin address was not available for allowlist matching."
          : "New proxy admin is not in knownAdmins allowlist."
    };
  }

  if (alert.ruleId === "GOVERNANCE_PAYLOAD_EXECUTED") {
    const match = findAllowlistMatch(alert.address, allowlists.knownGovernanceContracts);

    if (match !== undefined) {
      return {
        finalSeverity: "INFO",
        matchedAllowlist: true,
        allowlist: "knownGovernanceContracts",
        matchedAddress: match.address,
        matchedName: match.name,
        reason: "Governance payload emitter is in knownGovernanceContracts allowlist."
      };
    }

    return {
      finalSeverity: "WARNING",
      matchedAllowlist: false,
      allowlist: "knownGovernanceContracts",
      matchedAddress: alert.address,
      reason: "Governance payload emitter is not in knownGovernanceContracts allowlist."
    };
  }

  if (alert.ruleId === "PROXY_UPGRADED") {
    const match = findAllowlistMatch(alert.address, allowlists.knownProxyAddresses);

    if (match !== undefined) {
      return {
        finalSeverity: "WARNING",
        matchedAllowlist: true,
        allowlist: "knownProxyAddresses",
        matchedAddress: match.address,
        matchedName: match.name,
        reason: "Upgrade event emitter is in knownProxyAddresses allowlist."
      };
    }

    return {
      finalSeverity: "WARNING",
      matchedAllowlist: false,
      allowlist: "knownProxyAddresses",
      matchedAddress: alert.address,
      reason: "Upgrade event emitter is not in knownProxyAddresses allowlist; severity unchanged for v1."
    };
  }

  return {
    finalSeverity: alert.severity,
    matchedAllowlist: false,
    reason: "No allowlist severity refinement rule matched this alert type."
  };
}

function readEip1967Address(alert: Alert, key: "newAddress" | "previousAddress"): Address | undefined {
  const eip1967 = alert.metadata.eip1967;

  if (!isRecord(eip1967)) {
    return undefined;
  }

  const value = eip1967[key];

  if (typeof value !== "string" || !isAddress(value)) {
    return undefined;
  }

  return getAddress(value);
}

function findAllowlistMatch(address: string | undefined, entries: AllowlistEntry[]): AllowlistEntry | undefined {
  if (address === undefined || !isAddress(address)) {
    return undefined;
  }

  const normalized = getAddress(address);

  return entries.find((entry) => getAddress(entry.address) === normalized);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
