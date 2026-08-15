import type { AlertSeverity } from "./alerts.js";

export type RuleDefinition = {
  ruleId: string;
  ruleName: string;
  defaultSeverity: AlertSeverity;
  summary: (address: string, decoded?: Record<string, unknown>) => string;
};

const EVENT_RULES = new Map<string, RuleDefinition>([
  [
    "OwnershipTransferred(address,address)",
    {
      ruleId: "OWNERSHIP_TRANSFERRED",
      ruleName: "Ownership/Admin Changed",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const previousOwner = getDecodedString(decoded, "previousOwner");
        const newOwner = getDecodedString(decoded, "newOwner");

        if (previousOwner !== undefined && newOwner !== undefined) {
          return `Ownership transferred from ${previousOwner} to ${newOwner}.`;
        }

        return `Ownership transfer event emitted by ${address}.`;
      }
    }
  ],
  [
    "RoleGranted(bytes32,address,address)",
    {
      ruleId: "ROLE_GRANTED",
      ruleName: "Ownership/Admin Changed",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const role = getDecodedString(decoded, "role");
        const account = getDecodedString(decoded, "account");
        const sender = getDecodedString(decoded, "sender");

        if (role !== undefined && account !== undefined && sender !== undefined) {
          return `Role granted: ${role} to ${account} by ${sender}.`;
        }

        return `AccessControl role grant event emitted by ${address}.`;
      }
    }
  ],
  [
    "RoleRevoked(bytes32,address,address)",
    {
      ruleId: "ROLE_REVOKED",
      ruleName: "Ownership/Admin Changed",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const role = getDecodedString(decoded, "role");
        const account = getDecodedString(decoded, "account");
        const sender = getDecodedString(decoded, "sender");

        if (role !== undefined && account !== undefined && sender !== undefined) {
          return `Role revoked: ${role} from ${account} by ${sender}.`;
        }

        return `AccessControl role revoke event emitted by ${address}.`;
      }
    }
  ],
  [
    "Paused(address)",
    {
      ruleId: "PAUSED",
      ruleName: "Pause or Unpause Detected",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const account = getDecodedString(decoded, "account");
        return account === undefined ? `Pause event emitted by ${address}.` : `Contract paused by ${account}.`;
      }
    }
  ],
  [
    "Unpaused(address)",
    {
      ruleId: "UNPAUSED",
      ruleName: "Pause or Unpause Detected",
      defaultSeverity: "INFO",
      summary: (address, decoded) => {
        const account = getDecodedString(decoded, "account");
        return account === undefined ? `Unpause event emitted by ${address}.` : `Contract unpaused by ${account}.`;
      }
    }
  ],
  [
    "Upgraded(address)",
    {
      ruleId: "PROXY_UPGRADED",
      ruleName: "Proxy Implementation Upgraded",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const implementation = getDecodedString(decoded, "implementation");

        if (implementation !== undefined) {
          return `Proxy upgraded to implementation ${implementation}.`;
        }

        return `Proxy upgrade event emitted by ${address}.`;
      }
    }
  ],
  [
    "AdminChanged(address,address)",
    {
      ruleId: "PROXY_ADMIN_CHANGED",
      ruleName: "Proxy Implementation Upgraded",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const previousAdmin = getDecodedString(decoded, "previousAdmin");
        const newAdmin = getDecodedString(decoded, "newAdmin");

        if (previousAdmin !== undefined && newAdmin !== undefined) {
          return `Proxy admin changed from ${previousAdmin} to ${newAdmin}.`;
        }

        return `Proxy admin change event emitted by ${address}.`;
      }
    }
  ],
  [
    "ExecutionSuccess(bytes32,uint256)",
    {
      ruleId: "SAFE_EXECUTION_SUCCESS",
      ruleName: "Safe Multisig Execution",
      defaultSeverity: "INFO",
      summary: (address, decoded) => {
        const txHash = getDecodedString(decoded, "txHash");
        return txHash === undefined ? `Safe execution success event emitted by ${address}.` : `Safe execution succeeded: ${txHash}.`;
      }
    }
  ],
  [
    "ExecutionFailure(bytes32,uint256)",
    {
      ruleId: "SAFE_EXECUTION_FAILURE",
      ruleName: "Safe Multisig Execution",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const txHash = getDecodedString(decoded, "txHash");
        return txHash === undefined ? `Safe execution failure event emitted by ${address}.` : `Safe execution failed: ${txHash}.`;
      }
    }
  ],
  [
    "ExecutionFromModuleSuccess(address)",
    {
      ruleId: "SAFE_MODULE_EXECUTION_SUCCESS",
      ruleName: "Safe Module Execution",
      defaultSeverity: "INFO",
      summary: (address, decoded) => {
        const module = getDecodedString(decoded, "module");
        return module === undefined ? `Safe module execution success emitted by ${address}.` : `Safe module ${module} executed successfully.`;
      }
    }
  ],
  [
    "ExecutionFromModuleFailure(address)",
    {
      ruleId: "SAFE_MODULE_EXECUTION_FAILURE",
      ruleName: "Safe Module Execution",
      defaultSeverity: "WARNING",
      summary: (address, decoded) => {
        const module = getDecodedString(decoded, "module");
        return module === undefined ? `Safe module execution failure emitted by ${address}.` : `Safe module ${module} execution failed.`;
      }
    }
  ],
  ["AddedOwner(address)", safeNativeRule("SAFE_OWNER_ADDED", "Safe Owner Added", "owner", "Safe owner added")],
  ["RemovedOwner(address)", safeNativeRule("SAFE_OWNER_REMOVED", "Safe Owner Removed", "owner", "Safe owner removed")],
  ["ChangedThreshold(uint256)", safeNativeRule("SAFE_THRESHOLD_CHANGED", "Safe Threshold Changed", "threshold", "Safe threshold changed to")],
  ["EnabledModule(address)", safeNativeRule("SAFE_MODULE_ENABLED", "Safe Module Enabled", "module", "Safe module enabled")],
  ["DisabledModule(address)", safeNativeRule("SAFE_MODULE_DISABLED", "Safe Module Disabled", "module", "Safe module disabled")],
  ["ChangedGuard(address)", safeNativeRule("SAFE_GUARD_CHANGED", "Safe Guard Changed", "guard", "Safe guard changed to")],
  ["ChangedFallbackHandler(address)", safeNativeRule("SAFE_FALLBACK_HANDLER_CHANGED", "Safe Fallback Handler Changed", "handler", "Safe fallback handler changed to")],
  [
    "PayloadExecuted(uint40)",
    {
      ruleId: "GOVERNANCE_PAYLOAD_EXECUTED",
      ruleName: "Governance Payload Executed",
      defaultSeverity: "INFO",
      summary: (address, decoded) => {
        const payloadId = getDecodedString(decoded, "payloadId");

        if (payloadId !== undefined) {
          return `Governance payload executed: payloadId ${payloadId}.`;
        }

        return `Governance payload execution event emitted by ${address}.`;
      }
    }
  ]
]);

function safeNativeRule(
  ruleId: string,
  ruleName: string,
  parameter: string,
  label: string
): RuleDefinition {
  return {
    ruleId,
    ruleName,
    defaultSeverity: "WARNING",
    summary: (address, decoded) => {
      const value = getDecodedString(decoded, parameter);
      return value === undefined ? `${ruleName} event emitted by ${address}.` : `${label} ${value}.`;
    }
  };
}

export function getRuleForEventSignature(eventSignature: string): RuleDefinition | undefined {
  return EVENT_RULES.get(eventSignature);
}

export function countAlertsByRuleId(ruleIds: string[]): Map<string, number> {
  const counts = new Map<string, number>();

  for (const ruleId of ruleIds) {
    counts.set(ruleId, (counts.get(ruleId) ?? 0) + 1);
  }

  return counts;
}

function getDecodedString(decoded: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = decoded?.[key];

  if (typeof value === "string" && value !== "") {
    return value;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return value.toString();
  }

  return undefined;
}
