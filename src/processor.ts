import type { Alert, RawLogForAlert } from "./alerts.js";
import { createAlertFromLog } from "./alerts.js";
import type { AllowlistConfig } from "./config.js";
import type { EventTopicMap } from "./events.js";
import { getRuleForEventSignature } from "./rules.js";
import { refineAlertSeverity } from "./severity.js";

export type UnprocessedLog = {
  log: RawLogForAlert;
  matchedEventSignature: string;
};

export type ProcessLogsResult = {
  alerts: Alert[];
  unprocessedLogs: UnprocessedLog[];
};

export type ProcessorClock = () => string;

export function processLogs(params: {
  chain: "ethereum";
  logs: readonly RawLogForAlert[];
  topicMap: EventTopicMap;
  allowlists: AllowlistConfig;
  clock: ProcessorClock;
}): ProcessLogsResult {
  const alerts: Alert[] = [];
  const unprocessedLogs: UnprocessedLog[] = [];

  for (const log of params.logs) {
    const topic0 = log.topics[0];
    const eventSignature = topic0 === undefined ? undefined : params.topicMap.get(topic0);

    if (eventSignature === undefined) {
      unprocessedLogs.push({ log, matchedEventSignature: "unknown" });
      continue;
    }

    const rule = getRuleForEventSignature(eventSignature);

    if (rule === undefined) {
      unprocessedLogs.push({ log, matchedEventSignature: eventSignature });
      continue;
    }

    const alert = createAlertFromLog({
      chain: params.chain,
      log,
      eventSignature,
      rule,
      createdAt: params.clock()
    });

    alerts.push(refineAlertSeverity(alert, params.allowlists));
  }

  return { alerts: deduplicateAlerts(alerts), unprocessedLogs };
}

export function deduplicateAlerts(alerts: readonly Alert[]): Alert[] {
  const seenIds = new Set<string>();
  const uniqueAlerts: Alert[] = [];

  for (const alert of alerts) {
    if (seenIds.has(alert.id)) {
      continue;
    }

    seenIds.add(alert.id);
    uniqueAlerts.push(alert);
  }

  return uniqueAlerts;
}
