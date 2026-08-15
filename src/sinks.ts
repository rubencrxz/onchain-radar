import type { Alert } from "./alerts.js";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { writeAlertsJsonl } from "./alertWriter.js";

export interface AlertSink {
  write(alerts: readonly Alert[]): Promise<void> | void;
}

export class JsonlAlertSink implements AlertSink {
  constructor(private readonly filePath: string) {}

  write(alerts: readonly Alert[]): void {
    writeAlertsJsonl(this.filePath, alerts);
  }
}

export class AppendJsonlAlertSink implements AlertSink {
  constructor(private readonly filePath: string) {}
  write(alerts: readonly Alert[]): void {
    if (alerts.length === 0) return;
    mkdirSync(dirname(this.filePath), { recursive: true });
    appendFileSync(this.filePath, alerts.map((alert) => JSON.stringify(alert)).join("\n") + "\n", "utf8");
  }
}

export class TerminalAlertSink implements AlertSink {
  constructor(private readonly writeLine: (line: string) => void = console.log) {}

  write(alerts: readonly Alert[]): void {
    for (const alert of alerts) {
      this.writeLine(`[${alert.severity}] ${alert.ruleId}`);
      this.writeLine(`  summary: ${alert.summary}`);
      this.writeLine(`  blockNumber: ${alert.blockNumber}`);
      this.writeLine(`  transactionHash: ${alert.transactionHash}`);
      this.writeLine(`  address: ${alert.address}`);
      this.writeLine(`  eventSignature: ${alert.eventSignature}`);
      this.writeLine("");
    }
  }
}
