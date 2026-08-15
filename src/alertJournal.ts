import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Alert } from "./alerts.js";

export type JournalRecord = {
  alertId: string;
  blockNumber: string;
  blockHash: string;
  transactionHash: string;
  ruleId: string;
  recordedAt: string;
};

export class AlertJournalError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "AlertJournalError";
  }
}

export class AlertJournal {
  private readonly ids = new Set<string>();
  private loaded = false;

  constructor(private readonly filePath: string) {}

  load(): void {
    if (this.loaded) return;
    const path = resolve(this.filePath);
    if (existsSync(path)) {
      let contents: string;
      try { contents = readFileSync(path, "utf8"); } catch (error) { throw new AlertJournalError(`Cannot read journal ${path}.`, { cause: error }); }
      for (const [index, line] of contents.split("\n").entries()) {
        if (line.trim() === "") continue;
        let value: unknown;
        try { value = JSON.parse(line); } catch (error) { throw new AlertJournalError(`Corrupt journal line ${index + 1}.`, { cause: error }); }
        if (!isRecord(value) || typeof value.alertId !== "string" || typeof value.blockNumber !== "string" || typeof value.blockHash !== "string" || typeof value.transactionHash !== "string" || typeof value.ruleId !== "string" || typeof value.recordedAt !== "string") {
          throw new AlertJournalError(`Invalid journal record at line ${index + 1}.`);
        }
        this.ids.add(value.alertId);
      }
    }
    this.loaded = true;
  }

  has(alertId: string): boolean { this.load(); return this.ids.has(alertId); }
  filterNew(alerts: readonly Alert[]): Alert[] { this.load(); return alerts.filter((alert) => !this.ids.has(alert.id)); }

  append(alerts: readonly Alert[], blockHashes: ReadonlyMap<string, string>, recordedAt: string): void {
    this.load();
    if (alerts.length === 0) return;
    const path = resolve(this.filePath);
    mkdirSync(dirname(path), { recursive: true });
    const records = alerts.map((alert) => {
      const blockHash = blockHashes.get(alert.blockNumber);
      if (blockHash === undefined) throw new AlertJournalError(`Missing block hash for alert ${alert.id}.`);
      return JSON.stringify({ alertId: alert.id, blockNumber: alert.blockNumber, blockHash, transactionHash: alert.transactionHash, ruleId: alert.ruleId, recordedAt });
    }).join("\n") + "\n";
    try { appendFileSync(path, records, "utf8"); } catch (error) { throw new AlertJournalError(`Cannot append alert journal ${path}.`, { cause: error }); }
    for (const alert of alerts) this.ids.add(alert.id);
  }
}

function isRecord(value: unknown): value is Record<string, string> { return typeof value === "object" && value !== null && !Array.isArray(value); }
