import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Alert } from "./alerts.js";

const ALERTS_DIR = "alerts";

export function buildAlertsFilePath(chain: "ethereum", startBlock: bigint, endBlock: bigint): string {
  return resolve(ALERTS_DIR, `${chain}-${startBlock.toString()}-${endBlock.toString()}-alerts.jsonl`);
}

export function writeAlertsJsonl(filePath: string, alerts: readonly Alert[]): void {
  mkdirSync(dirname(filePath), { recursive: true });

  const contents = alerts.map((alert) => JSON.stringify(alert)).join("\n");
  writeFileSync(filePath, contents.length === 0 ? "" : `${contents}\n`, "utf8");
}
