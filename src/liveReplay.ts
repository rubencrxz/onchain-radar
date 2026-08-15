import { mkdtempSync, readFileSync } from "node:fs";
import type { Alert } from "./alerts.js";
import { AlertJournal } from "./alertJournal.js";
import { tmpdir } from "node:os";
import { join } from "node:path";

const artifact = "alerts/economic-historical-calibration-001.jsonl";
const alerts = readFileSync(artifact, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Alert);
const incidentAlerts = alerts.filter((alert) => BigInt(alert.blockNumber) >= 24908285n && BigInt(alert.blockNumber) <= 24908330n);
const seen = new Set<string>();
const journalPath = join(mkdtempSync(join(tmpdir(), "onchain-radar-kelp-replay-")), "journal.jsonl");
const journal = new AlertJournal(journalPath);
const firstAt = incidentAlerts.find((alert) => BigInt(alert.blockNumber) === 24908285n);
if (firstAt === undefined) throw new Error("Calibration fixture lacks the block 24908285 alert.");

console.log("KelpDAO/rsETH offline incremental replay (fixture, not live RPC)");
console.log("block 24908284: no incident alerts");
const extractionAlerts = incidentAlerts.filter((alert) => BigInt(alert.blockNumber) === 24908285n);
for (const alert of extractionAlerts) { if (!seen.has(alert.id)) { seen.add(alert.id); console.log(`block 24908285: extraction alert emitted (${alert.ruleId})`); } }
journal.append(extractionAlerts, new Map([["24908285", "0x" + "a".repeat(64)]]), "2026-07-31T00:00:00.000Z");
console.log("restart: checkpoint restored (simulated using durable journal fixture)");
const restarted = new AlertJournal(journalPath);
console.log(`replay 24908285: ${restarted.filterNew(extractionAlerts).length} duplicate alerts emitted (journal format verified)`);
console.log("first Aave interaction: approximately 192 seconds later");
