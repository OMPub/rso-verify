// Reproduce the doc-chain spine from the published daily manifest (SPEC §5).
// Independently recomputes every daily blockHash, monthly Merkle root, and the
// month-root spine — the three anchors from vectors/daily_manifest.txt alone.

import { readFileSync } from "node:fs";
import { blockHash, dayDocRef, monthDocRef, merkleRoot, parse32 } from "./hashing.ts";

export interface ManifestDay {
  year: number;
  month: number;
  day: number;
  contentHash: Uint8Array;
  recordCount: number;
}

export interface MonthResult {
  year: number;
  month: number;
  dayCount: number;
  monthRoot: Uint8Array;
  blockHash: Uint8Array;
  parentHash: Uint8Array;
}

export interface SpineResult {
  days: number;
  months: number;
  genesisDay: string;
  genesisHash: Uint8Array;
  weldDay: string;
  weldHash: Uint8Array;
  spineHead: Uint8Array;
  monthResults: MonthResult[];
}

// Proleptic-Gregorian helpers for the SPEC §1.1 calendar-validity check.
const MONTH_LEN = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const isLeap = (y: number): boolean => y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
const daysInMonth = (y: number, m: number): number => (m === 2 && isLeap(y) ? 29 : MONTH_LEN[m - 1]);
function nextDay(y: number, m: number, d: number): [number, number, number] {
  d++;
  if (d > daysInMonth(y, m)) { d = 1; m++; if (m > 12) { m = 1; y++; } }
  return [y, m, d];
}

const MANIFEST_LINE = /^(\d{4})-(\d{2})-(\d{2}) ([0-9a-f]{64}) (0|[1-9][0-9]*)$/;

/**
 * Parse "YYYY-MM-DD <contentHash> <recordCount>" lines under the SPEC §5
 * grammar: LF lines, exactly two single-space separators, bare lowercase hex,
 * calendar-valid dates advancing by exactly one day, canonical recordCount.
 * Reject anything else — a malformed manifest MUST never yield anchors.
 */
export function parseManifest(path: string): ManifestDay[] {
  const text = readFileSync(path, "utf8");
  const days: ManifestDay[] = [];
  const lines = text.split("\n");
  for (let ln = 0; ln < lines.length; ln++) {
    const line = lines[ln];
    if (line === "") continue;
    if (line.length > 96) throw new Error(`manifest line ${ln + 1}: longer than 96 bytes`);
    const m = MANIFEST_LINE.exec(line);
    if (!m) throw new Error(`manifest line ${ln + 1}: does not match the SPEC §5 grammar`);
    const year = Number(m[1]);
    const month = Number(m[2]);
    const day = Number(m[3]);
    if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) {
      throw new Error(`manifest line ${ln + 1}: '${m[1]}-${m[2]}-${m[3]}' is not a calendar date`);
    }
    if (days.length > 0) {
      const p = days[days.length - 1];
      const [ey, em, ed] = nextDay(p.year, p.month, p.day);
      if (year !== ey || month !== em || day !== ed) {
        throw new Error(`manifest line ${ln + 1}: date does not follow the previous line by exactly one day`);
      }
    }
    if (m[5].length > 15) throw new Error(`manifest line ${ln + 1}: recordCount too large`);
    days.push({ year, month, day, contentHash: parse32(m[4]), recordCount: Number(m[5]) });
  }
  return days;
}

const ZERO32 = new Uint8Array(32);

function dayStr(d: ManifestDay): string {
  const p = (n: number, w: number) => String(n).padStart(w, "0");
  return `${p(d.year, 4)}-${p(d.month, 2)}-${p(d.day, 2)}`;
}

/** Replay the manifest into the full spine. */
export function buildSpine(days: ManifestDay[]): SpineResult {
  if (days.length === 0) throw new Error("empty manifest");

  const order: Array<[number, number]> = [];
  const leaves = new Map<string, Uint8Array[]>();

  let parent: Uint8Array = ZERO32;
  let genesisHash: Uint8Array = ZERO32;
  let weldHash: Uint8Array = ZERO32;
  let genesisDay = "";
  let weldDay = "";

  for (let i = 0; i < days.length; i++) {
    const d = days[i];
    const bh = blockHash(dayDocRef(d.year, d.month, d.day), parent, d.contentHash);
    if (i === 0) {
      genesisDay = dayStr(d);
      genesisHash = bh;
    }
    if (i === days.length - 1) {
      weldDay = dayStr(d);
      weldHash = bh;
    }
    const key = `${d.year}-${d.month}`;
    let bucket = leaves.get(key);
    if (!bucket) {
      bucket = [];
      leaves.set(key, bucket);
      order.push([d.year, d.month]);
    }
    bucket.push(bh);
    parent = bh;
  }

  const monthResults: MonthResult[] = [];
  let mParent: Uint8Array = ZERO32;
  for (const [y, m] of order) {
    const bucket = leaves.get(`${y}-${m}`)!;
    const root = merkleRoot(bucket);
    const mbh = blockHash(monthDocRef(y, m), mParent, root);
    monthResults.push({ year: y, month: m, dayCount: bucket.length, monthRoot: root, blockHash: mbh, parentHash: mParent });
    mParent = mbh;
  }

  return {
    days: days.length,
    months: order.length,
    genesisDay,
    genesisHash,
    weldDay,
    weldHash,
    spineHead: mParent,
    monthResults,
  };
}
