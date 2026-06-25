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

/** Parse "YYYY-MM-DD <contentHash> <recordCount>" lines. */
export function parseManifest(path: string): ManifestDay[] {
  const text = readFileSync(path, "utf8");
  const days: ManifestDay[] = [];
  const lines = text.split("\n");
  for (let ln = 0; ln < lines.length; ln++) {
    const line = lines[ln].trim();
    if (line === "") continue;
    const f = line.split(/\s+/);
    if (f.length !== 3) throw new Error(`manifest line ${ln + 1}: want 3 fields, got ${f.length}`);
    const dp = f[0].split("-");
    if (dp.length !== 3) throw new Error(`manifest line ${ln + 1}: bad day '${f[0]}'`);
    days.push({
      year: Number(dp[0]),
      month: Number(dp[1]),
      day: Number(dp[2]),
      contentHash: parse32(f[1]),
      recordCount: Number(f[2]),
    });
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
