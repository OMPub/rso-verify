// Canonical numeric core projection — schema rso-core-omm-v1 (SPEC §2).
// Clean-room TypeScript port; byte-identical to the Go client and the producer's
// tle_normalize.py. NO IEEE-754 float in any value path: the epoch microsecond
// arithmetic uses BigInt (frac × 86_400_000_000 overflows Number.MAX_SAFE_INTEGER),
// everything else is string/integer work.

import { createHash } from "node:crypto";

const enc = new TextEncoder();

// Alpha-5: index of the first satnum char IS the high-digit value; I and O skipped.
const ALPHA5 = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";

const USEC_PER_DAY = 86_400_000_000n;
const EPOCH_GRID_USEC = 864; // 1e-8 day exactly; every TLE epoch is a multiple of this

/** The 11 hashed fields (the pure orbit), in canonical (sorted) order. */
export const CORE_KEYS = [
  "ARG_OF_PERICENTER", "BSTAR", "ECCENTRICITY", "EPOCH", "INCLINATION",
  "MEAN_ANOMALY", "MEAN_MOTION", "MEAN_MOTION_DDOT", "MEAN_MOTION_DOT",
  "NORAD_CAT_ID", "RA_OF_ASC_NODE",
] as const;

/** One canonical 11-field orbit record; every value is a string token. */
export interface CoreRecord {
  ARG_OF_PERICENTER: string;
  BSTAR: string;
  ECCENTRICITY: string;
  EPOCH: string;
  INCLINATION: string;
  MEAN_ANOMALY: string;
  MEAN_MOTION: string;
  MEAN_MOTION_DDOT: string;
  MEAN_MOTION_DOT: string;
  NORAD_CAT_ID: string;
  RA_OF_ASC_NODE: string;
}

function asciiDigits(s: string): boolean {
  if (s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

function isAllZero(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "0" && s[i] !== ".") return false;
  }
  return true;
}

// The assumed-exponent field's exponent: an optional sign then EXACTLY 1 or 2
// ASCII digits (SPEC §2.2 shape bounds).
function validAssumedExpStr(s: string): boolean {
  if (s.length === 0) return false;
  if (s[0] === "+" || s[0] === "-") s = s.slice(1);
  return (s.length === 1 || s.length === 2) && asciiDigits(s);
}

// Whitespace handling is ASCII-only by spec (SPEC §2.2): exactly \t\n\v\f\r and
// space. Unicode whitespace (NBSP U+00A0, NEL U+0085, BOM U+FEFF, the C0
// information separators U+001C–001F, ideographic space U+3000, …) is
// NON-canonical and left in place so the ascii-digit guards reject it
// fail-closed — this is what makes every client agree byte-for-byte. Do NOT use
// String.prototype.trim() (it strips a different Unicode set: drops BOM, keeps NEL).
const ASCII_WS_LEFT = /^[ \t\n\v\f\r]+/;
const ASCII_WS_RIGHT = /[ \t\n\v\f\r]+$/;
function stripAscii(s: string): string {
  return s.replace(ASCII_WS_LEFT, "").replace(ASCII_WS_RIGHT, "");
}
function rstripAscii(s: string): string {
  return s.replace(ASCII_WS_RIGHT, "");
}

function applyExponent(mantissa: string, exp: number): string {
  let intPart = mantissa;
  let fracPart = "";
  const dot = mantissa.indexOf(".");
  if (dot >= 0) {
    intPart = mantissa.slice(0, dot);
    fracPart = mantissa.slice(dot + 1);
  }
  const digits = intPart + fracPart;
  const point = intPart.length + exp;
  if (point <= 0) return "0." + "0".repeat(-point) + digits;
  if (point >= digits.length) return digits + "0".repeat(point - digits.length);
  return digits.slice(0, point) + "." + digits.slice(point);
}

/** The shared numeric tokenizer (SPEC §2.2): shortest plain-decimal of a terminating decimal. */
export function canonDecimal(input: string): string {
  let s = stripAscii(input);
  s = s.replace(/\\+$/, "");
  s = stripAscii(s);
  if (s === "") throw new Error("empty decimal field");
  let neg = false;
  if (s[0] === "+" || s[0] === "-") {
    neg = s[0] === "-";
    s = s.slice(1);
  }
  if (s.indexOf("e") >= 0 || s.indexOf("E") >= 0) {
    const low = s.toLowerCase();
    const i = low.indexOf("e");
    const mant = low.slice(0, i);
    let exp = low.slice(i + 1);
    let esign = "";
    if (exp.length > 0 && (exp[0] === "+" || exp[0] === "-")) {
      esign = exp[0];
      exp = exp.slice(1);
    }
    if (!asciiDigits(exp) || mant === "") throw new Error(`bad exponent form: '${s}'`);
    const ev = Number(esign + exp);
    // SPEC §2.2 step 3: |exponent| ≤ 999, the identical bound in every language.
    if (ev > 999 || ev < -999) throw new Error(`exponent out of bounds: '${s}'`);
    s = applyExponent(mant, ev);
  }
  if (s.indexOf(".") < 0) s += ".";
  const dot = s.indexOf(".");
  const intPartRaw = s.slice(0, dot);
  let fracPart = s.slice(dot + 1);
  if (!asciiDigits(intPartRaw + fracPart)) throw new Error(`non-numeric decimal field: '${s}'`);
  fracPart = fracPart.replace(/0+$/, "");
  let intPart = intPartRaw.replace(/^0+/, "");
  if (intPart === "") intPart = "0";
  let out = fracPart !== "" ? intPart + "." + fracPart : intPart;
  if (isAllZero(out)) return "0";
  return neg ? "-" + out : out;
}

/**
 * Decode a TLE assumed-decimal-exponent field (BSTAR, MEAN_MOTION_DDOT) under the
 * one unified rule (SPEC §2.2). Fail-closed.
 */
export function decodeAssumedExp(field: string): string {
  if (field.length < 7) throw new Error(`assumed-exponent field too short: '${field}'`);
  let msign = "";
  let rest: string;
  const c0 = field[0];
  if (c0 === "+" || c0 === "-") {
    if (c0 === "-") msign = "-";
    rest = rstripAscii(field.slice(1));
  } else if (c0 === " ") {
    rest = rstripAscii(field.slice(1));
  } else if (c0 >= "0" && c0 <= "9") {
    rest = rstripAscii(field);
  } else {
    throw new Error(`malformed assumed-exponent field: '${field}'`);
  }
  const sp = Math.max(rest.lastIndexOf("+"), rest.lastIndexOf("-"));
  let mantDigits: string;
  let expStr: string;
  if (sp > 0) {
    mantDigits = rest.slice(0, sp);
    expStr = rest.slice(sp);
  } else {
    if (rest.length < 5) throw new Error(`malformed assumed-exponent field: '${field}'`);
    mantDigits = rest.slice(0, 5);
    expStr = rest.slice(5);
  }
  // SPEC §2.2 shape bounds: mantissa EXACTLY 5 or 6 digits, exponent 1–2 digits.
  if (mantDigits.length < 5 || mantDigits.length > 6 || !asciiDigits(mantDigits) || !validAssumedExpStr(expStr)) {
    throw new Error(`malformed assumed-exponent field: '${field}'`);
  }
  if (isAllZero(mantDigits)) return "0";
  let intPart = mantDigits.slice(0, mantDigits.length - 5).replace(/^0+/, "");
  if (intPart === "") intPart = "0";
  const frac = mantDigits.slice(mantDigits.length - 5);
  return canonDecimal(`${msign}${intPart}.${frac}e${Number(expStr)}`);
}

/**
 * Decode an Alpha-5 / plain satnum field to its integer value (SPEC §2.4).
 * Bounded + ASCII-strict: a plain numeric id is ≤ 9 digits (≤ 999,999,999, the
 * documented OMM max); an Alpha-5 id is EXACTLY 5 chars (ASCII letter + 4 ASCII
 * digits, ≤ 339,999). The leading char is ASCII-uppercased only (a–z → A–Z, never
 * Unicode case-folding such as long-s ſ → S). Both bounds keep the value < 2^53 so
 * Number() is exact; larger or non-ASCII inputs are non-canonical → fail closed.
 */
export function decodeSatnum(field: string): number {
  field = stripAscii(field);
  if (field === "") throw new Error("empty satnum");
  const c0 = field[0];
  if (c0 >= "0" && c0 <= "9") {
    if (!asciiDigits(field)) throw new Error(`bad numeric satnum: '${field}'`);
    const sig = field.replace(/^0+/, "") || "0";
    if (sig.length > 9) throw new Error(`numeric satnum out of range: '${field}'`);
    return Number(sig);
  }
  if (field.length !== 5) throw new Error(`bad Alpha-5 satnum length: '${field}'`);
  const upper = c0 >= "a" && c0 <= "z" ? String.fromCharCode(c0.charCodeAt(0) - 32) : c0;
  const idx = ALPHA5.indexOf(upper);
  if (idx < 10) throw new Error(`bad Alpha-5 leading char: '${field}'`); // must be a letter (index ≥ 10)
  const rest = field.slice(1);
  if (!asciiDigits(rest)) throw new Error(`bad Alpha-5 satnum: '${field}'`);
  return idx * 10000 + Number(rest);
}

/** Canonical base-10 integer-string NORAD token. */
export function canonNorad(n: number): string {
  if (n < 0) throw new Error(`negative NORAD id: ${n}`);
  return String(n);
}

// --- EPOCH (SPEC §2.3): fixed-width civil UTC on the 864-microsecond grid ---

function isLeap(y: number): boolean {
  return y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
}
function daysInYear(y: number): number {
  return isLeap(y) ? 366 : 365;
}

const MONTH_LENGTHS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function doyToMD(year: number, doy: number): [number, number] {
  const leap = isLeap(year);
  for (let m = 1; m <= 12; m++) {
    let length = MONTH_LENGTHS[m - 1];
    if (m === 2 && leap) length++;
    if (doy <= length) return [m, doy];
    doy -= length;
  }
  throw new Error(`day-of-year out of range for ${year}`);
}

function pad(n: number, w: number): string {
  return String(n).padStart(w, "0");
}

function renderEpoch(year: number, doy: number, usecOfDay: number): string {
  while (usecOfDay >= 86_400_000_000) {
    usecOfDay -= 86_400_000_000;
    doy++;
  }
  while (doy > daysInYear(year)) {
    doy -= daysInYear(year);
    year++;
  }
  if (usecOfDay % EPOCH_GRID_USEC !== 0) {
    throw new Error(`epoch off the ${EPOCH_GRID_USEC}us grid: ${usecOfDay}`);
  }
  const [month, day] = doyToMD(year, doy);
  const h = Math.floor(usecOfDay / 3_600_000_000);
  let rem = usecOfDay % 3_600_000_000;
  const mi = Math.floor(rem / 60_000_000);
  rem %= 60_000_000;
  const sec = Math.floor(rem / 1_000_000);
  const us = rem % 1_000_000;
  return `${pad(year, 4)}-${pad(month, 2)}-${pad(day, 2)}T${pad(h, 2)}:${pad(mi, 2)}:${pad(sec, 2)}.${pad(us, 6)}`;
}

// pySlice mimics Python s[i:j]: clamps to bounds, never throws.
function pySlice(s: string, i: number, j: number): string {
  const n = s.length;
  if (i < 0) i = 0;
  if (j > n) j = n;
  if (i >= j) return "";
  return s.slice(i, j);
}

/** Canonical EPOCH token from a TLE line-1 YYDDD.FFFFFFFF field. */
export function epochFromTLE(line1: string): string {
  const raw = stripAscii(pySlice(line1, 18, 32));
  if (raw.length < 2 || !asciiDigits(raw.slice(0, 2))) {
    throw new Error(`non-ASCII/invalid epoch year: '${raw}'`);
  }
  const yy = Number(raw.slice(0, 2));
  const year = yy >= 57 ? 1900 + yy : 2000 + yy;
  const body = raw.slice(2);
  const dotIdx = body.indexOf(".");
  const doyStr = dotIdx >= 0 ? body.slice(0, dotIdx) : body;
  const fracStr = dotIdx >= 0 ? body.slice(dotIdx + 1) : "";
  if (!asciiDigits(doyStr) || (fracStr !== "" && !asciiDigits(fracStr))) {
    throw new Error(`non-ASCII/invalid epoch field: '${raw}'`);
  }
  const doy = Number(doyStr);
  if (doy < 1 || doy > daysInYear(year)) {
    throw new Error(`day-of-year ${doy} out of range for ${year}`);
  }
  // SPEC §2.3: L ≤ 8 keeps F·USEC_PER_DAY < 2^63 (exact in 64-bit ints everywhere).
  if (fracStr.length > 8) throw new Error(`epoch fraction longer than 8 digits: '${raw}'`);
  let usecOfDay = 0;
  if (fracStr !== "") {
    const fracVal = BigInt(fracStr);
    const scale = 10n ** BigInt(fracStr.length);
    usecOfDay = Number((fracVal * USEC_PER_DAY + scale / 2n) / scale);
  }
  return renderEpoch(year, doy, usecOfDay);
}

function line1Offset(line1: string): number {
  if (line1.length > 23 && line1[23] === ".") return 0;
  if (line1.length > 24 && line1[24] === ".") return 1;
  return 0;
}

// §1.1 input model: a TLE line is a byte string of the §2.2 whitespace set
// (0x09–0x0D) and printable ASCII (0x20–0x7E) ONLY. Enforcing it makes byte,
// UTF-16 and code-point slicing coincide across clients (surrogates, astral
// chars and control bytes all reject here).
function asciiTLELine(line: string): void {
  for (let i = 0; i < line.length; i++) {
    const c = line.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7e) || (c >= 0x09 && c <= 0x0d)) continue;
    throw new Error(`non-ASCII/control byte 0x${c.toString(16)} at offset ${i} in TLE line`);
  }
}

/** Build the canonical 11-field record from a TLE line pair (SPEC §2.5). */
export function coreRecordFromTLE(line1: string, line2: string): CoreRecord {
  asciiTLELine(line1);
  asciiTLELine(line2);
  const off = line1Offset(line1);
  const l1 = off > 0 ? line1.slice(off) : line1;
  return {
    NORAD_CAT_ID: canonNorad(decodeSatnum(pySlice(line2, 2, 7))),
    EPOCH: epochFromTLE(l1),
    INCLINATION: canonDecimal(pySlice(line2, 8, 16)),
    RA_OF_ASC_NODE: canonDecimal(pySlice(line2, 17, 25)),
    ECCENTRICITY: canonDecimal("0." + stripAscii(pySlice(line2, 26, 33))),
    ARG_OF_PERICENTER: canonDecimal(pySlice(line2, 34, 42)),
    MEAN_ANOMALY: canonDecimal(pySlice(line2, 43, 51)),
    MEAN_MOTION: canonDecimal(pySlice(line2, 52, 63)),
    MEAN_MOTION_DOT: canonDecimal(pySlice(l1, 33, 43)),
    MEAN_MOTION_DDOT: decodeAssumedExp(pySlice(l1, 44, 52)),
    BSTAR: decodeAssumedExp(pySlice(l1, 53, 61)),
  };
}

// --- serialization → contentHash (SPEC §2.6) ---

/** Canonical JSON string for ONE record: sorted ASCII keys, pinned separators, every value a string. */
export function recordJSONString(r: CoreRecord): string {
  return (
    `{"ARG_OF_PERICENTER":"${r.ARG_OF_PERICENTER}"` +
    `,"BSTAR":"${r.BSTAR}"` +
    `,"ECCENTRICITY":"${r.ECCENTRICITY}"` +
    `,"EPOCH":"${r.EPOCH}"` +
    `,"INCLINATION":"${r.INCLINATION}"` +
    `,"MEAN_ANOMALY":"${r.MEAN_ANOMALY}"` +
    `,"MEAN_MOTION":"${r.MEAN_MOTION}"` +
    `,"MEAN_MOTION_DDOT":"${r.MEAN_MOTION_DDOT}"` +
    `,"MEAN_MOTION_DOT":"${r.MEAN_MOTION_DOT}"` +
    `,"NORAD_CAT_ID":"${r.NORAD_CAT_ID}"` +
    `,"RA_OF_ASC_NODE":"${r.RA_OF_ASC_NODE}"}`
  );
}

/** Canonical bytes for ONE record (byte-identical to the Python record_json_bytes). */
export function recordJSONBytes(r: CoreRecord): Uint8Array {
  return enc.encode(recordJSONString(r));
}

// ^(0|[1-9][0-9]*)$ with ≤ 9 digits (SPEC §2.6) — makes the int() sort exact everywhere.
function canonicalNoradToken(s: string): boolean {
  if (!asciiDigits(s) || s.length > 9) return false;
  return s.length === 1 || s[0] !== "0";
}

// Non-empty, drawn from [0-9.\-T:] (SPEC §2.6) — the charset that guarantees no
// JSON escaping can ever fire.
function canonicalValueToken(s: string): boolean {
  if (s === "") return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || c === 46 || c === 45 || c === 84 || c === 58)) return false;
  }
  return true;
}

/** Sort by int(NORAD), reject duplicates + non-canonical tokens, serialize the array. */
export function canonicalBytes(records: CoreRecord[]): Uint8Array {
  const seen = new Set<string>();
  for (const r of records) {
    if (!canonicalNoradToken(r.NORAD_CAT_ID)) throw new Error(`non-canonical NORAD_CAT_ID token: '${r.NORAD_CAT_ID}'`);
    for (const k of CORE_KEYS) {
      if (!canonicalValueToken(r[k])) throw new Error(`non-canonical value token '${r[k]}' in record ${r.NORAD_CAT_ID}`);
    }
    if (seen.has(r.NORAD_CAT_ID)) throw new Error(`duplicate NORAD_CAT_ID in catalog: ${r.NORAD_CAT_ID}`);
    seen.add(r.NORAD_CAT_ID);
  }
  // tokens pre-validated ≤ 9 digits: Number() is exact
  const ordered = records.slice().sort((a, b) => Number(a.NORAD_CAT_ID) - Number(b.NORAD_CAT_ID));
  return enc.encode("[" + ordered.map(recordJSONString).join(",") + "]");
}

/** contentHash = SHA-256 of the canonical core projection, lowercase hex. */
export function contentHash(records: CoreRecord[]): string {
  return createHash("sha256").update(canonicalBytes(records)).digest("hex");
}
