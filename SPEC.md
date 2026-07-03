# RSO Doc-Chain Verification Spec

**Status:** normative · **Schema:** `rso-core-omm-v1` · **Chain:** `https://om.pub/rso/doc-chain`

This is the source of truth for **verifying** the RSO deep-history doc-chain — a
verifiable daily archive of the public space-object catalog from Sputnik
(1957-10-04) through the present, with monthly Merkle roots and daily block hashes
committed on Ethereum.

It is written for **re-implementers**. Like Ethereum's
[execution-specs](https://github.com/ethereum/execution-specs), this English spec
plus the language-neutral [`vectors/`](vectors/) suite defines the protocol; the
clients in [`go/`](go/), [`ts/`](ts/), `rust/`, `python/` are independent implementations
that must all reproduce the vectors byte-for-byte. **No producer/pipeline code
lives here** — only the spec, the vectors, and clean-room verifiers.

A conforming verifier, given the published sources, reproduces three things and
checks them against what is committed on-chain:

1. each day's **`contentHash`** — from the raw orbital elements (§2);
2. each day's **`blockHash`** and the monthly **Merkle roots** (§3–§4);
3. the **anchors** — genesis, weld, and spine head — by replaying the whole chain
   (§5).

Everything below is integer/string arithmetic. **No IEEE-754 float appears
anywhere** (parse or serialize); that is what lets Go, JS, Rust, and Python all
produce identical bytes.

---

## 1. Conventions and constants

| Name | Value |
|---|---|
| `docChainId` | `keccak256("https://om.pub/rso/doc-chain")` = `0x6011620b5a3faa23f8078c2af0bb1a87bb85a68f784abdf3dbae67939c399bea` |
| `DOC_BLOCK_TYPEHASH` | `keccak256("DocBlock(bytes32 docChainId,uint64 docRef,bytes32 parentHash,bytes32 contentHash)")` = `0xb84212102d711af6fc7ae9fa3e37753befb8b25762a552631b0e9ff9e8d07894` |
| `USEC_PER_DAY` | `86400000000` |
| `EPOCH_GRID_USEC` | `864` (= `1e-8` day exactly) |
| `ALPHA5` | `0123456789ABCDEFGHJKLMNPQRSTUVWXYZ` |

Both 32-byte constants MUST be **derived** by the verifier from their preimages,
not hardcoded — that proves the keccak implementation is correct. `keccak256` is
Ethereum **Keccak-256** (padding byte `0x01`), **not** NIST SHA3-256 (`0x06`);
`keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
(`vectors/anchors.json → keccak_empty`).

### 1.1 Input model, rejection semantics, hex, calendar

- **Byte strings.** Every input this spec consumes — TLE lines, decoder fields,
  manifest lines — is a **byte string**; all indices and slices are **0-based
  byte offsets**. A TLE line MUST contain only the bytes `0x09–0x0D` (the §2.2
  whitespace set) and `0x20–0x7E`; **any other byte anywhere in either line
  rejects the elset**. With that guard, byte / UTF-16 / code-point indexing
  coincide, so implementations in every string model slice identically.
- **Reject = no result.** Wherever this spec says *reject*, the enclosing
  computation MUST produce **no value at all** (raise / return an error).
  Skipping the offending record, substituting a default, or hashing a partial
  result is non-conforming.
- **Hex.** 32-byte values in JSON vectors are lowercase hex with a `0x` prefix;
  in `daily_manifest.txt` they are **bare lowercase** hex. On input a verifier
  accepts an optional `0x` prefix and either case, **except** in the manifest
  (bare lowercase only). Surrounding whitespace is never accepted, and a 64-char
  hex parse MUST reject any non-hex character — silently mapping bad digits to
  zero bytes is the classic fail-open. All hex output is lowercase.
- **Calendar.** All dates are **proleptic Gregorian** (leap year: divisible by
  4, except centuries, which must be divisible by 400) and MUST be
  calendar-valid wherever they appear.

---

## 2. Canonical core projection — `rso-core-omm-v1`

An orbital element set has several serializations (modern 69-column TLE; the
legacy spaced-designator / 5-wide / trailing-backslash export; McDowell 1957
lines; live OMM JSON) that byte-differ but encode identical orbits. The
`contentHash` is taken over the **canonical numeric mean-elements as all-string
tokens**, never raw source strings.

### 2.1 `core_record` — 11 mandatory fields (the pure orbit)

```
ARG_OF_PERICENTER, BSTAR, ECCENTRICITY, EPOCH, INCLINATION,
MEAN_ANOMALY, MEAN_MOTION, MEAN_MOTION_DDOT, MEAN_MOTION_DOT,
NORAD_CAT_ID, RA_OF_ASC_NODE
```

All 11 are required; every value is a JSON **string**. The bookkeeping fields
`REV_AT_EPOCH`, `EPHEMERIS_TYPE`, `ELEMENT_SET_NO` are provider counters, **not**
the orbit — they are **excluded from the hash** so the commitment is a pure,
source-independent statement about the orbit.

### 2.2 `canon_decimal(s)` — the shared numeric tokenizer (integer/string only)

The shortest plain-decimal form of a terminating decimal:

1. Strip ASCII whitespace — **exactly** the bytes `0x09 0x0A 0x0B 0x0C 0x0D 0x20`
   (`\t \n \v \f \r` and space), **never** Unicode whitespace (NBSP U+00A0, NEL
   U+0085, BOM U+FEFF, the C0 information separators U+001C–001F, ideographic space
   U+3000, …). Then strip any **run of trailing `\`** characters (legacy artifact),
   then ASCII whitespace again. This narrow, language-neutral rule is load-bearing:
   `str.strip()` (Python), `unicode.IsSpace` (Go), and `String.trim()` (JS) each
   strip a *different* exotic set, so a client that defers to its language's trim
   **will** diverge. Anything non-ASCII surviving the strip is rejected fail-closed
   by the ASCII-digit guard. These strip rules belong to `canon_decimal` **alone**;
   the assumed-exponent and satnum decoders define their own pre-processing below.
2. Capture sign: one leading `-` → negative; a leading `+` is dropped; no other
   signs are permitted (the *exponent* in step 3 may carry one optional leading
   `+`/`-` of its own).
3. If `e`/`E` is present, expand to plain decimal by shifting the point per the
   integer exponent (no float). The exponent, after its optional sign, MUST be all
   ASCII digits with value ≤ `999` — anything larger is malformed → reject (no
   real orbital field needs even two digits; the bound keeps expansion trivially
   cheap and identically bounded in every language).
4. Ensure exactly one `.`; split int/frac. `frac = frac.rstrip('0')`;
   `int = int.lstrip('0') or '0'`.
5. Recombine: `int`, or `int + '.' + frac` if `frac` is non-empty.
6. **Zero guard:** all-zero → `"0"` (never `-0`, never `0.0`).
7. Re-apply `-` iff negative and the result ≠ `"0"`.

There is **no rounding** here — every field is a terminating decimal, so all
implementations converge on one form.

Per field: `INCLINATION`, `RA_OF_ASC_NODE`, `ARG_OF_PERICENTER`, `MEAN_ANOMALY`,
`MEAN_MOTION` → `canon_decimal` of the published value, no quantization.
`ECCENTRICITY`: the 7-digit TLE field has an implied `0.` → build `"0." + field`
first (`0004499` → `0.0004499`). `MEAN_MOTION_DOT` (ndot/2): `canon_decimal` of the
TLE field directly (`canon_decimal` supplies the leading `0` for a bare `.`).

#### Assumed-exponent decode (`BSTAR`, `MEAN_MOTION_DDOT`) — one unified rule

Covers the standard form **and** every Space-Track historical overflow form for
large drag terms on near-reentry objects. The raw field, **before any
stripping**, MUST be at least 7 characters — shorter is malformed → reject.

1. The **first character only** is the sign slot: `+` / `-` / space (`-` →
   negative, else positive); a leading ASCII digit means no sign; any other
   first character → reject. After removing the sign slot, right-strip the §2.2
   ASCII whitespace set — **no backslash strip, no left-strip** (further leading
   whitespace is malformed and fails the digit checks below).
2. If an interior `+`/`-` remains, the **exponent** is the substring from the last
   one (e.g. `-3`, `+1`, `-10`) and the **mantissa** is the digits before it.
   If there is **no** interior sign, the mantissa is the first 5 digits and the
   remainder is a **positive** exponent.
3. Shape bounds — reject anything else: the mantissa is **exactly 5 or 6 ASCII
   digits**; the exponent, after its optional sign, is **exactly 1 or 2 ASCII
   digits**. The mantissa has an **implied decimal point 5 places from the
   right**: 5 digits → `0.MMMMM`, 6 digits → `M.MMMMM`.

An all-zero mantissa yields `"0"` — but only once the **whole field** has
validated (sign slot, mantissa shape, exponent shape); **fail closed** on
anything else. Verified byte-for-byte against the authoritative Space-Track
`gp_history` JSON:

| field | → | field | → |
|---|---|---|---|
| `17028-3` | `0.00017028` | `+2083500` | `0.20835` |
| `-2979601` | `-2.9796` | `+1582202` | `15.822` |
| `49000-10` | `0.000000000049` | `973196+1` | `97.3196` |
| `+028410 ` | `0.02841` | `+00000-0` | `0` |

**Column-shift tolerance.** A subset of legacy records have a blank international
designator + one extra space, shifting every line-1 field by +1. Detect it from
the epoch decimal point — byte 23 (standard) vs 24 (shifted) — and read line-1
fields at that offset. Precedence: byte 23 is checked **first**, then byte 24;
if **neither** holds `.`, the line is treated as standard (offset 0) and epoch
parsing decides its fate. Line 2 is never shifted.

### 2.3 `EPOCH` — `YYYY-MM-DDThh:mm:ss.ffffff`, integer-only, on the 864-µs grid

The one canonical epoch token. Because `1e-8 day = 864 µs` exactly, every TLE
epoch's microsecond-of-day is a multiple of 864 and the TLE path **never rounds**.

- **TLE `YYDDD.FFFFFFFF`** (line 1, the 14-byte window at bytes 18–32,
  ASCII-stripped per §2.2 first): year pivot `YY≥57 ⇒ 1900+YY`, `YY≤56 ⇒
  2000+YY` (representable range 1957–2056); day-of-year MUST be `1…365/366` for
  that (proleptic-Gregorian) year; `usec = (int(F)·86400000000 + 10^L/2) / 10^L`
  (integer division, `L` = number of fraction digits). **`L` MUST be ≤ 8** — a
  longer fraction is malformed → reject. With `L ≤ 8` the product is < 2^63
  (exact in 64-bit integers everywhere) and the `+10^L/2` term is inert — the
  TLE path never rounds. `L = 0` (no digits after an optional `.`, or no `.` at
  all) ⇒ `usec = 0`. Then leap-correct day-of-year → (month, day); `divmod` to
  h/m/s/µs; render fixed-width `YYYY-MM-DDThh:mm:ss.ffffff`.
- Any epoch whose µs-of-day is **not** a multiple of 864 is an ingest error →
  **reject** (a genuine sub-864-µs source needs a new schema id, never an in-place
  change). With `L ≤ 8` every TLE epoch lands on the grid *by construction*; the
  grid check guards the rendering API and any future ingest path.

> *Informative:* the producer also ingests OMM ISO-8601 epochs
> (`…T18:27:32.932224Z`), normalising them to this same token. That is a
> producer concern — the **normative verifier surface is TLE-only**, and the
> OMM↔TLE equivalence is witnessed by the published record vectors, not by a
> second decoder in every client.

Worked: ISS `26172.76913116` → `2026-06-21T18:27:32.932224`; Sputnik
`57277.80437500` → `1957-10-04T19:18:18.000000`.

### 2.4 `NORAD_CAT_ID` — base-10 integer string `^(0|[1-9][0-9]*)$`

**Bounded and ASCII-strict.** The field is first stripped with the §2.2 ASCII
whitespace rule; an empty (or whitespace-only) field → reject. A plain numeric
id is all ASCII digits with **at most 9 significant digits** (`≤ 999,999,999`,
the Space-Track/OMM ceiling; leading zeros allowed and stripped — the **raw**
length is unbounded, only significant digits are bounded). An **Alpha-5** id is
**exactly 5 characters**: an
ASCII letter followed by 4 ASCII digits → `ALPHA5.index(first)·10000 + int(last4)`
(`I`/`O` excluded; `T0000` → `270000`, `Z9999` → `339999`, so `≤ 339,999`). The
leading character is ASCII-uppercased **only** (`a`–`z` → `A`–`Z`; never Unicode
case-folding — e.g. long-s `ſ` must **not** fold to `S`). Validate digits with an
**ASCII-only** test, never Unicode `isdigit`. Both bounds keep the value below
`2^53`, so a `Number`/`int` decode is exact in every language; anything larger,
non-ASCII, or mis-shaped is non-canonical → **reject** (a 17-digit "catalog
number" is corruption, not a satellite).

### 2.5 `core_record` from a TLE pair

With line-1 offset `off` from §2.2, `l1 = line1[off:]`:

| field | source |
|---|---|
| `NORAD_CAT_ID` | `canon_norad(decode_satnum(line2[2:7]))` |
| `EPOCH` | `epoch_from_tle(l1)` |
| `INCLINATION` | `canon_decimal(line2[8:16])` |
| `RA_OF_ASC_NODE` | `canon_decimal(line2[17:25])` |
| `ECCENTRICITY` | `canon_decimal("0." + strip_ascii(line2[26:33]))` |
| `ARG_OF_PERICENTER` | `canon_decimal(line2[34:42])` |
| `MEAN_ANOMALY` | `canon_decimal(line2[43:51])` |
| `MEAN_MOTION` | `canon_decimal(line2[52:63])` |
| `MEAN_MOTION_DOT` | `canon_decimal(l1[33:43])` |
| `MEAN_MOTION_DDOT` | `decode_assumed_exp(l1[44:52])` |
| `BSTAR` | `decode_assumed_exp(l1[53:61])` |

Slices are 0-based **byte** offsets, Python-style (clamped, never panic); both
lines MUST first pass the §1.1 byte check, which is what makes byte and
character slicing coincide. **No byte outside the listed slices is examined**:
line tags, checksums, and line-1 / line-2 satnum agreement are deliberately
*not* validated — source hygiene belongs to the producer's capture rule; the
verifier owns exactly the hashed projection.

### 2.6 Serialization → `contentHash`

One record's canonical bytes = its 11 keys in **sorted ASCII order**, pinned
separators, every value a quoted string — equivalent to
`json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)`.
A serializer MUST require every `NORAD_CAT_ID` token to be canonical
(`^(0|[1-9][0-9]*)$`, ≤ 9 digits — so the `int()` sort below is exact in every
language) and every value to be non-empty and drawn from `[0-9.\-T:]` — which
is why no JSON escaping can ever fire; anything else → reject.

A day's catalog: a repeated `NORAD_CAT_ID` MUST **abort the day's hash
computation** (hard error — silent de-duplication is non-conforming) → **sort
ascending by `int(NORAD_CAT_ID)`** → `"[" + rec₀ + "," + … + "]"`, no whitespace;
an empty day is `"[]"`. These `canonical_bytes` are the **sole** hash input (no
newline, BOM, or length prefix).

```
contentHash = SHA-256(canonical_bytes)        # lowercase hex; committed as raw 32 bytes
```

`recordCount = len(array)` is published per day (in `daily_manifest.txt`) but is
**not** hashed. It is informative for manifest replay; a verifier that
recomputes a day's catalog **from records** MUST check its count against the
published value (truncation detection).

Byte-exact ISS record:

```json
{"ARG_OF_PERICENTER":"89.579","BSTAR":"0.00017028","ECCENTRICITY":"0.0004499","EPOCH":"2026-06-21T18:27:32.932224","INCLINATION":"51.6326","MEAN_ANOMALY":"270.663","MEAN_MOTION":"15.4935758","MEAN_MOTION_DDOT":"0","MEAN_MOTION_DOT":"0.00016717","NORAD_CAT_ID":"25544","RA_OF_ASC_NODE":"277.4139"}
```

---

## 3. `blockHash` — the leaf and the on-chain commitment

Replicates `DocChain.sol`'s `_hashDocBlockFields` exactly:

```
blockHash = keccak256(
    DOC_BLOCK_TYPEHASH                 # 32 bytes
  ‖ docChainId                         # 32 bytes
  ‖ uint64(docRef) left-zero-padded to 32 bytes   # big-endian
  ‖ parentHash                         # 32 bytes; genesis parent = 0x00…00
  ‖ contentHash )                      # 32 bytes
```

160 bytes total. `recordCount` is **not** in the struct. `blockHash` is
**EIP-712-domain-independent** — chainId/contract enter only the *signature*, never
the block hash — so every leaf is final regardless of which network attests it.

**`docRef` sentinels** (uint64): `YYYYMMDD000000` with `DD` 01–31 is a **daily**
catalog; `YYYYMM00000000` (`DD = 00`) is a **monthly Merkle root**. They never
collide.

**On-chain self-check.** With `docRef = 20260420000000`, `parentHash = 0x00…00`,
`contentHash = 0x1838a066…231a740`, `blockHash` MUST equal
`0xe651a583…96e103e` — the live Sepolia genesis block. (`vectors/anchors.json →
onchain_sepolia_genesis_selfcheck`.)

---

## 4. Monthly Merkle tree

Leaves = that month's daily `blockHash`es as **opaque 32-byte values, in
chronological day order**. The tree hash is a **separate SHA-256 domain** (not
keccak), **sorted-pair** so it is commutative:

```
combine(a, b) = sha256(min(a,b) ‖ max(a,b))
```

`min`/`max` compare the **raw 32-byte values byte-wise lexicographically**
(equivalently: as big-endian unsigned integers). Nodes pair **left-to-right
from index 0**; on an odd-length level the final lone node is **promoted
unchanged** (carried up — *not* the Bitcoin/OpenZeppelin duplicate-last rule).
`monthRoot` is the fold to one 32-byte value. A **single leaf is its own root**
(no hashing); **zero leaves is an error**.

An inclusion proof is the **flat list of sibling hashes** (no left/right flags,
since `combine` is commutative); a promoted leaf contributes no sibling at that
level, so its proof is shorter. Verify by folding the leaf with each sibling
and **byte-comparing** to `monthRoot` — a mismatch is a failed proof (`false`).
Because the flat commutative path has no leaf/node domain separation, the leaf
MUST be a value the verifier **recomputed itself** (a daily `blockHash`), never
a caller-supplied hash.

---

## 5. The spine — replaying the whole chain

This is the headline check: from `vectors/daily_manifest.txt` alone (one
`YYYY-MM-DD contentHash recordCount` line per day), a verifier recomputes every
commitment with no other input.

**Manifest grammar — reject anything else.** The file is ASCII with
LF-terminated lines (no CR). Every non-empty line MUST match

```
^\d{4}-\d{2}-\d{2} [0-9a-f]{64} (0|[1-9][0-9]*)$
```

— exactly two single-space (`0x20`) separators, bare lowercase hex, no leading
or trailing whitespace, at most 96 bytes per line, `recordCount < 2^53`. The
date MUST be calendar-valid (§1.1) and the day sequence MUST advance by
**exactly one calendar day per line** — the chain is defined over consecutive
UTC days, so a gap, duplicate, or reordering is a *different chain*, not a
tolerable variation.

1. **Daily chain.** One continuous chain over all days in order. `parentHash`
   starts at `0x00…00`; for each day
   `blockHash = BlockHash(DayDocRef(y,m,d), parent, contentHash)`, then
   `parent ← blockHash`. The first day's hash is the **genesis anchor**; the last
   day's (2025-12-31) is the **weld value** (the parent of the first live day).
2. **Monthly roots.** Bucket the daily `blockHash`es by calendar month (still in
   day order) and fold each bucket with §4 → one `monthRoot` per month.
3. **Month-root spine.** A second chain over the months: `parent` starts at
   `0x00…00`; for each month
   `monthBlockHash = BlockHash(MonthDocRef(y,m), parent, monthRoot)`, then
   `parent ← monthBlockHash`. The final value is the **spine head**.

The published anchors (`vectors/anchors.json`) for the genesis-to-2025 history:

| anchor | value |
|---|---|
| days | `24926` |
| months | `819` (1957-10 → 2025-12 inclusive) |
| genesis `blockHash` (1957-10-04) | `0xac994f034640eb73c4367346b9a47c1a599458b840dec599d38a288595936fc0` |
| weld value (2025-12-31) | `0x1bc2b0f3495fd3ecdc3e8ae271a33c2cc0ea6ac0d1c682adc2825638e0a5596b` |
| spine head (Dec-2025 month-root block) | `0x9e41f7c2c549770465885a46b26fa1140a52bc6b76ad84674915bfea4769e4c5` |

A conforming client reproduces all three from the manifest, and each of the 819
recomputed `monthRoot`/`blockHash` pairs matches `vectors/month_roots.json`.

> **Set selection** (which elsets populate each day) is a larger reproducibility
> surface than the hash and is fixed by the producer's capture rule (carry-forward
> membership by latest `EPOCH ≤` end-of-UTC-day; window on `EPOCH`, never
> `CREATION_DATE`). This spec verifies the **published** per-day `contentHash`es
> and their on-chain commitment; reproducing the day *contents* from raw
> Space-Track/McDowell sources is the producer's domain.

---

## 6. Conformance

A client is conforming iff, against this repo's `vectors/`, it:

- derives `docChainId` and `DOC_BLOCK_TYPEHASH` from their preimages and matches
  `keccak_empty` (proving the Keccak-256 padding byte);
- passes the on-chain Sepolia `blockHash` self-check (§3);
- reproduces every `vectors/decode.json`, `vectors/records.json`,
  `vectors/blockhashes.json` and `vectors/catalogs.json` value — including the
  ISS `contentHash` `d21f9317…36a5b3f1`, the empty-day hash, and the
  multi-record catalog (which pins the **integer** NORAD sort);
- **fail-closed rejects** every entry of `vectors/decode.json → reject` (exotic
  whitespace, non-ASCII digits/letters, out-of-range or mis-shaped satnums, …) —
  these guard against the language-specific trim/parse divergences in §2.2/§2.4 —
  plus the `vectors/catalogs.json` duplicate-NORAD case and every
  `vectors/merkle.json → reject` case (corrupted proof → `false`, zero
  leaves → error);
- reproduces `vectors/merkle.json` in full: the 5-leaf root and inclusion proof,
  the single-leaf and two-leaf roots, the **promoted-leaf short proof**, and the
  seven-leaf root;
- replays `vectors/daily_manifest.txt` into the §5 anchors and matches all 819
  entries of `vectors/month_roots.json`;
- treats a **missing or empty vector class as a conformance failure** — a suite
  that silently skips an absent file or empty array proves nothing — and treats
  an unknown `fn` name in the reject vectors as a failure, never as a
  successful rejection.

The Go client in [`go/`](go/) is the reference; `go test ./...` runs the whole
suite.
