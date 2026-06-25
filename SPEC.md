# RSO Doc-Chain Verification Spec

**Status:** normative · **Schema:** `rso-core-omm-v1` · **Chain:** `https://om.pub/rso/doc-chain`

This is the source of truth for **verifying** the RSO deep-history doc-chain — a
verifiable daily archive of the public space-object catalog from Sputnik
(1957-10-04) through the present, with monthly Merkle roots and daily block hashes
committed on Ethereum.

It is written for **re-implementers**. Like Ethereum's
[execution-specs](https://github.com/ethereum/execution-specs), this English spec
plus the language-neutral [`vectors/`](vectors/) suite defines the protocol; the
clients in [`go/`](go/), `js/`, `rust/`, `python/` are independent implementations
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

## 0. Constants

| Name | Value |
|---|---|
| `docChainId` | `keccak256("https://om.pub/rso/doc-chain")` = `0x6011620b5a3faa23f8078c2af0bb1a87bb85a68f784abdf3dbae67939c399bea` |
| `DOC_BLOCK_TYPEHASH` | `keccak256("DocBlock(bytes32 docChainId,uint64 docRef,bytes32 parentHash,bytes32 contentHash)")` = `0xb84212102d711af6fc7ae9fa3e37753befb8b25762a552631b0e9ff9e8d07894` |
| `USEC_PER_DAY` | `86400000000` |
| `EPOCH_GRID_USEC` | `864` (= `1e-8` day exactly) |
| `ALPHA5` | `0123456789ABCDEFGHJKLMNPQRSTUVWXYZ` |

Both 32-byte constants MUST be **derived** by the verifier from their preimages,
not hardcoded — that proves the keccak implementation is correct. `keccak256` is
Ethereum **Keccak-256** (padding byte `0x01`), **not** NIST SHA3-256 (`0x06`).

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

1. Strip ASCII whitespace, then a trailing `\` (legacy artifact), then whitespace.
2. Capture sign: one leading `-` → negative; a leading `+` is dropped; no other
   signs are permitted.
3. If `e`/`E` is present, expand to plain decimal by shifting the point per the
   integer exponent (no float).
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
large drag terms on near-reentry objects:

1. A leading `+`/`-`/space is the **mantissa sign** (`-` negative, else positive);
   a leading digit means no sign.
2. If there is an interior `+`/`-`, the **exponent** is the substring from the last
   one (e.g. `-3`, `+1`, `-10`) and the **mantissa** is the digits before it.
   If there is **no** interior sign, the mantissa is the first 5 digits and the
   rest (1–2 digits) is a **positive** exponent.
3. The mantissa has an **implied decimal point 5 places from the right**: 5 digits
   → `0.MMMMM`, 6 digits → `M.MMMMM`.

All-zero mantissa → `"0"`; **fail closed** on anything else. Verified byte-for-byte
against the authoritative Space-Track `gp_history` JSON:

| field | → | field | → |
|---|---|---|---|
| `17028-3` | `0.00017028` | `+2083500` | `0.20835` |
| `-2979601` | `-2.9796` | `+1582202` | `15.822` |
| `49000-10` | `0.000000000049` | `973196+1` | `97.3196` |
| `+028410 ` | `0.02841` | `+00000-0` | `0` |

**Column-shift tolerance.** A subset of legacy records have a blank international
designator + one extra space, shifting every line-1 field by +1. Detect it from
the epoch decimal point — index 23 (standard) vs 24 (shifted) — and read line-1
fields at that offset. Line 2 is never shifted.

### 2.3 `EPOCH` — `YYYY-MM-DDThh:mm:ss.ffffff`, integer-only, on the 864-µs grid

The one canonical epoch token. Because `1e-8 day = 864 µs` exactly, every TLE
epoch's microsecond-of-day is a multiple of 864 and the TLE path **never rounds**.

- **TLE `YYDDD.FFFFFFFF`** (line 1, cols 19–32): year pivot `YY≥57 ⇒ 1900+YY`,
  `YY≤56 ⇒ 2000+YY`; `usec = (int(F)·86400000000 + 10^L/2) / 10^L` (integer
  division, `L` = number of fraction digits); leap-correct day-of-year →
  (month, day); `divmod` to h/m/s/µs; render fixed-width.
- **OMM ISO**: strip `Z`; parse integer parts; round-half-up the seconds fraction
  to exactly 6 digits with the same integer carry.
- Any epoch whose µs-of-day is **not** a multiple of 864 is an ingest error →
  **reject** (a genuine sub-864-µs source needs a new schema id, never an in-place
  change).

Worked: ISS `26172.76913116` → `2026-06-21T18:27:32.932224`; Sputnik
`57277.80437500` → `1957-10-04T19:18:18.000000`.

### 2.4 `NORAD_CAT_ID` — base-10 integer string `^(0|[1-9][0-9]*)$`

Plain numeric (`<100000` or any all-digit OMM) → `int()`. **Alpha-5** (5-char
satnum, letter first) → `ALPHA5.index(first)·10000 + int(last4)` (I/O skipped;
`T0000` → `270000`, `Z9999` → `339999`). Validate with an **ASCII-only** digit
test, never Unicode `isdigit`.

### 2.5 `core_record` from a TLE pair

With line-1 offset `off` from §2.2, `l1 = line1[off:]`:

| field | source |
|---|---|
| `NORAD_CAT_ID` | `canon_norad(decode_satnum(line2[2:7]))` |
| `EPOCH` | `epoch_from_tle(l1)` |
| `INCLINATION` | `canon_decimal(line2[8:16])` |
| `RA_OF_ASC_NODE` | `canon_decimal(line2[17:25])` |
| `ECCENTRICITY` | `canon_decimal("0." + line2[26:33].strip())` |
| `ARG_OF_PERICENTER` | `canon_decimal(line2[34:42])` |
| `MEAN_ANOMALY` | `canon_decimal(line2[43:51])` |
| `MEAN_MOTION` | `canon_decimal(line2[52:63])` |
| `MEAN_MOTION_DOT` | `canon_decimal(l1[33:43])` |
| `MEAN_MOTION_DDOT` | `decode_assumed_exp(l1[44:52])` |
| `BSTAR` | `decode_assumed_exp(l1[53:61])` |

Slices are Python-style (clamped, never panic).

### 2.6 Serialization → `contentHash`

One record's canonical bytes = its 11 keys in **sorted ASCII order**, pinned
separators, every value a quoted string — equivalent to
`json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)`. Values
are drawn from `[0-9.\-T:]` so no JSON escaping ever fires.

A day's catalog: dedup by `NORAD_CAT_ID` (a duplicate is a hard error) → **sort
ascending by `int(NORAD_CAT_ID)`** → `"[" + rec₀ + "," + … + "]"`, no whitespace;
an empty day is `"[]"`. These `canonical_bytes` are the **sole** hash input (no
newline, BOM, or length prefix).

```
contentHash = SHA-256(canonical_bytes)        # lowercase hex; committed as raw 32 bytes
```

`recordCount = len(array)` is published per day (in `daily_manifest.txt`) but is
**not** hashed; verifiers use it to detect truncation.

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

On an odd level the lone node is **promoted unchanged** (carried up — *not* the
Bitcoin/OpenZeppelin duplicate-last rule). `monthRoot` is the fold to one 32-byte
value. An inclusion proof is the **flat list of sibling hashes** (no left/right
flags, since `combine` is commutative); verify by folding the leaf with each
sibling and comparing to `monthRoot`.

---

## 5. The spine — replaying the whole chain

This is the headline check: from `vectors/daily_manifest.txt` alone (one
`YYYY-MM-DD  contentHash  recordCount` line per day), a verifier recomputes every
commitment with no other input.

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

- derives `docChainId` and `DOC_BLOCK_TYPEHASH` from their preimages (keccak OK);
- passes the on-chain Sepolia `blockHash` self-check (§3);
- reproduces every `vectors/decode.json` and `vectors/records.json` value,
  including the ISS `contentHash` `d21f9317…36a5b3f1`;
- reproduces `vectors/merkle.json` (root + inclusion proof);
- replays `vectors/daily_manifest.txt` into the §5 anchors and matches all 819
  entries of `vectors/month_roots.json`.

The Go client in [`go/`](go/) is the reference; `go test ./...` runs the whole
suite.
