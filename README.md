# rso-verify

**Independent, multi-language verifiers for the RSO deep-history doc-chain.**

The [RSO archive](https://github.com/OMPub/RSO) is a verifiable daily record of
the public space-object catalog from Sputnik (**1957-10-04**) through the present:
each day's orbital catalog is hashed, the day hashes are linked into a chain,
monthly Merkle roots are committed on Ethereum, and the live daily chain welds
onto that history with no seam.

This repo lets **anyone re-derive those on-chain commitments from the raw data**,
in the language of their choice — the way Ethereum has Geth, Reth, Besu, and
Nethermind all implement one spec. Nothing here trusts the producer: each client
recomputes the hashes and checks them against what is published and what is
on-chain.

```
┌─────────────┐     defines      ┌──────────────────────────────┐
│  SPEC.md    │ ───────────────► │ vectors/  (consensus suite)  │
│ (normative) │                  │ daily_manifest, month_roots, │
└─────────────┘                  │ anchors, decode, records, …  │
       │                         └──────────────────────────────┘
       │ implemented by                      ▲
       ▼                                      │ must reproduce, byte-for-byte
  go/   ts/   rust/   python/  ───────────────┘
  (clean-room clients — NO producer code)
```

- **[`SPEC.md`](SPEC.md)** — the source of truth. The canonicalization, hashing,
  Merkle, and spine rules, in English.
- **[`vectors/`](vectors/)** — language-neutral test vectors generated from the
  producer. The contract every client must satisfy.
- **[`go/`](go/)** — client #1 (reference). Pure Go standard library, **zero
  external dependencies** (hand-written Keccak-256).
- **[`ts/`](ts/)** — client #2. TypeScript, runs on Node ≥22.6 with no runtime
  dependencies (hand-written Keccak, Node stdlib sha256); typecheck-only devDeps.
  `rust/`, `python/` follow.

> **Why no reference code from RSO here?** The RSO repo is the *producer* (it
> builds the catalog and signs the transactions). Keeping the verifiers in a
> separate repo with their own clean-room implementations means a bug in the
> producer can't hide in the verifier — they share only the English spec and the
> vectors, never code.

## Quick start (Go)

```sh
cd go

# run the whole consensus suite (decode, records, merkle, blockHash, full spine)
go test ./...

# or use the CLI:
go run ./cmd/rso-verify selftest   # keccak, constants, on-chain self-check, decode vectors
go run ./cmd/rso-verify anchors    # replay daily_manifest.txt → genesis / weld / head
```

Replaying the manifest reproduces, from 24,926 daily content hashes and nothing
else:

```
replayed 24926 days into 819 monthly roots
genesis  1957-10-04  0xac994f034640eb73c4367346b9a47c1a599458b840dec599d38a288595936fc0
weld     2025-12-31  0x1bc2b0f3495fd3ecdc3e8ae271a33c2cc0ea6ac0d1c682adc2825638e0a5596b
head                0x9e41f7c2c549770465885a46b26fa1140a52bc6b76ad84674915bfea4769e4c5
  days / months / genesis / weld / head / month_roots.json (all 819)   OK
```

## Quick start (TypeScript)

Runs on Node ≥22.6 with no install (native TypeScript via `--experimental-strip-types`):

```sh
cd ts

# consensus suite
node --test --experimental-strip-types 'test/*.test.ts'

# or the CLI:
node --experimental-strip-types cmd/rso-verify.ts selftest
node --experimental-strip-types cmd/rso-verify.ts anchors

# optional typecheck (the only devDeps are typescript + @types/node):
npm install && npm run typecheck
```

Same anchors, reproduced independently by the TypeScript implementation.

## What's in `vectors/`

| file | what it pins |
|---|---|
| `daily_manifest.txt` | every day `YYYY-MM-DD  contentHash  recordCount` (24,926 lines) — replayed into the anchors |
| `month_roots.json` | the 819 monthly Merkle roots + their block hashes (1957-10 → 2025-12) |
| `anchors.json` | genesis / weld / spine-head, counts, `docChainId`, typehash, and the live on-chain Sepolia self-check |
| `blockhashes.json` | sampled day-level `blockHash` vectors (genesis, early days, the 2025-12-31 weld) |
| `decode.json` | unit vectors for `decode_assumed_exp`, `canon_decimal`, `decode_satnum`, `epoch_from_tle` |
| `records.json` | a full TLE → 11-field `core_record` → canonical bytes → `contentHash` (ISS) |
| `merkle.json` | a small deterministic Merkle root + inclusion proof |
| `sources.sha256` | SHA-256 of every upstream source file (Space-Track annual zips, McDowell) for provenance |

## Conformance

A client conforms iff it reproduces every value in `vectors/` — see
[SPEC.md §6](SPEC.md#6-conformance). The headline check: replay
`daily_manifest.txt` into the genesis, weld, and spine-head anchors and match all
819 month-roots.

## Status

| client | status |
|---|---|
| `go/` | ✅ reference — full suite passing |
| `ts/` | ✅ full suite passing (Node ≥22.6, zero runtime deps) |
| `rust/` | planned |
| `python/` | planned (clean-room — distinct from the producer's pipeline) |

## License

MIT — see [LICENSE](LICENSE).
