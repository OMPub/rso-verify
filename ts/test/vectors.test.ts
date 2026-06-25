// Consensus test suite: every check runs against the language-neutral vectors in
// ../../vectors. A passing run means this TS client agrees with the producer (and
// the Go client) byte-for-byte. Run with: node --test --experimental-strip-types

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  keccak256, typeHash, docChainId, blockHash,
  merkleRoot, verifyProof, parse32, toHex,
  decodeAssumedExp, canonDecimal, decodeSatnum, epochFromTLE,
  coreRecordFromTLE, recordJSONString, contentHash,
  parseManifest, buildSpine,
} from "../src/index.ts";

const VEC = fileURLToPath(new URL("../../vectors/", import.meta.url));
const j = (name: string): any => JSON.parse(readFileSync(VEC + name, "utf8"));
const hex = (b: Uint8Array): string => "0x" + toHex(b);

test("keccak256 of empty string", () => {
  assert.equal(toHex(keccak256(new Uint8Array(0))),
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
});

test("constants derive from preimages", () => {
  const a = j("anchors.json");
  assert.equal(hex(typeHash()), a.doc_block_typehash);
  assert.equal(hex(docChainId()), a.docChainId);
});

test("on-chain Sepolia genesis self-check", () => {
  const c = j("anchors.json").onchain_sepolia_genesis_selfcheck;
  const got = toHex(blockHash(BigInt(c.doc_ref), parse32(c.parent), parse32(c.content)));
  assert.equal(got, c.block.replace(/^0x/, ""));
});

test("decode vectors", () => {
  const d = j("decode.json");
  for (const [inp, want] of d.decode_assumed_exp) assert.equal(decodeAssumedExp(inp), want, `decodeAssumedExp(${inp})`);
  for (const [inp, want] of d.canon_decimal) assert.equal(canonDecimal(inp), want, `canonDecimal(${inp})`);
  for (const [inp, want] of d.decode_satnum) assert.equal(decodeSatnum(inp), want, `decodeSatnum(${inp})`);
  for (const [inp, want] of d.epoch_from_tle) assert.equal(epochFromTLE(inp), want, `epochFromTLE(${inp})`);
});

test("reject vectors: non-canonical inputs fail closed", () => {
  const fns: Record<string, (s: string) => unknown> = {
    canon_decimal: canonDecimal,
    decode_assumed_exp: decodeAssumedExp,
    decode_satnum: decodeSatnum,
    epoch_from_tle: epochFromTLE,
  };
  const reject = j("decode.json").reject as Array<{ fn: string; args: string[] }>;
  assert.ok(reject.length > 0, "reject vectors present");
  for (const r of reject) {
    assert.throws(() => fns[r.fn](r.args[0]), `${r.fn}(${JSON.stringify(r.args[0])}) should reject`);
  }
});

test("record vectors: TLE → core record → contentHash", () => {
  for (const r of j("records.json")) {
    const cr = coreRecordFromTLE(r.line1, r.line2);
    assert.equal(recordJSONString(cr), r.record_json_bytes, `${r.name} bytes`);
    assert.equal(contentHash([cr]), r.single_record_contentHash, `${r.name} contentHash`);
  }
});

test("merkle root + inclusion proof", () => {
  const mk = j("merkle.json");
  const leaves = mk.leaves.map(parse32);
  const root = merkleRoot(leaves);
  assert.equal(toHex(root), mk.root.replace(/^0x/, ""));
  const proof = mk.proof.map(parse32);
  assert.ok(verifyProof(leaves[mk.proof_index], proof, root));
});

test("block-hash vectors", () => {
  for (const b of j("blockhashes.json")) {
    const got = hex(blockHash(BigInt(b.docRef), parse32(b.parentHash), parse32(b.contentHash)));
    assert.equal(got, b.blockHash, `blockHash docRef=${b.docRef}`);
  }
});

test("spine reproduction: replay manifest → genesis / weld / head + all 819 months", () => {
  const a = j("anchors.json");
  const days = parseManifest(VEC + "daily_manifest.txt");
  const res = buildSpine(days);

  assert.equal(res.days, a.days, "days");
  assert.equal(res.months, a.months, "months");
  assert.equal(hex(res.genesisHash), a.genesis.blockHash, "genesis");
  assert.equal(hex(res.weldHash), a.weld_value_2025_12_31, "weld");
  assert.equal(hex(res.spineHead), a.spine_head_blockHash, "head");

  const months = j("month_roots.json");
  assert.equal(res.monthResults.length, months.length, "month count");
  for (let i = 0; i < months.length; i++) {
    assert.equal(hex(res.monthResults[i].monthRoot), months[i].monthRoot, `month[${i}] root`);
    assert.equal(hex(res.monthResults[i].blockHash), months[i].blockHash, `month[${i}] blockHash`);
  }
});
