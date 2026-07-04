// Consensus test suite: every check runs against the language-neutral vectors in
// ../../vectors. A passing run means this TS client agrees with the producer (and
// the Go client) byte-for-byte. Run with: node --test --experimental-strip-types

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  keccak256, typeHash, docChainId, blockHash,
  merkleRoot, merkleProof, verifyProof, parse32, toHex,
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
  // pinned in the language-neutral vectors too, not just client lore
  assert.equal(j("anchors.json").keccak_empty,
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
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
  // SPEC §6: a missing or empty vector class is a conformance failure — a
  // typo'd key must fail loudly, never shrink coverage silently.
  for (const key of ["decode_assumed_exp", "canon_decimal", "decode_satnum", "epoch_from_tle"]) {
    assert.ok(Array.isArray(d[key]) && d[key].length > 0, `decode.json '${key}' present and non-empty`);
  }
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
    // an unknown fn or missing arg must FAIL the suite — the TypeError either
    // would raise inside assert.throws would otherwise count as a rejection
    assert.ok(Object.hasOwn(fns, r.fn), `known reject fn '${r.fn}'`);
    assert.ok(typeof r.args?.[0] === "string", `reject ${r.fn} has a string arg`);
    assert.throws(() => fns[r.fn](r.args[0]), `${r.fn}(${JSON.stringify(r.args[0])}) should reject`);
  }
});

test("record vectors: TLE → core record → contentHash", () => {
  const recs = j("records.json");
  assert.ok(Array.isArray(recs) && recs.length > 0, "record vectors present");
  for (const r of recs) {
    const cr = coreRecordFromTLE(r.line1, r.line2);
    assert.equal(recordJSONString(cr), r.record_json_bytes, `${r.name} bytes`);
    assert.equal(contentHash([cr]), r.single_record_contentHash, `${r.name} contentHash`);
  }
});

test("catalog vectors: empty day, INTEGER NORAD sort, duplicate reject", () => {
  const cat = j("catalogs.json");
  assert.ok(cat.empty_day_contentHash && cat.unsorted_input?.tles?.length >= 2, "catalog vectors present");
  assert.equal(contentHash([]), cat.empty_day_contentHash, "empty day");
  const recs = cat.unsorted_input.tles.map(([l1, l2]: [string, string]) => coreRecordFromTLE(l1, l2));
  assert.equal(contentHash(recs), cat.unsorted_input.contentHash, "int-sorted multi-record hash");
  const ri = cat.reject_duplicate_norad?.tles_repeat_index;
  assert.ok(Number.isInteger(ri) && ri >= 0 && ri < recs.length, "tles_repeat_index in range");
  assert.throws(() => contentHash([...recs, recs[ri]]), "duplicate NORAD must be a hard error");
});

test("merkle: roots, proofs (incl. promoted short path), degenerate + negative cases", () => {
  const mk = j("merkle.json");
  assert.ok(mk.leaves?.length && mk.single_leaf?.leaves?.length === 1 && mk.two_leaves?.leaves?.length === 2
    && mk.promoted_leaf_proof?.proof?.length && mk.seven_leaves_root?.root && mk.reject?.length,
    "all merkle vector classes present");
  const leaves = mk.leaves.map(parse32);
  const root = merkleRoot(leaves);
  assert.equal(toHex(root), mk.root.replace(/^0x/, ""));
  const proof = mk.proof.map(parse32);
  assert.ok(verifyProof(leaves[mk.proof_index], proof, root));
  // degenerate shapes
  assert.equal(toHex(merkleRoot(mk.single_leaf.leaves.map(parse32))), mk.single_leaf.root.replace(/^0x/, ""), "single leaf");
  assert.equal(toHex(merkleRoot(mk.two_leaves.leaves.map(parse32))), mk.two_leaves.root.replace(/^0x/, ""), "two leaves");
  // promoted leaf: sibling-less levels are skipped → SHORT path
  const pp: Uint8Array[] = mk.promoted_leaf_proof.proof.map(parse32);
  const gotPP = merkleProof(leaves, mk.promoted_leaf_proof.proof_index);
  assert.equal(gotPP.length, pp.length, "promoted-leaf proof length");
  gotPP.forEach((s, i) => assert.equal(toHex(s), toHex(pp[i]), `promoted-leaf sibling ${i}`));
  assert.ok(verifyProof(leaves[mk.promoted_leaf_proof.proof_index], pp, root), "promoted-leaf proof verifies");
  // seven leaves 1..7 big-endian: odd counts at two levels
  const seven = Array.from({ length: 7 }, (_, i) => { const b = new Uint8Array(32); b[31] = i + 1; return b; });
  assert.equal(toHex(merkleRoot(seven)), mk.seven_leaves_root.root.replace(/^0x/, ""), "seven leaves");
  // negative cases — a verifyProof that always returns true MUST fail here
  for (const rej of mk.reject) {
    if (rej.must_verify_false) {
      // shape first: a malformed entry must fail loudly, not TypeError-as-pass
      assert.ok(Number.isInteger(rej.proof_index) && rej.proof_index >= 0 && rej.proof_index < leaves.length
        && Array.isArray(rej.proof), `${rej.comment}: well-formed entry`);
      assert.equal(verifyProof(leaves[rej.proof_index], rej.proof.map(parse32), root), false, rej.comment);
    } else if (rej.must_error) {
      assert.ok(Array.isArray(rej.leaves), `${rej.comment}: well-formed entry`);
      assert.throws(() => merkleRoot(rej.leaves.map(parse32)), rej.comment);
    } else {
      assert.fail(`merkle reject (${rej.comment}): entry declares no expectation`);
    }
  }
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
