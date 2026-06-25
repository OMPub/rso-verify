// CLI: independently reproduce the RSO doc-chain anchors from the published vectors.
//   node --experimental-strip-types cmd/rso-verify.ts <selftest|spine|anchors> [vectorsDir]
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  typeHash, docChainId, blockHash, merkleRoot, verifyProof, parse32, toHex,
  decodeAssumedExp, canonDecimal, decodeSatnum, epochFromTLE,
  coreRecordFromTLE, recordJSONString, contentHash,
  parseManifest, buildSpine,
} from "../src/index.ts";

function resolveVectors(arg?: string): string {
  if (arg) return arg.endsWith("/") ? arg : arg + "/";
  if (process.env.RSO_VERIFY_VECTORS) return process.env.RSO_VERIFY_VECTORS.replace(/\/?$/, "/");
  for (const c of ["vectors/", "../vectors/", "../../vectors/"]) {
    try { if (statSync(c).isDirectory()) return c; } catch { /* keep looking */ }
  }
  return fileURLToPath(new URL("../../vectors/", import.meta.url));
}

const hex = (b: Uint8Array): string => "0x" + toHex(b);
const j = (dir: string, name: string): any => JSON.parse(readFileSync(dir + name, "utf8"));

function selftest(dir: string): void {
  const a = j(dir, "anchors.json");
  console.log(`DOC_BLOCK_TYPEHASH  ${hex(typeHash())}`);
  console.log(`docChainId          ${hex(docChainId())}`);
  if (hex(typeHash()) !== a.doc_block_typehash) throw new Error("typehash mismatch");
  if (hex(docChainId()) !== a.docChainId) throw new Error("docChainId mismatch");

  const c = a.onchain_sepolia_genesis_selfcheck;
  const got = toHex(blockHash(BigInt(c.doc_ref), parse32(c.parent), parse32(c.content)));
  if (got !== c.block.replace(/^0x/, "")) throw new Error(`on-chain self-check FAILED: ${got} != ${c.block}`);
  console.log(`on-chain Sepolia genesis blockHash  0x${got}  OK`);

  const d = j(dir, "decode.json");
  for (const [inp, want] of d.decode_assumed_exp) if (decodeAssumedExp(inp) !== want) throw new Error(`decodeAssumedExp(${inp})`);
  for (const [inp, want] of d.canon_decimal) if (canonDecimal(inp) !== want) throw new Error(`canonDecimal(${inp})`);
  for (const [inp, want] of d.decode_satnum) if (decodeSatnum(inp) !== want) throw new Error(`decodeSatnum(${inp})`);
  for (const [inp, want] of d.epoch_from_tle) if (epochFromTLE(inp) !== want) throw new Error(`epochFromTLE(${inp})`);
  console.log(`decode vectors: ${d.decode_assumed_exp.length} assumed-exp, ${d.canon_decimal.length} canon-decimal, ${d.decode_satnum.length} satnum, ${d.epoch_from_tle.length} epoch  OK`);

  const rejectFns: Record<string, (s: string) => unknown> = {
    canon_decimal: canonDecimal, decode_assumed_exp: decodeAssumedExp,
    decode_satnum: decodeSatnum, epoch_from_tle: epochFromTLE,
  };
  for (const r of d.reject as Array<{ fn: string; args: string[] }>) {
    let rejected = false;
    try { rejectFns[r.fn](r.args[0]); } catch { rejected = true; }
    if (!rejected) throw new Error(`reject vector ${r.fn}(${JSON.stringify(r.args[0])}) was NOT rejected`);
  }
  console.log(`reject vectors: ${d.reject.length} non-canonical inputs all fail-closed  OK`);

  for (const r of j(dir, "records.json")) {
    const cr = coreRecordFromTLE(r.line1, r.line2);
    if (recordJSONString(cr) !== r.record_json_bytes) throw new Error(`${r.name}: record bytes mismatch`);
    const ch = contentHash([cr]);
    if (ch !== r.single_record_contentHash) throw new Error(`${r.name}: contentHash ${ch}`);
    console.log(`record ${r.name.padEnd(26)} contentHash ${ch}  OK`);
  }

  const mk = j(dir, "merkle.json");
  const leaves = mk.leaves.map(parse32);
  const root = merkleRoot(leaves);
  if (toHex(root) !== mk.root.replace(/^0x/, "")) throw new Error("merkle root mismatch");
  if (!verifyProof(leaves[mk.proof_index], mk.proof.map(parse32), root)) throw new Error("merkle proof failed");
  console.log(`merkle: root ${toHex(root)} + inclusion proof for leaf ${mk.proof_index}  OK`);

  console.log("\nselftest: ALL OK");
}

function anchors(dir: string, compare: boolean): void {
  const days = parseManifest(dir + "daily_manifest.txt");
  const res = buildSpine(days);
  console.log(`replayed ${res.days} days into ${res.months} monthly roots`);
  console.log(`genesis  ${res.genesisDay}  ${hex(res.genesisHash)}`);
  console.log(`weld     ${res.weldDay}  ${hex(res.weldHash)}`);
  console.log(`head                ${hex(res.spineHead)}`);
  if (!compare) return;

  const a = j(dir, "anchors.json");
  const months = j(dir, "month_roots.json");
  let monthMismatch = months.length !== res.monthResults.length ? 1 : 0;
  for (let i = 0; i < res.monthResults.length && monthMismatch === 0; i++) {
    if (hex(res.monthResults[i].blockHash) !== months[i].blockHash || hex(res.monthResults[i].monthRoot) !== months[i].monthRoot) monthMismatch++;
  }
  const checks: Array<[string, string, string]> = [
    ["days", String(res.days), String(a.days)],
    ["months", String(res.months), String(a.months)],
    ["genesis", hex(res.genesisHash), a.genesis.blockHash],
    ["weld", hex(res.weldHash), a.weld_value_2025_12_31],
    ["head", hex(res.spineHead), a.spine_head_blockHash],
    ["month_roots.json (all 819)", String(monthMismatch), "0"],
  ];
  console.log();
  let ok = true;
  for (const [name, got, want] of checks) {
    const mark = got === want ? "OK" : "MISMATCH";
    if (got !== want) ok = false;
    console.log(`  ${name.padEnd(28)} ${mark}`);
  }
  if (!ok) throw new Error("anchor comparison failed");
  console.log("\nanchors: ALL MATCH the published vectors/anchors.json");
}

const cmd = process.argv[2];
const dir = resolveVectors(process.argv[3]);
try {
  if (cmd === "selftest") selftest(dir);
  else if (cmd === "spine") anchors(dir, false);
  else if (cmd === "anchors") anchors(dir, true);
  else {
    console.error("usage: rso-verify <selftest|spine|anchors> [vectorsDir]");
    process.exit(2);
  }
} catch (e) {
  console.error("FAIL:", e instanceof Error ? e.message : e);
  process.exit(1);
}
