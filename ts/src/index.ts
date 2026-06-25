// Public surface of the rso-verify TypeScript client. See ../../SPEC.md.
export { keccak256 } from "./keccak.ts";
export {
  typeHash,
  docChainId,
  blockHash,
  merkleRoot,
  merkleProof,
  verifyProof,
  dayDocRef,
  monthDocRef,
  toHex,
  parse32,
} from "./hashing.ts";
export {
  CORE_KEYS,
  canonDecimal,
  decodeAssumedExp,
  decodeSatnum,
  canonNorad,
  epochFromTLE,
  coreRecordFromTLE,
  recordJSONString,
  recordJSONBytes,
  canonicalBytes,
  contentHash,
} from "./canon.ts";
export type { CoreRecord } from "./canon.ts";
export { parseManifest, buildSpine } from "./spine.ts";
export type { ManifestDay, MonthResult, SpineResult } from "./spine.ts";
