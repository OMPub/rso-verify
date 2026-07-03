// Doc-chain commitment primitives: blockHash (keccak struct hash), monthly Merkle
// tree (sorted-pair sha256, lone node promoted), and the docRef sentinels. Mirrors
// the Go client's hashing.go and the producer's spine.py + merkle.py. See ../../SPEC.md.

import { createHash } from "node:crypto";
import { keccak256 } from "./keccak.ts";

const enc = new TextEncoder();

// DocBlock(bytes32 docChainId,uint64 docRef,bytes32 parentHash,bytes32 contentHash)
const DOC_BLOCK_TYPE_STRING =
  "DocBlock(bytes32 docChainId,uint64 docRef,bytes32 parentHash,bytes32 contentHash)";
const DOC_CHAIN_URI = "https://om.pub/rso/doc-chain";

/** DOC_BLOCK_TYPEHASH, derived (never hardcoded) so the self-test proves keccak. */
export function typeHash(): Uint8Array {
  return keccak256(enc.encode(DOC_BLOCK_TYPE_STRING));
}

/** docChainId = keccak256 of the canonical chain URI. */
export function docChainId(): Uint8Array {
  return keccak256(enc.encode(DOC_CHAIN_URI));
}

/**
 * blockHash replicates DocChain.sol _hashDocBlockFields:
 *   keccak256( TYPEHASH ‖ docChainId ‖ uint64(docRef)→32B ‖ parentHash ‖ contentHash )
 * 160 bytes; recordCount is NOT hashed; docRef is left-zero-padded big-endian.
 */
export function blockHash(docRef: bigint, parent: Uint8Array, content: Uint8Array): Uint8Array {
  // Uint8Array.set would silently zero-pad a short hash into the payload —
  // reject instead (Go's [32]byte makes this unrepresentable; match it).
  if (parent.length !== 32 || content.length !== 32) {
    throw new Error(`blockHash: parent/content must be 32 bytes, got ${parent.length}/${content.length}`);
  }
  if (docRef < 0n || docRef >= 1n << 64n) throw new Error(`blockHash: docRef out of uint64 range`);
  const payload = new Uint8Array(160);
  payload.set(typeHash(), 0);
  payload.set(docChainId(), 32);
  let v = docRef;
  for (let i = 95; i >= 88; i--) {
    payload[i] = Number(v & 0xffn); // last 8 bytes of the 32-byte slot
    v >>= 8n;
  }
  payload.set(parent, 96);
  payload.set(content, 128);
  return keccak256(payload);
}

// --- monthly Merkle tree: sorted-pair sha256, lone node promoted (SPEC §4) ---

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length && i < b.length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function sha256(...chunks: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const c of chunks) h.update(c);
  return new Uint8Array(h.digest());
}

function combine(a: Uint8Array, b: Uint8Array): Uint8Array {
  return compareBytes(a, b) > 0 ? sha256(b, a) : sha256(a, b);
}

/** merkleRoot folds leaves to one root; the lone node on an odd level is promoted. */
export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error("cannot build a Merkle tree over zero leaves");
  let level = leaves.slice();
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? combine(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

/** merkleProof returns the flat sibling path for leaf index (combine is commutative). */
export function merkleProof(leaves: Uint8Array[], index: number): Uint8Array[] {
  if (index < 0 || index >= leaves.length) throw new Error(`leaf index ${index} out of range`);
  let level = leaves.slice();
  const proof: Uint8Array[] = [];
  while (level.length > 1) {
    const sib = index ^ 1;
    if (sib < level.length) proof.push(level[sib]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? combine(level[i], level[i + 1]) : level[i]);
    }
    level = next;
    index = Math.floor(index / 2);
  }
  return proof;
}

/** verifyProof recomputes the root from a leaf + sibling path. */
export function verifyProof(leaf: Uint8Array, proof: Uint8Array[], root: Uint8Array): boolean {
  let node = leaf;
  for (const sib of proof) node = combine(node, sib);
  return compareBytes(node, root) === 0;
}

// --- docRef sentinels (uint64 YYYYMMDD000000; DD=00 marks a month-root) ---

export function dayDocRef(year: number, month: number, day: number): bigint {
  return BigInt(year * 10000 + month * 100 + day) * 1_000_000n;
}

export function monthDocRef(year: number, month: number): bigint {
  return BigInt(year * 10000 + month * 100) * 1_000_000n;
}

// --- hex helpers (lowercase, optional 0x; nodes/leaves are 32 bytes) ---

export function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function parse32(s: string): Uint8Array {
  // SPEC §1.1: optional 0x, either case, NO surrounding whitespace, and every
  // character must be a hex digit — parseInt's NaN→0 coercion is the classic
  // fail-open (64 chars of garbage silently becoming the zero hash).
  const hex = s.startsWith("0x") ? s.slice(2) : s;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error(`expected 64 hex chars, got '${s.length > 80 ? s.slice(0, 80) + "…" : s}'`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
