package rsoverify

// Doc-chain commitment primitives: blockHash (keccak, EIP-712-style struct hash),
// monthly Merkle tree (sorted-pair sha256), and the docRef sentinels. Mirrors the
// producer's attestation/spine.py + attestation/merkle.py. See ../SPEC.md §3, §4.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// DocBlock(bytes32 docChainId,uint64 docRef,bytes32 parentHash,bytes32 contentHash)
// keccak256 of that string. Recomputed (not trusted) by TypeHash().
const docBlockTypeString = "DocBlock(bytes32 docChainId,uint64 docRef,bytes32 parentHash,bytes32 contentHash)"

// docChainId = keccak256("https://om.pub/rso/doc-chain"), the one unversioned chain id.
const docChainURI = "https://om.pub/rso/doc-chain"

// TypeHash returns DOC_BLOCK_TYPEHASH, derived (never hardcoded) so the self-test
// proves keccak + the constant agree.
func TypeHash() [32]byte { return Keccak256([]byte(docBlockTypeString)) }

// DocChainID returns the doc-chain id, derived from its canonical URI.
func DocChainID() [32]byte { return Keccak256([]byte(docChainURI)) }

// BlockHash replicates DocChain.sol _hashDocBlockFields:
//
//	keccak256( TYPEHASH ‖ docChainId ‖ uint64(docRef)→32B ‖ parentHash ‖ contentHash )
//
// 160 bytes, EIP-712-domain-independent (recordCount is NOT hashed). docRef is
// left-zero-padded to 32 bytes big-endian.
func BlockHash(docRef uint64, parent, content [32]byte) [32]byte {
	var payload [160]byte
	th := TypeHash()
	dc := DocChainID()
	copy(payload[0:32], th[:])
	copy(payload[32:64], dc[:])
	binary.BigEndian.PutUint64(payload[88:96], docRef) // last 8 of the 32-byte slot
	copy(payload[96:128], parent[:])
	copy(payload[128:160], content[:])
	return Keccak256(payload[:])
}

// --- monthly Merkle tree: sorted-pair sha256, lone node promoted (SPEC §4) ---

func merkleCombine(a, b [32]byte) [32]byte {
	lo, hi := a, b
	if bytesGreater(a, b) {
		lo, hi = b, a
	}
	h := sha256.New()
	h.Write(lo[:])
	h.Write(hi[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func bytesGreater(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// MerkleRoot folds leaves to one root: sorted-pair sha256, promoting the lone node
// on an odd level (NOT the Bitcoin duplicate-last rule).
func MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, fmt.Errorf("cannot build a Merkle tree over zero leaves")
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, merkleCombine(level[i], level[i+1]))
			} else {
				next = append(next, level[i]) // promote lone node unchanged
			}
		}
		level = next
	}
	return level[0], nil
}

// MerkleProof returns the flat sibling path for leaf index (no left/right flags;
// combine is commutative).
func MerkleProof(leaves [][32]byte, index int) ([][32]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("leaf index %d out of range (%d leaves)", index, len(leaves))
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	var proof [][32]byte
	for len(level) > 1 {
		sib := index ^ 1
		if sib < len(level) {
			proof = append(proof, level[sib])
		}
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, merkleCombine(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		level = next
		index /= 2
	}
	return proof, nil
}

// VerifyProof recomputes the root from a leaf + sibling path.
func VerifyProof(leaf [32]byte, proof [][32]byte, root [32]byte) bool {
	node := leaf
	for _, sib := range proof {
		node = merkleCombine(node, sib)
	}
	return node == root
}

// --- docRef sentinels (uint64 YYYYMMDD000000; DD=00 marks a month-root) ---

// DayDocRef = YYYYMMDD000000.
func DayDocRef(year, month, day int) uint64 {
	return uint64(year*10000+month*100+day) * 1_000_000
}

// MonthDocRef = YYYYMM00000000 (DD == 00).
func MonthDocRef(year, month int) uint64 {
	return uint64(year*10000+month*100) * 1_000_000
}

// --- hex helpers (lowercase, optional 0x; nodes/leaves are 32 bytes) ---

func Hex32(b [32]byte) string { return hex.EncodeToString(b[:]) }

func Parse32(s string) ([32]byte, error) {
	// SPEC §1.1: optional 0x, either case, NO surrounding whitespace, and every
	// character must be a hex digit — bad digits must reject, never zero-fill.
	s = strings.TrimPrefix(s, "0x")
	var out [32]byte
	if len(s) != 64 {
		return out, fmt.Errorf("expected 64 hex chars, got %d", len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}
