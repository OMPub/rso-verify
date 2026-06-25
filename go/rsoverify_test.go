package rsoverify

// Consensus test suite: every check runs against the language-neutral vectors in
// ../vectors. A passing `go test ./...` means this Go client agrees with the
// producer (and the other clients) byte-for-byte.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vecDir = "../vectors"

func readJSON(t *testing.T, name string, v interface{}) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vecDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func TestKeccakEmpty(t *testing.T) {
	// canonical keccak-256("") vector
	const want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got := Hex32(Keccak256(nil)); got != want {
		t.Fatalf("keccak256(\"\") = %s want %s", got, want)
	}
}

func TestConstantsDerive(t *testing.T) {
	var a struct {
		DocChainID       string `json:"docChainId"`
		DocBlockTypehash string `json:"doc_block_typehash"`
	}
	readJSON(t, "anchors.json", &a)
	if "0x"+Hex32(TypeHash()) != a.DocBlockTypehash {
		t.Fatalf("TypeHash mismatch: %s vs %s", Hex32(TypeHash()), a.DocBlockTypehash)
	}
	if "0x"+Hex32(DocChainID()) != a.DocChainID {
		t.Fatalf("DocChainID mismatch")
	}
}

func TestOnChainSelfCheck(t *testing.T) {
	var a struct {
		C struct {
			DocRef  uint64 `json:"doc_ref"`
			Parent  string `json:"parent"`
			Content string `json:"content"`
			Block   string `json:"block"`
		} `json:"onchain_sepolia_genesis_selfcheck"`
	}
	readJSON(t, "anchors.json", &a)
	p, _ := Parse32(a.C.Parent)
	c, _ := Parse32(a.C.Content)
	if got := Hex32(BlockHash(a.C.DocRef, p, c)); got != strings.TrimPrefix(a.C.Block, "0x") {
		t.Fatalf("on-chain self-check: %s want %s", got, a.C.Block)
	}
}

func TestDecodeVectors(t *testing.T) {
	var d struct {
		AE [][2]interface{} `json:"decode_assumed_exp"`
		CD [][2]interface{} `json:"canon_decimal"`
		SN [][2]interface{} `json:"decode_satnum"`
		EP [][2]interface{} `json:"epoch_from_tle"`
	}
	readJSON(t, "decode.json", &d)
	for _, v := range d.AE {
		in, want := v[0].(string), v[1].(string)
		if got, err := DecodeAssumedExp(in); err != nil || got != want {
			t.Errorf("DecodeAssumedExp(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, v := range d.CD {
		in, want := v[0].(string), v[1].(string)
		if got, err := CanonDecimal(in); err != nil || got != want {
			t.Errorf("CanonDecimal(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, v := range d.SN {
		in, want := v[0].(string), int(v[1].(float64))
		if got, err := DecodeSatnum(in); err != nil || got != want {
			t.Errorf("DecodeSatnum(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, v := range d.EP {
		in, want := v[0].(string), v[1].(string)
		if got, err := EpochFromTLE(in); err != nil || got != want {
			t.Errorf("EpochFromTLE(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestRecordVectors(t *testing.T) {
	var recs []struct {
		Name        string `json:"name"`
		Line1       string `json:"line1"`
		Line2       string `json:"line2"`
		Bytes       string `json:"record_json_bytes"`
		ContentHash string `json:"single_record_contentHash"`
	}
	readJSON(t, "records.json", &recs)
	for _, r := range recs {
		cr, err := CoreRecordFromTLE(r.Line1, r.Line2)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if string(cr.JSONBytes()) != r.Bytes {
			t.Errorf("%s: bytes\n got %s\nwant %s", r.Name, cr.JSONBytes(), r.Bytes)
		}
		ch, err := ContentHash([]CoreRecord{cr})
		if err != nil {
			t.Fatal(err)
		}
		if ch != r.ContentHash {
			t.Errorf("%s: contentHash %s want %s", r.Name, ch, r.ContentHash)
		}
	}
}

func TestMerkleVector(t *testing.T) {
	var mk struct {
		Leaves []string `json:"leaves"`
		Root   string   `json:"root"`
		Index  int      `json:"proof_index"`
		Proof  []string `json:"proof"`
	}
	readJSON(t, "merkle.json", &mk)
	leaves := make([][32]byte, len(mk.Leaves))
	for i, h := range mk.Leaves {
		leaves[i], _ = Parse32(h)
	}
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if Hex32(root) != strings.TrimPrefix(mk.Root, "0x") {
		t.Fatalf("root %s want %s", Hex32(root), mk.Root)
	}
	proof := make([][32]byte, len(mk.Proof))
	for i, h := range mk.Proof {
		proof[i], _ = Parse32(h)
	}
	if !VerifyProof(leaves[mk.Index], proof, root) {
		t.Fatalf("proof for leaf %d did not verify", mk.Index)
	}
}

func TestBlockHashVectors(t *testing.T) {
	var bhs []struct {
		DocRef      uint64 `json:"docRef"`
		ParentHash  string `json:"parentHash"`
		ContentHash string `json:"contentHash"`
		BlockHash   string `json:"blockHash"`
	}
	readJSON(t, "blockhashes.json", &bhs)
	for _, b := range bhs {
		p, _ := Parse32(b.ParentHash)
		c, _ := Parse32(b.ContentHash)
		if got := "0x" + Hex32(BlockHash(b.DocRef, p, c)); got != b.BlockHash {
			t.Errorf("blockHash(docRef=%d) = %s want %s", b.DocRef, got, b.BlockHash)
		}
	}
}

// TestSpineReproduction is the headline check: replay daily_manifest.txt into the
// three anchors with no input but the manifest, and confirm they match.
func TestSpineReproduction(t *testing.T) {
	var a struct {
		Days    int `json:"days"`
		Months  int `json:"months"`
		Genesis struct {
			BlockHash string `json:"blockHash"`
		} `json:"genesis"`
		Weld      string `json:"weld_value_2025_12_31"`
		SpineHead string `json:"spine_head_blockHash"`
	}
	readJSON(t, "anchors.json", &a)

	days, err := ParseManifest(filepath.Join(vecDir, "daily_manifest.txt"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := BuildSpine(days)
	if err != nil {
		t.Fatal(err)
	}
	if res.Days != a.Days {
		t.Errorf("days %d want %d", res.Days, a.Days)
	}
	if res.Months != a.Months {
		t.Errorf("months %d want %d", res.Months, a.Months)
	}
	if "0x"+Hex32(res.GenesisHash) != a.Genesis.BlockHash {
		t.Errorf("genesis %s want %s", "0x"+Hex32(res.GenesisHash), a.Genesis.BlockHash)
	}
	if "0x"+Hex32(res.WeldHash) != a.Weld {
		t.Errorf("weld %s want %s", "0x"+Hex32(res.WeldHash), a.Weld)
	}
	if "0x"+Hex32(res.SpineHead) != a.SpineHead {
		t.Errorf("head %s want %s", "0x"+Hex32(res.SpineHead), a.SpineHead)
	}

	// every recomputed month-root must match month_roots.json
	var months []struct {
		MonthRoot string `json:"monthRoot"`
		BlockHash string `json:"blockHash"`
	}
	readJSON(t, "month_roots.json", &months)
	if len(months) != len(res.MonthResults) {
		t.Fatalf("month count %d want %d", len(res.MonthResults), len(months))
	}
	for i, m := range res.MonthResults {
		if "0x"+Hex32(m.MonthRoot) != months[i].MonthRoot {
			t.Errorf("month %d-%02d root mismatch", m.Year, m.Month)
		}
		if "0x"+Hex32(m.BlockHash) != months[i].BlockHash {
			t.Errorf("month %d-%02d blockHash mismatch", m.Year, m.Month)
		}
	}
}
