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
	// canonical keccak-256("") vector — pinned in vectors/anchors.json too, so the
	// padding-byte contract is part of the language-neutral suite, not client lore
	const want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got := Hex32(Keccak256(nil)); got != want {
		t.Fatalf("keccak256(\"\") = %s want %s", got, want)
	}
	var a struct {
		KeccakEmpty string `json:"keccak_empty"`
	}
	readJSON(t, "anchors.json", &a)
	if a.KeccakEmpty != "0x"+want {
		t.Fatalf("anchors.json keccak_empty = %s want 0x%s", a.KeccakEmpty, want)
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
	p, err := Parse32(a.C.Parent)
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	c, err := Parse32(a.C.Content)
	if err != nil {
		t.Fatalf("content: %v", err)
	}
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
	// SPEC §6: a missing or empty vector class is a conformance failure — this
	// guard is what makes a gutted/typo'd decode.json fail instead of pass vacuously.
	if len(d.AE) == 0 || len(d.CD) == 0 || len(d.SN) == 0 || len(d.EP) == 0 {
		t.Fatal("decode.json: one or more accept vector classes are missing or empty")
	}
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

func TestRejectVectors(t *testing.T) {
	var d struct {
		Reject []struct {
			Fn   string   `json:"fn"`
			Args []string `json:"args"`
		} `json:"reject"`
	}
	readJSON(t, "decode.json", &d)
	if len(d.Reject) == 0 {
		t.Fatal("no reject vectors loaded")
	}
	for _, r := range d.Reject {
		var err error
		switch r.Fn {
		case "canon_decimal":
			_, err = CanonDecimal(r.Args[0])
		case "decode_assumed_exp":
			_, err = DecodeAssumedExp(r.Args[0])
		case "decode_satnum":
			_, err = DecodeSatnum(r.Args[0])
		case "epoch_from_tle":
			_, err = EpochFromTLE(r.Args[0])
		default:
			t.Fatalf("unknown fn %q in reject vectors", r.Fn)
		}
		if err == nil {
			t.Errorf("expected %s(%q) to reject, but it succeeded", r.Fn, r.Args[0])
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
	if len(recs) == 0 {
		t.Fatal("records.json: no record vectors")
	}
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

func parseAll(t *testing.T, hs []string) [][32]byte {
	t.Helper()
	out := make([][32]byte, len(hs))
	var err error
	for i, h := range hs {
		if out[i], err = Parse32(h); err != nil {
			t.Fatalf("hex %q: %v", h, err)
		}
	}
	return out
}

func TestMerkleVector(t *testing.T) {
	var mk struct {
		Leaves     []string `json:"leaves"`
		Root       string   `json:"root"`
		Index      int      `json:"proof_index"`
		Proof      []string `json:"proof"`
		SingleLeaf struct {
			Leaves []string `json:"leaves"`
			Root   string   `json:"root"`
		} `json:"single_leaf"`
		TwoLeaves struct {
			Leaves []string `json:"leaves"`
			Root   string   `json:"root"`
		} `json:"two_leaves"`
		PromotedProof struct {
			Index int      `json:"proof_index"`
			Proof []string `json:"proof"`
		} `json:"promoted_leaf_proof"`
		SevenLeaves struct {
			Root string `json:"root"`
		} `json:"seven_leaves_root"`
		Reject []struct {
			Comment   string   `json:"comment"`
			Index     int      `json:"proof_index"`
			Proof     []string `json:"proof"`
			Leaves    []string `json:"leaves"`
			MustFalse bool     `json:"must_verify_false"`
			MustError bool     `json:"must_error"`
		} `json:"reject"`
	}
	readJSON(t, "merkle.json", &mk)
	if len(mk.Leaves) == 0 || len(mk.SingleLeaf.Leaves) != 1 || len(mk.TwoLeaves.Leaves) != 2 ||
		len(mk.PromotedProof.Proof) == 0 || mk.SevenLeaves.Root == "" || len(mk.Reject) == 0 {
		t.Fatal("merkle.json: one or more vector classes are missing or empty")
	}
	leaves := parseAll(t, mk.Leaves)
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if Hex32(root) != strings.TrimPrefix(mk.Root, "0x") {
		t.Fatalf("root %s want %s", Hex32(root), mk.Root)
	}
	if !VerifyProof(leaves[mk.Index], parseAll(t, mk.Proof), root) {
		t.Fatalf("proof for leaf %d did not verify", mk.Index)
	}
	// degenerate shapes: single leaf is its own root; two leaves = one combine
	if r1, _ := MerkleRoot(parseAll(t, mk.SingleLeaf.Leaves)); Hex32(r1) != strings.TrimPrefix(mk.SingleLeaf.Root, "0x") {
		t.Fatal("single-leaf root mismatch")
	}
	if r2, _ := MerkleRoot(parseAll(t, mk.TwoLeaves.Leaves)); Hex32(r2) != strings.TrimPrefix(mk.TwoLeaves.Root, "0x") {
		t.Fatal("two-leaf root mismatch")
	}
	// promoted leaf: sibling-less levels are skipped → SHORT path
	pp := parseAll(t, mk.PromotedProof.Proof)
	gotPP, err := MerkleProof(leaves, mk.PromotedProof.Index)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotPP) != len(pp) {
		t.Fatalf("promoted-leaf proof length %d want %d", len(gotPP), len(pp))
	}
	for i := range pp {
		if gotPP[i] != pp[i] {
			t.Fatalf("promoted-leaf proof sibling %d mismatch", i)
		}
	}
	if !VerifyProof(leaves[mk.PromotedProof.Index], pp, root) {
		t.Fatal("promoted-leaf proof did not verify")
	}
	// seven leaves 0x00..01 … 0x00..07: odd counts at two levels
	seven := make([][32]byte, 7)
	for i := range seven {
		seven[i][31] = byte(i + 1)
	}
	if r7, _ := MerkleRoot(seven); Hex32(r7) != strings.TrimPrefix(mk.SevenLeaves.Root, "0x") {
		t.Fatal("seven-leaf root mismatch")
	}
	// negative cases — a VerifyProof that always returns true MUST fail here
	for _, rej := range mk.Reject {
		switch {
		case rej.MustFalse:
			if VerifyProof(leaves[rej.Index], parseAll(t, rej.Proof), root) {
				t.Fatalf("reject (%s): corrupted proof VERIFIED", rej.Comment)
			}
		case rej.MustError:
			if _, err := MerkleRoot(parseAll(t, rej.Leaves)); err == nil {
				t.Fatalf("reject (%s): expected an error", rej.Comment)
			}
		default:
			t.Fatalf("reject (%s): entry declares no expectation", rej.Comment)
		}
	}
}

// TestCatalogVectors pins §2.6 serialization: the empty day, the INTEGER NORAD
// sort (string sort would put "25544" before "5"), and the duplicate hard error.
func TestCatalogVectors(t *testing.T) {
	var cat struct {
		EmptyDayHash  string `json:"empty_day_contentHash"`
		UnsortedInput struct {
			TLEs        [][2]string `json:"tles"`
			ContentHash string      `json:"contentHash"`
		} `json:"unsorted_input"`
		RejectDuplicate struct {
			RepeatIndex int `json:"tles_repeat_index"`
		} `json:"reject_duplicate_norad"`
	}
	readJSON(t, "catalogs.json", &cat)
	if cat.EmptyDayHash == "" || len(cat.UnsortedInput.TLEs) < 2 {
		t.Fatal("catalogs.json: vector classes missing or empty")
	}
	if ch, err := ContentHash(nil); err != nil || ch != cat.EmptyDayHash {
		t.Fatalf("empty-day contentHash %s (%v) want %s", ch, err, cat.EmptyDayHash)
	}
	var recs []CoreRecord
	for _, pair := range cat.UnsortedInput.TLEs {
		cr, err := CoreRecordFromTLE(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, cr)
	}
	if ch, err := ContentHash(recs); err != nil || ch != cat.UnsortedInput.ContentHash {
		t.Fatalf("multi-record contentHash %s (%v) want %s", ch, err, cat.UnsortedInput.ContentHash)
	}
	dup := append(append([]CoreRecord{}, recs...), recs[cat.RejectDuplicate.RepeatIndex])
	if _, err := ContentHash(dup); err == nil {
		t.Fatal("duplicate-NORAD catalog was NOT rejected")
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
	if len(bhs) == 0 {
		t.Fatal("blockhashes.json: no vectors")
	}
	for _, b := range bhs {
		p, err := Parse32(b.ParentHash)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse32(b.ContentHash)
		if err != nil {
			t.Fatal(err)
		}
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
