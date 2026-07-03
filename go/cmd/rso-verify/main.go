// Command rso-verify independently reproduces the RSO deep-history doc-chain
// anchors from the published vectors, in pure Go with no external dependencies.
//
//	rso-verify selftest [vectorsDir]   # keccak, blockHash, canonicalizer, Merkle vectors
//	rso-verify spine    [vectorsDir]   # replay daily_manifest.txt -> genesis/weld/head
//	rso-verify anchors  [vectorsDir]   # spine + compare against vectors/anchors.json
//
// vectorsDir defaults to ../../vectors relative to the binary's source tree, or
// the RSO_VERIFY_VECTORS env var, or ./vectors.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	rv "github.com/OMPub/rso-verify/go"
)

func vectorsDir(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	if v := os.Getenv("RSO_VERIFY_VECTORS"); v != "" {
		return v
	}
	for _, c := range []string{"vectors", "../vectors", "../../vectors"} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return "vectors"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rso-verify <selftest|spine|anchors> [vectorsDir]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	dir := vectorsDir(os.Args[2:])
	var err error
	switch cmd {
	case "selftest":
		err = runSelftest(dir)
	case "spine":
		_, err = runSpine(dir, false)
	case "anchors":
		_, err = runSpine(dir, true)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func runSelftest(dir string) error {
	// keccak + constants derive correctly
	th := rv.Hex32(rv.TypeHash())
	dc := rv.Hex32(rv.DocChainID())
	fmt.Printf("DOC_BLOCK_TYPEHASH  0x%s\n", th)
	fmt.Printf("docChainId          0x%s\n", dc)

	var anchors struct {
		DocChainID       string `json:"docChainId"`
		DocBlockTypehash string `json:"doc_block_typehash"`
		KeccakEmpty      string `json:"keccak_empty"`
		OnchainSelfcheck struct {
			DocRef  uint64 `json:"doc_ref"`
			Parent  string `json:"parent"`
			Content string `json:"content"`
			Block   string `json:"block"`
		} `json:"onchain_sepolia_genesis_selfcheck"`
	}
	if err := readJSON(filepath.Join(dir, "anchors.json"), &anchors); err != nil {
		return err
	}
	if "0x"+th != anchors.DocBlockTypehash {
		return fmt.Errorf("typehash mismatch vs anchors.json")
	}
	if "0x"+dc != anchors.DocChainID {
		return fmt.Errorf("docChainId mismatch vs anchors.json")
	}

	// keccak-256 padding self-check from the vectors (not hardcoded in clients only)
	if anchors.KeccakEmpty != "" && "0x"+rv.Hex32(rv.Keccak256(nil)) != anchors.KeccakEmpty {
		return fmt.Errorf("keccak256(\"\") mismatch vs anchors.json keccak_empty")
	}

	// real on-chain Sepolia genesis block: blockHash must match the live value
	pc, err := rv.Parse32(anchors.OnchainSelfcheck.Parent)
	if err != nil {
		return fmt.Errorf("anchors.json selfcheck parent: %w", err)
	}
	cc, err := rv.Parse32(anchors.OnchainSelfcheck.Content)
	if err != nil {
		return fmt.Errorf("anchors.json selfcheck content: %w", err)
	}
	got := rv.Hex32(rv.BlockHash(anchors.OnchainSelfcheck.DocRef, pc, cc))
	if got != strings.TrimPrefix(anchors.OnchainSelfcheck.Block, "0x") {
		return fmt.Errorf("on-chain Sepolia self-check FAILED: %s != %s", got, anchors.OnchainSelfcheck.Block)
	}
	fmt.Printf("on-chain Sepolia genesis blockHash  0x%s  OK\n", got)

	// decode vectors
	var dec struct {
		DecodeAssumedExp [][2]interface{} `json:"decode_assumed_exp"`
		CanonDecimal     [][2]interface{} `json:"canon_decimal"`
		DecodeSatnum     [][2]interface{} `json:"decode_satnum"`
		EpochFromTLE     [][2]interface{} `json:"epoch_from_tle"`
		Reject           []struct {
			Fn   string   `json:"fn"`
			Args []string `json:"args"`
		} `json:"reject"`
	}
	if err := readJSON(filepath.Join(dir, "decode.json"), &dec); err != nil {
		return err
	}
	// SPEC §6: a missing or empty vector class is a conformance FAILURE — a suite
	// that silently skips an absent array proves nothing.
	if len(dec.DecodeAssumedExp) == 0 || len(dec.CanonDecimal) == 0 ||
		len(dec.DecodeSatnum) == 0 || len(dec.EpochFromTLE) == 0 || len(dec.Reject) == 0 {
		return fmt.Errorf("decode.json: one or more vector classes are missing or empty")
	}
	for _, v := range dec.DecodeAssumedExp {
		in, want := v[0].(string), v[1].(string)
		got, err := rv.DecodeAssumedExp(in)
		if err != nil || got != want {
			return fmt.Errorf("DecodeAssumedExp(%q) = %q,%v want %q", in, got, err, want)
		}
	}
	for _, v := range dec.CanonDecimal {
		in, want := v[0].(string), v[1].(string)
		got, err := rv.CanonDecimal(in)
		if err != nil || got != want {
			return fmt.Errorf("CanonDecimal(%q) = %q,%v want %q", in, got, err, want)
		}
	}
	for _, v := range dec.DecodeSatnum {
		in := v[0].(string)
		want := int(v[1].(float64))
		got, err := rv.DecodeSatnum(in)
		if err != nil || got != want {
			return fmt.Errorf("DecodeSatnum(%q) = %d,%v want %d", in, got, err, want)
		}
	}
	for _, v := range dec.EpochFromTLE {
		in, want := v[0].(string), v[1].(string)
		got, err := rv.EpochFromTLE(in)
		if err != nil || got != want {
			return fmt.Errorf("EpochFromTLE(%q) = %q,%v want %q", in, got, err, want)
		}
	}
	fmt.Printf("decode vectors: %d assumed-exp, %d canon-decimal, %d satnum, %d epoch  OK\n",
		len(dec.DecodeAssumedExp), len(dec.CanonDecimal), len(dec.DecodeSatnum), len(dec.EpochFromTLE))

	for _, r := range dec.Reject {
		var e error
		switch r.Fn {
		case "canon_decimal":
			_, e = rv.CanonDecimal(r.Args[0])
		case "decode_assumed_exp":
			_, e = rv.DecodeAssumedExp(r.Args[0])
		case "decode_satnum":
			_, e = rv.DecodeSatnum(r.Args[0])
		case "epoch_from_tle":
			_, e = rv.EpochFromTLE(r.Args[0])
		default:
			return fmt.Errorf("unknown reject fn %q", r.Fn)
		}
		if e == nil {
			return fmt.Errorf("reject vector %s(%q) was NOT rejected", r.Fn, r.Args[0])
		}
	}
	fmt.Printf("reject vectors: %d non-canonical inputs all fail-closed  OK\n", len(dec.Reject))

	// full record → canonical bytes + contentHash
	var recs []struct {
		Name            string `json:"name"`
		Line1           string `json:"line1"`
		Line2           string `json:"line2"`
		RecordJSONBytes string `json:"record_json_bytes"`
		ContentHash     string `json:"single_record_contentHash"`
	}
	if err := readJSON(filepath.Join(dir, "records.json"), &recs); err != nil {
		return err
	}
	if len(recs) == 0 {
		return fmt.Errorf("records.json: no record vectors")
	}
	for _, r := range recs {
		cr, err := rv.CoreRecordFromTLE(r.Line1, r.Line2)
		if err != nil {
			return fmt.Errorf("%s: %w", r.Name, err)
		}
		if string(cr.JSONBytes()) != r.RecordJSONBytes {
			return fmt.Errorf("%s: record bytes mismatch\n got %s\nwant %s", r.Name, cr.JSONBytes(), r.RecordJSONBytes)
		}
		ch, err := rv.ContentHash([]rv.CoreRecord{cr})
		if err != nil {
			return err
		}
		if ch != r.ContentHash {
			return fmt.Errorf("%s: contentHash %s want %s", r.Name, ch, r.ContentHash)
		}
		fmt.Printf("record %-26s contentHash %s  OK\n", r.Name, ch)
	}

	// merkle vectors: 5-leaf root + proof, degenerate shapes, promoted-leaf short
	// proof, and the NEGATIVE cases (a verifyProof that always returns true must fail here)
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
	if err := readJSON(filepath.Join(dir, "merkle.json"), &mk); err != nil {
		return err
	}
	if len(mk.Leaves) == 0 || len(mk.SingleLeaf.Leaves) != 1 || len(mk.TwoLeaves.Leaves) != 2 ||
		len(mk.PromotedProof.Proof) == 0 || mk.SevenLeaves.Root == "" || len(mk.Reject) == 0 {
		return fmt.Errorf("merkle.json: one or more vector classes are missing or empty")
	}
	parseAll := func(hs []string) ([][32]byte, error) {
		out := make([][32]byte, len(hs))
		var err error
		for i, h := range hs {
			if out[i], err = rv.Parse32(h); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	leaves, err := parseAll(mk.Leaves)
	if err != nil {
		return err
	}
	root, err := rv.MerkleRoot(leaves)
	if err != nil {
		return err
	}
	if rv.Hex32(root) != strings.TrimPrefix(mk.Root, "0x") {
		return fmt.Errorf("merkle root %s want %s", rv.Hex32(root), mk.Root)
	}
	proof, err := parseAll(mk.Proof)
	if err != nil {
		return err
	}
	if !rv.VerifyProof(leaves[mk.Index], proof, root) {
		return fmt.Errorf("merkle proof for index %d did not verify", mk.Index)
	}
	// single leaf is its own root; two leaves = one combine
	single, err := parseAll(mk.SingleLeaf.Leaves)
	if err != nil {
		return err
	}
	if r1, _ := rv.MerkleRoot(single); rv.Hex32(r1) != strings.TrimPrefix(mk.SingleLeaf.Root, "0x") {
		return fmt.Errorf("single-leaf root mismatch")
	}
	two, err := parseAll(mk.TwoLeaves.Leaves)
	if err != nil {
		return err
	}
	if r2, _ := rv.MerkleRoot(two); rv.Hex32(r2) != strings.TrimPrefix(mk.TwoLeaves.Root, "0x") {
		return fmt.Errorf("two-leaf root mismatch")
	}
	// promoted leaf: sibling-less levels are skipped, so the path is SHORT
	pp, err := parseAll(mk.PromotedProof.Proof)
	if err != nil {
		return err
	}
	gotPP, err := rv.MerkleProof(leaves, mk.PromotedProof.Index)
	if err != nil {
		return err
	}
	if len(gotPP) != len(pp) {
		return fmt.Errorf("promoted-leaf proof length %d want %d", len(gotPP), len(pp))
	}
	for i := range pp {
		if gotPP[i] != pp[i] {
			return fmt.Errorf("promoted-leaf proof sibling %d mismatch", i)
		}
	}
	if !rv.VerifyProof(leaves[mk.PromotedProof.Index], pp, root) {
		return fmt.Errorf("promoted-leaf proof did not verify")
	}
	// seven leaves 0x00..01 … 0x00..07: odd counts at two levels
	seven := make([][32]byte, 7)
	for i := range seven {
		seven[i][31] = byte(i + 1)
	}
	if r7, _ := rv.MerkleRoot(seven); rv.Hex32(r7) != strings.TrimPrefix(mk.SevenLeaves.Root, "0x") {
		return fmt.Errorf("seven-leaf root mismatch")
	}
	// negative cases
	for _, rej := range mk.Reject {
		switch {
		case rej.MustFalse:
			bp, err := parseAll(rej.Proof)
			if err != nil {
				return err
			}
			if rv.VerifyProof(leaves[rej.Index], bp, root) {
				return fmt.Errorf("merkle reject (%s): corrupted proof VERIFIED", rej.Comment)
			}
		case rej.MustError:
			zl, err := parseAll(rej.Leaves)
			if err != nil {
				return err
			}
			if _, err := rv.MerkleRoot(zl); err == nil {
				return fmt.Errorf("merkle reject (%s): expected an error", rej.Comment)
			}
		default:
			return fmt.Errorf("merkle reject (%s): entry declares no expectation", rej.Comment)
		}
	}
	fmt.Printf("merkle: root %s, proofs (incl. promoted short path), degenerate + negative cases  OK\n", rv.Hex32(root))

	// catalog vectors: empty day, multi-record INT sort, duplicate-NORAD reject
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
	if err := readJSON(filepath.Join(dir, "catalogs.json"), &cat); err != nil {
		return err
	}
	if cat.EmptyDayHash == "" || len(cat.UnsortedInput.TLEs) < 2 {
		return fmt.Errorf("catalogs.json: vector classes missing or empty")
	}
	if ch, err := rv.ContentHash(nil); err != nil || ch != cat.EmptyDayHash {
		return fmt.Errorf("empty-day contentHash %s (%v) want %s", ch, err, cat.EmptyDayHash)
	}
	var catRecs []rv.CoreRecord
	for _, pair := range cat.UnsortedInput.TLEs {
		cr, err := rv.CoreRecordFromTLE(pair[0], pair[1])
		if err != nil {
			return fmt.Errorf("catalogs.json TLE: %w", err)
		}
		catRecs = append(catRecs, cr)
	}
	if ch, err := rv.ContentHash(catRecs); err != nil || ch != cat.UnsortedInput.ContentHash {
		return fmt.Errorf("multi-record contentHash %s (%v) want %s", ch, err, cat.UnsortedInput.ContentHash)
	}
	dup := append(append([]rv.CoreRecord{}, catRecs...), catRecs[cat.RejectDuplicate.RepeatIndex])
	if _, err := rv.ContentHash(dup); err == nil {
		return fmt.Errorf("duplicate-NORAD catalog was NOT rejected")
	}
	fmt.Printf("catalogs: empty day, %d-record int-sorted hash, duplicate reject  OK\n", len(catRecs))

	fmt.Println("\nselftest: ALL OK")
	return nil
}

func runSpine(dir string, compare bool) (rv.SpineResult, error) {
	days, err := rv.ParseManifest(filepath.Join(dir, "daily_manifest.txt"))
	if err != nil {
		return rv.SpineResult{}, err
	}
	res, err := rv.BuildSpine(days)
	if err != nil {
		return res, err
	}
	fmt.Printf("replayed %d days into %d monthly roots\n", res.Days, res.Months)
	fmt.Printf("genesis  %s  0x%s\n", res.GenesisDay, rv.Hex32(res.GenesisHash))
	fmt.Printf("weld     %s  0x%s\n", res.WeldDay, rv.Hex32(res.WeldHash))
	fmt.Printf("head                0x%s\n", rv.Hex32(res.SpineHead))

	if !compare {
		return res, nil
	}
	var a struct {
		Days    int `json:"days"`
		Months  int `json:"months"`
		Genesis struct {
			BlockHash string `json:"blockHash"`
		} `json:"genesis"`
		Weld      string `json:"weld_value_2025_12_31"`
		SpineHead string `json:"spine_head_blockHash"`
	}
	if err := readJSON(filepath.Join(dir, "anchors.json"), &a); err != nil {
		return res, err
	}
	type chk struct {
		name      string
		got, want string
	}
	checks := []chk{
		{"days", fmt.Sprint(res.Days), fmt.Sprint(a.Days)},
		{"months", fmt.Sprint(res.Months), fmt.Sprint(a.Months)},
		{"genesis", "0x" + rv.Hex32(res.GenesisHash), a.Genesis.BlockHash},
		{"weld", "0x" + rv.Hex32(res.WeldHash), a.Weld},
		{"head", "0x" + rv.Hex32(res.SpineHead), a.SpineHead},
	}

	// also confirm every recomputed month-root blockHash matches month_roots.json.
	// A read/parse failure here MUST be fatal: silently dropping this check row
	// and still printing ALL MATCH was the audit's worst fail-open finding.
	var months []struct {
		MonthRoot string `json:"monthRoot"`
		BlockHash string `json:"blockHash"`
	}
	if err := readJSON(filepath.Join(dir, "month_roots.json"), &months); err != nil {
		return res, fmt.Errorf("month_roots.json: %w", err)
	}
	if len(months) == 0 {
		return res, fmt.Errorf("month_roots.json: no month vectors")
	}
	mismatch := 0
	if len(months) != len(res.MonthResults) {
		mismatch++
	} else {
		for i, m := range res.MonthResults {
			if "0x"+rv.Hex32(m.BlockHash) != months[i].BlockHash || "0x"+rv.Hex32(m.MonthRoot) != months[i].MonthRoot {
				mismatch++
			}
		}
	}
	checks = append(checks, chk{"month_roots.json (all 819)", fmt.Sprint(mismatch), "0"})

	fmt.Println()
	ok := true
	for _, c := range checks {
		mark := "OK"
		if c.got != c.want {
			mark, ok = "MISMATCH", false
		}
		fmt.Printf("  %-28s %s\n", c.name, mark)
	}
	if !ok {
		return res, fmt.Errorf("anchor comparison failed")
	}
	fmt.Println("\nanchors: ALL MATCH the published vectors/anchors.json")
	return res, nil
}

func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
