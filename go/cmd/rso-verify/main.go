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

	// real on-chain Sepolia genesis block: blockHash must match the live value
	pc, _ := rv.Parse32(anchors.OnchainSelfcheck.Parent)
	cc, _ := rv.Parse32(anchors.OnchainSelfcheck.Content)
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
	}
	if err := readJSON(filepath.Join(dir, "decode.json"), &dec); err != nil {
		return err
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

	// merkle vector
	var mk struct {
		Leaves []string `json:"leaves"`
		Root   string   `json:"root"`
		Index  int      `json:"proof_index"`
		Proof  []string `json:"proof"`
	}
	if err := readJSON(filepath.Join(dir, "merkle.json"), &mk); err != nil {
		return err
	}
	var err error
	leaves := make([][32]byte, len(mk.Leaves))
	for i, h := range mk.Leaves {
		if leaves[i], err = rv.Parse32(h); err != nil {
			return err
		}
	}
	root, err := rv.MerkleRoot(leaves)
	if err != nil {
		return err
	}
	if rv.Hex32(root) != strings.TrimPrefix(mk.Root, "0x") {
		return fmt.Errorf("merkle root %s want %s", rv.Hex32(root), mk.Root)
	}
	proof := make([][32]byte, len(mk.Proof))
	for i, h := range mk.Proof {
		if proof[i], err = rv.Parse32(h); err != nil {
			return err
		}
	}
	if !rv.VerifyProof(leaves[mk.Index], proof, root) {
		return fmt.Errorf("merkle proof for index %d did not verify", mk.Index)
	}
	fmt.Printf("merkle: root %s + inclusion proof for leaf %d  OK\n", rv.Hex32(root), mk.Index)

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

	// also confirm every recomputed month-root blockHash matches month_roots.json
	var months []struct {
		MonthRoot string `json:"monthRoot"`
		BlockHash string `json:"blockHash"`
	}
	if err := readJSON(filepath.Join(dir, "month_roots.json"), &months); err == nil {
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
	}

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
