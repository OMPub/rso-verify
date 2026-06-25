package rsoverify

// Reproduce the doc-chain spine from the published daily manifest (SPEC §5).
// Independently recomputes every daily blockHash, every monthly Merkle root, and
// the month-root spine — yielding the genesis, weld, and head anchors with no
// input but vectors/daily_manifest.txt. This is the Ethereum "re-execute the
// chain" check: a third party derives the on-chain commitments from raw data.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ManifestDay is one published daily catalog line: day, contentHash, recordCount.
type ManifestDay struct {
	Year, Month, Day int
	ContentHash      [32]byte
	RecordCount      int
}

// MonthResult is one recomputed monthly commitment.
type MonthResult struct {
	Year, Month int
	DayCount    int
	MonthRoot   [32]byte
	BlockHash   [32]byte
	ParentHash  [32]byte
}

// SpineResult is the reproduced spine: the three anchors plus per-month detail.
type SpineResult struct {
	Days         int
	Months       int
	GenesisDay   string
	GenesisHash  [32]byte
	WeldDay      string
	WeldHash     [32]byte
	SpineHead    [32]byte
	MonthResults []MonthResult
}

// ParseManifest reads "YYYY-MM-DD <contentHash> <recordCount>" lines.
func ParseManifest(path string) ([]ManifestDay, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var days []ManifestDay
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("manifest line %d: want 3 fields, got %d", ln, len(fields))
		}
		dparts := strings.Split(fields[0], "-")
		if len(dparts) != 3 {
			return nil, fmt.Errorf("manifest line %d: bad day %q", ln, fields[0])
		}
		y, _ := strconv.Atoi(dparts[0])
		m, _ := strconv.Atoi(dparts[1])
		d, _ := strconv.Atoi(dparts[2])
		ch, err := Parse32(fields[1])
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: bad contentHash: %w", ln, err)
		}
		rc, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: bad recordCount: %w", ln, err)
		}
		days = append(days, ManifestDay{y, m, d, ch, rc})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return days, nil
}

// BuildSpine replays the manifest into the full spine.
func BuildSpine(days []ManifestDay) (SpineResult, error) {
	var res SpineResult
	if len(days) == 0 {
		return res, fmt.Errorf("empty manifest")
	}

	// 1. continuous daily blockHash chain; bucket leaves by month in order.
	type monthKey struct{ y, m int }
	var order []monthKey
	leaves := map[monthKey][][32]byte{}

	var parent [32]byte // genesis parent = 0x00..00
	for i, d := range days {
		bh := BlockHash(DayDocRef(d.Year, d.Month, d.Day), parent, d.ContentHash)
		if i == 0 {
			res.GenesisDay = fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
			res.GenesisHash = bh
		}
		if i == len(days)-1 {
			res.WeldDay = fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
			res.WeldHash = bh
		}
		k := monthKey{d.Year, d.Month}
		if _, seen := leaves[k]; !seen {
			order = append(order, k)
		}
		leaves[k] = append(leaves[k], bh)
		parent = bh
	}
	res.Days = len(days)
	res.Months = len(order)

	// 2. monthly Merkle roots, then the month-root spine (parent = prev month-root blockHash).
	var mParent [32]byte // first month-root parent = 0x00..00
	for _, k := range order {
		root, err := MerkleRoot(leaves[k])
		if err != nil {
			return res, err
		}
		mbh := BlockHash(MonthDocRef(k.y, k.m), mParent, root)
		res.MonthResults = append(res.MonthResults, MonthResult{
			Year: k.y, Month: k.m, DayCount: len(leaves[k]),
			MonthRoot: root, BlockHash: mbh, ParentHash: mParent,
		})
		mParent = mbh
	}
	res.SpineHead = mParent
	return res, nil
}
