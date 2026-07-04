package rsoverify

// Reproduce the doc-chain spine from the published daily manifest (SPEC §5).
// Independently recomputes every daily blockHash, every monthly Merkle root, and
// the month-root spine — yielding the genesis, weld, and head anchors with no
// input but vectors/daily_manifest.txt. This is the Ethereum "re-execute the
// chain" check: a third party derives the on-chain commitments from raw data.

import (
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

// daysInMonth for a proleptic-Gregorian calendar-validity check (SPEC §1.1).
func daysInMonth(y, m int) int {
	if m == 2 && isLeap(y) {
		return 29
	}
	return monthLengths[m-1]
}

// nextDay advances (y, m, d) by exactly one calendar day.
func nextDay(y, m, d int) (int, int, int) {
	d++
	if d > daysInMonth(y, m) {
		d = 1
		m++
		if m > 12 {
			m = 1
			y++
		}
	}
	return y, m, d
}

func asciiDigitsExactly(s string, n int) bool {
	return len(s) == n && asciiDigits(s)
}

func lowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ParseManifest reads "YYYY-MM-DD <contentHash> <recordCount>" lines under the
// SPEC §5 grammar: LF lines, exactly two single-space separators, bare lowercase
// hex, calendar-valid dates advancing by exactly one day, recordCount canonical.
// Reject anything else — a malformed manifest MUST never yield anchors.
func ParseManifest(path string) ([]ManifestDay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var days []ManifestDay
	// Raw split on LF — NOT bufio.ScanLines, which silently strips a trailing
	// \r and made the Go client fail-open on CRLF manifests the SPEC (and the
	// TS client) reject.
	for ln0, line := range strings.Split(string(data), "\n") {
		ln := ln0 + 1
		if line == "" {
			continue
		}
		if strings.ContainsRune(line, '\r') {
			return nil, fmt.Errorf("manifest line %d: CR not allowed (SPEC §5: LF lines only)", ln)
		}
		if len(line) > 96 {
			return nil, fmt.Errorf("manifest line %d: longer than 96 bytes", ln)
		}
		fields := strings.Split(line, " ")
		if len(fields) != 3 {
			return nil, fmt.Errorf("manifest line %d: want 3 single-space fields, got %d", ln, len(fields))
		}
		date, hash, count := fields[0], fields[1], fields[2]
		if len(date) != 10 || date[4] != '-' || date[7] != '-' ||
			!asciiDigitsExactly(date[0:4], 4) || !asciiDigitsExactly(date[5:7], 2) || !asciiDigitsExactly(date[8:10], 2) {
			return nil, fmt.Errorf("manifest line %d: bad date %q", ln, date)
		}
		y, err := strconv.Atoi(date[0:4])
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: bad year: %w", ln, err)
		}
		m, err := strconv.Atoi(date[5:7])
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: bad month: %w", ln, err)
		}
		d, err := strconv.Atoi(date[8:10])
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: bad day: %w", ln, err)
		}
		if m < 1 || m > 12 || d < 1 || d > daysInMonth(y, m) {
			return nil, fmt.Errorf("manifest line %d: %q is not a calendar date", ln, date)
		}
		if len(days) > 0 {
			p := days[len(days)-1]
			ey, em, ed := nextDay(p.Year, p.Month, p.Day)
			if y != ey || m != em || d != ed {
				return nil, fmt.Errorf("manifest line %d: %q does not follow %04d-%02d-%02d by exactly one day",
					ln, date, p.Year, p.Month, p.Day)
			}
		}
		if !lowerHex64(hash) {
			return nil, fmt.Errorf("manifest line %d: contentHash is not 64 bare lowercase hex chars", ln)
		}
		ch, err := Parse32(hash)
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: bad contentHash: %w", ln, err)
		}
		if !asciiDigits(count) || (len(count) > 1 && count[0] == '0') || len(count) > 15 {
			return nil, fmt.Errorf("manifest line %d: bad recordCount %q", ln, count)
		}
		rc, err := strconv.Atoi(count)
		if err != nil {
			return nil, fmt.Errorf("manifest line %d: bad recordCount: %w", ln, err)
		}
		days = append(days, ManifestDay{y, m, d, ch, rc})
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
