package rsoverify

// Canonical numeric core projection — schema rso-core-omm-v1 (SPEC §2).
// Byte-exact port of the producer's pipeline/tle_normalize.py. NO IEEE-754 float
// anywhere: every value is produced by integer / string operations so this Go
// verifier reproduces byte-identical canonical_bytes with the Python/JS/Rust ones.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Alpha5: index of the first satnum char IS the high-digit value; I and O skipped.
const alpha5 = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"

const usecPerDay = 86_400_000_000
const epochGridUsec = 864 // 1e-8 day exactly; every TLE epoch is a multiple of this

// CoreKeys, the 11 hashed fields (the pure orbit), in canonical (sorted) order.
var CoreKeys = [11]string{
	"ARG_OF_PERICENTER", "BSTAR", "ECCENTRICITY", "EPOCH", "INCLINATION",
	"MEAN_ANOMALY", "MEAN_MOTION", "MEAN_MOTION_DDOT", "MEAN_MOTION_DOT",
	"NORAD_CAT_ID", "RA_OF_ASC_NODE",
}

// CoreRecord is one canonical 11-field orbit record; every value is a string token.
type CoreRecord struct {
	ArgOfPericenter string
	BStar           string
	Eccentricity    string
	Epoch           string
	Inclination     string
	MeanAnomaly     string
	MeanMotion      string
	MeanMotionDDot  string
	MeanMotionDot   string
	NoradCatID      string
	RaOfAscNode     string
}

func asciiDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isAllZero(s string) bool {
	for _, c := range s {
		if c != '0' && c != '.' {
			return false
		}
	}
	return true
}

func signedIntStr(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	return asciiDigits(s)
}

func rstripSpace(s string) string { return strings.TrimRightFunc(s, unicode.IsSpace) }

// applyExponent shifts the decimal point of an unsigned decimal string by exp.
func applyExponent(mantissa string, exp int) string {
	intPart, fracPart := mantissa, ""
	if i := strings.IndexByte(mantissa, '.'); i >= 0 {
		intPart, fracPart = mantissa[:i], mantissa[i+1:]
	}
	digits := intPart + fracPart
	point := len(intPart) + exp
	if point <= 0 {
		return "0." + strings.Repeat("0", -point) + digits
	}
	if point >= len(digits) {
		return digits + strings.Repeat("0", point-len(digits))
	}
	return digits[:point] + "." + digits[point:]
}

// CanonDecimal is the shared numeric tokenizer (SPEC §2.2): the shortest plain-
// decimal form of a terminating decimal string.
func CanonDecimal(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "\\")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty decimal field")
	}
	neg := false
	if s[0] == '+' || s[0] == '-' {
		neg = s[0] == '-'
		s = s[1:]
	}
	if strings.ContainsAny(s, "eE") {
		low := strings.ToLower(s)
		i := strings.IndexByte(low, 'e')
		mant, exp := low[:i], low[i+1:]
		esign := ""
		if len(exp) > 0 && (exp[0] == '+' || exp[0] == '-') {
			esign, exp = string(exp[0]), exp[1:]
		}
		if !asciiDigits(exp) || mant == "" {
			return "", fmt.Errorf("bad exponent form: %q", s)
		}
		ev, err := strconv.Atoi(esign + exp)
		if err != nil {
			return "", err
		}
		s = applyExponent(mant, ev)
	}
	if !strings.Contains(s, ".") {
		s += "."
	}
	i := strings.IndexByte(s, '.')
	intPart, fracPart := s[:i], s[i+1:]
	if !asciiDigits(intPart + fracPart) {
		return "", fmt.Errorf("non-numeric decimal field: %q", s)
	}
	fracPart = strings.TrimRight(fracPart, "0")
	intPart = strings.TrimLeft(intPart, "0")
	if intPart == "" {
		intPart = "0"
	}
	out := intPart
	if fracPart != "" {
		out = intPart + "." + fracPart
	}
	if isAllZero(out) {
		return "0", nil
	}
	if neg {
		return "-" + out, nil
	}
	return out, nil
}

// DecodeAssumedExp decodes a TLE assumed-decimal-exponent field (BSTAR,
// MEAN_MOTION_DDOT) under the one unified rule (SPEC §2.2). Fail-closed.
func DecodeAssumedExp(field string) (string, error) {
	if len(field) < 7 {
		return "", fmt.Errorf("assumed-exponent field too short: %q", field)
	}
	var msign, rest string
	switch c0 := field[0]; {
	case c0 == '+' || c0 == '-':
		if c0 == '-' {
			msign = "-"
		}
		rest = rstripSpace(field[1:])
	case c0 == ' ':
		rest = rstripSpace(field[1:])
	case c0 >= '0' && c0 <= '9':
		rest = rstripSpace(field)
	default:
		return "", fmt.Errorf("malformed assumed-exponent field: %q", field)
	}
	sp := strings.LastIndexAny(rest, "+-")
	var mantDigits, expStr string
	if sp > 0 { // interior exponent sign: -3, +1, -10
		mantDigits, expStr = rest[:sp], rest[sp:]
	} else { // no sign: 5-digit mantissa, the rest is a +exponent
		if len(rest) < 5 {
			return "", fmt.Errorf("malformed assumed-exponent field: %q", field)
		}
		mantDigits, expStr = rest[:5], rest[5:]
	}
	if len(mantDigits) < 5 || !asciiDigits(mantDigits) || !signedIntStr(expStr) {
		return "", fmt.Errorf("malformed assumed-exponent field: %q", field)
	}
	if isAllZero(mantDigits) {
		return "0", nil
	}
	ev, err := strconv.Atoi(expStr)
	if err != nil {
		return "", err
	}
	intPart := strings.TrimLeft(mantDigits[:len(mantDigits)-5], "0")
	if intPart == "" {
		intPart = "0"
	}
	return CanonDecimal(msign + intPart + "." + mantDigits[len(mantDigits)-5:] + "e" + strconv.Itoa(ev))
}

// DecodeSatnum decodes an Alpha-5 / plain satnum field to its integer value.
func DecodeSatnum(field string) (int, error) {
	field = strings.TrimSpace(field)
	if field == "" {
		return 0, fmt.Errorf("empty satnum")
	}
	c0 := unicode.ToUpper(rune(field[0]))
	if c0 >= '0' && c0 <= '9' {
		if !asciiDigits(field) {
			return 0, fmt.Errorf("bad numeric satnum: %q", field)
		}
		return strconv.Atoi(field)
	}
	idx := strings.IndexRune(alpha5, c0)
	if idx < 0 {
		return 0, fmt.Errorf("bad Alpha-5 leading char: %q", field)
	}
	rest := field[1:]
	if !asciiDigits(rest) {
		return 0, fmt.Errorf("bad Alpha-5 satnum: %q", field)
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, err
	}
	return idx*10000 + n, nil
}

// CanonNorad returns the canonical base-10 integer-string NORAD token.
func CanonNorad(n int) (string, error) {
	if n < 0 {
		return "", fmt.Errorf("negative NORAD id: %d", n)
	}
	return strconv.Itoa(n), nil
}

// --- EPOCH (SPEC §2.3): fixed-width civil UTC on the 864-microsecond grid ---

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }
func daysInYear(y int) int {
	if isLeap(y) {
		return 366
	}
	return 365
}

var monthLengths = [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

func doyToMD(year, doy int) (int, int, error) {
	leap := isLeap(year)
	for m := 1; m <= 12; m++ {
		length := monthLengths[m-1]
		if m == 2 && leap {
			length++
		}
		if doy <= length {
			return m, doy, nil
		}
		doy -= length
	}
	return 0, 0, fmt.Errorf("day-of-year out of range for %d", year)
}

func renderEpoch(year, doy, usecOfDay int) (string, error) {
	for usecOfDay >= usecPerDay {
		usecOfDay -= usecPerDay
		doy++
	}
	for doy > daysInYear(year) {
		doy -= daysInYear(year)
		year++
	}
	if usecOfDay%epochGridUsec != 0 {
		return "", fmt.Errorf("epoch off the %dus grid: %d", epochGridUsec, usecOfDay)
	}
	month, day, err := doyToMD(year, doy)
	if err != nil {
		return "", err
	}
	h := usecOfDay / 3_600_000_000
	rem := usecOfDay % 3_600_000_000
	mi := rem / 60_000_000
	rem %= 60_000_000
	sec := rem / 1_000_000
	us := rem % 1_000_000
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%06d", year, month, day, h, mi, sec, us), nil
}

// EpochFromTLE renders the canonical EPOCH token from a TLE line-1 YYDDD.FFFFFFFF.
func EpochFromTLE(line1 string) (string, error) {
	raw := strings.TrimSpace(pySlice(line1, 18, 32))
	if len(raw) < 2 || !asciiDigits(raw[:2]) {
		return "", fmt.Errorf("non-ASCII/invalid epoch year: %q", raw)
	}
	yy, _ := strconv.Atoi(raw[:2])
	year := 2000 + yy
	if yy >= 57 {
		year = 1900 + yy
	}
	body := raw[2:]
	doyStr, fracStr := body, ""
	if i := strings.IndexByte(body, '.'); i >= 0 {
		doyStr, fracStr = body[:i], body[i+1:]
	}
	if !asciiDigits(doyStr) || (fracStr != "" && !asciiDigits(fracStr)) {
		return "", fmt.Errorf("non-ASCII/invalid epoch field: %q", raw)
	}
	doy, _ := strconv.Atoi(doyStr)
	if doy < 1 || doy > daysInYear(year) {
		return "", fmt.Errorf("day-of-year %d out of range for %d", doy, year)
	}
	usecOfDay := 0
	if fracStr != "" {
		fracVal, err := strconv.ParseInt(fracStr, 10, 64)
		if err != nil {
			return "", err
		}
		scale := int64(1)
		for range fracStr {
			scale *= 10
		}
		usecOfDay = int((fracVal*int64(usecPerDay) + scale/2) / scale)
	}
	return renderEpoch(year, doy, usecOfDay)
}

// --- core record from a TLE line pair (SPEC §2.5) ---

// pySlice mimics Python s[i:j]: clamps to bounds, never panics.
func pySlice(s string, i, j int) string {
	n := len(s)
	if i < 0 {
		i = 0
	}
	if j > n {
		j = n
	}
	if i >= j {
		return ""
	}
	return s[i:j]
}

func line1Offset(line1 string) int {
	if len(line1) > 23 && line1[23] == '.' {
		return 0
	}
	if len(line1) > 24 && line1[24] == '.' {
		return 1
	}
	return 0
}

// CoreRecordFromTLE builds the canonical 11-field record from a TLE line pair.
func CoreRecordFromTLE(line1, line2 string) (CoreRecord, error) {
	var r CoreRecord
	off := line1Offset(line1)
	l1 := line1
	if off > 0 {
		l1 = line1[off:]
	}
	sat, err := DecodeSatnum(pySlice(line2, 2, 7))
	if err != nil {
		return r, err
	}
	if r.NoradCatID, err = CanonNorad(sat); err != nil {
		return r, err
	}
	if r.Epoch, err = EpochFromTLE(l1); err != nil {
		return r, err
	}
	if r.Inclination, err = CanonDecimal(pySlice(line2, 8, 16)); err != nil {
		return r, err
	}
	if r.RaOfAscNode, err = CanonDecimal(pySlice(line2, 17, 25)); err != nil {
		return r, err
	}
	if r.Eccentricity, err = CanonDecimal("0." + strings.TrimSpace(pySlice(line2, 26, 33))); err != nil {
		return r, err
	}
	if r.ArgOfPericenter, err = CanonDecimal(pySlice(line2, 34, 42)); err != nil {
		return r, err
	}
	if r.MeanAnomaly, err = CanonDecimal(pySlice(line2, 43, 51)); err != nil {
		return r, err
	}
	if r.MeanMotion, err = CanonDecimal(pySlice(line2, 52, 63)); err != nil {
		return r, err
	}
	if r.MeanMotionDot, err = CanonDecimal(pySlice(l1, 33, 43)); err != nil {
		return r, err
	}
	if r.MeanMotionDDot, err = DecodeAssumedExp(pySlice(l1, 44, 52)); err != nil {
		return r, err
	}
	if r.BStar, err = DecodeAssumedExp(pySlice(l1, 53, 61)); err != nil {
		return r, err
	}
	return r, nil
}

// --- serialization → contentHash (SPEC §2.6) ---

// JSONBytes returns the canonical bytes for ONE record: sorted ASCII keys, pinned
// separators, every value a string. Byte-identical to Python record_json_bytes.
func (r CoreRecord) JSONBytes() []byte {
	return []byte(`{"ARG_OF_PERICENTER":"` + r.ArgOfPericenter +
		`","BSTAR":"` + r.BStar +
		`","ECCENTRICITY":"` + r.Eccentricity +
		`","EPOCH":"` + r.Epoch +
		`","INCLINATION":"` + r.Inclination +
		`","MEAN_ANOMALY":"` + r.MeanAnomaly +
		`","MEAN_MOTION":"` + r.MeanMotion +
		`","MEAN_MOTION_DDOT":"` + r.MeanMotionDDot +
		`","MEAN_MOTION_DOT":"` + r.MeanMotionDot +
		`","NORAD_CAT_ID":"` + r.NoradCatID +
		`","RA_OF_ASC_NODE":"` + r.RaOfAscNode + `"}`)
}

// CanonicalBytes sorts a catalog ascending by int(NORAD), rejects duplicates, and
// serializes the JSON array (the sole hash input). Empty day → "[]".
func CanonicalBytes(records []CoreRecord) ([]byte, error) {
	seen := map[string]bool{}
	for _, r := range records {
		if seen[r.NoradCatID] {
			return nil, fmt.Errorf("duplicate NORAD_CAT_ID in catalog: %s", r.NoradCatID)
		}
		seen[r.NoradCatID] = true
	}
	ordered := make([]CoreRecord, len(records))
	copy(ordered, records)
	sort.SliceStable(ordered, func(i, j int) bool {
		ni, _ := strconv.Atoi(ordered[i].NoradCatID)
		nj, _ := strconv.Atoi(ordered[j].NoradCatID)
		return ni < nj
	})
	out := []byte{'['}
	for i, r := range ordered {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, r.JSONBytes()...)
	}
	out = append(out, ']')
	return out, nil
}

// ContentHash = SHA-256 of the canonical core projection, lowercase hex.
func ContentHash(records []CoreRecord) (string, error) {
	b, err := CanonicalBytes(records)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
