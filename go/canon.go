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

// validAssumedExpStr: the assumed-exponent field's exponent — an optional sign
// then EXACTLY 1 or 2 ASCII digits (SPEC §2.2 shape bounds).
func validAssumedExpStr(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}
	return (len(s) == 1 || len(s) == 2) && asciiDigits(s)
}

// Whitespace is ASCII-only by spec (SPEC §2.2): exactly \t\n\v\f\r and space.
// Unicode whitespace (NBSP, NEL, BOM, the C0 information separators, ideographic
// space, …) is non-canonical and left in place so the ascii-digit guards reject
// it fail-closed — uniform across every client. NOT strings.TrimSpace /
// unicode.IsSpace, which strip a different (and inter-language-divergent) set.
const asciiWS = " \t\n\v\f\r"

func stripASCII(s string) string  { return strings.Trim(s, asciiWS) }
func rstripASCII(s string) string { return strings.TrimRight(s, asciiWS) }

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
	s = stripASCII(s)
	s = strings.TrimRight(s, "\\")
	s = stripASCII(s)
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
		if !asciiDigits(exp) || !strings.ContainsAny(mant, "0123456789") {
			// the mantissa must contain at least one digit — ".e5" must not
			// materialize zeros through the exponent shift
			return "", fmt.Errorf("bad exponent form: %q", s)
		}
		ev, err := strconv.Atoi(esign + exp)
		if err != nil {
			return "", err
		}
		if ev > 999 || ev < -999 { // SPEC §2.2 step 3: |exponent| ≤ 999, identical bound in every language
			return "", fmt.Errorf("exponent out of bounds: %q", s)
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
		rest = rstripASCII(field[1:])
	case c0 == ' ':
		rest = rstripASCII(field[1:])
	case c0 >= '0' && c0 <= '9':
		rest = rstripASCII(field)
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
	// SPEC §2.2 shape bounds: mantissa EXACTLY 5 or 6 digits, exponent 1–2 digits.
	if len(mantDigits) < 5 || len(mantDigits) > 6 || !asciiDigits(mantDigits) || !validAssumedExpStr(expStr) {
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

// DecodeSatnum decodes an Alpha-5 / plain satnum field to its integer value
// (SPEC §2.4). Bounded + ASCII-strict: a plain numeric id is ≤ 9 digits
// (≤ 999,999,999); an Alpha-5 id is EXACTLY 5 chars (ASCII letter + 4 ASCII
// digits, ≤ 339,999); the leading char is ASCII-uppercased only (a–z → A–Z, never
// Unicode case-folding). Larger or non-ASCII inputs are non-canonical → fail closed.
func DecodeSatnum(field string) (int, error) {
	field = stripASCII(field)
	if field == "" {
		return 0, fmt.Errorf("empty satnum")
	}
	c0 := field[0]
	if c0 >= '0' && c0 <= '9' {
		if !asciiDigits(field) {
			return 0, fmt.Errorf("bad numeric satnum: %q", field)
		}
		sig := strings.TrimLeft(field, "0")
		if sig == "" {
			sig = "0"
		}
		if len(sig) > 9 { // ≤ 9-digit OMM max
			return 0, fmt.Errorf("numeric satnum out of range: %q", field)
		}
		return strconv.Atoi(sig)
	}
	if len(field) != 5 { // Alpha-5 is exactly 5 chars
		return 0, fmt.Errorf("bad Alpha-5 satnum length: %q", field)
	}
	upper := c0
	if upper >= 'a' && upper <= 'z' {
		upper -= 32 // ASCII uppercase only
	}
	idx := strings.IndexByte(alpha5, upper)
	if idx < 10 { // must be a letter (index ≥ 10), not a digit or non-ASCII
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
// The §1.1 line check runs HERE too (not only in CoreRecordFromTLE): the epoch
// window is located by byte offset, so a non-ASCII byte anywhere before it
// would silently shift the slice differently in byte- vs UTF-16- vs code-point-
// indexed implementations. Redundant for guarded callers, load-bearing for the
// direct decoder surface the vectors exercise.
func EpochFromTLE(line1 string) (string, error) {
	if err := asciiTLELine(line1); err != nil {
		return "", err
	}
	raw := stripASCII(pySlice(line1, 18, 32))
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
	if len(fracStr) > 8 { // SPEC §2.3: L ≤ 8 keeps F·USEC_PER_DAY < 2^63 (exact everywhere)
		return "", fmt.Errorf("epoch fraction longer than 8 digits: %q", raw)
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

// asciiTLELine enforces the §1.1 input model: a TLE line is a byte string of
// the §2.2 whitespace set (0x09–0x0D) and printable ASCII (0x20–0x7E) ONLY.
// This is what makes byte, UTF-16 and code-point slicing coincide across clients.
func asciiTLELine(line string) error {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if (c >= 0x20 && c <= 0x7e) || (c >= 0x09 && c <= 0x0d) {
			continue
		}
		return fmt.Errorf("non-ASCII/control byte 0x%02x at offset %d in TLE line", c, i)
	}
	return nil
}

// CoreRecordFromTLE builds the canonical 11-field record from a TLE line pair.
func CoreRecordFromTLE(line1, line2 string) (CoreRecord, error) {
	var r CoreRecord
	if err := asciiTLELine(line1); err != nil {
		return r, err
	}
	if err := asciiTLELine(line2); err != nil {
		return r, err
	}
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
	if r.Eccentricity, err = CanonDecimal("0." + stripASCII(pySlice(line2, 26, 33))); err != nil {
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

// canonicalNoradToken: ^(0|[1-9][0-9]*)$ with ≤ 9 digits (SPEC §2.6) — makes the
// int() sort exact in every language.
func canonicalNoradToken(s string) bool {
	if !asciiDigits(s) || len(s) > 9 {
		return false
	}
	return len(s) == 1 || s[0] != '0'
}

// canonicalValueToken: non-empty, drawn from [0-9.\-T:] (SPEC §2.6) — the charset
// that guarantees no JSON escaping can ever fire.
func canonicalValueToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || c == '.' || c == '-' || c == 'T' || c == ':') {
			return false
		}
	}
	return true
}

// CanonicalBytes sorts a catalog ascending by int(NORAD), rejects duplicates and
// non-canonical tokens, and serializes the JSON array (the sole hash input).
// Empty day → "[]".
func CanonicalBytes(records []CoreRecord) ([]byte, error) {
	seen := map[string]bool{}
	for _, r := range records {
		if !canonicalNoradToken(r.NoradCatID) {
			return nil, fmt.Errorf("non-canonical NORAD_CAT_ID token: %q", r.NoradCatID)
		}
		for _, v := range [11]string{
			r.ArgOfPericenter, r.BStar, r.Eccentricity, r.Epoch, r.Inclination,
			r.MeanAnomaly, r.MeanMotion, r.MeanMotionDDot, r.MeanMotionDot,
			r.NoradCatID, r.RaOfAscNode,
		} {
			if !canonicalValueToken(v) {
				return nil, fmt.Errorf("non-canonical value token %q in record %s", v, r.NoradCatID)
			}
		}
		if seen[r.NoradCatID] {
			return nil, fmt.Errorf("duplicate NORAD_CAT_ID in catalog: %s", r.NoradCatID)
		}
		seen[r.NoradCatID] = true
	}
	ordered := make([]CoreRecord, len(records))
	copy(ordered, records)
	sort.SliceStable(ordered, func(i, j int) bool {
		ni, _ := strconv.Atoi(ordered[i].NoradCatID) // token pre-validated: Atoi cannot fail
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
