package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// AWGRange is an AmneziaWG parameter that may be a single value or an inclusive
// range ("100-140").
//
// AmneziaWG 2.0 made the header magics H1..H4 accept ranges, and 3.0 introduced
// a family of timing parameters (RekeyAfterTime, KeepaliveTimeout, …) that are
// ranges by nature — the point of randomising them is that a censor cannot
// fingerprint a fixed value. Modelling them as an int can express the 1.5-era
// config and nothing since.
//
// It unmarshals from a JSON number OR string, so inbounds stored when these
// fields were int64 keep loading. It marshals as a string.
type AWGRange string

// UnmarshalJSON accepts 1234567, "1234567" and "1500000000-1500999999".
func (r *AWGRange) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		*r = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*r = AWGRange(strings.TrimSpace(s))
		return nil
	}
	// A bare number: the shape every AmneziaWG inbound created before 3.x
	// support was stored in.
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("amneziawg range: want a number or \"lo-hi\" string, got %s", b)
	}
	*r = AWGRange(n.String())
	return nil
}

func (r AWGRange) MarshalJSON() ([]byte, error) { return json.Marshal(string(r)) }

func (r AWGRange) String() string { return string(r) }
func (r AWGRange) Empty() bool    { return strings.TrimSpace(string(r)) == "" }

// Bounds reports the low and high ends. A single value is a range of width 0.
// ok is false when the text is not a value or a range at all.
func (r AWGRange) Bounds() (lo, hi int64, ok bool) {
	s := strings.TrimSpace(string(r))
	if s == "" {
		return 0, 0, false
	}
	// A leading '-' would be a negative number, which no AmneziaWG parameter
	// accepts; splitting on the first '-' after position 0 keeps that honest.
	if i := strings.Index(s[1:], "-"); i >= 0 {
		i++
		a, err1 := strconv.ParseInt(strings.TrimSpace(s[:i]), 10, 64)
		b, err2 := strconv.ParseInt(strings.TrimSpace(s[i+1:]), 10, 64)
		if err1 != nil || err2 != nil {
			return 0, 0, false
		}
		if a > b {
			a, b = b, a
		}
		return a, b, true
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return v, v, true
}

// AWGRangeFromInt builds a single-value range, for defaults and migration.
func AWGRangeFromInt(v int64) AWGRange { return AWGRange(strconv.FormatInt(v, 10)) }
