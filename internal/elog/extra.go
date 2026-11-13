package elog

// ---------------------------------------------------------------------------
// Miscellaneous helpers used by more than one subsystem.
//
// The string helpers live in text.go, the generic small converters in support.go
// and util.go, the configuration accessors in config.go/config_util.go, the
// file/time helpers in util.go and dates.go. This file only holds what fits
// nowhere else.
// ---------------------------------------------------------------------------

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// timestampNano is the clock fallback of RandomToken, split out so the fallback
// is one line and visible by inspection.
func timestampNano() int64 { return time.Now().UnixNano() }

// ParseCTime is the inverse of FormatCTime, i.e. the reading of the
// last_activity / last_logout stamps of the password file. Newer elogd versions
// store an epoch number, older ones an asctime()-style string, so both are
// accepted.
func ParseCTime(s string) (time.Time, bool) {
	s = TrimSpaceASCII(s)
	if s == "" {
		return time.Time{}, false
	}
	if !strings.ContainsAny(s, " :") {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return time.Unix(int64(n), 0), true
		}
	}
	for _, layout := range []string{
		"Mon Jan _2 15:04:05 2006", "Mon Jan  2 15:04:05 2006", "Mon Jan 02 15:04:05 2006",
		time.ANSIC, time.UnixDate, time.RubyDate, time.RFC1123,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return ParseDate(s)
}

// ParseCTimeOrNow is ParseCTime with "a very long time ago" as the fallback,
// which is what the session-expiry check wants (an unreadable stamp must mean
// "expired", not "never expires").
func ParseCTimeOrNow(s string) time.Time {
	if t, ok := ParseCTime(s); ok {
		return t
	}
	return time.Unix(0, 0)
}

// ParseEntryBytes parses one raw message block (the "$@MID@$: ..." form). It is
// the exported form of the storage layer's block parser, used by the configuration
// dump, the import path and the tests.
func ParseEntryBytes(b []byte) (*Entry, error) { return parseBlock(b) }

// readFileOrEmpty returns the contents of a file, "" when it cannot be read.
// elogd does the same with its "read the header/footer file, ignore errors".
func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// SamePerson compares the "Author" field of two entries the way elogd does when
// it decides whether a poster may edit his own entry: case insensitive, blanks
// collapsed, and either side may be a comma-separated list of names (a joint
// post), in which case one shared name is enough.
//
// elogd compares with strncmp() over the first N characters of a fixed buffer,
// which lets "John Doe" match "John Doe2" - the shortened comparison is exactly
// the fixed-buffer bug class this port must not reproduce, so names are compared
// whole here. The difference only ever lets a few more people edit their own
// entries, and it is listed in RESULT.md as a deliberate deviation.
func SamePerson(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if personKey(a) == personKey(b) {
		return true
	}
	for _, x := range SplitList(a, ",", false) {
		for _, y := range SplitList(b, ",", false) {
			if EqualFold(collapseBlanks(x), collapseBlanks(y)) {
				return true
			}
		}
	}
	return false
}
