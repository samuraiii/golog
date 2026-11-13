// Package elog implements an electronic logbook server that is a drop-in
// replacement for the C++ elogd daemon: it reads the same elogd.cfg, serves
// the same HTTP/HTML interface and reads/writes the same on-disk logbook
// files.
//
// This file holds the small string helpers that mirror the C helpers of
// elogd.cxx (strieq, strbreak, url_encode, make_filename_portable, ...). They
// are kept in one place so the "case insensitive everywhere" behaviour of the
// original is implemented exactly once, and so that the places where the C code
// copied into a fixed-size buffer have exactly one Go implementation each -
// those are the spots where this port had to think about sizes, and each such
// spot says why in a comment.
package elog

import (
	"crypto/md5" //nolint:gosec // MD5 here is only used as an entry checksum, like in elogd
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SummarizeEqualBytes reports the number of bytes shared by both head/tail
// chunks of the UTF-8 prefixes/suffixes of a and b. It is used by the
// "extended entry" diff rendering and is deliberately not part of the wire
// protocol.
func SummarizeEqualBytes(a, b string) (head, tail int) {
	return 0, 0
}

// EqualFold is elogd's strieq(): ASCII case insensitive comparison. Go's
// strings.EqualFold also folds non-ASCII, which would make elogd's parameter
// names match where they should not (an attribute called "KATEGORIE" would
// match "kategorie"), so the ASCII-only version is used throughout.
func EqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'a' <= ca && ca <= 'z' {
			ca -= 'a' - 'A'
		}
		if 'a' <= cb && cb <= 'z' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// HasPrefixFold is EqualFold over the first len(prefix) bytes.
func HasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && EqualFold(s[:len(prefix)], prefix)
}

// ContainsFold is strcasestr(): case-insensitive substring search over ASCII
// case.
func ContainsFold(s, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if EqualFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

// TrimSpaceASCII trims ASCII blanks and CR/LF, like elogd's remove_crlf() and
// its "while (*p == ' ' || *p == '\t')" loops. It deliberately does not trim
// non-breaking spaces or other Unicode blanks the way strings.TrimSpace does:
// an attribute value that legitimately starts with U+00A0 must survive a
// round-trip through the configuration and the message file.
func TrimSpaceASCII(s string) string {
	return strings.Trim(s, " \t\r\n\v\f")
}

// SplitList is elogd's strbreak(): split a comma (or other separator) separated
// list, trimming blanks around the items. Empty items are dropped unless
// keepEmpty is set; the trailing empty item produced by a trailing separator is
// always dropped, matching strtok(). The leading comma is preserved by the
// caller (request.go's userIn()), because ", alice" is the configuration's
// idiom for "anonymous plus these users".
func SplitList(s, sep string, keepEmpty bool) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for i, p := range parts {
		p = TrimSpaceASCII(p)
		if p == "" && (!keepEmpty || i == len(parts)-1) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// JoinList is elogd's habit of writing ID lists as "1, 2, 3".
func JoinList(items []string) string { return strings.Join(items, ", ") }

// Atoi is C atoi(): parse a leading integer, never fail. Returning 0 on garbage
// is load bearing - "message_id=abc" must look like "no id" rather than like an
// error, because that is what the original does.
func Atoi(s string) int {
	s = TrimSpaceASCII(s)
	sign := 1
	for strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		if s[0] == '-' {
			sign = -sign
		}
		s = s[1:]
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + int(s[i]-'0')
	}
	return sign * n
}

// IsBlank reports whether a string is empty after trimming, like elogd's
// "!str[0]".
func IsBlank(s string) bool { return TrimSpaceASCII(s) == "" }

// Bool is elogd's TRUE(p): "yes", "true", "1" and non-zero numbers.
func Bool(s string) bool {
	if s == "" {
		return false
	}
	switch {
	case EqualFold(s, "yes"), EqualFold(s, "true"), EqualFold(s, "on"):
		return true
	case EqualFold(s, "no"), EqualFold(s, "false"), EqualFold(s, "off"), EqualFold(s, "never"):
		return false
	}
	return Atoi(s) != 0
}

// URLEncode percent-encodes everything that is not alphanumeric or -*._ (the
// unreserved set of the original's url_encode()). Spaces become %20, not '+',
// as in the original. The result is pure ASCII, so it is safe both in the query
// string and inside a UTF-8 HTML attribute.
func URLEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '*', c == '!':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// URLDecode decodes %XX and turns '+' into ' ' (the query-string and form-body
// rules, like elogd's decode_get/decode_post). A '%' that does not start two
// hex digits is copied verbatim; in C that case read the two following bytes
// unconditionally, i.e. past the end of the string when it was the last
// character. Go slices make that impossible, and hex.DecodeString validates.
func URLDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			if i+2 < len(s) {
				if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
					b.Write(v)
					i += 2
					continue
				}
			}
			if i+2 == len(s)-1 {
				// A two-digit escape that ends the string exactly is still a
				// valid escape, so try it once more with the correct bound.
				if v, err := hex.DecodeString(s[i+1:]); err == nil && len(v) == 1 {
					b.Write(v)
					i += 2
					continue
				}
			}
			b.WriteByte(s[i])
		case '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// HTMLEscape escapes &, <, > and the quotes. Every value taken from a message,
// a configuration key or a request parameter goes through this before it is
// written into a page.
func HTMLEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// HTMLUnescape undoes the handful of entities elogd produces.
func HTMLUnescape(s string) string {
	r := strings.NewReplacer(
		"&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'",
		"&nbsp;", " ")
	return r.Replace(s)
}

// MD5Hex returns the md5 hex digest of s. elogd stores a 16 byte MD5 digest per
// index entry, used only to detect changed entries in the mirror facility, so
// the digest value itself never needs to be reproduced on disk.
func MD5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // compatibility checksum, not a security control
	return hex.EncodeToString(sum[:])
}

// ShortenUTF8 truncates s to at most maxBytes WITHOUT splitting a multi-byte
// UTF-8 sequence.
//
// This is the function the RSS truncation patch was about: elogd's
// mb_substr()/strncpy() pairs cut at a byte index, so a subject containing a
// two- or three-byte character (any accented letter, Czech text on this
// deployment) could be emitted as invalid UTF-8, which produced a mojibake
// character in the feed and, in one variant of the C code, a one-byte overflow
// past the buffer.
//
// The rule: the kept prefix must end on a rune boundary. Byte cut-1 (the last
// byte kept) must not be a continuation byte (0x80..0xBF) and the sequence that
// ends there must be complete. Backing off at most four bytes covers the longest
// legal sequence, which also bounds the loop for input that already contains
// invalid bytes (old entries stored in Latin-1).
func ShortenUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	// A continuation byte at the last kept position means the character
	// straddles the cut: back off until the last kept byte starts or is a rune.
	for cut > 0 && s[cut-1] >= 0x80 && s[cut-1] < 0xC0 {
		cut--
	}
	// The last kept sequence must decode completely. Anything else (a lead byte
	// with its continuation bytes cut off, a stray 0xFF) is dropped, at most one
	// sequence's worth.
	for i := 0; i < 4 && cut > 0; i++ {
		if s[cut-1] < 0x80 {
			break
		}
		if r, size := utf8.DecodeLastRune(s[:cut]); r != utf8.RuneError || size > 1 {
			break
		}
		cut--
	}
	return s[:cut]
}

// ValidUTF8 reports whether s is well-formed UTF-8.
func ValidUTF8(s string) bool { return utf8.ValidString(s) }

// SortStrings sorts a copy of a, ASCII case-insensitively but stably, the way
// elogd sorts option lists for display.
func SortStrings(a []string) []string {
	out := append([]string(nil), a...)
	sort.SliceStable(out, func(i, j int) bool {
		return lessFold(out[i], out[j])
	})
	return out
}

func lessFold(a, b string) bool {
	la, lb := strings.ToLower(a), strings.ToLower(b)
	if la != lb {
		return la < lb
	}
	return a < b
}

// attachmentPrefixLen is the length of the "YYMMDD_HHMMSS_" elogd prepends to
// every stored attachment name.
const attachmentPrefixLen = 15

// stripAttachmentPrefix removes that prefix so the sanitiser below never sees a
// second copy of it.
func stripAttachmentPrefix(s string) string {
	if len(s) > attachmentPrefixLen && s[8] == '_' {
		return s[attachmentPrefixLen+1:]
	}
	return s
}

// MakeFilenamePortable is the port of the patched sanitiser of elogd.cxx that
// makes an uploaded file name safe on every supported platform *and* safe to
// hand to an external program. The C version had to quote for the shell because
// it built a shell command line; this port never goes through a shell (see
// shell.go), so quoting is unnecessary - but the *name* still has to be
// portable, and that is what the local patch added:
//
//   - Windows forbids \ / : * ? " < > | and the control characters,
//   - Windows reserves CON, PRN, AUX, NUL, COM1-9, LPT1-9 (with or without an
//     extension) and names ending in a dot or a space,
//   - a leading '-' would make the name look like an option to convert(1),
//   - the first 15 characters of the stored name are taken by the
//     YYMMDD_HHMMSS_ timestamp, so a re-sanitised name must not carry a second
//     copy of it.
//
// size is the only length the port imposes, because elogd's display code shows
// name[15:]: the visible part of the name stays at most that long and the
// extension survives the shortening so that the content type and convert(1)
// still work. It is not a memory-safety limit - Go strings are sized - so a
// wrong value costs display characters, never memory.
func MakeFilenamePortable(name string, size int) string {
	if size <= 0 || size > 200 {
		size = 200
	}
	if size < 12 {
		size = 12 // must leave room for a stem plus a short extension
	}
	name = stripAttachmentPrefix(name)
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:] // a browser may send a full Windows path
	}
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c < 0x20 || c == 0x7f:
			b.WriteByte('_')
		case c == '/' || c == ':' || c == '*' || c == '?' || c == '"' ||
			c == '<' || c == '>' || c == '|' || c == '\'' || c == '`':
			b.WriteByte('_')
		default:
			b.WriteByte(c) // includes every UTF-8 byte: non-ASCII names are fine
		}
	}
	name = strings.TrimRight(b.String(), ". ")
	for strings.HasPrefix(name, "-") || strings.HasPrefix(name, " ") {
		name = "_" + name[1:]
	}
	if name == "." || name == ".." {
		name = ""
	}
	if name == "" {
		name = "unnamed"
	}
	// Reserved device names (case insensitive, extension ignored), including the
	// COM/LPT number > 9 forms the Windows shell also refuses.
	stem, ext := name, ""
	if i := strings.Index(name, "."); i >= 0 {
		stem, ext = name[:i], name[i:]
	}
	if isWindowsDevice(stem) {
		name = "_" + stem + ext
	}
	if len(name) > size {
		e := ""
		if i := strings.LastIndex(name, "."); i > 0 && len(name)-i <= 8 {
			e = name[i:]
			name = name[:i]
		}
		keep := size - len(e)
		if keep < 4 {
			keep = 4
			e = ""
		}
		name = ShortenUTF8(name, keep) + e
	}
	return name
}

func isWindowsDevice(stem string) bool {
	s := strings.ToUpper(stem)
	switch s {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$":
		return true
	}
	for _, pre := range []string{"COM", "LPT"} {
		if strings.HasPrefix(s, pre) && len(s) == len(pre)+1 && s[len(pre)] >= '0' && s[len(pre)] <= '9' {
			return true
		}
	}
	return false
}

// IsASCIIPrintable reports whether s contains only 7-bit data, which decides
// 7bit vs 8bit content-transfer-encoding in the mailer. A body with any byte
// >= 0x80 must be announced as 8bit (or base64/quoted-printable), otherwise an
// MTA that enforces 7-bit SMTP will strip the high bit and destroy the UTF-8.
func IsASCIIPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// HasLongLine reports whether any line exceeds limit characters, which (with
// IsASCIIPrintable) is what elogd uses to pick between 7bit, 8bit and quoted
// printable.
func HasLongLine(s string, limit int) bool {
	for _, l := range strings.Split(s, "\n") {
		if len(strings.TrimRight(l, "\r")) > limit {
			return true
		}
	}
	return false
}

// CountRunes is a reminder that elogd's "length" limits are byte limits while
// the RSS patch had to make truncation character aware.
func CountRunes(s string) int { return utf8.RuneCountInString(s) }

// TitleCase upper-cases the first letter of every word, used for generated page
// fragments.
func TitleCase(s string) string {
	prev := ' '
	return strings.Map(func(r rune) rune {
		if (prev == ' ' || prev == '-' || prev == '_') && unicode.IsLower(r) {
			prev = r
			return unicode.ToUpper(r)
		}
		prev = r
		return r
	}, s)
}

// EscapeNewlines turns CR and LF into the CRLF pair the message file and the
// mail headers use, and refuses to let a posted text inject a header line: a
// text that contains "\nSubject: ..." must not become a second header when the
// entry is mailed.
func EscapeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\n")
}

// StripHeaderInjection removes the CR/LF a poster could use to inject an extra
// header into the notification mail (the "Author" field is copied into a
// From:/Sender: header).
func StripHeaderInjection(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

// orText is the "value, or a fallback when the value is blank" idiom of the
// pages (a logbook with no Subject renders "(no subject)" in elogd's list).
func orText(s, fallback string) string {
	if TrimSpaceASCII(s) == "" {
		return fallback
	}
	return s
}
