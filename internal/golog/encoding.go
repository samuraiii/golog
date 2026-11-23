// ELOG rewritten in Go - the character-encoding layer.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

// ---------------------------------------------------------------------------
// Why this file exists
// ---------------------------------------------------------------------------
//
// golog stores UTF-8 and nothing else. That is a decision, not a default:
//
//   - every string this program WRITES into a logbook file, an XML password
//     file or an e-mail body is UTF-8 first (see PrepareUTF8, the single place
//     where text becomes storable);
//   - what it READS may still be a file the classic C elogd wrote in a national
//     code page - ISO-8859-2 or windows-1250 for the Czech sites, windows-1251
//     or KOI8-R for the Russian ones, ISO-8859-1 for the rest. Such a file is
//     decoded on the fly into UTF-8 Go strings and is never rewritten by the
//     server: reading a legacy logbook must not modify it. The one-time
//     conversion is a separate command ("gologd -convert").
//
// The C original does neither half. It has no charset configuration key at all
// (verified against inputs/elog/src: there is no "Charset"/"Codepage"/
// "Character set" getcfg() call anywhere in elogd.cxx), it stores whatever
// bytes the browser posted, and it declares a character set taken from the
// machine's locale - which is why real log directories are a mixture of code
// pages today. The option introduced here ("Legacy codepage", with
// "Charset"/"Codepage"/"Code page" accepted as aliases for sites that already
// set one) is therefore a golog concept, and the legacy value is only ever an
// INPUT assumption, never an output one.
//
// The two rules this file enforces:
//
//	(1) READ  - bytes that are well-formed UTF-8 are UTF-8 (a pure-ASCII file is
//		    both, and the converter leaves it alone); otherwise the bytes are
//		    decoded with the configured legacy code page. A byte sequence that
//		    cannot be decoded becomes U+FFFD and is counted and logged, so one
//		    broken byte costs one glyph and never the entry. The web layer
//		    therefore only ever sees UTF-8 strings.
//	(2) WRITE - input is repaired, never rejected: invalid UTF-8 in a posted
//		    value becomes U+FFFD, a NUL byte is dropped, both counted and
//		    logged. The alternative - an error page - throws away the rest of
//		    what the user typed, and elogd's behaviour on odd input has always
//		    been "store something". The count is returned, so a caller that
//		    wants to be strict (the conversion tool, an API POST) can reject on
//		    it; see PrepareUTF8.
//
// Byte offsets are the one thing that must never be confused: the logbook index
// holds BYTE OFFSETS INTO THE FILE (storage.go), and an entry decoded from
// windows-1250 has MORE bytes in memory than it occupies on disk - one Czech
// letter is one byte in windows-1250 and two in UTF-8. Nothing in this package
// turns a memory position into a file offset: legacy.go decodes strictly AFTER
// the raw bytes have been split and their offsets recorded, and the marker
// search that produces those offsets always runs on undecoded file bytes.
//
// The code pages themselves come from the vendored golang.org/x/text:
// golang.org/x/text/encoding/charmap for the byte tables (its exported
// variables are exactly the set referenced by vendor/golang.org/x/text/
// encoding/ianaindex/ianaindex.go, which is where the names below are taken
// from) and golang.org/x/text/encoding/ianaindex for the name resolution, so
// "latin2", "cp1250", "ms-ee", "ISO_8859-2:1987" and "csISOLatin2" all work
// without golog maintaining a registry of its own.

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/ianaindex"
	xunicode "golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// ---------------------------------------------------------------------------
// Names and constants
// ---------------------------------------------------------------------------

const (
	// UTF8Name is the canonical spelling of the only encoding golog writes.
	UTF8Name = "UTF-8"

	// UTF8Charset is the spelling used in HTTP and MIME parameters (lower case
	// by RFC 2046 convention, and the spelling the C code used).
	UTF8Charset = "utf-8"

	// LegacyASCIIName is the last-resort code page, used when a file is
	// neither valid UTF-8 nor decodable with the configured code page. Every
	// byte maps to its Latin-1 rune, which is the "one byte, one glyph, never
	// worse" behaviour an operator expects when nothing else fits.
	LegacyASCIIName = "Legacy-ASCII"

	// EncodingMarker is the line golog records an entry's original encoding
	// with. It is written at the top of the TEXT section rather than in the
	// header section, and in the configuration-file idiom ("key = value"): the
	// header section is parsed by every client of the format (elogd, elns, the
	// hand-written readers), where an unknown header line is not guaranteed to
	// be ignored, while the text section is free-form by contract.
	//
	// It is READ wherever it is the first text line (a file may legitimately
	// carry one added by hand or by the conversion tool) and it is WRITTEN only
	// by the conversion tool, for the entries it converted. A file that is
	// already UTF-8 needs no marker at all: the UTF-8-or-legacy decision is
	// made per file by inspecting the bytes.
	EncodingMarker = "golog-encoding"
)

// BOM sequences. They are handled explicitly rather than through a transformer
// so that the byte count of a stripped BOM is known: a BOM shifts every offset
// in the file, and offsets must stay file-relative (see the note above).
var (
	utf8BOMBytes   = []byte{0xEF, 0xBB, 0xBF}
	utf16LEBOMByte = []byte{0xFF, 0xFE}
	utf16BEBOMByte = []byte{0xFE, 0xFF}
)

// UTF-16 with a byte order mark, for reading only: elogd could never write a
// UTF-16 log file, but an operator who round-tripped a logbook through a
// Windows editor must not get mojibake out of golog.
var (
	utf16BEWithBOM = xunicode.UTF16(xunicode.BigEndian, xunicode.UseBOM)
	utf16LEWithBOM = xunicode.UTF16(xunicode.LittleEndian, xunicode.UseBOM)
)

// ErrUnknownCodepage is returned for a code page name that neither golog's own
// table nor the IANA registry knows. The caller decides whether that is fatal:
// a wrong value in the configuration must not stop the daemon, so the server
// logs it once and reads the logbook as UTF-8 (see LegacyCodecsForScope), while
// the conversion tool exits with an error because there the user is watching.
var ErrUnknownCodepage = errors.New("unknown codepage")

// ErrNotText is returned when a file that should hold text holds something
// else (a NUL byte, a terminal escape stream). Converting it would turn a
// binary blob into plausible-looking mojibake, so the conversion tool refuses.
var ErrNotText = errors.New("not a text file")

// ErrAlreadyUTF8 is returned by the conversion path for a file that needs no
// conversion. It is a report, not a failure: converting is idempotent, and the
// tool counts these files as "skipped".
var ErrAlreadyUTF8 = errors.New("already UTF-8")

// ---------------------------------------------------------------------------
// Codecs: one resolved code page
// ---------------------------------------------------------------------------

// Codecs is a resolved character encoding: a canonical name and the decoder
// that does the work. It is immutable once built and safe for concurrent use;
// a new vendored Decoder is created per conversion, which is what the x/text
// transformer contract requires.
//
// The name says "the code page this scope uses" and cannot be confused with
// encoding.Encoding, the vendored interface it wraps.
type Codecs struct {
	name   string
	enc    encoding.Encoding // nil only for utf8Codecs: identity, see decodeBytes
	legacy bool              // false only for UTF-8 itself
}

// Name is the canonical (IANA-style) spelling of this code page.
func (c *Codecs) Name() string {
	if c == nil {
		return UTF8Name
	}
	return c.name
}

// IsLegacy reports whether this is a national code page, i.e. something golog
// may read but must never write.
func (c *Codecs) IsLegacy() bool { return c != nil && c.legacy }

// String implements fmt.Stringer for log lines.
func (c *Codecs) String() string { return c.Name() }

// UTF8Codecs is the code page golog writes, and the one a file is assumed to
// hold when no "Legacy codepage" is configured.
func UTF8Codecs() *Codecs { return utf8Codecs }

// LegacyASCIICodecs is the last-resort code page (Latin-1 with replacement).
func LegacyASCIICodecs() *Codecs { return legacyASCIICodecs }

// utf8Codecs carries enc == nil, which decodeBytes reads as "identity". That
// keeps the UTF-8 fast path free of any transformer work, and it is the only
// place in this file where a nil encoder is meaningful.
var utf8Codecs = &Codecs{name: UTF8Name}

var legacyASCIICodecs = &Codecs{name: LegacyASCIIName, enc: charmap.ISO8859_1, legacy: true}

// builtinCodepages is the set of code pages golog resolves by itself, which is
// also the set whose byte tables the tests cover. Every variable name below is
// copied from the exported declarations of the vendored charmap package as
// referenced by vendor/golang.org/x/text/encoding/ianaindex/ianaindex.go
// (encodings list), so no name here is a guess. Names outside this set fall
// through to the IANA registry, which knows the registered aliases.
var builtinCodepages = []struct {
	name string
	enc  encoding.Encoding
}{
	{"ISO-8859-1", charmap.ISO8859_1},
	{"ISO-8859-2", charmap.ISO8859_2},
	{"ISO-8859-3", charmap.ISO8859_3},
	{"ISO-8859-4", charmap.ISO8859_4},
	{"ISO-8859-5", charmap.ISO8859_5},
	{"ISO-8859-6", charmap.ISO8859_6},
	{"ISO-8859-7", charmap.ISO8859_7},
	{"ISO-8859-8", charmap.ISO8859_8},
	{"ISO-8859-9", charmap.ISO8859_9},
	{"ISO-8859-10", charmap.ISO8859_10},
	{"ISO-8859-13", charmap.ISO8859_13},
	{"ISO-8859-14", charmap.ISO8859_14},
	{"ISO-8859-15", charmap.ISO8859_15},
	{"ISO-8859-16", charmap.ISO8859_16},
	{"windows-1250", charmap.Windows1250},
	{"windows-1251", charmap.Windows1251},
	{"windows-1252", charmap.Windows1252},
	{"windows-1253", charmap.Windows1253},
	{"windows-1254", charmap.Windows1254},
	{"windows-1255", charmap.Windows1255},
	{"windows-1256", charmap.Windows1256},
	{"windows-1257", charmap.Windows1257},
	{"windows-1258", charmap.Windows1258},
	{"windows-874", charmap.Windows874},
	{"KOI8-R", charmap.KOI8R},
	{"KOI8-U", charmap.KOI8U},
	{"macintosh", charmap.Macintosh},
	{"IBM437", charmap.CodePage437},
	{"IBM850", charmap.CodePage850},
	{"IBM852", charmap.CodePage852},
	{"IBM855", charmap.CodePage855},
	{"IBM866", charmap.CodePage866},
}

// aliasToCanonical maps the spellings an operator actually types to a name of
// builtinCodepages. The IANA registry covers far more (it is tried second), so
// this list only carries the forms that are worth a direct hit - in particular
// the ones people write for Czech logs.
var aliasToCanonical = map[string]string{
	"utf8":      "UTF-8",
	"unicode":   "UTF-8",
	"usascii":   "UTF-8",
	"ascii":     "UTF-8",
	"latin2":    "ISO-8859-2",
	"iso88592":  "ISO-8859-2",
	"iso8859-2": "ISO-8859-2",
	"l2":        "ISO-8859-2",
	"latin1":    "ISO-8859-1",
	"iso88591":  "ISO-8859-1",
	"iso8859-1": "ISO-8859-1",
	"l1":        "ISO-8859-1",
	"latin9":    "ISO-8859-15",
	"iso885915": "ISO-8859-15",
	"latin5":    "ISO-8859-9",
	"iso88599":  "ISO-8859-9",
	"latin7":    "ISO-8859-13",
	"iso885913": "ISO-8859-13",
	"latin4":    "ISO-8859-4",
	"iso88594":  "ISO-8859-4",
	"latin3":    "ISO-8859-3",
	"iso88593":  "ISO-8859-3",
	"latin10":   "ISO-8859-16",
	"iso885916": "ISO-8859-16",
	"latin6":    "ISO-8859-10",
	"iso885910": "ISO-8859-10",
	"cp1250":    "windows-1250",
	"ms-ee":     "windows-1250",
	"cee":       "windows-1250",
	"cp1251":    "windows-1251",
	"ms-cyr":    "windows-1251",
	"cp1252":    "windows-1252",
	"ms-ansi":   "windows-1252",
	"cp1253":    "windows-1253",
	"cp1254":    "windows-1254",
	"cp1255":    "windows-1255",
	"cp1256":    "windows-1256",
	"cp1257":    "windows-1257",
	"baltic":    "windows-1257",
	"cp1258":    "windows-1258",
	"cp874":     "windows-874",
	"koi8":      "KOI8-R",
	"koi8r":     "KOI8-R",
	"koi8u":     "KOI8-U",
	"cp852":     "IBM852",
	"mazovia":   "IBM852",
	"cp850":     "IBM850",
	"cp437":     "IBM437",
	"cp855":     "IBM855",
	"cp866":     "IBM866",
	"macroman":  "macintosh",
	"mac-roman": "macintosh",
}

// autoCodepageKeys is the order in which AutoLegacyCodecs tries the code pages
// when the conversion operator asked for "--codepage auto". Central European
// first, because that is the deployment this batch was written for.
var autoCodepageKeys = []string{
	"ISO-8859-2", "windows-1250", "IBM852", "ISO-8859-1", "windows-1252",
	"ISO-8859-15", "windows-1251", "KOI8-R", "ISO-8859-5", "ISO-8859-7",
	"windows-1253", "windows-1254", "windows-1257", "ISO-8859-16",
	"macintosh", "IBM866", "IBM850", "IBM437",
}

// normaliseCodepage lower-cases and drops blanks, tabs and underscores. It
// never rejects anything: an unknown name simply stays unknown and reaches the
// IANA lookup, so a typo in the configuration is a logged warning, never a
// daemon that refuses to start.
func normaliseCodepage(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ', c == '\t', c == '_', c == '\v', c == '\f':
			// dropped: "ISO_8859_2" and "ISO 8859 2" name the same code page
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		default:
			b.WriteByte(c)
		}
	}
	return strings.Trim(b.String(), " ,;")
}

// builtinFor returns the decoder of a name in builtinCodepages, matching on the
// normalised spelling so that "iso 8859-2" and "ISO_8859_2" hit.
func builtinFor(name string) (string, encoding.Encoding, bool) {
	key := normaliseCodepage(name)
	for _, b := range builtinCodepages {
		if normaliseCodepage(b.name) == key {
			return b.name, b.enc, true
		}
	}
	return "", nil, false
}

// LookupCodecs resolves a code page name and is the only name-to-decoder path
// in the program, so a configuration value, a command-line argument and a
// per-entry marker cannot mean three different things.
//
// The order is: golog's own table, then the IANA registry through ianaindex
// (case-insensitive; it knows the registered aliases and the "iso_8859-2:1987"
// style spellings). A name that means UTF-8 or US-ASCII yields the UTF-8 Codecs
// with IsLegacy() false: "nothing to convert" is the answer the caller needs.
func LookupCodecs(name string) (*Codecs, error) {
	raw := TrimSpaceASCII(name)
	key := normaliseCodepage(raw)
	if key == "" {
		return nil, fmt.Errorf("%w: empty name", ErrUnknownCodepage)
	}
	if key == "utf-8" || key == "utf8" {
		return utf8Codecs, nil
	}
	switch key {
	case "us-ascii", "ascii", "ansi_x3.4-1968", "iso646-us", "us", "646":
		return utf8Codecs, nil // ASCII is a subset of UTF-8
	case "legacy-ascii":
		return legacyASCIICodecs, nil
	}
	if strings.HasPrefix(key, "cp-") {
		key = "cp" + key[3:]
	}
	if i := strings.IndexByte(key, ':'); i > 0 && strings.HasPrefix(key, "iso") {
		key = key[:i] // "ISO_8859-2:1987" is ISO-8859-2
		raw = key
	}
	if canon, ok := aliasToCanonical[key]; ok {
		return newCodecs(canon)
	}
	if cname, _, ok := builtinFor(raw); ok {
		return newCodecs(cname)
	}
	// The registry is keyed on the registered spelling: try what the operator
	// wrote, then the normalised form. A registered-but-unsupported name comes
	// back as (nil, nil) and falls through to the error below, which is the
	// right answer - golog must not silently read a file with the wrong code
	// page just because the name was real.
	for _, cand := range []string{raw, key} {
		if cand == "" {
			continue
		}
		if enc, err := ianaindex.IANA.Encoding(cand); err == nil && enc != nil {
			name := raw
			if m, err := ianaindex.MIME.Name(enc); err == nil && "" != m {
				name = m
			}
			return newCodecsFrom(name, enc), nil
		}
		if enc, err := ianaindex.MIME.Encoding(cand); err == nil && enc != nil {
			return newCodecsFrom(raw, enc), nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownCodepage, name)
}

// newCodecs builds (and caches) the Codecs of a name in builtinCodepages.
// Caching keeps the per-file and per-request path free of allocations for the
// common code pages.
func newCodecs(canonical string) (*Codecs, error) {
	if canonical == UTF8Name {
		return utf8Codecs, nil
	}
	codecsMu.Lock()
	defer codecsMu.Unlock()
	if c, ok := codecsCache[canonical]; ok {
		return c, nil
	}
	name, enc, ok := builtinFor(canonical)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownCodepage, canonical)
	}
	c := &Codecs{name: name, enc: enc, legacy: true}
	codecsCache[canonical] = c
	return c, nil
}

// newCodecsFrom wraps a code page that came from the IANA registry. Its display
// name is the name the operator used, which is the spelling that appears in the
// log and in a conversion report.
func newCodecsFrom(name string, enc encoding.Encoding) *Codecs {
	if n := normaliseCodepage(name); n == "utf-8" || n == "utf8" {
		return utf8Codecs
	}
	key := "iana:" + normaliseCodepage(name)
	codecsMu.Lock()
	defer codecsMu.Unlock()
	if c, ok := codecsCache[key]; ok {
		return c
	}
	c := &Codecs{name: name, enc: enc, legacy: true}
	codecsCache[key] = c
	return c
}

var (
	codecsMu    sync.Mutex
	codecsCache = map[string]*Codecs{}
)

// CodepageNames lists the code pages golog knows by name, for the conversion
// tool's "--list-codepages" and for the documentation. The IANA registry knows
// many more; this is the list whose byte tables the tests cover.
func CodepageNames() []string {
	out := make([]string, 0, len(builtinCodepages)+2)
	for _, b := range builtinCodepages {
		out = append(out, b.name)
	}
	out = append(out, UTF8Name, LegacyASCIIName)
	return SortStrings(out)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// decodeBytes turns raw bytes into a UTF-8 Go string with one code page.
//
// A charmap decoder never fails: every byte in its range maps, and an unmapped
// slot yields U+FFFD. "replaced" therefore counts the U+FFFD the decoder
// produced plus the ones already present in the input, which is the number an
// operator wants in a conversion report ("this file had N bytes we could not
// map").
func decodeBytes(b []byte, c *Codecs) (text string, replaced int) {
	if c == nil || c.enc == nil {
		s := string(b)
		return s, CountReplacementRunes(s)
	}
	out, err := c.enc.NewDecoder().Bytes(b)
	if err != nil {
		// Only the UTF-16 decoders report an error (a byte-order requirement
		// that was not met). Keep the raw bytes rather than lose data, and let
		// the caller's repair step count and log what is left.
		s := string(b)
		return s, CountBadUTF8(s)
	}
	s := string(out)
	return s, CountReplacementRunes(s)
}

// DecodeToUTF8 is the exported form of decodeBytes.
func DecodeToUTF8(b []byte, c *Codecs) (string, int) { return decodeBytes(b, c) }

// DecodeReader decodes a stream: apart from the result, only the copy buffer of
// the transform is in memory, which is what lets the conversion tool handle a
// multi-gigabyte log file.
func DecodeReader(r io.Reader, c *Codecs) (string, int, error) {
	if r == nil {
		return "", 0, nil
	}
	if c == nil || c.enc == nil {
		b, err := io.ReadAll(r)
		s := string(b)
		return s, CountReplacementRunes(s), err
	}
	b, err := io.ReadAll(transform.NewReader(r, c.enc.NewDecoder()))
	s := string(b)
	if err != nil {
		return s, CountReplacementRunes(s), err
	}
	return s, CountReplacementRunes(s), nil
}

// EncodeToCodepage renders a UTF-8 string in another code page. It exists for
// the conversion tool alone (re-encoding a file from one legacy page to
// another); THE SERVER NEVER CALLS IT. That is the invariant of this batch, and
// this function is the only way to produce legacy bytes anywhere in golog,
// which makes the invariant greppable.
func EncodeToCodepage(s string, c *Codecs) ([]byte, error) {
	if c == nil || c.enc == nil {
		return []byte(s), nil
	}
	return c.enc.NewEncoder().Bytes([]byte(s))
}

// ---------------------------------------------------------------------------
// Inspection: what is this byte string?
// ---------------------------------------------------------------------------

// TextState is what ProbeBytes knows about a byte string. It is deliberately a
// statement about BYTES and not about a decoded string: the storage layer needs
// the answer before it decodes anything, because the answer decides which
// offsets it may keep.
type TextState struct {
	Scanned   int64 // bytes examined
	Truncated bool  // the string was a sample of a larger file
	ASCII     bool  // every byte < 0x80, hence valid UTF-8 in any ASCII superset
	ValidUTF8 bool  // well-formed UTF-8
	BOM       int   // 0, 3 (UTF-8 BOM) or 2 (UTF-16 BOM)
	HasNUL    bool  // contains 0x00: binary or UTF-16, not 8-bit text
	HasESC    bool  // contains 0x1B: a terminal escape stream, not text
	Bad       int   // ill-formed UTF-8 sequences
	High      int   // bytes >= 0x80
}

// IsBinary reports that the bytes cannot be log text at all. A log file is
// 7-bit text plus 8-bit letters; a NUL byte appears in UTF-16 files and in a
// binary blob that a crash spliced into a log file, and an escape stream
// appears when somebody pointed a terminal at the log file. In none of those
// cases may golog decode the file as a code page: it would turn the damage into
// plausible-looking text.
func (t TextState) IsBinary() bool { return t.HasNUL || t.HasESC }

// probeChunk inspects b. atEOF says whether b is the whole text or the leading
// chunk of a bigger file, which decides whether a truncated rune at the end is
// damage or just a cut.
func probeChunk(b []byte, atEOF bool) TextState {
	st := TextState{Scanned: int64(len(b))}
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c == 0:
			st.HasNUL = true
		case c == 0x1B:
			st.HasESC = true
		case c < 0x80:
			// plain ASCII: nothing to record
		default:
			st.High++
		}
	}
	if len(b) >= 3 && b[0] == utf8BOMBytes[0] && b[1] == utf8BOMBytes[1] && b[2] == utf8BOMBytes[2] {
		st.BOM = 3
	} else if len(b) >= 2 {
		if (b[0] == utf16LEBOMByte[0] && b[1] == utf16LEBOMByte[1]) ||
			(b[0] == utf16BEBOMByte[0] && b[1] == utf16BEBOMByte[1]) {
			st.BOM = 2
		}
	}
	st.Bad = countIllFormed(b, atEOF)
	st.ValidUTF8 = st.Bad == 0
	st.ASCII = st.High == 0
	return st
}

// ProbeBytes classifies a byte slice holding a whole text.
func ProbeBytes(b []byte) TextState { return probeChunk(b, true) }

// countIllFormed counts the maximal sub-parts of b that are not valid UTF-8.
// With atEOF false an incomplete sequence at the very end is NOT counted: a
// chunk boundary is not damage. The sub-part rule is Unicode's and is the one
// Go's DecodeRune implements, so no second UTF-8 decoder is introduced here.
func countIllFormed(b []byte, atEOF bool) int {
	bad := 0
	for i := 0; i < len(b); {
		if b[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			if !atEOF && !utf8.FullRune(b[i:]) {
				return bad
			}
			bad++
			i++
			continue
		}
		i += size
	}
	return bad
}

// HasInvalidUTF8 reports whether s contains an ill-formed UTF-8 sequence.
func HasInvalidUTF8(s string) bool { return countIllFormed([]byte(s), true) > 0 }

// CountBadUTF8 counts the ill-formed UTF-8 sequences of s.
func CountBadUTF8(s string) int { return countIllFormed([]byte(s), true) }

// CountReplacementRunes counts the U+FFFD of s. A U+FFFD somebody typed is
// counted too: the question this answers is "how much of this text is already a
// replacement", which is what a report shows, and a decoder cannot tell the two
// apart after the fact.
func CountReplacementRunes(s string) int {
	n := 0
	for _, r := range s {
		if r == utf8.RuneError {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// The write path
// ---------------------------------------------------------------------------

// PrepareUTF8 is the gate every string passes before golog stores or sends it.
// It returns well-formed UTF-8 and the number of substitutions made.
//
// The repairs, in the order applied:
//
//   - a byte sequence that is not valid UTF-8 becomes one U+FFFD (the maximal
//     sub-part rule, which is what Go's range-over-string already does, so no
//     second UTF-8 decoder is involved);
//   - a NUL byte is dropped: it cannot live in a log file, because the C reader
//     stops at it and would truncate the entry, so keeping one corrupts the
//     file rather than the text;
//   - CR is folded into LF, so that the line-oriented block splitting of the
//     storage layer sees the line ends it expects (a lone CR would otherwise
//     make the next reader see one enormous line). EscapeNewlines in text.go
//     applies the same rule to header values; applying it here too means the
//     message file contains no CR at all, which is what keeps "byte offsets in
//     the file" and "line numbers in the text" talking about the same thing.
//
// Nothing else changes: no NFC normalisation, no tab folding, no HTML
// sanitising. Normalising would silently rewrite data the operator typed, and
// this batch is about encodings, not about text policy.
//
// POLICY (documented in docs/encoding.md): repair, do not reject. A poster whose
// browser sent one stray 0x92 must not lose the text he typed. The count is
// returned so that a caller which wants to be strict (the conversion tool, an
// API POST) can reject on it, and every repair is logged by SanitizeForWrite.
//
// Attachment CONTENT is never run through this: those bytes are the user's.
// Attachment NAMES are, because they are text that ends up in HTML and in the
// XML password/log metadata.
func PrepareUTF8(s string) (string, int) {
	if IsASCIIPrintable(s) && !strings.ContainsAny(s, "\x00\r") {
		return s, 0
	}
	bad := CountBadUTF8(s)
	if bad == 0 && !strings.ContainsAny(s, "\x00\r") {
		return s, 0
	}
	n := bad
	var b strings.Builder
	b.Grow(len(s))
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch r := rs[i]; r {
		case 0:
			n++ // dropped, and counted as a substitution
		case '\r':
			n++
			if i+1 < len(rs) && '\n' == rs[i+1] {
				i++ // CRLF becomes one LF
			}
			b.WriteByte('\n')
		default:
			b.WriteRune(r) // WriteRune turns an invalid rune into U+FFFD
		}
	}
	return b.String(), n
}

// SanitizeForWrite is PrepareUTF8 plus the log line, for call sites that have no
// use for the count. label names the field ("Title", "Text", "Author", ...) so
// that the log says where the damage was.
func SanitizeForWrite(label, s string) string {
	out, n := PrepareUTF8(s)
	if n > 0 {
		logEncodingOnce("write:"+label,
			"golog: input for %s contained %d invalid or unrepresentable UTF-8 sequence(s), replaced with U+FFFD",
			label, n)
	}
	return out
}

// logEncodingOnce throttles a diagnostic to one line per key: a logbook with one
// damaged entry is read on every request, and the daemon log must not fill up
// with repeats. The map is capped, so a hostile or broken store cannot grow it
// without bound (past the cap, messages are simply not repeated).
func logEncodingOnce(key, format string, args ...any) {
	encodingLogMu.Lock()
	if _, seen := encodingLogSeen[key]; seen {
		encodingLogMu.Unlock()
		return
	}
	if len(encodingLogSeen) < 512 {
		encodingLogSeen[key] = struct{}{}
	}
	encodingLogMu.Unlock()
	Logf(format, args...)
}

var (
	encodingLogMu   sync.Mutex
	encodingLogSeen = map[string]struct{}{}
)

// ResetEncodingLogForTest clears the throttle so a test that checks the log
// output sees the message even when it runs after another test.
func ResetEncodingLogForTest() {
	encodingLogMu.Lock()
	encodingLogSeen = map[string]struct{}{}
	encodingLogMu.Unlock()
}

// ---------------------------------------------------------------------------
// Web output: the UTF-8-only surface
// ---------------------------------------------------------------------------

// ContentTypeUTF8 is the Content-Type value for a media type served as UTF-8. It
// exists so that HTML, RSS, JSON, CSV and the raw view cannot drift apart; the
// C original printed a charset in some places and none in others, which is how
// its feeds ended up mis-declared.
func ContentTypeUTF8(mediaType string) string {
	if mediaType == "" {
		mediaType = "text/html"
	}
	if ContainsFold(mediaType, "charset") {
		return mediaType
	}
	if strings.HasSuffix(mediaType, ";") {
		return mediaType + "charset=" + UTF8Charset
	}
	return mediaType + "; charset=" + UTF8Charset
}

// UTF8MetaTags is the pair of meta tags every generated page emits, for the
// consumers that ignore the HTTP header (an HTML mail client, a browser opening
// a saved copy of a page).
func UTF8MetaTags() string {
	return "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=" + UTF8Charset + "\">\n" +
		"<meta charset=\"" + UTF8Charset + "\">\n"
}

// FormAcceptCharset is the accept-charset value every generated form carries.
// Without it a browser may submit a form in the encoding of the page instead of
// UTF-8, which would put ISO-8859-2 bytes into a UTF-8-only store.
const FormAcceptCharset = UTF8Charset

// MailContentTypeUTF8 is the Content-Type header line of a UTF-8 mail body.
func MailContentTypeUTF8(mediaType string) string {
	if mediaType == "" {
		mediaType = "text/plain"
	}
	return "Content-Type: " + ContentTypeUTF8(mediaType)
}

// ---------------------------------------------------------------------------
// The per-entry encoding marker
// ---------------------------------------------------------------------------

// encIndexOfByte is bytes.IndexByte without importing bytes: this file works on
// both strings and byte slices and the byte-wise loop is the one storage.go
// uses for the same search.
func encIndexOfByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// encTrimEOL drops the CR/LF of one line of a message block.
func encTrimEOL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// MarkerLine is the text line that records an entry's original encoding.
func MarkerLine(name string) string {
	return EncodingMarker + " = " + name + "\n"
}

// WithEncodingMarker prefixes text with the marker for name, unless the text
// already carries one or name is UTF-8. It is idempotent, which the conversion
// tool relies on: running the tool twice must not add a second line.
func WithEncodingMarker(text, name string) string {
	if name == "" {
		return text
	}
	if n := normaliseCodepage(name); n == "utf-8" || n == "utf8" {
		return text
	}
	if ExtractEncodingMarker(text) != "" {
		return text
	}
	return MarkerLine(name) + text
}

// WithoutEncodingMarker removes the marker line from a text so that it never
// reaches a page, a feed or a mail body.
func WithoutEncodingMarker(text string) string {
	line, rest, ok := strings.Cut(text, "\n")
	if !ok {
		if isMarkerLine(line) {
			return ""
		}
		return text
	}
	if !isMarkerLine(line) {
		return text
	}
	return rest
}

// isMarkerLine reports whether one line is an encoding marker. Both the
// "key = value" and the header-like "key: value" spelling are accepted when
// reading, because an operator may add the line by hand in either style; only
// the first spelling is ever written.
func isMarkerLine(line string) bool {
	l := TrimSpaceASCII(line)
	if !HasPrefixFold(l, EncodingMarker) {
		return false
	}
	rest := TrimSpaceASCII(l[len(EncodingMarker):])
	return strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, ":")
}

// ExtractEncodingMarker is the code page named by the marker of a text, "" when
// it carries none or when the name is not a code page golog can load (so a
// hand-typed "golog-encoding = banana" stays inert).
func ExtractEncodingMarker(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	if !isMarkerLine(line) {
		return ""
	}
	rest := TrimSpaceASCII(line[len(EncodingMarker):])
	if i := strings.IndexAny(rest, "=:"); i >= 0 {
		rest = rest[i+1:]
	}
	name := TrimSpaceASCII(rest)
	if name == "" {
		return ""
	}
	if _, err := LookupCodecs(name); err != nil {
		return ""
	}
	return name
}

// MarkerFromBlock finds the marker in a raw message block. It looks only at the
// first line of the TEXT section - the only place a marker may legally be - and
// only after the separator line, so a header line that happens to start with the
// word cannot be mistaken for one. The block is undecoded file bytes; the marker
// itself is 7-bit by construction, so it can be looked for before decoding.
func MarkerFromBlock(block []byte) string {
	sep := indexSeparator(block)
	if sep < 0 {
		return ""
	}
	rest := block[sep+len(SeparatorLine):]
	for len(rest) > 0 && (rest[0] == '\n' || rest[0] == '\r') {
		rest = rest[1:]
	}
	line := rest
	if i := encIndexOfByte(rest, '\n'); i >= 0 {
		line = rest[:i]
	}
	return ExtractEncodingMarker(string(encTrimEOL(line)))
}

// ---------------------------------------------------------------------------
// Auto-detection of a code page (the conversion tool's --codepage auto only)
// ---------------------------------------------------------------------------

// AutoLegacyCodecs picks a legacy code page for a byte string by trying the
// known candidates. It is honest about being a guess: ok is true only when
// EXACTLY ONE candidate decodes the input without producing a single replacement
// rune. For the Latin-2 family that almost never happens - windows-1250 and
// ISO-8859-2 both map every byte of 0xA0..0xFF - so the tool then prints the
// candidates it found and asks for an explicit code page, instead of picking one
// at random and silently producing "ř" where "ž" was meant.
//
// The server never calls this: an ambiguous guess would mean a page whose text
// changes after a restart, which is worse than a documented default.
func AutoLegacyCodecs(b []byte) (c *Codecs, ok bool, reason string) {
	if len(b) == 0 {
		return nil, false, "empty input"
	}
	st := ProbeBytes(b)
	if st.IsBinary() {
		return nil, false, "binary content, not a code page"
	}
	if st.ASCII {
		return utf8Codecs, true, "pure ASCII"
	}
	if st.ValidUTF8 {
		return utf8Codecs, true, "valid UTF-8"
	}
	var fits []*Codecs
	for _, key := range autoCodepageKeys {
		cand, err := LookupCodecs(key)
		if err != nil {
			continue
		}
		text, replaced := decodeBytes(b, cand)
		if replaced != 0 || HasInvalidUTF8(text) {
			continue
		}
		fits = append(fits, cand)
	}
	switch len(fits) {
	case 0:
		return legacyASCIICodecs, false, "no known code page decodes the file cleanly"
	case 1:
		return fits[0], true, "single candidate"
	default:
		names := make([]string, 0, len(fits))
		for _, f := range fits {
			names = append(names, f.Name())
		}
		return fits[0], false, "ambiguous: " + strings.Join(names, ", ") + " all decode cleanly"
	}
}
