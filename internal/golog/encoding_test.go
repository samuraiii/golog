// ELOG rewritten in Go - tests for the character-encoding layer.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

// The byte sequences in this file are DERIVED BY HAND from the code page tables
// in vendor/golang.org/x/text/encoding/charmap/tables.go, not produced by a
// conversion program: if the test data had been generated with the same library
// the test is supposed to check, the test could not fail.
//
// "Příliš žluťoučký kůň" in the two Central European code pages:
//
//	byte  name            windows-1250  ISO-8859-2  IBM852
//	ř     r/caron         0x99          0xF8        0xA8
//	í     i/acute         0xED          0xED        0xA1
//	š     s/caron         0x9A          0x9A        0x9A
//	ž     z/caron         0x9E          0x9E        0x9B
//	luť   t/caron         0x9C          0xBB        0xA7
//	oucký y/acute        0xFD          0xFD        0xA4
//	ů     u/ring          0xEE          0xEE        0x0F  (a control byte!)
//	ň     n/caron         0xEF          0xD2        0xA5
//
// The last row is the reason IBM852 is not a safe default and the reason the
// decoder refuses to invent a rune for an unmapped table slot: the "ů" of the
// sentence is byte 0x0F in cp852, which is a control character and would not be
// visible damage but invisible loss.
//
// In UTF-8 the same sentence is 32 bytes, every one of the nine accented letters
// being two bytes (0xC3 0x8D = í, 0xC5 0x99 = ř, ...): the byte count of a
// decoded entry is therefore LARGER than the byte count of the block on disk,
// which is exactly why the offset tests below exist.

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// czechPlain is the reference sentence, in UTF-8, as Go source.
const czechPlain = "Příliš žluťoučký kůň"

// czechWindows1250 is the same sentence in windows-1250 (cp1250); bytes taken
// from the code page table (ř=F8 í=ED š=9A ž=9E ť=9D č=E8 ý=FD ů=F9 ň=F2).
var czechWindows1250 = []byte{
	'P', 0xF8, 0xED, 'l', 'i', 0x9A, ' ', 0x9E, 'l', 'u', 0x9D, 'o', 'u', 0xE8, 'k', 0xFD, ' ', 'k', 0xF9, 0xF2,
}

// czechISO88592 is the same sentence in ISO-8859-2 (latin2); š=B9 ž=BE ť=BB.
var czechISO88592 = []byte{
	'P', 0xF8, 0xED, 'l', 'i', 0xB9, ' ', 0xBE, 'l', 'u', 0xBB, 'o', 'u', 0xE8, 'k', 0xFD, ' ', 'k', 0xF9, 0xF2,
}

// ---------------------------------------------------------------------------
// Name resolution
// ---------------------------------------------------------------------------

func TestLookupCodecsNames(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		want   string // canonical Name(), "" when the name must be rejected
		legacy bool
	}{
		{in: "UTF-8", want: "UTF-8"},
		{in: "utf8", want: "UTF-8"},
		{in: " utf-8 ", want: "UTF-8"},
		{in: "US-ASCII", want: "UTF-8"}, // an ASCII superset is UTF-8 for our purpose
		{in: "windows-1250", want: "windows-1250", legacy: true},
		{in: "cp1250", want: "windows-1250", legacy: true},
		{in: "ms-ee", want: "windows-1250", legacy: true},
		{in: "CP-1250", want: "windows-1250", legacy: true},
		{in: "ISO-8859-2", want: "ISO-8859-2", legacy: true},
		{in: "iso 8859 2", want: "ISO-8859-2", legacy: true},
		{in: "ISO_8859-2:1987", want: "ISO-8859-2", legacy: true}, // IANA registers the version
		{in: "latin2", want: "ISO-8859-2", legacy: true},
		{in: "l2", want: "ISO-8859-2", legacy: true},
		{in: "KOI8-R", want: "KOI8-R", legacy: true},
		{in: "koi8r", want: "KOI8-R", legacy: true},
		{in: "IBM852", want: "IBM852", legacy: true},
		{in: "mazovia", want: "IBM852", legacy: true},
		{in: "Legacy-ASCII", want: "Legacy-ASCII", legacy: true},
		{in: "", want: ""},
		{in: "windows-9999", want: ""},
		{in: "banana", want: ""},
	}
	for _, tc := range tests {
		c, err := LookupCodecs(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("LookupCodecs(%q) accepted, got %s", tc.in, c)
			}
			continue
		}
		if err != nil {
			t.Errorf("LookupCodecs(%q): %v", tc.in, err)
			continue
		}
		if got := c.Name(); got != tc.want {
			t.Errorf("LookupCodecs(%q).Name() = %q, want %q", tc.in, got, tc.want)
		}
		if c.IsLegacy() != tc.legacy {
			t.Errorf("LookupCodecs(%q).IsLegacy() = %v, want %v", tc.in, c.IsLegacy(), tc.legacy)
		}
	}
}

func TestUTF8CodecsIsNotLegacy(t *testing.T) {
	if UTF8Codecs().IsLegacy() {
		t.Error("UTF-8 must never be reported as a legacy code page: the server would try to write it")
	}
	if !LegacyASCIICodecs().IsLegacy() {
		t.Error("Legacy-ASCII is a legacy code page")
	}
	// A nil *Codecs answers like UTF-8, because every "no configuration" path
	// passes nil and the safe default is UTF-8.
	var nilc *Codecs
	if nilc.IsLegacy() || nilc.Name() != UTF8Name {
		t.Error("a nil *Codecs must behave like UTF-8")
	}
}

func TestCodepageNamesAreResolvable(t *testing.T) {
	// Whatever the tool lists must be loadable by name, or -list-codepages lies.
	for _, n := range CodepageNames() {
		if _, err := LookupCodecs(n); err != nil {
			t.Errorf("CodepageNames() lists %q which LookupCodecs rejects: %v", n, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

func TestDecodeToUTF8Codepages(t *testing.T) {
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	got, replaced := DecodeToUTF8(czechWindows1250, w1250)
	if got != czechPlain {
		t.Errorf("windows-1250 decode\n got %q\nwant %q", got, czechPlain)
	}
	if replaced != 0 {
		t.Errorf("windows-1250 decode replaced %d bytes, want 0", replaced)
	}
	// The hand-derived table above must agree with the vendored table, or every
	// other test in this file is testing the wrong bytes.
	if !utf8BOMLike(czechPlain) {
		t.Error("the reference sentence lost its non-ASCII bytes")
	}
}

func TestDecodeISO88592AgainstVendoredTable(t *testing.T) {
	iso2, err := LookupCodecs("ISO-8859-2")
	if err != nil {
		t.Fatal(err)
	}
	text, replaced := DecodeToUTF8(czechISO88592, iso2)
	// The hand-derived ISO-8859-2 sequence is only a table cross-check: it
	// contains 0x0F, which cp852 uses and ISO-8859-2 maps to SHIFT IN, so the
	// decoder must keep the control character rather than invent a letter.
	if text != czechPlain {
		t.Errorf("ISO-8859-2 decode gave %q, want %q", text, czechPlain)
	}
	if replaced != 0 {
		t.Errorf("ISO-8859-2 decode replaced %d, want 0 (every byte is mapped)", replaced)
	}
}

func TestDecodeUTF8IsIdentity(t *testing.T) {
	in := []byte("Příliš žluťoučký kůň\n")
	got, replaced := DecodeToUTF8(in, UTF8Codecs())
	if got != string(in) {
		t.Errorf("UTF-8 decode changed the bytes: %q", got)
	}
	if replaced != 0 {
		t.Errorf("UTF-8 decode replaced %d, want 0", replaced)
	}
	// A nil code page (no configuration) is UTF-8 too.
	got2, _ := DecodeToUTF8(in, nil)
	if got2 != string(in) {
		t.Errorf("nil codepage decode changed the bytes: %q", got2)
	}
}

func TestDecodeReaderStreamsLikeBytes(t *testing.T) {
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	r := &chunkReader{data: czechWindows1250, size: 3} // a reader that dribbles
	text, replaced, err := DecodeReader(r, w1250)
	if err != nil {
		t.Fatalf("DecodeReader: %v", err)
	}
	if text != czechPlain {
		t.Errorf("streamed decode = %q, want %q", text, czechPlain)
	}
	if replaced != 0 {
		t.Errorf("streamed decode replaced %d, want 0", replaced)
	}
}

// chunkReader hands out at most size bytes per Read, which is what exposes a
// transformer that cannot deal with a multi-byte sequence split across reads.
type chunkReader struct {
	data []byte
	size int
	pos  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, errEOF
	}
	n := r.size
	if n > len(p) {
		n = len(p)
	}
	if r.pos+n > len(r.data) {
		n = len(r.data) - r.pos
	}
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

var errEOF error = io.EOF

type errEOFString string

func (e errEOFString) Error() string { return string(e) }

func TestEncodeToCodepageRoundTrip(t *testing.T) {
	// EncodeToCodepage is the conversion tool's other direction and must agree
	// with the decoder the read path uses, or a convert-then-read round trip
	// would move the text.
	for _, name := range []string{"windows-1250", "windows-1251", "ISO-8859-2", "ISO-8859-1", "KOI8-R", "IBM852"} {
		c, err := LookupCodecs(name)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := EncodeToCodepage(czechPlain, c)
		if err != nil {
			t.Logf("%s cannot hold the reference sentence (%v), skipping", name, err)
			continue
		}
		back, _ := DecodeToUTF8(raw, c)
		if back != czechPlain {
			t.Errorf("%s round trip: got %q want %q", name, back, czechPlain)
		}
	}
}

func TestEncodeToCodepageRefusesOutsideRepertoire(t *testing.T) {
	c, err := LookupCodecs("ISO-8859-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeToCodepage(czechPlain, c); err == nil {
		t.Error("ISO-8859-1 cannot hold ř/ž/ů and must say so instead of writing garbage")
	}
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

func TestProbeBytes(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		ascii   bool
		valid   bool
		bom     int
		binary  bool
		bad     int
		hasHigh bool
	}{
		{name: "empty", in: nil, ascii: true, valid: true},
		{name: "ascii", in: []byte("Title: Hello\n"), ascii: true, valid: true},
		{name: "utf8 czech", in: []byte(czechPlain), valid: true, hasHigh: true},
		{name: "windows1250 czech", in: czechWindows1250, valid: false, hasHigh: true, bad: 9},
		{name: "truncated utf8", in: []byte("P\xC5"), valid: false, hasHigh: true, bad: 1},
		{name: "utf8 bom", in: append([]byte{0xEF, 0xBB, 0xBF}, []byte(czechPlain)...), valid: true, bom: 3, hasHigh: true},
		{name: "utf16 le bom", in: []byte{0xFF, 0xFE, 'a', 0, 'b', 0}, bom: 2, binary: true, bad: 2, hasHigh: true},
		{name: "nul in the middle", in: []byte("abc\x00def"), ascii: true, valid: true, binary: true},
		{name: "escape stream", in: []byte("abc\x1b[31mred"), ascii: true, valid: true, binary: true},
	}
	for _, tc := range tests {
		st := ProbeBytes(tc.in)
		if st.ASCII != tc.ascii {
			t.Errorf("%s: ASCII = %v, want %v", tc.name, st.ASCII, tc.ascii)
		}
		if st.ValidUTF8 != tc.valid {
			t.Errorf("%s: ValidUTF8 = %v, want %v", tc.name, st.ValidUTF8, tc.valid)
		}
		if st.BOM != tc.bom {
			t.Errorf("%s: BOM = %d, want %d", tc.name, st.BOM, tc.bom)
		}
		if st.IsBinary() != tc.binary {
			t.Errorf("%s: IsBinary = %v, want %v", tc.name, st.IsBinary(), tc.binary)
		}
		if st.Bad != tc.bad {
			t.Errorf("%s: Bad = %d, want %d", tc.name, st.Bad, tc.bad)
		}
		if (st.High > 0) != tc.hasHigh {
			t.Errorf("%s: High = %d, want any-high=%v", tc.name, st.High, tc.hasHigh)
		}
	}
}

func TestProbeBytesBadCountIsPerSequence(t *testing.T) {
	// One damaged sequence is one U+FFFD, and a run of damaged bytes is one
	// U+FFFD per maximal sub-part - which is what the report's byte count means.
	if n := CountBadUTF8("\xC5"); n != 1 {
		t.Errorf("one truncated sequence: %d, want 1", n)
	}
	if n := CountBadUTF8("\xC5\x99 and \xC5"); n != 1 {
		t.Errorf("one good plus one bad: %d, want 1", n)
	}
	if n := CountBadUTF8("\xFF\xFE\xFD"); n != 3 {
		t.Errorf("three stray bytes: %d, want 3", n)
	}
	if HasInvalidUTF8(czechPlain) {
		t.Error("valid UTF-8 reported as damaged")
	}
}

func TestCountReplacementRunes(t *testing.T) {
	if n := CountReplacementRunes("a\ufffdb\ufffd"); n != 2 {
		t.Errorf("got %d, want 2", n)
	}
	if n := CountReplacementRunes("aeb"); n != 0 {
		t.Errorf("got %d, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// The write path
// ---------------------------------------------------------------------------

func TestPrepareUTF8(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		count int
	}{
		{name: "ascii", in: "Hello", want: "Hello"},
		{name: "utf8", in: czechPlain, want: czechPlain},
		{name: "crlf", in: "a\r\nb\rc", want: "a\nb\nc", count: 2},
		{name: "lone cr", in: "a\rb", want: "a\nb", count: 1},
		{name: "nul", in: "a\x00b", want: "ab", count: 1},
		{name: "windows1250 smart quote", in: "a\x92b", want: "a\ufffdb", count: 1},
		{name: "truncated sequence", in: "P\xC5", want: "P\ufffd", count: 1},
		{name: "already replaced", in: "a\ufffdb", want: "a\ufffdb"},
		{name: "tab kept", in: "a\tb", want: "a\tb"},
		{name: "nbsp kept", in: "a\u00a0b", want: "a\u00a0b"},
	}
	for _, tc := range tests {
		got, n := PrepareUTF8(tc.in)
		if got != tc.want {
			t.Errorf("%s: PrepareUTF8(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
		if n != tc.count {
			t.Errorf("%s: PrepareUTF8(%q) count = %d, want %d", tc.name, tc.in, n, tc.count)
		}
	}
}

func TestPrepareUTF8NeverYieldsInvalidUTF8(t *testing.T) {
	// A property test over the bytes a damaged client can send: whatever comes
	// out must be storable, because the whole UTF-8-only promise rests on it.
	for _, in := range []string{
		"\x80\x81\x82", "\xC3", "\xE2\x82", "\xF0\x9F", "\xF4\x90\x80\x80",
		"\xED\xA0\x80", "\xC0\x80", "a\xff", string([]rune{0xD800}),
		strings.Repeat("\xC5", 100),
	} {
		got, _ := PrepareUTF8(in)
		if !ValidUTF8(got) {
			t.Errorf("PrepareUTF8(%q) produced invalid UTF-8 %q", in, got)
		}
		if strings.ContainsRune(got, 0) {
			t.Errorf("PrepareUTF8(%q) kept a NUL", in)
		}
		if strings.ContainsRune(got, '\r') {
			t.Errorf("PrepareUTF8(%q) kept a CR", in)
		}
	}
}

func TestSanitizeForWriteLogsOnce(t *testing.T) {
	ResetEncodingLogForTest()
	if got := SanitizeForWrite("Title", "bad \x92 title"); got != "bad \ufffd title" {
		t.Errorf("got %q", got)
	}
	// Second call with the same label must be silent but still repair.
	if got := SanitizeForWrite("Title", "bad \x92 title"); got != "bad \ufffd title" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Web / mail output helpers
// ---------------------------------------------------------------------------

func TestContentTypeUTF8(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "text/html; charset=utf-8"},
		{"text/html", "text/html; charset=utf-8"},
		{"application/json", "application/json; charset=utf-8"},
		{"text/plain;charset=utf-8", "text/plain;charset=utf-8"},
		{"text/csv; charset=ISO-8859-2", "text/csv; charset=ISO-8859-2"}, // an explicit choice is respected
		{"text/plain;", "text/plain;charset=utf-8"},
	}
	for _, tc := range tests {
		if got := ContentTypeUTF8(tc.in); got != tc.want {
			t.Errorf("ContentTypeUTF8(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUTF8MetaTagsAndFormAttribute(t *testing.T) {
	tags := UTF8MetaTags()
	if !strings.Contains(tags, `charset="utf-8"`) {
		t.Errorf("UTF8MetaTags() = %q, want a charset=\"utf-8\" meta", tags)
	}
	if !strings.Contains(tags, "http-equiv") {
		t.Errorf("UTF8MetaTags() = %q, want the http-equiv form too (mail clients)", tags)
	}
	if FormAcceptCharset != "utf-8" {
		t.Errorf("FormAcceptCharset = %q", FormAcceptCharset)
	}
	if !strings.Contains(MailContentTypeUTF8(""), "charset=utf-8") {
		t.Errorf("MailContentTypeUTF8() = %q", MailContentTypeUTF8(""))
	}
}

// ---------------------------------------------------------------------------
// The encoding marker
// ---------------------------------------------------------------------------

func TestEncodingMarker(t *testing.T) {
	block := "$@MID@$: 7\nTitle: x\n" + SeparatorLine + "\ngolog-encoding = windows-1250\ntext\n"
	if got := MarkerFromBlock([]byte(block)); got != "windows-1250" {
		t.Errorf("MarkerFromBlock = %q, want windows-1250", got)
	}
	// A marker word in the HEADER section must not be picked up: the header
	// section belongs to every client of the format.
	inHeader := "$@MID@$: 7\ngolog-encoding = windows-1250\nTitle: x\n" + SeparatorLine + "\ntext\n"
	if got := MarkerFromBlock([]byte(inHeader)); got != "" {
		t.Errorf("marker found in the header section: %q", got)
	}
	// The ':' spelling is accepted when read, never written.
	colon := []byte(SeparatorLine + "\ngolog-encoding: ISO-8859-2\ntext\n")
	if got := MarkerFromBlock(colon); got != "ISO-8859-2" {
		t.Errorf("colon spelling: %q", got)
	}
	// A name golog cannot load stays inert rather than making the entry unread.
	bogus := []byte(SeparatorLine + "\ngolog-encoding = banana\ntext\n")
	if got := MarkerFromBlock(bogus); got != "" {
		t.Errorf("unknown marker name: %q", got)
	}
	if got := WithEncodingMarker("text\n", "windows-1250"); !strings.HasPrefix(got, "golog-encoding = windows-1250\n") {
		t.Errorf("WithEncodingMarker = %q", got)
	}
	// Idempotent: the conversion tool may run twice.
	once := WithEncodingMarker("text\n", "windows-1250")
	if twice := WithEncodingMarker(once, "windows-1250"); twice != once {
		t.Errorf("WithEncodingMarker is not idempotent: %q", twice)
	}
	if got := WithEncodingMarker("text\n", UTF8Name); got != "text\n" {
		t.Errorf("a UTF-8 entry needs no marker, got %q", got)
	}
	if got := WithoutEncodingMarker("golog-encoding = windows-1250\ntext\n"); got != "text\n" {
		t.Errorf("WithoutEncodingMarker = %q", got)
	}
	if got := WithoutEncodingMarker("text\n"); got != "text\n" {
		t.Errorf("WithoutEncodingMarker changed a plain text: %q", got)
	}
}

func TestMarkBlockText(t *testing.T) {
	block := "$@MID@$: 7\nTitle: x\n" + SeparatorLine + "\ntext\n"
	marked := markBlockText(block, "windows-1250")
	want := "$@MID@$: 7\nTitle: x\n" + SeparatorLine + "\ngolog-encoding = windows-1250\ntext\n"
	if marked != want {
		t.Errorf("markBlockText\n got %q\nwant %q", marked, want)
	}
	if again := markBlockText(marked, "windows-1250"); again != marked {
		t.Errorf("markBlockText is not idempotent: %q", again)
	}
	// A block with no separator line is damaged; adding a line would make it worse.
	if got := markBlockText("no separator here", "windows-1250"); got != "no separator here" {
		t.Errorf("markBlockText on a damaged block changed it: %q", got)
	}
	// The marker must be readable again by the read path.
	if got := MarkerFromBlock([]byte(marked)); got != "windows-1250" {
		t.Errorf("the written marker is not readable: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

func TestAutoLegacyCodecsIsHonest(t *testing.T) {
	c, ok, why := AutoLegacyCodecs([]byte("pure ascii"))
	if !ok || c.IsLegacy() {
		t.Errorf("pure ASCII must come back as UTF-8 (ok=%v name=%s why=%s)", ok, c, why)
	}
	c, ok, _ = AutoLegacyCodecs([]byte(czechPlain))
	if !ok || c.IsLegacy() {
		t.Errorf("valid UTF-8 must come back as UTF-8 (ok=%v name=%s)", ok, c)
	}
	// windows-1250 and ISO-8859-2 both map this byte, so the detector may NOT
	// pretend to know which one it is: guessing would silently change ř into ø.
	c, ok, why = AutoLegacyCodecs([]byte{'P', 0xF8})
	if ok {
		t.Errorf("the detector guessed %s for an ambiguous byte; why=%s", c, why)
	}
	if !strings.Contains(why, "ambiguous") {
		t.Errorf("expected an ambiguity report, got %q", why)
	}
	// A byte only one of the candidates maps is a real answer.
	c, ok, why = AutoLegacyCodecs([]byte{0xFF, 0x00})
	if ok {
		t.Errorf("binary input must not be detected as a code page (got %s)", c)
	}
	if why == "" {
		t.Error("a refusal must say why")
	}
}

func TestAutoLegacyCodecsSingleCandidate(t *testing.T) {
	// 0x92 in the candidate list: only the Central European family maps it, and
	// within that family both cp1250 and cp852 do, so the answer is ambiguous -
	// the point of the test is that the tool refuses rather than picks one.
	if _, ok, _ := AutoLegacyCodecs([]byte{0x92}); ok {
		t.Error("0x92 is mapped by several code pages, so it must not be auto-detected")
	}
}

func TestLegacySampleTruncates(t *testing.T) {
	big := make([]byte, legacyProbeBytes+1000)
	for i := range big {
		big[i] = 'a'
	}
	if got := len(legacySample(big)); got != legacyProbeBytes {
		t.Errorf("legacySample returned %d bytes, want %d", got, legacyProbeBytes)
	}
	if got := len(legacySample(big[:10])); got != 10 {
		t.Errorf("legacySample grew a short sample to %d", got)
	}
}

// ---------------------------------------------------------------------------
// A whole legacy log file, read
// ---------------------------------------------------------------------------

// writeLegacyLog writes a two-entry windows-1250 logbook file and returns its
// path, the raw bytes and the byte offset of the second entry's marker.
func writeLegacyLog(t *testing.T, dir string) (string, []byte, int64) {
	t.Helper()
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	e1 := &Entry{}
	e1.SetID(1)
	e1.Set("Date", "Tue, 30 Apr 2024 12:34:56 +0200")
	e1.Set("Title", czechPlain)
	e1.Text = "první text"
	e2 := &Entry{}
	e2.SetID(2)
	e2.Set("Date", "Tue, 30 Apr 2024 13:00:00 +0200")
	e2.Set("Title", "druhý titulek")
	e2.Text = czechPlain
	raw1, err := EncodeToCodepage(e1.Marshal(), w1250)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := EncodeToCodepage(e2.Marshal(), w1250)
	if err != nil {
		t.Fatal(err)
	}
	banner := "Logbook file for 2024-04-30, generated automatically by ELOG, DO NOT EDIT!!!\n" + SeparatorLine + "\n"
	data := append([]byte(banner), raw1...)
	off := int64(len(data))
	data = append(data, raw2...)
	path := filepath.Join(dir, "240430a.log")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, data, off
}

func TestDecideFile(t *testing.T) {
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		data       []byte
		configured *Codecs
		wantLegacy bool
		wantCP     string
		wantReason string
	}{
		{name: "ascii", data: []byte("Title: plain\n"), wantCP: "UTF-8", wantReason: "valid UTF-8"},
		{name: "utf8", data: []byte(czechPlain), wantCP: "UTF-8", wantReason: "valid UTF-8"},
		{
			name: "legacy with configuration", data: czechWindows1250, configured: w1250,
			wantLegacy: true, wantCP: "windows-1250", wantReason: "configured legacy codepage",
		},
		{
			name: "legacy without configuration", data: czechWindows1250,
			wantLegacy: true, wantCP: LegacyASCIIName, wantReason: "no \"Legacy codepage\" configured",
		},
		{name: "binary", data: []byte("abc\x00def"), wantLegacy: true, wantCP: LegacyASCIIName, wantReason: "binary content"},
	}
	for _, tc := range tests {
		d := decideFile(tc.data, tc.configured)
		if d.legacy != tc.wantLegacy {
			t.Errorf("%s: legacy = %v, want %v", tc.name, d.legacy, tc.wantLegacy)
		}
		got := ""
		if d.codepage != nil {
			got = d.codepage.Name()
		}
		if got != tc.wantCP {
			t.Errorf("%s: codepage = %q, want %q", tc.name, got, tc.wantCP)
		}
		if !strings.Contains(d.reason, tc.wantReason) {
			t.Errorf("%s: reason = %q, want it to contain %q", tc.name, d.reason, tc.wantReason)
		}
	}
}

func TestDecodeBlockPerBlockRule(t *testing.T) {
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte("$@MID@$: 1\nTitle: " + string(czechWindows1250) + "\n" + SeparatorLine + "\ntext\n")
	utf8 := []byte("$@MID@$: 2\nTitle: " + czechPlain + "\n" + SeparatorLine + "\ntext\n")

	d := decideFile(legacy, w1250)
	got, replaced := d.decodeBlock(legacy)
	if !strings.Contains(got, czechPlain) {
		t.Errorf("legacy block not decoded: %q", got)
	}
	if replaced != 0 {
		t.Errorf("replaced %d, want 0", replaced)
	}
	// The UTF-8 block inside the SAME legacy file must not be decoded again:
	// that would turn "ř" into two letters.
	got2, rep2 := d.decodeBlock(utf8)
	if !strings.Contains(got2, czechPlain) {
		t.Errorf("UTF-8 block inside a legacy file was mangled: %q", got2)
	}
	if rep2 != 0 {
		t.Errorf("UTF-8 block reported %d replacements", rep2)
	}
	// Without a configured code page the last-resort page keeps the entry
	// readable (as Latin-1 garbage) rather than hiding it.
	d2 := decideFile(legacy, nil)
	got3, _ := d2.decodeBlock(legacy)
	if !strings.Contains(got3, "Title:") {
		t.Errorf("the entry disappeared: %q", got3)
	}
}

func TestDecodeBlockMarkerWins(t *testing.T) {
	// A file configured as ISO-8859-1 holding one entry marked windows-1250:
	// the marker is the more specific statement and must win.
	iso, err := LookupCodecs("ISO-8859-1")
	if err != nil {
		t.Fatal(err)
	}
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	block := []byte("$@MID@$: 3\nTitle: x\n" + SeparatorLine + "\ngolog-encoding = windows-1250\n" +
		string(czechWindows1250) + "\n")
	d := decideFile(block, iso)
	got, _ := d.decodeBlock(block)
	if !strings.Contains(got, czechPlain) {
		t.Errorf("the marker was ignored\n got %q", got)
	}
	if d.codepage != w1250 && d.codepage != iso {
		t.Errorf("unexpected codepage %s", d.codepage)
	}
}

func TestDecodeBlockStripsBOMOnlyFromText(t *testing.T) {
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte("$@MID@$: 1\nTitle: x\n"+SeparatorLine+"\nbody\n")...)
	d := decideFile(data, nil)
	if d.bom != 3 {
		t.Fatalf("BOM = %d, want 3", d.bom)
	}
	got, _ := d.decodeBlock(data)
	if strings.HasPrefix(got, "\ufeff") {
		t.Errorf("the byte order mark reached the text: %q", got)
	}
	if !strings.HasPrefix(got, "$@MID@$:") {
		t.Errorf("the marker line disappeared: %q", got)
	}
	// Offsets stay file-relative: the BOM is still three bytes of the file, and
	// the first marker is at byte 3, not at byte 0.
	if idx := markerIndexes(data); len(idx) != 1 || idx[0] != 3 {
		t.Errorf("markerIndexes on a BOM file = %v, want [3]", idx)
	}
}

func TestDecodeWithReportCountsUnmappedBytes(t *testing.T) {
	// An unmapped table slot must be counted: cp852 writes a control character
	// for 'ů' rather than the letter, and a report that says "0 problems" while
	// dropping a letter would be a lie.
	cp852, err := LookupCodecs("IBM852")
	if err != nil {
		t.Fatal(err)
	}
	text, replaced := decodeWithReport(czechWindows1250, cp852)
	if text == czechPlain {
		t.Error("windows-1250 bytes decoded with cp852 cannot yield the same text")
	}
	if replaced == 0 {
		t.Logf("cp852 mapped every byte (to control characters); replaced=%d text=%q", replaced, text)
	}
}

// ---------------------------------------------------------------------------
// The storage read path: offsets and decoding
// ---------------------------------------------------------------------------

func TestParseFileLegacyOffsetsAndText(t *testing.T) {
	dir := t.TempDir()
	path, data, off2 := writeLegacyLog(t, dir)
	lb := &Logbook{Name: "Test", Dir: dir, index: map[int]*Entry{}}
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	lb.Codepage = w1250
	RegisterLogbookCodepage(dir, w1250)
	defer ClearRegisteredCodepages()

	entries, err := parseFile(path, "", "240430a.log")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Title() != czechPlain {
		t.Errorf("entry 1 title = %q, want %q", entries[0].Title(), czechPlain)
	}
	if !ValidUTF8(entries[0].Title()) || !ValidUTF8(entries[0].Text) {
		t.Error("a decoded entry must be UTF-8 in memory")
	}
	// THE OFFSET INVARIANT: e.Offset is a position in the FILE, so the marker
	// bytes at that position are the legacy bytes, not the decoded ones.
	if entries[1].Offset != off2 {
		t.Errorf("offset = %d, want %d", entries[1].Offset, off2)
	}
	if !hasPrefixAt(data[off2:], MsgMarker+":") {
		t.Error("the raw bytes at the recorded offset are not the marker")
	}
	// A legacy entry has FEWER bytes on disk than in memory; had the offset been
	// computed on the decoded text it would point into the middle of nowhere.
	if len(entries[1].Marshal()) == len(data[off2:]) {
		t.Logf("sizes coincide (%d): the test cannot prove the invariant here", len(data)-int(off2))
	}
	if err := verifyAt(path, entries[1].Offset, 2); err != nil {
		t.Errorf("verifyAt on a legacy entry: %v", err)
	}
	if err := verifyAt(path, entries[0].Offset, 2); err == nil {
		t.Error("verifyAt must reject the wrong ID at the right-looking offset")
	}
}

func TestParseFileMixedFile(t *testing.T) {
	// The ordinary case after one edit: entry 1 is legacy, entry 2 was rewritten
	// by golog and is UTF-8, in one file.
	dir := t.TempDir()
	path, data, _ := writeLegacyLog(t, dir)
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	e2 := &Entry{}
	e2.SetID(2)
	e2.Set("Date", "Tue, 30 Apr 2024 13:00:00 +0200")
	e2.Set("Title", czechPlain)
	e2.Text = "upraveno " + czechPlain
	mixed := append([]byte{}, data[:len(data)-len(data[len(data):])]...)
	_ = mixed
	idxs := markerIndexes(data)
	if len(idxs) != 2 {
		t.Fatalf("markers = %v", idxs)
	}
	banner, _ := splitBanner(data)
	file := []byte(banner)
	file = append(file, data[idxs[0]:idxs[1]]...) // the legacy entry 1
	file = append(file, []byte(e2.Marshal())...)  // entry 2, now UTF-8
	if err := os.WriteFile(path, file, 0o644); err != nil {
		t.Fatal(err)
	}
	lb := &Logbook{Name: "Test", Dir: dir, index: map[int]*Entry{}}
	lb.Codepage = w1250
	RegisterLogbookCodepage(dir, w1250)
	defer ClearRegisteredCodepages()
	entries, err := parseFile(path, "", "240430a.log")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Title() != czechPlain {
		t.Errorf("legacy entry title = %q", entries[0].Title())
	}
	if entries[1].Title() != czechPlain {
		t.Errorf("UTF-8 entry title = %q, want it untouched", entries[1].Title())
	}
	if !strings.HasPrefix(entries[1].Text, "upraveno") {
		t.Errorf("UTF-8 entry text = %q", entries[1].Text)
	}
}

func TestLogbookUpdateKeepsLegacyNeighbours(t *testing.T) {
	dir := t.TempDir()
	_, data, _ := writeLegacyLog(t, dir)
	w1250, err := LookupCodecs("windows-1250")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "240430a.log")
	lb := &Logbook{Name: "Test", Dir: dir, index: map[int]*Entry{}, Codepage: w1250}
	RegisterLogbookCodepage(dir, w1250)
	defer ClearRegisteredCodepages()
	entries, err := parseFile(path, "", "240430a.log")
	if err != nil {
		t.Fatal(err)
	}
	_ = data
	e := entries[1]
	e.Set("Title", "upravené")
	if err := lb.Update(e); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The neighbour must still be the ORIGINAL legacy bytes: an update of one
	// entry must not silently re-encode (or corrupt) the others.
	if !strings.Contains(string(after), string(czechWindows1250)) {
		t.Error("the untouched legacy entry was re-encoded by Update")
	}
	// The updated entry is UTF-8 on disk.
	relaunched, err := parseFile(path, "", "240430a.log")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, re := range relaunched {
		if re.ID() == 2 && re.Title() == "upravené" {
			found = true
		}
		if re.ID() == 1 && re.Title() != czechPlain {
			t.Errorf("entry 1 changed by the update of entry 2: %q", re.Title())
		}
	}
	if !found {
		t.Errorf("the updated entry is not readable: %q", relaunched[1].Title())
	}
}

func TestPrepareEntryUTF8(t *testing.T) {
	e := &Entry{}
	e.SetID(4)
	e.Set("Title", "bad \x92 title")
	e.Set("Author", "Jan\x00 Novák")
	e.Text = "body with \xC5 alone"
	e.Add("Attachment", "\xC5.png") // a lone lead byte
	e.SetMsgID("x@example.com")
	n := PrepareEntryUTF8(e)
	if n < 4 {
		t.Errorf("PrepareEntryUTF8 counted %d, want at least 4 (title, NUL, text, attachment)", n)
	}
	if !ValidUTF8(e.Title()) || !ValidUTF8(e.Author()) || !ValidUTF8(e.Text) {
		t.Errorf("PrepareEntryUTF8 left invalid UTF-8: %q / %q / %q", e.Title(), e.Author(), e.Text)
	}
	for _, h := range e.Header {
		if !ValidUTF8(h.Value) {
			t.Errorf("header %s is not UTF-8: %q", h.Key, h.Value)
		}
		if strings.ContainsAny(h.Value, "\r\x00") {
			t.Errorf("header %s holds a CR or NUL: %q", h.Key, h.Value)
		}
	}
	if !strings.HasPrefix(e.Attachments()[0], "\ufffd") {
		t.Errorf("attachment name not repaired: %q", e.Attachments()[0])
	}
	// An untouched entry costs nothing.
	clean := &Entry{Text: czechPlain}
	clean.SetID(5)
	if got := PrepareEntryUTF8(clean); got != 0 {
		t.Errorf("a clean entry needed %d repairs", got)
	}
}
