// ELOG rewritten in Go - reading a logbook written in a legacy code page.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

// ---------------------------------------------------------------------------
// The encoding model of golog
// ---------------------------------------------------------------------------
//
//  1. A Go string is UTF-8. Every text this package hands to another package -
//     a title, a body, an attribute value, an attachment name - is UTF-8, and
//     every text it WRITES to disk is UTF-8 (encoding.go's PrepareUTF8 is the
//     gate; storage_encoding.go runs every entry through it before it is
//     marshalled).
//  2. A logbook FILE may hold something else, because the C original stored
//     whatever bytes its browser sent and had no charset configuration at all -
//     real log directories are a mixture of ISO-8859-2, windows-1250, KOI8-R and
//     UTF-8. Such a file is DECODED when it is read and is never rewritten by the
//     server.
//  3. Turning a legacy file into UTF-8 is a separate, explicit, one-time
//     operation: "gologd convert" (cmd/gologd/convert.go, legacy_convert.go,
//     legacy_write.go). No request handler can reach it, and nothing in this
//     file writes a file.
//  4. THE OFFSET INVARIANT: Entry.Offset is the BYTE OFFSET of the entry's
//     "$@MID@$" line IN THE FILE (storage.go). A message decoded from
//     windows-1250 has MORE bytes in memory than it occupies on disk - one Czech
//     letter is one byte there and two here - so decoded text and file offsets
//     live in different coordinate systems and are never mixed. A file is split
//     into blocks on its RAW bytes, the offsets are recorded from that split,
//     and only then is a block's text decoded. Nothing in golog computes a
//     position inside decoded text.
//  5. THE UNIT OF A DECODE is one message block. The code page is a property of
//     the writer, not of the transformer: decoding half a block would cut a
//     multi-byte sequence and produce U+FFFD where the original had a letter. A
//     block is also what the index points at and what the conversion rewrites, so
//     all three layers use the same unit.
//  6. Attachment CONTENT is never decoded and never re-encoded: those bytes are
//     the user's, and re-encoding a JPEG is data loss. Attachment NAMES are text
//     and are repaired as text (encoding_util.go).
//
// The layers, so that each symbol has one home:
//
//	encoding.go           the names, the code page table, decode/encode, the
//	                      per-entry marker, the UTF-8 write gate, UTF-8 output
//	                      helpers
//	encoding_config.go    which code page a scope / logbook / file is read with,
//	                      and FileDecoder (one file's blocks + counters)
//	encoding_read.go      read-only block and offset helpers
//	encoding_util.go      display and repair helpers for callers outside storage
//	legacy.go (this)      the option, the per-file decision, the conversion
//	                      vocabulary and the in-memory conversion
//	legacy_write.go       the atomic write, the backup, the verification, the
//	                      block reader, the streaming decode
//	legacy_convert.go     the entry points "gologd convert" calls: one file with
//	                      the strategy chosen by size, a whole tree, and the PID
//	                      file refusal
//
// The vendored tables this relies on are documented in encoding.go and
// docs/encoding.md.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// The option
// ---------------------------------------------------------------------------

// LegacyCodepageOption is the primary spelling of the option that names the
// national code page a logbook's files were WRITTEN in. It is a read-time
// statement only: golog always writes UTF-8, so the value can never change what
// goes to disk.
const LegacyCodepageOption = "Legacy codepage"

// CodepageOptionAliases are the deprecated spellings accepted for sites that
// already set one of them.
//
// "Charset" is the word the C source uses everywhere for "character encoding"
// (its XML metadata writes a <charset> element holding UTF-8/Latin-1/utf16le,
// the LOG_CHARSET_* enum of elogd.cxx), so an operator who set a charset for his
// logbook finds his option still honoured. The other two are the words people
// type when they mean the same thing. A deprecated spelling is read like the
// primary one and never written.
var CodepageOptionAliases = []string{"Charset", "Codepage", "Code page"}

// LegacyCodepageNames is the option plus its aliases, in lookup order.
func LegacyCodepageNames() []string {
	out := make([]string, 0, 1+len(CodepageOptionAliases))
	out = append(out, LegacyCodepageOption)
	out = append(out, CodepageOptionAliases...)
	return out
}

// ConfigCodepageName is the configured value of the option in one scope, "" when
// nothing is set, and which spelling carried it (so that a status page can say
// `"Charset" is deprecated, use "Legacy codepage"`).
func ConfigCodepageName(c *Config, scope ConfigScope) (value, option string, ok bool) {
	if c == nil {
		return "", "", false
	}
	for _, name := range LegacyCodepageNames() {
		if v, found := c.Get(scope, name); found && TrimSpaceASCII(v) != "" {
			return TrimSpaceASCII(v), name, true
		}
	}
	return "", "", false
}

// LogbookCodepageName is the code page one logbook section is configured with,
// for "gologd convert", which has a *Config and no *Server.
func LogbookCodepageName(c *Config, scope ConfigScope) string {
	v, _, ok := ConfigCodepageName(c, scope)
	if !ok {
		return ""
	}
	return v
}

// LegacyCodecsForScope resolves the option of one configuration scope.
//
// The answers are distinct on purpose, because the two callers need them to be:
// the server treats an unknown name as "read this logbook as UTF-8 and log a
// warning" (a typo must not take a logbook down - ConfigCodepage does that),
// while the conversion tool treats it as a fatal error, because there an
// operator asked for a write and the wrong code page during a conversion turns
// every letter into the wrong letter permanently.
func LegacyCodecsForScope(c *Config, scope ConfigScope) (codes *Codecs, present bool, err error) {
	value, option, ok := ConfigCodepageName(c, scope)
	if !ok {
		return nil, false, nil
	}
	codes, err = LookupCodecs(value)
	if err != nil {
		return nil, true, fmt.Errorf("%s = %q: %w", option, value, err)
	}
	if option != LegacyCodepageOption {
		logEncodingOnce("cfg:alias:"+scope.Group+":"+option,
			"golog: [%s] %q is deprecated, spell it %q", scope.Group, option, LegacyCodepageOption)
	}
	return codes, true, nil
}

// ResetCodepageCache forgets every resolved code page and every registered data
// directory, and clears the once-per-key log throttle. Tests use it between
// cases; a running daemon never needs it, because a code page is resolved at
// most once per name for the life of the process.
func ResetCodepageCache() {
	codecsMu.Lock()
	codecsCache = map[string]*Codecs{}
	codecsMu.Unlock()
	ClearRegisteredCodepages()
	ResetEncodingLogForTest()
}

// ---------------------------------------------------------------------------
// The block-level tools
// ---------------------------------------------------------------------------

// legacyProbeBytes is how much of a file is looked at to decide what it is.
//
// It is larger than a "sample" for one reason: the byte that says "this file is
// windows-1250" can be the fifth entry's title, three kilobytes in. It is
// bounded because the decision is made while a request is being served, and
// reading a whole 200 MB log file to find two bytes would be the wrong trade.
// What is NOT left to the sample is correctness: the per-block rule below
// decodes each message on its own, so an entry that disagrees with the head of
// the file is still read correctly.
const legacyProbeBytes = 256 * 1024

// legacySample is the part of a file's bytes the decision is taken from.
func legacySample(data []byte) []byte {
	if len(data) <= legacyProbeBytes {
		return data
	}
	return data[:legacyProbeBytes]
}

// maxConvertFileSize is where the in-memory conversion stops and the streaming
// one takes over (legacy_convert.go's ConvertFileAuto).
//
// The number is a memory argument, not a preference: the in-memory path holds
// the original, the converted bytes and the read-back copy at the same time, so
// three times the file size is live at once. On linux/386 and windows/386 a
// process gets 2 GB of address space, which is why the limit sits well below
// that and why the streaming path exists at all.
const maxConvertFileSize = int64(128 << 20)

// maxBlocksReported caps the per-entry list of a conversion report.
const maxBlocksReported = 50

// ValidUTF8 reports whether s is well-formed UTF-8. Every string this package
// hands out satisfies it; this is the assertion the tests and the status page
// check.
func ValidUTF8(s string) bool { return utf8.ValidString(s) }

// utf8BOMLike reports that s contains a byte above 0x7F, i.e. that it is not
// pure ASCII. The name says what it is used for: a text with high bytes is
// either UTF-8 or a legacy code page, and the tests use it to check that a
// reference string still holds its non-ASCII letters.
func utf8BOMLike(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// hasUTF8BOM, hasUTF16BOM and utf16BOMCodepage look at the byte order marks.
// They are functions rather than a transformer because a BOM shifts every offset
// in the file and the count has to stay visible (see the offset invariant).
func hasUTF8BOM(b []byte) bool {
	return len(b) >= 3 && b[0] == utf8BOMBytes[0] && b[1] == utf8BOMBytes[1] && b[2] == utf8BOMBytes[2]
}

func hasUTF16BOM(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	return (b[0] == utf16LEBOMByte[0] && b[1] == utf16LEBOMByte[1]) ||
		(b[0] == utf16BEBOMByte[0] && b[1] == utf16BEBOMByte[1])
}

// utf16BOMCodepage names the UTF-16 the file claims, for a report ("this file is
// UTF-16LE, it is read as such and converted to UTF-8"). The wrapped vendored
// decoders strip the mark themselves, which is why decodeBodyBytes is given the
// whole block.
func utf16BOMCodepage(b []byte) *Codecs {
	if !hasUTF16BOM(b) {
		return nil
	}
	if b[0] == utf16LEBOMByte[0] && b[1] == utf16LEBOMByte[1] {
		return newCodecsFrom("UTF-16LE", utf16LEWithBOM)
	}
	return newCodecsFrom("UTF-16BE", utf16BEWithBOM)
}

// stripBOMBytes removes a byte order mark, returning what is left and how many
// bytes were dropped (an offset question, again).
func stripBOMBytes(b []byte) ([]byte, int) {
	switch {
	case hasUTF8BOM(b):
		return b[3:], 3
	case hasUTF16BOM(b):
		return b[2:], 2
	}
	return b, 0
}

// hasNUL reports whether a block holds a 0 byte, which no 8-bit log text has.
func hasNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// blockIsUTF8 reports that a message block may be copied as it is. A pure-ASCII
// block is UTF-8 by definition, and an empty one is not worth a transformer.
func blockIsUTF8(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	return utf8.Valid(b)
}

// markBlockText puts the "golog-encoding = <codepage>" marker into the TEXT part
// of a message block, just after the separator line - which is where the text
// begins and where the readers look for it (encoding.go, EncodingMarker).
//
// It is idempotent, and it refuses a block with no separator line: such a block
// is damaged, and inserting a line into a header section would make it worse.
func markBlockText(block, codepage string) string {
	if block == "" || codepage == "" {
		return block
	}
	i := strings.Index(block, SeparatorLine)
	if i < 0 {
		return block
	}
	rest := block[i+len(SeparatorLine):]
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return block
	}
	body := rest[nl+1:]
	if strings.HasPrefix(body, EncodingMarker+" = ") || strings.HasPrefix(body, EncodingMarker+":") {
		return block // already marked, and the existing spelling is kept
	}
	return block[:i+len(SeparatorLine)+nl+1] + MarkerLine(codepage) + body
}

// decodeBodyBytes decodes one header/text region, removes a byte order mark from
// the result and counts what could not be mapped. The BOM belongs to the
// transport, not to the text: a U+FEFF in the first header line would hide the
// key from the parser.
func decodeBodyBytes(b []byte, codes *Codecs) (text string, bom, replaced int) {
	body, bom := stripBOMBytes(b)
	text, replaced = DecodeToUTF8(body, codes)
	return strings.ReplaceAll(text, "\ufeff", ""), bom, replaced
}

// decodeWithReport decodes bytes and counts the input bytes that the code page
// could not represent.
//
// The two mechanisms produce the same rune - U+FFFD - and neither can be
// preferred over the other: the vendored charmap decoders accept every byte
// outside their table and turn it into U+FFFD themselves, so they never report an
// error, and an unmapped table slot becomes a NUL in the output rather than a
// missing rune. The number a conversion report therefore needs is
//
//	input bytes that are not valid UTF-8 in  +  U+FFFD in the output
//
// which double-counts only when a U+FFFD was already in the input - and the
// result is then an UPPER bound, which is the honest direction for a report that
// promises "this many bytes were damaged".
func decodeWithReport(b []byte, codes *Codecs) (text string, replaced int) {
	text, replaced = DecodeToUTF8(b, codes)
	if codes == nil || !codes.IsLegacy() {
		return text, replaced
	}
	if ProbeBytes(b).IsBinary() {
		// A NUL in the INPUT is damage in the input, not in the code page.
		return text, replaced + CountBadUTF8(string(b))
	}
	return text, replaced + CountBadUTF8(string(b))
}

// ---------------------------------------------------------------------------
// The per-file decision
// ---------------------------------------------------------------------------
//
// decideFile answers ONE question for one file: "which code page are its
// messages written in?" It looks at the head of the file, which is cheap and
// which is what an operator means when he configures a logbook. It is not the
// last word about a single message: fileDecision.decodeBlock applies the
// per-block rule to every block, so a UTF-8 entry inside a legacy file (the
// ordinary case after one edit through golog) and a legacy entry inside a UTF-8
// file are both read correctly.

type fileDecision struct {
	// legacy says the file is decoded rather than copied.
	legacy bool
	// codepage is what its messages are decoded with (never nil).
	codepage *Codecs
	// reason is one line for a log or a report; it names the option when the
	// option is what is missing, because that is the action an operator can take.
	reason string
	// bom is the byte order mark found at the head of the file: 0, 3 (UTF-8) or
	// 2 (UTF-16). It is a count, not a flag, because it shifts every offset.
	bom int
	// utf16 is set when the file announced UTF-16 with a byte order mark.
	utf16 bool
	// scanned and truncated describe the sample the decision was taken from, for
	// a report that has to say "decided from the first N bytes".
	scanned   int
	truncated bool
	// repaired counts the bytes the decode of this file could not map. The
	// per-block counters live in FileDecoder; this is only the file's own copy.
	repaired int
}

// decideFile classifies a log file's bytes.
func decideFile(data []byte, configured *Codecs) fileDecision {
	sample := legacySample(data)
	st := ProbeBytes(sample)
	d := fileDecision{scanned: len(sample), truncated: len(data) > len(sample)}
	switch {
	case len(sample) == 0:
		// Nothing to see: no code page is needed, and an empty file is a valid
		// empty UTF-8 file.
		d.codepage = UTF8Codecs()
		d.reason = "empty file"
		return d
	case st.IsBinary():
		// UTF-16 with a byte order mark is the one binary-looking case that is
		// real text: the C daemon cannot have written it, an editor round trip
		// can have. It is read as UTF-16 and converted to UTF-8.
		if st.BOM == 2 {
			if codes := utf16BOMCodepage(sample); codes != nil {
				d.legacy, d.codepage, d.bom, d.utf16 = true, codes, 2, true
				d.reason = "UTF-16 with a byte order mark"
				return d
			}
		}
		// Everything else that is not text is read with the last-resort page, so
		// the entry stays visible, and the conversion refuses it (ErrNotText):
		// decoding a binary blob as a code page would turn damage into
		// plausible-looking text.
		d.legacy = true
		d.codepage = lastResortCodepage(configured)
		d.reason = "binary content"
		return d
	case st.ValidUTF8:
		// This is the branch a pure-ASCII file takes as well, and the reason
		// golog can mix UTF-8 and ASCII files in one logbook without asking: an
		// ASCII file IS a UTF-8 file.
		d.codepage = UTF8Codecs()
		d.bom = st.BOM
		d.reason = "valid UTF-8"
		if st.BOM == 3 {
			d.reason = "valid UTF-8 with a byte order mark"
		}
		return d
	case configured != nil && configured.IsLegacy():
		d.legacy = true
		d.codepage = configured
		d.bom = st.BOM
		d.reason = "configured legacy codepage (" + configured.Name() + ")"
		return d
	default:
		name := LegacyASCIIName
		if configured != nil {
			name = configured.Name()
		}
		d.legacy = true
		d.codepage = lastResortCodepage(configured)
		d.bom = st.BOM
		d.reason = fmt.Sprintf("not UTF-8 and no %q configured, read as %s - set %q in the "+
			"global or in the logbook section to read it correctly",
			LegacyCodepageOption, name, LegacyCodepageOption)
		return d
	}
}

// lastResortCodepage is what a non-UTF-8 file is read with when nothing usable
// was configured. A configured UTF-8 must not be the last resort - it would drop
// U+FFFD into every accented letter - so that case falls back to Legacy-ASCII,
// which never loses a byte.
func lastResortCodepage(configured *Codecs) *Codecs {
	if configured != nil && configured.IsLegacy() {
		return configured
	}
	return LegacyASCIICodecs()
}

// DecodeFileToUTF8 decodes a whole file with the code page configured for it,
// applying the same rules the read path uses. It never writes: converting is
// ConvertFile's job.
func DecodeFileToUTF8(path string, configured *Codecs) (string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	d := decideFile(data, configured)
	text, n := d.decodeBlock(data)
	return text, n, nil
}

// DecidedCodepage is the code page the decoder of a path uses, for the status
// page ("this file is read as windows-1250").
func DecidedCodepage(path string) string {
	codes, _ := codepageForFile(path)
	return decideFile(readHeadOfLogFile(path), codes).codepage.Name()
}

// CodepageForFile is the code page one log file is decoded with, after the
// per-file decision (so a file that holds clean UTF-8 answers UTF-8 even when
// its logbook is configured as legacy).
func CodepageForFile(path string) *Codecs {
	codes, _ := codepageForFile(path)
	return decideFile(readHeadOfLogFile(path), codes).codepage
}

// ForgetCodepageForDir drops the code page registered for one data directory, so
// that a configuration re-read takes effect for a logbook that is not reopened.
func ForgetCodepageForDir(dir string) {
	if dir == "" {
		return
	}
	logbookCodepageMu.Lock()
	delete(logbookCodepages, filepath.Clean(dir))
	logbookCodepageMu.Unlock()
}

// ---------------------------------------------------------------------------
// Reading a whole file
// ---------------------------------------------------------------------------

// ReadAction is what a file was read with. It is a string type so that a status
// page and a conversion report can print it without a switch.
type ReadAction string

// The actions of fileDecision.decodeBlock.
const (
	ReadAsUTF8    ReadAction = "utf-8"    // copied, nothing to do
	ReadDecoding  ReadAction = "decoding" // decoded with a legacy code page
	ReadFromUTF16 ReadAction = "utf-16"   // decoded from UTF-16 with a byte order mark
	ReadBinary    ReadAction = "binary"   // not text: never converted, only displayed
)

// Action names the action decodeBlock would take for this block.
func (d fileDecision) Action(block []byte) ReadAction {
	switch {
	case d.utf16:
		return ReadFromUTF16
	case !d.legacy || blockIsUTF8(block):
		return ReadAsUTF8
	case ProbeBytes(block).IsBinary():
		return ReadBinary
	default:
		return ReadDecoding
	}
}

// decodeBlock returns the UTF-8 text of one raw message block and the number of
// bytes that could not be mapped.
//
// The order of the tests is the order of specificity:
//
//  1. the file's own byte order mark, which says UTF-16 and beats any
//     configuration - it is written in front of the text;
//  2. a per-entry "golog-encoding" marker in the block's text section, which
//     beats the logbook's option, because it is a statement about one entry and
//     because the marker is only ever written by the conversion tool, i.e. by
//     something that knew;
//  3. the block's own bytes: valid UTF-8 is copied verbatim, so a UTF-8 entry in
//     a legacy file is never double-decoded (double-decoding would turn "ř" into
//     two letters) and a legacy entry in a UTF-8 file is still decoded;
//  4. otherwise the code page of the decision.
func (d fileDecision) decodeBlock(block []byte) (string, int) {
	if len(block) == 0 {
		return "", 0
	}
	if d.utf16 {
		text, _, replaced := decodeBodyBytes(block, d.codepage)
		return text, replaced
	}
	if name := MarkerFromBlock(block); name != "" {
		if codes, err := LookupCodecs(name); err == nil && codes.IsLegacy() {
			text, _, replaced := decodeBodyBytes(block, codes)
			return text, replaced
		}
	}
	if !d.legacy || blockIsUTF8(block) {
		text, bom, replaced := decodeBodyBytes(block, UTF8Codecs())
		if bom == 0 && replaced == 0 {
			// The common case: no byte order mark and nothing damaged, so the
			// bytes are handed over without extra work.
			return string(block), 0
		}
		return text, replaced
	}
	text, _, replaced := decodeBodyBytes(block, d.codepage)
	return text, replaced
}

// String is the one-line description of a decision.
func (d fileDecision) String() string {
	return fmt.Sprintf("%s: %s", d.codepage.Name(), d.reason)
}

// ReadActionDescription is the human sentence for a ReadAction.
func ReadActionDescription(a ReadAction) string {
	switch a {
	case ReadAsUTF8:
		return "read as UTF-8, nothing to convert"
	case ReadDecoding:
		return "decoded from a legacy code page on the fly"
	case ReadFromUTF16:
		return "decoded from UTF-16 (byte order mark)"
	case ReadBinary:
		return "not a text file, shown as it is"
	}
	return string(a)
}

// ---------------------------------------------------------------------------
// The one-time conversion: the vocabulary
// ---------------------------------------------------------------------------

// ConvertOptions is what "gologd convert" was told. The zero value is the safe
// default: dry run, no markers, refuse anything surprising.
type ConvertOptions struct {
	// DryRun only reports. It is the default, because the first question an
	// operator asks about a production tree is "what WOULD this do?".
	DryRun bool
	// Codepage is the code page to read the files with. nil means "not given on
	// the command line: use the configured one, and detect what is left".
	Codepage *Codecs
	// Auto permits AutoLegacyCodecs for the files no option covers. Detection is
	// a guess; the tool says so in the report and refuses an ambiguous one.
	Auto bool
	// Force overrides the refusals that are judgements rather than dangers: the
	// undecodable bytes (they become U+FFFD) and the PID file of a running
	// daemon. It never overrides the safety: a file that is already UTF-8 stays
	// untouched, because rewriting a correct file is data loss with no upside.
	Force bool
	// Backup keeps what was there before the rewrite. BackupDir is where: ""
	// means next to the original as "<file>.bak", a directory name collects the
	// backups of all files under their own name plus a time stamp.
	Backup bool
	// BackupDir is the backup destination ("." means next to the original).
	BackupDir string
	// AddMarkers writes the "golog-encoding" marker into every entry converted,
	// so that the source code page stays known inside the file.
	AddMarkers bool
	// KeepMTime restores the modification time of each converted file.
	KeepMTime bool
	// Progress receives one line per file, for the command and for ConvertTree.
	Progress func(string)
}

// FileConversion is the part of a conversion report that describes ONE message
// block: which entry it holds, which code page it was decoded with, and which
// bytes no code page can represent.
type FileConversion struct {
	// ID is the entry's number, 0 when it could not be read.
	ID int
	// Offset is the byte offset of the block IN THE FILE - the same coordinate
	// Entry.Offset uses, never a position in decoded text.
	Offset int64
	// Title is the entry's title, decoded, as one line.
	Title string
	// Codepage names the code page the block was decoded with ("" when the block
	// was already UTF-8).
	Codepage string
	// Replaced counts the bytes of this block that could not be mapped.
	Replaced int
	// BadOffsets are the file offsets of the damaged bytes, so that the operator
	// can look at them with hexdump before he decides to use -force.
	BadOffsets []int64
}

// ConvertReport is what ConvertFile and ConvertTree say about one file. Every
// count is per file, which is what an operator checks after a conversion of forty
// logbooks: "240430a.log: 41 messages, 2 undecodable bytes".
type ConvertReport struct {
	Path     string
	Bytes    int64 // size of the input
	OutBytes int64 // size of the result (0 in a dry run)
	// Codepage is the code page the file was converted from ("" when it needed no
	// conversion).
	Codepage string
	// Legacy is true when the file holds legacy bytes.
	Legacy bool
	// Entries counts the message blocks of the file.
	Entries int
	// Converted counts the blocks that were decoded (a mixed file has both).
	Converted int
	// Replaced counts the input bytes that could not be mapped.
	Replaced int
	// BadUTF8 counts the U+FFFD that stand in for them.
	BadUTF8 int
	// Changed is true when the file was written (never in a dry run).
	Changed bool
	// Skipped is true when the file was left alone, with Reason saying why.
	Skipped bool
	// Reason is one line for the report.
	Reason string
	// Err is the reason a file FAILED. It is separate from Skipped: "already
	// UTF-8" is a report, "permission denied" is a failure.
	Err error
	// Backups names the safety copies written for this file.
	Backups []string
	// Blocks is the per-entry detail, capped at maxBlocksReported.
	Blocks []FileConversion
	// Truncated says Blocks was capped.
	Truncated bool
	// Action and CodepageName describe how the file was READ (the dry-run answer
	// and the status-page answer).
	Action       ReadAction
	CodepageName string
}

// formatConversion is the per-entry line of a report (-v prints these). The
// offset is printed as a FILE offset, which is what hexdump wants.
func formatConversion(fc FileConversion) string {
	line := fmt.Sprintf("  entry %-6d offset %-10d", fc.ID, fc.Offset)
	if fc.Codepage != "" {
		line += " " + fc.Codepage
	}
	if fc.Replaced > 0 {
		line += fmt.Sprintf(" %d undecodable byte(s)", fc.Replaced)
	}
	if fc.Title != "" {
		line += "  " + fc.Title
	}
	return line
}

// ---------------------------------------------------------------------------
// The in-memory conversion of one file
// ---------------------------------------------------------------------------

// readFileForConvert reads a file that is about to be converted and records its
// size in the report. The size limit is checked here because only here it is
// known which report the answer belongs to (the streaming path in
// legacy_convert.go takes the other branch).
func readFileForConvert(path string, rep *ConvertReport) ([]byte, error) {
	sz, err := osFileSize(path)
	if err != nil {
		return nil, err
	}
	if rep != nil {
		rep.Bytes = sz
	}
	return osReadFile(path)
}

// ConvertFile converts one log file to UTF-8. The unit is the message block (see
// rule 5 above), which is what makes the operation safe in three of its
// meanings: a decode never cuts a multi-byte sequence, the offsets the daemon
// keeps address exactly the blocks that were rewritten, and an interrupted run
// can be resumed because the second run finds nothing to do.
//
// The order of the steps is the order of the risk: read only, decide, refuse,
// then - and only then - write. Nothing is written before the result is known,
// and the write verifies itself (legacy_write.go).
//
// A file larger than maxConvertFileSize is converted by ConvertFileAuto
// (legacy_convert.go) with the same rules and the same report.
func ConvertFile(path string, opts ConvertOptions) ConvertReport {
	rep := ConvertReport{Path: path}

	// 1. read.
	data, err := readFileForConvert(path, &rep)
	if err != nil {
		rep.Err = err
		return rep
	}

	// 2. classify the same way the read path does, so that the tool's answer and
	// the daemon's answer about the same file cannot disagree.
	codes, _ := codepageForFile(path)
	d := decideFile(data, codes)
	rep.Legacy = d.legacy
	rep.CodepageName = d.codepage.Name()
	rep.Action = d.Action(data)

	// A file that is already UTF-8 needs no conversion. Refusing is what makes
	// the command idempotent, and the refusal is not overridden by -force: a
	// rewrite that changes nothing would still change the file's mtime and leave a
	// backup, which teaches an operator to ignore his backups.
	if !d.legacy {
		rep.Skipped = true
		rep.Reason = "already valid UTF-8"
		rep.Err = fmt.Errorf("%w: %s", ErrAlreadyUTF8, rep.Reason)
		return rep
	}
	if rep.Action == ReadBinary {
		rep.Skipped = true
		rep.Reason = "not a text file (NUL or escape bytes): refusing to convert"
		rep.Err = ErrNotText
		return rep
	}

	// 3. the code page: the explicit one, the detected one when that was asked
	// for, else the one the decision settled on.
	page := opts.Codepage
	if (page == nil || !page.IsLegacy()) && opts.Auto {
		det, ok, why := AutoLegacyCodecs(legacySample(data))
		if !ok {
			rep.Err = fmt.Errorf("%w: %s: %s", ErrUnknownCodepage, path, why)
			rep.Reason = why
			return rep
		}
		page = det
	}
	if page == nil || !page.IsLegacy() {
		page = d.codepage
	}
	if !page.IsLegacy() {
		rep.Skipped = true
		rep.Reason = "nothing to convert"
		rep.Err = fmt.Errorf("%w: %s", ErrAlreadyUTF8, path)
		return rep
	}
	rep.Codepage = page.Name()

	// 4. convert block by block on the RAW bytes, so that the offsets of the
	// report are the file's offsets (see the offset invariant). The banner and any
	// stray text between blocks stay byte-identical: it is prose, not a message.
	blocks := splitLogBlocks(data)
	if len(blocks) == 0 {
		rep.Skipped = true
		rep.Reason = "no message marker: not a logbook file"
		rep.Err = ErrNotText
		return rep
	}
	out := make([]byte, 0, len(data)+len(data)/8)
	var undecodable int
	for _, bl := range blocks {
		rep.Entries += bl.count
		if !bl.isMsg || blockIsUTF8(bl.raw) {
			out = append(out, bl.raw...)
			continue
		}
		text, replaced := decodeWithReport(bl.raw, page)
		if !ValidUTF8(text) {
			// Belt and braces: the decoder output is UTF-8 by construction, and a
			// UTF-16 decoder is the one case that can report otherwise. Repairing
			// here keeps the promise "a converted file is valid UTF-8".
			text, _ = PrepareUTF8(text)
		}
		if opts.AddMarkers {
			text = markBlockText(text, page.Name())
		}
		out = append(out, []byte(text)...)
		rep.Converted++
		rep.Replaced += replaced
		rep.BadUTF8 += CountReplacementRunes(text)
		undecodable += replaced
		rep.noteBlock(bl, page.Name(), replaced)
	}
	rep.OutBytes = int64(len(out))
	rep.Reason = fmt.Sprintf("%d message(s) from %s, %d undecodable byte(s)",
		rep.Converted, page.Name(), rep.Replaced)

	// 5. refuse damaged input before anything was written. The temporary file of
	// the streaming path and these bytes cost nothing; a wrong conversion costs a
	// logbook, which is why -force has to be typed.
	if undecodable > 0 && !opts.Force {
		rep.Skipped = true
		rep.Reason = "undecodable bytes"
		rep.Err = fmt.Errorf("%s: %d byte(s) cannot be represented in %s; use -force to replace them with U+FFFD",
			path, undecodable, page.Name())
		return rep
	}
	if opts.DryRun {
		rep.Skipped = true
		rep.Reason = fmt.Sprintf("would convert %d message(s) from %s", rep.Converted, page.Name())
		return rep
	}
	if !bytesDiffer(data, out) {
		// The bytes are identical, so writing them would change only the file's
		// timestamps. Report it as skipped rather than pretend to convert.
		rep.Skipped = true
		rep.Reason = "the converted bytes are identical to the file's"
		return rep
	}

	// 6. write: backup, temporary file in the same directory, fsync, rename, read
	// back and compare, restore the original if anything failed. All of that lives
	// in legacy_write.go, which is the only writer in this package.
	rep.Changed = true
	if err := writeConvertedFile(path, data, out, opts, &rep); err != nil {
		rep.Changed = false
		rep.Err = err
		return rep
	}
	if opts.Progress != nil {
		opts.Progress(FormatConvertReport(rep))
	}
	return rep
}

// bytesDiffer reports whether two byte strings differ.
func bytesDiffer(a, b []byte) bool {
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return true
		}
	}
	return false
}

// noteBlock records one converted block in the report, within the cap.
func (rep *ConvertReport) noteBlock(bl logBlock, codepage string, replaced int) {
	if len(rep.Blocks) >= maxBlocksReported {
		rep.Truncated = true
		return
	}
	fc := FileConversion{ID: bl.id, Offset: bl.off, Codepage: codepage, Replaced: replaced}
	if fc.Title == "" && bl.isMsg {
		if e, err := parseBlock(bl.raw); err == nil {
			fc.ID = e.ID()
			fc.Title = TrimSpaceASCII(e.Title())
		}
	}
	if replaced > 0 {
		fc.BadOffsets = badUTF8Offsets(bl.raw, bl.off)
	}
	rep.Blocks = append(rep.Blocks, fc)
}

// badUTF8Offsets lists the file offsets of the maximal sub-parts of raw that are
// not valid UTF-8, added to base (the block's own offset in the file). The list
// is capped: it is a pointer for hexdump, not a full report.
func badUTF8Offsets(raw []byte, base int64) []int64 {
	var out []int64
	for i := 0; i < len(raw); {
		if raw[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			if !utf8.FullRune(raw[i:]) {
				break // the block was cut, not damaged
			}
			out = append(out, base+int64(i))
			i++
			continue
		}
		i += size
		if len(out) >= 32 {
			break
		}
	}
	return out
}

// logBlock is one message block, or the text between two blocks (the banner of a
// log file, which is prose and stays as it is).
type logBlock struct {
	raw   []byte
	off   int64
	isMsg bool
	id    int // the entry number, when it could be read cheaply
	count int // entries it holds (1 for a message block)
}

// splitLogBlocks cuts a log file at the raw MsgMarker bytes, which is the split
// the index uses (storage.go's markerIndexes) and the only split that keeps the
// offsets meaningful. It returns nil for a file with no marker at all: such a
// file is not a log file and is not converted.
func splitLogBlocks(data []byte) []logBlock {
	raw := markerIndexes(data)
	starts := make([]int64, 0, len(raw))
	for _, v := range raw {
		starts = append(starts, int64(v))
	}
	if len(starts) == 0 {
		return nil
	}
	out := make([]logBlock, 0, len(starts)+1)
	if starts[0] > 0 {
		out = append(out, logBlock{raw: data[:starts[0]], off: 0})
	}
	for i, start := range starts {
		end := int64(len(data))
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		if start >= end {
			continue
		}
		out = append(out, logBlock{raw: data[start:end], off: start, isMsg: true, count: 1})
	}
	return out
}

// splitBannerBytes is splitBanner's byte form (storage.go has the string form),
// used by the report of the conversion tool: the banner is the file's own text and
// is never decoded, so the tool has to know where it stops.
func splitBannerBytes(data []byte) (banner, rest []byte) {
	raw := markerIndexes(data)
	if len(raw) == 0 {
		return data, nil
	}
	first := int64(raw[0])
	return data[:first], data[first:]
}

// CodecsDescriptionOf is the short description of a code page name for
// "gologd convert -codepage list". An unknown name describes itself.
func CodecsDescriptionOf(name string) string {
	codes, err := LookupCodecs(name)
	if err != nil {
		return "unknown code page"
	}
	return CodepageDescription(codes)
}
