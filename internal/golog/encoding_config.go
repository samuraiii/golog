// ELOG rewritten in Go - which code page a logbook, a file or a block is read with.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

// ---------------------------------------------------------------------------
// What this file is for
// ---------------------------------------------------------------------------
//
// The option itself is declared and documented in legacy.go (legacyCodepageParams:
// "Legacy codepage", with the "Charset", "Codepage" and "Code page" spellings kept
// as deprecated aliases). What is decided here is where the answer comes from when
// a file is read:
//
//   1. the logbook's own Logbook.Codepage, set at open time by
//      (*Logbook).SetLegacyCodepage;
//   2. otherwise the configuration, the logbook's scope first and the global scope
//      second, read through the process's current configuration
//      (state.go's currentServerConfig);
//   3. otherwise nothing, which means "UTF-8 only" and, for a block that is not
//      UTF-8, legacy.go's last-resort reading with a log line naming the option the
//      operator has to set.
//
// A per-entry "golog-encoding = <name>" marker (encoding.go) beats all three, and
// it is honoured per block inside fileDecision.decodeBlock, because it is a
// statement about one entry rather than about a file or a logbook.
//
// THE OFFSET INVARIANT, which this file exists to keep:
//
//   Entry.Offset is the position of the entry's "$@MID@$" marker IN THE FILE, and
//   Entry.Text is DECODED. For a legacy file those are different coordinate
//   systems - one accented Czech letter is one byte in windows-1250 and two in
//   UTF-8 - so a file must be split into blocks on its RAW bytes, the offset
//   recorded from that split, and only the block's TEXT decoded. Nothing anywhere
//   in golog computes a position in decoded text, and nothing recomputes an offset
//   after a decode. Every walker here (parseFileDecoded) and in storage.go
//   (parseFile, updateLocked, Remove) follows that order.
//
// THE READ-ONLY INVARIANT: nothing in this file creates, renames or touches a
// file. A legacy logbook that is only browsed stays byte for byte as elogd left
// it, mtime with it. Turning a store into UTF-8 is the explicit
// "gologd -convert" operation (legacy.go, legacy_write.go, legacy_convert.go,
// cmd/gologd/convert.go), which is not reachable from a request handler.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ---------------------------------------------------------------------------
// Which code page a scope / a logbook uses
// ---------------------------------------------------------------------------

// ConfigCodepage resolves the legacy code page configured for one configuration
// scope. It returns nil for "nothing configured" and for "the value could not be
// interpreted" - the second case is logged once here, because a typo in one
// logbook's code page must not stop the daemon: the logbook is then read as UTF-8
// until the configuration is fixed, which is visible and recoverable. The
// conversion tool takes the other route and fails on it, which is right there
// because an operator asked for a write (see LegacyCodecsForScope, legacy.go).
func ConfigCodepage(scope ConfigScope) *Codecs {
	c := currentServerConfig()
	if c == nil {
		return nil
	}
	codes, present, err := LegacyCodecsForScope(c, scope)
	if err != nil {
		logEncodingOnce("cfgcodepage:"+scope.Group,
			"golog: ignoring the legacy codepage of [%s]: %v", scope.Group, err)
		return nil
	}
	if !present || codes == nil || !codes.IsLegacy() {
		return nil
	}
	return codes
}

// LegacyCodepageForLogbook is the code page a logbook's files are read with: its
// own configuration first, the global section second (nil means "read as UTF-8
// only"). (*Config).Get already walks logbook -> "global <top group>" -> "global",
// so the second lookup only matters for a logbook whose section is not in the file
// at all - which happens for a logbook discovered on the first request.
func LegacyCodepageForLogbook(name string) *Codecs {
	if c := ConfigCodepage(ConfigScopeForLogbook(name)); c != nil {
		return c
	}
	return ConfigCodepage(ConfigScope{})
}

// GlobalLegacyCodepage is the "Legacy codepage" of the global section, for the
// status page and for the conversion command's default.
func GlobalLegacyCodepage() *Codecs { return ConfigCodepage(ConfigScope{}) }

// codepageLocked is the logbook's code page WITHOUT taking lb.mu, for the callers
// that already hold it: loadLockedNoCheck runs under lb.mu.Lock() and
// sync.RWMutex is not reentrant, so calling the exported accessor there would
// deadlock.
func (lb *Logbook) codepageLocked() *Codecs {
	if lb == nil {
		return nil
	}
	if lb.Codepage != nil {
		return lb.Codepage
	}
	return LegacyCodepageForLogbook(lb.Name)
}

// LegacyCodecs is the code page this logbook's legacy files are read with, nil
// when it is read as UTF-8 only. Safe to call from a page or a status line.
func (lb *Logbook) LegacyCodecs() *Codecs {
	if lb == nil {
		return nil
	}
	lb.mu.RLock()
	c, name := lb.Codepage, lb.Name
	lb.mu.RUnlock()
	if c != nil {
		return c
	}
	return LegacyCodepageForLogbook(name)
}

// CodepageDescription is the one-line answer for the status page: "UTF-8", or
// "windows-1250 (legacy, read-only)". It is a method so that a template can print
// it without knowing where the value comes from.
func (lb *Logbook) CodepageDescription() string {
	if lb == nil {
		return UTF8Name
	}
	return CodepageDescription(lb.LegacyCodecs())
}

// ---------------------------------------------------------------------------
// Which code page one FILE is read with
// ---------------------------------------------------------------------------
//
// parseFile is a plain function - it is called from loadLockedNoCheck, from the
// conversion tool and from tests - so it cannot be handed the *Logbook whose
// option it needs. Passing the answer through this registry instead of reaching
// into the server's logbook map has two advantages: there is no lock ordering to
// get wrong (the map is written while a daemon opens logbooks, which is itself
// done from inside a Load that would call straight back into it), and a tool that
// has no server at all still gets the code page of the logbook it points at.
//
// The registry is written by SetLegacyCodepage and by loadLockedNoCheck, so the
// normal path (OpenLogbook -> SetLegacyCodepage -> Load) needs no extra call.

var (
	logbookCodepageMu sync.RWMutex
	// logbookCodepages maps a cleaned data directory to the code page its files
	// are read with. An entry is never removed: a data directory of a process is
	// stable, and the map holds one small entry per logbook.
	logbookCodepages = map[string]*Codecs{}
)

// RegisterLogbookCodepage records the code page of a data directory. It is called
// by (*Logbook).SetLegacyCodepage and by a load; a caller that assigns
// Logbook.Codepage by hand should call it too, or the plain-file reader will not
// see the assignment.
func RegisterLogbookCodepage(dir string, codes *Codecs) {
	if dir == "" {
		return
	}
	logbookCodepageMu.Lock()
	logbookCodepages[filepath.Clean(dir)] = codes
	logbookCodepageMu.Unlock()
}

// RegisteredCodepageForDir is the code page registered for a data directory. A nil
// answer with found == true means "this logbook is registered and read as UTF-8".
func RegisteredCodepageForDir(dir string) (codes *Codecs, found bool) {
	if dir == "" {
		return nil, false
	}
	logbookCodepageMu.RLock()
	codes, found = logbookCodepages[filepath.Clean(dir)]
	logbookCodepageMu.RUnlock()
	return codes, found
}

// ClearRegisteredCodepages forgets every registered data directory. Used by the
// tests, which build logbooks in temporary directories; a daemon never needs it.
func ClearRegisteredCodepages() {
	logbookCodepageMu.Lock()
	logbookCodepages = map[string]*Codecs{}
	logbookCodepageMu.Unlock()
}

// codepageForFile answers "which code page are the bytes of this file to be read
// with?". found says whether anything knew, so a caller that wants to warn about an
// unclaimed file (a conversion report, a status page) can.
func codepageForFile(path string) (codes *Codecs, found bool) {
	if codes, found = RegisteredCodepageForDir(filepath.Dir(path)); found {
		return codes, true
	}
	// A file of a logbook that was never opened with a configuration: ask the
	// configuration by the name the operator would write, which is the directory
	// name (gologd's data directories are named after their logbook).
	return LegacyCodepageForLogbook(filepath.Base(filepath.Dir(path))), false
}

// codecForFileLocked is the configured code page of a log file, for the callers in
// storage.go. The name says "locked" because it must only be called from a path
// that holds no logbook lock it could deadlock with; it takes only this file's own
// lock.
func codecForFileLocked(path string) *Codecs {
	codes, _ := codepageForFile(path)
	return codes
}

// ---------------------------------------------------------------------------
// One file's decoder
// ---------------------------------------------------------------------------
//
// A file is classified once (decideFile on its bytes) and every block of it is then
// decoded with that decision (fileDecision.decodeBlock, which also honours a
// per-entry marker). FileDecoder carries the classification plus the counters a
// report and the log line need; it lives for the duration of one load and needs no
// locking, because it never leaves the goroutine that parses a file.

// FileDecoder decodes the blocks of one log file and counts what it had to repair.
type FileDecoder struct {
	// Path is the log file this decoder reads ("" when it was built from bytes a
	// caller holds).
	Path string
	// decision is the classification of the file's bytes (see decideFile,
	// legacy.go). It is kept unexported on purpose: the type of fileDecision is an
	// implementation detail, and callers go through the methods below.
	decision fileDecision
	// Replaced counts the bytes that could not be mapped to the code page.
	Replaced int
	// Decoded counts the blocks that were decoded from a legacy code page.
	Decoded int
	// UTF8Blocks counts the blocks copied as UTF-8, which is what makes a mixed
	// file (an edited entry in a legacy file) visible in a report.
	UTF8Blocks int
}

// NewFileDecoder classifies a log file's bytes with the code page configured for
// its logbook (nil: UTF-8 only). Only the head of the file is read: the
// classification samples the same amount (legacy.go's legacyProbeBytes), so this
// never costs more than the decision needs.
func NewFileDecoder(path string, configured *Codecs) *FileDecoder {
	return &FileDecoder{Path: path, decision: decideFile(readHeadOfLogFile(path), configured)}
}

// newFileDecoderOf reuses bytes a caller already read, which is the common case:
// the parser has the whole file in hand.
func newFileDecoderOf(path string, data []byte, configured *Codecs) *FileDecoder {
	return &FileDecoder{Path: path, decision: decideFile(data, configured)}
}

// decoderForFile builds the block decoder of one log file whose bytes the caller
// has already read, resolving the code page from the registry.
func decoderForFile(path string, data []byte) *FileDecoder {
	return newFileDecoderOf(path, data, codecForFileLocked(path))
}

// readHeadOfLogFile reads the beginning of a file for its classification. A file
// that cannot be read classifies as empty, which decideFile answers as "UTF-8":
// the caller then fails on the read it performs itself, with its own error.
func readHeadOfLogFile(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, legacyProbeBytes)
	n, _ := f.Read(buf)
	return buf[:n]
}

// decode decodes one block and updates the counters.
func (fd *FileDecoder) decode(block []byte) string {
	text, n := fd.decision.decodeBlock(block)
	fd.Replaced += n
	if n == 0 {
		fd.UTF8Blocks++
	} else {
		fd.Decoded++
	}
	return text
}

// Decision is the file's classification, for the conversion tool and the tests
// (fileDecision stays unexported; this returns a copy).
func (fd *FileDecoder) Decision() fileDecision { return fd.decision }

// Reason is the one-line explanation of the file's classification, for the log and
// for a report.
func (fd *FileDecoder) Reason() string { return fd.decision.reason }

// Legacy is true when the file is decoded with a code page rather than copied.
func (fd *FileDecoder) Legacy() bool { return fd.decision.legacy }

// CodepageName is the code page the decoder uses ("" for a file read as UTF-8).
func (fd *FileDecoder) CodepageName() string {
	if fd == nil || fd.decision.codepage == nil {
		return ""
	}
	return fd.decision.codepage.Name()
}

// String is the one-line description of a decoder, for a conversion report or a
// log line: "windows-1250: not UTF-8, decoded with ... (3 block(s) decoded, 12
// byte(s) replaced)". It reuses the wording decideFile produced, so what the daemon
// logged and what the tool printed can be compared by eye.
func (fd *FileDecoder) String() string {
	if fd == nil {
		return UTF8Name + " (no decoder)"
	}
	return fmt.Sprintf("%s: %s (%d block(s) decoded, %d block(s) already UTF-8, %d byte(s) replaced)",
		orText(fd.CodepageName(), UTF8Name), fd.Reason(), fd.Decoded, fd.UTF8Blocks, fd.Replaced)
}

// lbDecoder is the block decoder of the log file at path, for the callers in
// storage.go that have a path and nothing else.
func lbDecoder(path string) *FileDecoder {
	return decoderForFile(path, readHeadOfLogFile(path))
}

// ---------------------------------------------------------------------------
// Reading a file
// ---------------------------------------------------------------------------
//
// parseFile in storage.go is the format's parser. What changed there is its body's
// inner loop, which now asks this file for the decoded text instead of calling
// parseBlock on raw bytes; the offsets still come from markerIndexes/nextMarker on
// the undecoded data. That single line is the whole integration - see
// MERGE-NOTES.md.

// parseFileDecoded reads one daily message file and returns its entries with their
// offsets, decoding every block's text with the logbook's code page. It is the form
// parseFile calls; keeping it here means storage.go needs one call, not a decoder.
// The returned FileDecoder says how the file was read (nil-safe to print).
func parseFileDecoded(full, subdir, name string, configured *Codecs) ([]*Entry, *FileDecoder, error) {
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, nil, err
	}
	fd := newFileDecoderOf(full, data, configured)
	var out []*Entry
	for _, i := range markerIndexes(data) {
		end := len(data)
		if next := nextMarker(data, i+1); next >= 0 {
			end = next
		}
		// The offset comes from the undecoded bytes; only the text below is
		// decoded. That ordering is the invariant at the top of this file.
		e, err := parseBlock([]byte(fd.decode(data[i:end])))
		if err != nil {
			break
		}
		e.File = name
		e.Subdir = subdir
		e.Offset = int64(i)
		e.Text = trimBlockTail(e.Text)
		out = append(out, e)
	}
	return out, fd, nil
}

// ReadLogFileEntries reads a log file the way a logbook load does, without a
// logbook: it is what the conversion command's report, a "-list" listing and the
// tests use. The returned decoder says how the file was read.
func ReadLogFileEntries(path string, configured *Codecs) ([]*Entry, *FileDecoder, error) {
	return parseFileDecoded(path, "", filepath.Base(path), configured)
}

// ReadLogFileEntry decodes one block of file bytes (the client protocol's retrieval
// at an offset, where the caller holds the raw window and its position). The int
// result is the number of bytes that could not be mapped.
func ReadLogFileEntry(block []byte, configured *Codecs) (*Entry, int, error) {
	fd := &FileDecoder{decision: decideFile(block, configured)}
	e, err := parseBlock([]byte(fd.decode(block)))
	if err != nil {
		return nil, fd.Replaced, err
	}
	return e, fd.Replaced, nil
}

// DecodeEntryBlock is the text of one raw message block as a UTF-8-only golog
// serves it, marker line removed and damage replaced: the bytes of a legacy file
// and the bytes golog itself wrote go through the same two steps here, so the
// display of a legacy logbook and of a converted one cannot differ.
func DecodeEntryBlock(block []byte, configured *Codecs) string {
	fd := &FileDecoder{decision: decideFile(block, configured)}
	return WithoutEncodingMarker(SanitizeUTF8(fd.decode(block)))
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

// CodepageOnDiskNote is the tail of the status line: the promise that reading does
// not change the store.
const CodepageOnDiskNote = "unchanged"

// LogbookEncodingReport is the sentence the status page prints about a logbook's
// encoding: what it is read with, and what the option is called.
func (lb *Logbook) LogbookEncodingReport() string {
	if lb == nil {
		return UTF8Name + " (no logbook)"
	}
	c := lb.LegacyCodecs()
	if c == nil {
		return UTF8Name + " (no legacy codepage configured)"
	}
	return fmt.Sprintf("%s; legacy files are decoded with %s for display, %s on disk; convert with \"gologd -convert -codepage %s\"",
		UTF8Name, c.Name(), CodepageOnDiskNote, c.Name())
}

// CodepageSummary is the short "logbook: codepage" listing of the conversion
// command and of the status page, one line per logbook.
func CodepageSummary(name string, c *Codecs) string {
	if c == nil || !c.IsLegacy() {
		return fmt.Sprintf("%-24s %s", name, UTF8Name)
	}
	return fmt.Sprintf("%-24s %s (legacy, read only)", name, c.Name())
}
