// ELOG rewritten in Go - reading one message block of a log file as UTF-8.
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
// The decoding POLICY of golog lives in exactly two places, and this file is the
// outer one:
//
//   - legacy.go's decideFile classifies a file's bytes once and fileDecision's
//     decodeBlock turns one message block into a UTF-8 string, honouring a
//     per-entry "golog-encoding" marker;
//   - encoding_config.go's FileDecoder applies that to a whole log file, with the
//     counters a report and the start-up log line need;
//   - THIS file applies the same two to callers that hold a block or an offset and
//     have no logbook and no file decoder: the client protocol's "give me entry at
//     offset N", the search that walks raw files, the export commands, the
//     conversion tool's report, and the tests.
//
// Nothing here decides anything about code pages on its own. If a second policy
// grew up here, a legacy logbook would read one way on a web page and another way
// in a search result or in a CSV export, and that is precisely the class of bug the
// encoding feature must not have.
//
// THE OFFSET INVARIANT, restated because this file takes an offset as an argument:
//
//	Entry.Offset is a BYTE position in the RAW file - the offset of the entry's
//	"$@MID@$" marker, the number el_build_index() kept in log->off - and
//	Entry.Text is DECODED UTF-8. One accented Czech letter is one byte in
//	windows-1250 and two in UTF-8, so the two coordinate systems are not
//	interchangeable and nothing may recompute a position after a decode. A caller
//	that reads one entry at an offset therefore reads RAW bytes from that offset
//	and decodes afterwards, which is what ReadEntryAtOffset does.
//
// THE READ-ONLY INVARIANT: no function in this file creates, renames, truncates or
// otherwise touches a file. Reading a legacy logbook never modifies it. The one
// operation that rewrites a legacy store is the explicit
//
//	gologd convert        (or: gologd -convert)
//
// command of cmd/gologd/convert.go, which is not reachable from a request handler.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// maxBlockRead caps how far ReadEntryAtOffset reads forward to find the end of one
// entry. A message of more than 32 MB is a mistake, and reading the rest of a log
// file of a gigabyte to find the next marker is not worth the memory on a
// linux/386 or windows/386 build.
const maxBlockRead = 32 << 20

// blockReadChunk is how much of the file is read per step while looking for the end
// of one entry: enough that a normal message is found in one read.
const blockReadChunk = 1 << 20

// DecodeBlockUTF8 returns the text of one raw message block as a UTF-8 Go string.
//
// configured is the code page of the logbook the block came from (nil: read as
// UTF-8 only). A block that carries its own "golog-encoding = <codepage>" marker
// line - which "gologd convert -markers" writes, and which the C tool elconvert is
// expected to write - is decoded with THAT code page whatever the logbook says; the
// marker line is dropped from the returned text, because it describes bytes that no
// longer exist once the block is UTF-8 in memory, and it is returned separately so
// that a caller can keep or rewrite it.
//
// This is DecodeEntryBlock's cousin for callers that also want the marker and the
// damage count, and it goes through the same fileDecision, so the text cannot
// disagree with what a web page shows.
func DecodeBlockUTF8(block []byte, configured *Codecs) (text, marker string, replaced int) {
	d := decideFile(block, configured)
	text, replaced = d.decodeBlock(block)
	marker = MarkerFromBlock(block)
	if marker != "" {
		text = WithoutEncodingMarker(text)
	}
	return text, marker, replaced
}

// DecodeTextForFile is the text of a whole log file as the web would show it: the
// blocks decoded with the logbook's code page, joined in file order. The search over
// raw files and the export commands use it so that they search and print what a user
// reads, which is the only way a search for "žluťoučký" finds a windows-1250 file.
func DecodeTextForFile(raw []byte, path string, configured *Codecs) string {
	fd := newFileDecoderOf(path, raw, configured)
	var b bytes.Buffer
	b.Grow(len(raw) + len(raw)/8)
	for _, block := range RawBlocks(raw) {
		b.WriteString(fd.decode(block))
	}
	return b.String()
}

// RawBlocks splits the content of a log file into its message blocks, in RAW bytes:
// each result starts at a "$@MID@$" marker and runs to the next one, with the
// trailing blank line and separator line removed. The offsets a caller derives from
// the results are offsets in data, which is the whole point - a caller that then
// decodes a block still knows where that block sits in the file.
//
// banner is the file's banner line, which is skipped (it is ASCII by construction,
// so skipping it works for every code page); pass "" when it is not known, which is
// harmless because no marker sits inside it.
func RawBlocks(data []byte) [][]byte {
	var out [][]byte
	const marker = MsgMarker
	pos := 0
	for pos < len(data) {
		i := bytes.Index(data[pos:], []byte(marker))
		if i < 0 {
			break
		}
		i += pos
		j := bytes.Index(data[i+len(marker):], []byte(marker))
		var end int
		if j < 0 {
			end = len(data)
		} else {
			end = i + len(marker) + j
		}
		out = append(out, trimBlockTailBytes(data[i:end]))
		if j < 0 {
			break
		}
		pos = end
	}
	return out
}

// trimBlockTailBytes is storage.go's trimBlockTail for a block held as bytes rather
// than as a string: it drops the blank line and the separator line that end a
// message block and returns a sub-slice, without a copy.
func trimBlockTailBytes(b []byte) []byte {
	t := bytes.TrimRight(b, " \t\r\n")
	if k := bytes.LastIndex(t, []byte(SeparatorLine)); k >= 0 {
		t = t[:k]
	}
	return bytes.TrimRight(t, " \t\r\n")
}

// ReadEntryAtOffset reads ONE entry of a log file from the byte offset an index
// recorded for it - el_find_entry(offset, ..., SEEK_SET) plus the decode - and stops
// as soon as the marker of the next entry is in sight. It is the cheap path for "show
// me this entry" in a legacy logbook whose daily files are large: nothing before the
// offset is read, and nothing after the entry is decoded.
//
// The caller verifies the offset against its own index when it has one
// ((*Logbook).verifyAt does exactly that); here there is no index to check, so only
// the marker itself is checked, and a mismatch is an error rather than a surprise.
//
// Like every read path in golog this function never writes: the file's content, mode
// and modification time are unchanged.
func ReadEntryAtOffset(path string, offset int64, configured ...*Codecs) (*Entry, error) {
	var cfg *Codecs
	if len(configured) > 0 {
		cfg = configured[0]
	}
	if cfg == nil {
		cfg, _ = codepageForFile(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if offset < 0 || offset >= st.Size() {
		return nil, fmt.Errorf("%s: offset %d is past the end of the file (%d bytes)", path, offset, st.Size())
	}
	data, err := readFirstBlock(f, offset, st.Size())
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, []byte(MsgMarker)) {
		return nil, fmt.Errorf("%s: offset %d is not the start of an entry", path, offset)
	}
	text, _, _ := DecodeBlockUTF8(data, cfg)
	e, err := parseBlock([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("%s: offset %d: %w", path, offset, err)
	}
	e.File = filepath.Base(path)
	e.Subdir = YearDirOf(path)
	e.Offset = offset
	e.Text = trimBlockTail(e.Text)
	return e, nil
}

// readFirstBlock reads from offset until the start of the next entry is in the
// buffer, the cap is reached, or the file ends.
func readFirstBlock(f *os.File, offset, size int64) ([]byte, error) {
	marker := []byte(MsgMarker)
	limit := size - offset
	if limit > maxBlockRead {
		limit = maxBlockRead
	}
	var out []byte
	for int64(len(out)) < limit {
		n := int64(blockReadChunk)
		if limit-int64(len(out)) < n {
			n = limit - int64(len(out))
		}
		buf := make([]byte, n)
		got, rerr := f.ReadAt(buf, offset+int64(len(out)))
		if got > 0 {
			out = append(out, buf[:got]...)
			// One marker at offset 0 is this entry; a second one is its end.
			if bytes.Index(out[len(out)-got+1:], marker) >= 0 ||
				(got == len(buf) && bytes.Count(out, marker) > 1) {
				if k := bytes.Index(out[len(marker):], marker); k >= 0 {
					out = out[:len(marker)+k]
				}
				break
			}
		}
		if rerr != nil {
			return out, nil // io.EOF or a short tail: what we have is the entry
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: nothing to read at offset %d", f.Name(), offset)
	}
	return out, nil
}

// YearDirOf is the year sub-directory of a log file path ("" for a flat one). A
// logbook directory holds both "251025a.log" and "2025/251025a.log", and the
// sub-directory is part of the path an update has to write back, so a caller that
// builds an Entry from a file path must set it.
func YearDirOf(path string) string {
	base := filepath.Base(filepath.Dir(path))
	if len(base) != 4 {
		return ""
	}
	for i := 0; i < 4; i++ {
		if base[i] < '0' || base[i] > '9' {
			return ""
		}
	}
	return base
}

// IsYearDirName reports whether a directory name is a logbook's year directory.
func IsYearDirName(name string) bool { return YearDirOf(filepath.Join("x", name, "y.log")) == name }

// DecodeSummaryForFile is the one line an operator wants about a log file: which
// code page it is read with, how many entries it holds, and how many bytes had to be
// replaced. It reads the file; a daemon, which has an index and a decoder already,
// uses (lb *Logbook).LogbookEncodingReport instead.
func DecodeSummaryForFile(path string, configured *Codecs) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("%s: %v", filepath.Base(path), err)
	}
	fd := newFileDecoderOf(path, data, configured)
	blocks := RawBlocks(data)
	for _, b := range blocks {
		fd.decode(b)
	}
	if len(blocks) == 0 {
		return fmt.Sprintf("%s: empty or not a log file", filepath.Base(path))
	}
	return fmt.Sprintf("%s: %d entries, %s", filepath.Base(path), len(blocks), fd)
}
