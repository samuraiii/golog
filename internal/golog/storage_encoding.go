// ELOG rewritten in Go - the UTF-8 gate every write goes through.
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
// encoding.go owns the codec layer (names, lookups, probing, the UTF-8 primitives),
// legacy.go owns the read decision for a file's bytes and the configuration option,
// encoding_config.go owns "which code page does this logbook/file use" plus the
// block decoder and the read helpers. This file is the WRITE half of the join with
// the storage engine: it turns "store an Entry" into "write bytes that are valid
// UTF-8", and it is the only place a write of user text is repaired.
//
// THE WRITE INVARIANT: (*Entry).Marshal is the only way an Entry becomes the bytes
// of a log file (Append writes its result; updateLocked replaces one block with it;
// the conversion tool rebuilds blocks from it), and Marshal calls PrepareStoredEntry
// before it renders a byte. So no call site - submit, edit, reply, revert, hook,
// import - can put a non-UTF-8 byte into a logbook, and none has to remember to.
//
// THE READ-ONLY INVARIANT: nothing here creates a file except through writeAtomic,
// and nothing here is a conversion. The one-time conversion of a legacy store is
// legacy_write.go / legacy_convert.go / cmd/gologd/convert.go, which is not
// reachable from a request handler.

import (
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// Writing an entry
// ---------------------------------------------------------------------------

// PrepareStoredEntry repairs one entry so that the bytes it will produce are valid
// UTF-8. (*Entry).Marshal calls it, and Marshal is the only way an Entry becomes
// the bytes of a log file, so submit, edit, reply, revert, the hooks and the import
// path are all covered by that single call.
//
// The policy is REPAIR, NOT REJECT, and docs/encoding.md says why: dropping a
// user's text because his browser posted it in the wrong code page is worse than
// showing him one replacement character, and an error page in the middle of a 3 kB
// message would lose the whole submission. What is not accepted is silent damage:
// the count goes to the daemon log, and a caller that wants to be strict (an API
// POST) can look at the returned number and refuse on it.
//
// The "golog-encoding" marker line is removed as well. It is metadata, not user
// text: an entry read from a legacy file and stored again must not carry the record
// of an encoding its bytes no longer have.
//
// The result is the number of header values that had to be changed plus the number
// of byte sequences replaced in the text; 0 means the entry was already clean.
func PrepareStoredEntry(e *Entry) int {
	if e == nil {
		return 0
	}
	replaced := 0
	for i := range e.Header {
		v := StripHeaderInjection(e.Header[i].Value)
		if v != e.Header[i].Value {
			replaced++
		}
		e.Header[i].Value = SanitizeForWrite(e.Header[i].Key, v)
	}
	e.Text = WithoutEncodingMarker(e.Text)
	text, n := PrepareUTF8(e.Text)
	if n > 0 {
		replaced += n
		logEncodingOnce("entrytext",
			"golog: repaired %d invalid or unrepresentable UTF-8 sequence(s) in the text of entry %d before writing",
			n, e.ID())
	}
	e.Text = text
	return replaced
}

// PrepareEntryForWrite is PrepareStoredEntry under the name the call sites in the
// submit path read best. One implementation, one policy.
func PrepareEntryForWrite(e *Entry) int { return PrepareStoredEntry(e) }

// MarshalEntryUTF8 is the bytes an Entry would be written as. Exported for the
// conversion tool (it compares a re-rendered block with the one in the file) and
// for tests; it never writes anything.
func MarshalEntryUTF8(e *Entry) []byte {
	PrepareStoredEntry(e)
	return []byte(e.Marshal())
}

// MarshalBlockUTF8 decodes a raw message block from a log file and renders it
// again as UTF-8. This is the whole conversion of one entry: decode with the code
// page, repair, re-render. The offsets of the file are the caller's business - see
// the offset invariant in encoding_config.go.
func MarshalBlockUTF8(block []byte, configured *Codecs) (string, int, error) {
	e, replaced, err := ReadLogFileEntry(block, configured)
	if err != nil {
		return "", replaced, err
	}
	return string(MarshalEntryUTF8(e)), replaced, nil
}

// ---------------------------------------------------------------------------
// Writing another text file
// ---------------------------------------------------------------------------
//
// The data directory holds more than message files: the password file (whose
// display names and e-mail addresses carry the users' real names), the user-file
// includes, the header/footer text files the pages print, and the configuration the
// admin pages write back. Any of them can hold non-ASCII, so they go through the
// same gate. The rule is the one of the log files: what golog writes is UTF-8.

// WriteTextFileUTF8 writes data to path after repairing anything that is not
// UTF-8, and returns the number of substitutions. It is storage.go's writeAtomic
// plus the gate, so it inherits the durability of that function (temp file, fsync,
// rename) and a caller cannot forget one of the two steps.
func WriteTextFileUTF8(path string, data []byte) (int, error) {
	out, n := PrepareUTF8(string(data))
	if n > 0 {
		logEncodingOnce("writefile:"+filepath.Base(path),
			"golog: %s: repaired %d invalid byte sequence(s) while writing the file", filepath.Base(path), n)
	}
	if err := writeAtomic(path, []byte(out)); err != nil {
		return n, err
	}
	return n, nil
}

// WriteTextUTF8 writes a string the same way.
func WriteTextUTF8(path, text string) (int, error) { return WriteTextFileUTF8(path, []byte(text)) }

// ReadTextFileUTF8 reads a text file (a header/footer include, a user file) and
// returns UTF-8: a file a human edited on a Windows box in 1998 can still hold
// national code page bytes, and the page that prints it is served as UTF-8.
func ReadTextFileUTF8(path string, configured *Codecs) (string, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	text, n := DecodeTextBytes(data, configured)
	if HasInvalidUTF8(text) {
		var m int
		text, m = PrepareUTF8(text)
		n += m
	}
	return text, n, nil
}

// ReadTextFileOrEmpty is ReadTextFileUTF8 with elogd's "a missing include is not an
// error" behaviour, for the header/footer files the pages print.
func ReadTextFileOrEmpty(path string, configured *Codecs) string {
	text, _, err := ReadTextFileUTF8(path, configured)
	if err != nil {
		return ""
	}
	return text
}

// ---------------------------------------------------------------------------
// Attachment names
// ---------------------------------------------------------------------------
//
// An attachment NAME is the one place where a file name carries user text. The C
// server stored the bytes the browser sent, so an old logbook has names in the
// poster's code page, and a file system has no idea what a valid encoding is - those
// bytes survive every copy. text.go's MakeFilenamePortable already keeps every
// UTF-8 byte of a name (it only replaces the characters Windows forbids), so the two
// helpers below only have to get the name INTO UTF-8 before it is passed there. The
// attachment CONTENT is never touched: those bytes are the user's, they are copied
// with io.Copy and served with a content type that names no charset
// (encoding_util.go's BinaryContentType).

// AttachNameFromLegacyBytes turns the raw name bytes of an old "Attachment:" header
// (or a name on a file system that still holds legacy bytes) into UTF-8 text.
func AttachNameFromLegacyBytes(raw []byte, configured *Codecs) string {
	text, _ := DecodeTextBytes(raw, configured)
	return SanitizeUTF8(text)
}

// AttachNameForWrite is the name to hand to MakeFilenamePortable for a name that
// arrived in a request: UTF-8, no NUL, and no CR/LF that could split the header line
// it is written into.
func AttachNameForWrite(name string) string {
	return SanitizeUTF8(StripHeaderInjection(name))
}
