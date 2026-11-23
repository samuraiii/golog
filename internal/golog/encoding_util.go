// ELOG rewritten in Go - the encoding plumbing the pages, feeds and mail use.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"io"
	"strings"
)

// ---------------------------------------------------------------------------
// What this file is for
// ---------------------------------------------------------------------------
//
// encoding.go owns the codec layer (names, lookups, probing, the UTF-8 gate),
// legacy.go owns the read decision for a log file, storage_encoding.go owns the
// configuration option and the storage seam. This file is the last piece: the
// small, exported helpers that a page, a feed, a mail or an attachment response
// calls, so that none of them has to know which of those three files answers its
// question:
//
//   - DisplayText / DisplayAttrValue: UTF-8 text of an entry, safe for a page;
//   - the four HTML form constants: what a generated <form> and <head> must say;
//   - TextualContentType / AttachmentContentType: which responses declare
//     charset=utf-8 and which must not;
//   - DecodeTextBytes / RepairUTF8String / SanitizeUTF8 for callers holding bytes
//     or bare strings instead of a whole entry.
//
// THE ONE-WAY RULE, which is the reason the surface below is small: decoding
// happens once, at read time, into UTF-8 strings in memory. From that point on
// every layer - search, display, thread, feed, mail - works on the same UTF-8
// strings, so there is exactly one place where the byte form of a legacy file
// matters and it is not reachable from a request. Offsets are a separate matter
// and are covered in legacy.go: they come from raw file bytes and are never
// recomputed after decoding.

// ---------------------------------------------------------------------------
// Text of an entry, for display
// ---------------------------------------------------------------------------

// DisplayText is the display text of an entry: the stored text with its
// "golog-encoding" marker line removed, and with invalid UTF-8 replaced so that a
// damaged byte can never cut a page short or reach a template unescaped.
//
// The marker removal happens HERE and at no other place, so an entry whose
// encoding was recorded by the conversion tool shows its text and not the record.
// It is a no-op for every entry golog itself wrote (the daemon never writes a
// marker), which is what makes it cheap.
func DisplayText(e *Entry) string {
	if e == nil {
		return ""
	}
	return SanitizeUTF8(WithoutEncodingMarker(e.Text))
}

// DisplayTitle is the Title: header prepared for a page, list row, feed item or
// mail subject.
func DisplayTitle(e *Entry) string {
	if e == nil {
		return ""
	}
	return SanitizeUTF8(e.Title())
}

// DisplayAuthor is the Author: header prepared for display.
func DisplayAuthor(e *Entry) string {
	if e == nil {
		return ""
	}
	return SanitizeUTF8(e.Author())
}

// DisplayAttrValue is the value of one header (attribute) of an entry prepared
// for display. The second result is the header's absence, so a caller can tell
// "no such header" from "empty header" the way it can with (*Entry).Get.
func DisplayAttrValue(e *Entry, key string) (string, bool) {
	if e == nil {
		return "", false
	}
	v, ok := e.Get(key)
	if !ok {
		return "", false
	}
	return SanitizeUTF8(v), true
}

// DisplayAttrStrings is DisplayAttrValue for a header that may repeat.
func DisplayAttrStrings(e *Entry, key string) []string {
	if e == nil {
		return nil
	}
	vals := e.GetAll(key)
	for i, v := range vals {
		vals[i] = SanitizeUTF8(v)
	}
	return vals
}

// EntryHasEncodingMarker reports whether an entry carries the marker, which the
// status page and the conversion tool's listing use to show "this entry still
// records its original code page".
func EntryHasEncodingMarker(e *Entry) (string, bool) {
	if e == nil {
		return "", false
	}
	name := ExtractEncodingMarker(e.Text)
	if name == "" {
		return "", false
	}
	return name, true
}

// ---------------------------------------------------------------------------
// Strings and bytes
// ---------------------------------------------------------------------------

// SanitizeUTF8 is the display-time repair: every ill-formed UTF-8 sequence
// becomes U+FFFD, a NUL byte is dropped. It is idempotent and returns its
// argument unchanged (no copy) when there is nothing to repair, which is every
// string that came out of a decoder or from PrepareUTF8.
func SanitizeUTF8(s string) string {
	if !HasInvalidUTF8(s) && !strings.ContainsRune(s, 0) {
		return s
	}
	out, _ := PrepareUTF8(s)
	return out
}

// RepairUTF8String is SanitizeUTF8 with the count of substitutions, for callers
// that report or log (the write path uses SanitizeForWrite, which logs).
func RepairUTF8String(s string) (string, int) { return PrepareUTF8(s) }

// CountReplacements is the number of bytes that could not be represented: the
// ill-formed UTF-8 sequences of s plus the U+FFFD already in it. A conversion
// report prints this, because "N bytes could not be mapped" is the number an
// operator acts on.
func CountReplacements(s string) int {
	return CountBadUTF8(s) + CountReplacementRunes(s)
}

// IsProbablyBinary reports that a byte string is not text at all: it holds NUL
// bytes or a terminal escape stream. A file like that is never decoded with a
// code page - doing so invents plausible-looking text out of damage - which is
// what makes the conversion tool refuse it.
func IsProbablyBinary(b []byte) bool { return ProbeBytes(b).IsBinary() }

// DecodeTextBytes is the byte-level form of the read decision for a caller that
// already holds a whole file or a whole field: the bytes are classified exactly
// like a message block is (an explicit marker first, then "valid UTF-8 means
// UTF-8", then the configured code page), and the result is always valid UTF-8.
// The count is the number of bytes that could not be mapped.
func DecodeTextBytes(b []byte, configured *Codecs) (string, int) {
	if len(b) == 0 {
		return "", 0
	}
	return decideFile(b, configured).decodeBlock(b)
}

// DecodeBlockBytes decodes exactly one message block of a file the caller has
// already classified, so that a caller walking a file (the conversion tool, a
// test) pays the classification once instead of once per block.
func DecodeBlockBytes(block []byte, dec fileDecision) (string, int) {
	return dec.decodeBlock(block)
}

// DecideTextBytes classifies a byte string the way the read path does, and
// returns both the decision and the decoded text. Exported so that the
// conversion tool's report and a test can show WHY a file was read the way it
// was, not only what came out.
func DecideTextBytes(b []byte, configured *Codecs) (string, int, fileDecision) {
	dec := decideFile(b, configured)
	text, n := dec.decodeBlock(b)
	return text, n, dec
}

// CodepageDescription is the human sentence for a resolved code page, for the
// status page and the conversion report ("UTF-8", "windows-1250 (legacy)").
func CodepageDescription(codes *Codecs) string {
	if codes == nil || !codes.IsLegacy() {
		return UTF8Name
	}
	return codes.Name() + " (legacy, read-only)"
}

// DecodeReaderToUTF8 is the streaming read used by the conversion tool on files
// too big to hold twice in memory. c == nil or the UTF-8 code page copies.
func DecodeReaderToUTF8(w io.Writer, r io.Reader, codes *Codecs) (int64, error) {
	return StreamDecodeToUTF8(w, r, codes)
}

// ---------------------------------------------------------------------------
// The web surface: what a generated page must say
// ---------------------------------------------------------------------------
//
// golog serves UTF-8 and only UTF-8, whatever is on disk. Three things have to be
// true for that promise to survive a browser, and they are constants here so the
// pages cannot drift apart:
//
//   - the HTTP header says charset=utf-8 (ContentTypeUTF8 in encoding.go, and
//     TextualContentType below for the responses that are not HTML);
//   - the <head> says it too, for the consumer that ignores the header - a mail
//   - client previewing an HTML notification, or a browser opening a saved copy of
//     a page (HTMLMetaCharset);
//   - every form states the encoding it submits in, because without
//     accept-charset a browser is free to submit in the encoding of the PAGE,
//     which used to be a national code page and would then put those bytes into a
//     UTF-8-only store (FormCharsetAttr).

// HTMLMetaCharset is the <meta> pair every generated page emits in its <head>.
// UTF8MetaTags is the same thing as one ready-to-print string with both the
// http-equiv and the HTML5 spelling, which is deliberate: an old mail client
// reads the first, an old proxy the second, a browser ignores whichever it does
// not understand.
func HTMLMetaCharset() string { return UTF8MetaTags() }

// FormCharsetAttr is the encoding declaration of a generated <form>. It is a
// full attribute so that the call site reads
//
//	fmt.Fprintf(q.W, "<form %s method=\"post\" action=\"%s\">\n", golog.FormCharsetAttr, action)
//
// rather than carrying a bare value that could be quoted wrongly.
const FormCharsetAttr = `accept-charset="` + UTF8Charset + `"`

// FormTagOpen is a complete opening <form> tag with the encoding declaration:
// the shortest thing a page can print that cannot be wrong.
const FormTagOpen = "<form " + FormCharsetAttr + " method=\"post\">"

// CharsetMetaHTMLEquiv is the http-equiv spelling alone, for the templates that
// already print their own <meta charset>.
const CharsetMetaHTMLEquiv = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=" + UTF8Charset + "\">"

// HTMLDocStart is the doctype plus the <head> opening and the charset declaration
// of a generated page: print it first and the page cannot be mis-declared.
func HTMLDocStart(title string) string {
	return "<!DOCTYPE html>\n<html>\n<head>\n" +
		"<title>" + HTMLEscape(title) + "</title>\n" +
		HTMLMetaCharset()
}

// ---------------------------------------------------------------------------
// Content types
// ---------------------------------------------------------------------------

// TextualContentType is the Content-Type of a response that carries text and must
// therefore declare UTF-8 (HTML, plain text, CSV, XML, JSON). A media type that
// already names a charset is returned as it is, so calling it twice is harmless.
func TextualContentType(mediaType string) string { return ContentTypeUTF8(mediaType) }

// BinaryContentType is the Content-Type of a response that carries bytes - an
// attachment, a thumbnail - and must therefore NOT claim a charset: appending
// "charset=utf-8" to "image/png" is a bug that a strict client acts on, and an
// attachment's bytes are the user's and are never re-encoded by golog.
func BinaryContentType(mediaType, name string) string {
	t := TrimSpaceASCII(mediaType)
	if t == "" || !strings.Contains(t, "/") {
		t = ContentTypeFor(name)
	}
	if i := strings.IndexByte(t, ';'); i >= 0 {
		t = TrimSpaceASCII(t[:i])
	}
	return t
}

// FilenameDisposition is the Content-Disposition value for a downloadable name,
// RFC 6266 style: an ASCII-only "filename=" fallback for the clients that cannot
// do more, plus the UTF-8 form for every client that can. This is how an
// attachment called "Protokol Záznamu.pdf" survives a download from a legacy
// logbook: the name in memory is UTF-8 (decoded at read time), and this is the
// one place its bytes are chosen.
func FilenameDisposition(disposition, name string) string {
	d := TrimSpaceASCII(disposition)
	if d == "" {
		d = "attachment"
	}
	ascii := ASCIIFallbackFilename(name)
	out := d + "; filename=\"" + ascii + "\""
	if name != "" && name != ascii {
		out += "; filename*=UTF-8''" + URLEncode(name)
	}
	return out
}

// ASCIIFallbackFilename is the name a client that understands no UTF-8 extension
// receives: non-ASCII letters become '_', which loses nothing that the
// filename* form does not carry correctly.
func ASCIIFallbackFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "'")
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r == 0 || r == '\n' || r == '\r':
			// dropped: a header must not be splittable
		case r < 0x20 || r == 0x7f:
			b.WriteByte('_')
		case r < 0x80:
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if TrimSpaceASCII(out) == "" {
		return "download"
	}
	return out
}

// PrepareEntryUTF8 makes every header value and the text of e valid UTF-8
// (ill-formed sequences become U+FFFD) and returns how many were repaired.
func PrepareEntryUTF8(e *Entry) int {
	total := 0
	for i := range e.Header {
		v, n := PrepareUTF8(e.Header[i].Value)
		e.Header[i].Value = v
		total += n
	}
	t, n := PrepareUTF8(e.Text)
	e.Text = t
	return total + n
}
