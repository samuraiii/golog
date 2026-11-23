// ELOG rewritten in Go - small glue the transcribed call sites need: the
// command-line splitter, the header helpers and the two page-URL spellings.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"bufio"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
)

// hasFile reports whether a form file part actually carries a file: browsers
// send an empty part for the "Attach file" input even when nothing was chosen.
func hasFile(h *multipart.FileHeader) bool {
	return h != nil && h.Filename != ""
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

// sendFile streams a file from the resource directory (stylesheets, icons). The
// whole file is buffered: these are small static files, and buffering keeps the
// code free of the Range/Last-Modified machinery a real request needs.
func sendFile(w http.ResponseWriter, path, ctype string) {
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if ctype == "" {
		ctype = ContentTypeFor(path)
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

// ---------------------------------------------------------------------------
// Commands configured in the configuration file
// ---------------------------------------------------------------------------

// splitCommandLine turns a command line from the configuration file into an
// argv slice. It is the implementation behind SplitCommand (shell.go), which is
// the spelling the rest of the tree calls; it lives here so that the quoting
// rules have exactly one home.
//
// elogd handed the whole string to system(), which let anybody who could write a
// configuration value run a shell with metacharacters; this port never starts a
// shell (one of the five local patches to the C original), so the quoting rules
// are reproduced here for double- and single-quoted arguments and everything
// else - ';', '|', "$( )", redirections - stays plain argument text. Quoting is
// still needed for real configurations ("sh -c 'a b'", a sendmail line with an
// option containing a space).
func splitCommandLine(line string) []string {
	var out []string
	var cur strings.Builder
	started := false
	for i := 0; i < len(line); {
		switch c := line[i]; c {
		case ' ', '\t', '\n', '\r':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
			i++
		case '\'':
			started = true
			i++
			for i < len(line) && line[i] != '\'' {
				cur.WriteByte(line[i])
				i++
			}
			if i < len(line) {
				i++
			}
		case '"':
			started = true
			i++
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) {
					i++
				}
				cur.WriteByte(line[i])
				i++
			}
			if i < len(line) {
				i++
			}
		case '\\':
			started = true
			if i+1 < len(line) {
				cur.WriteByte(line[i+1])
				i += 2
			} else {
				i++
			}
		default:
			started = true
			cur.WriteByte(c)
			i++
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

// ParseHeaderBlock parses one block of RFC 822 headers (the header part of an
// entry written back from a mail, or a whole notification) into a map keyed by
// the canonical MIME header spelling.
func ParseHeaderBlock(raw string) (map[string][]string, error) {
	r := textproto.NewReader(bufio.NewReader(strings.NewReader(raw)))
	h, err := r.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	return h, nil
}

// wordDecoder decodes the RFC 2047 encoded words of an incoming header. It is a
// plain stdlib decoder: the MaxDecodedHeaderWordSize knob only exists from
// go1.22 on and this tree targets go1.21, so the stdlib default applies.
var wordDecoder = &mime.WordDecoder{}

// DecodeHeaderWord decodes the encoded words of one header value ("=?UTF-8?Q?..?=
// forms written by other mail readers, and by elogd itself when an entry was
// posted by e-mail). A word that cannot be decoded is left as it is rather than
// making the whole submission fail, which is what the C parser does too: it
// copies the raw text when its own decoder gives up.
func DecodeHeaderWord(h string) string {
	if h == "" || !strings.Contains(h, "=?") {
		return h
	}
	out, err := wordDecoder.DecodeHeader(h)
	if err != nil {
		return h
	}
	return out
}

// encodeWord is the lowercase spelling of EncodeWord used by the transcribed
// call sites.
func encodeWord(s string) string { return EncodeWord(s) }

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

// SplitAddressList splits a To:/Cc:/Fcc: value into its items, honouring the
// angle brackets so that "Doe, John <j@d.e>, ann@d.e" yields two items. elogd
// used its own regex-based parser for this (the vendored regex.c, which this
// port replaces with the standard library and with hand-written code).
func SplitAddressList(s string) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case '<', '(':
			if !inQuote {
				depth++
			}
			cur.WriteByte(c)
		case '>', ')':
			if !inQuote && depth > 0 {
				depth--
			}
			cur.WriteByte(c)
		case ',', ';':
			if !inQuote && depth == 0 {
				out = appendSplitItem(out, cur.String())
				cur.Reset()
			} else {
				cur.WriteByte(c)
			}
		default:
			cur.WriteByte(c)
		}
	}
	out = appendSplitItem(out, cur.String())
	return out
}

func appendSplitItem(out []string, item string) []string {
	if item = TrimSpaceASCII(item); item != "" {
		return append(out, item)
	}
	return out
}

// parseAddrList splits a notification-list value into bare addresses, in order.
func parseAddrList(s string) []string {
	var out []string
	for _, item := range SplitAddressList(s) {
		if a := emailAddress(item); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// parseOneAddress splits one address item into its display name and its bare
// address. An item without angle brackets yields the same string for both, which
// is what the password-file merge code expects (it overwrites the name from the
// user's "Real name" afterwards).
func parseOneAddress(item string) (name, addr string) {
	item = TrimSpaceASCII(item)
	if item == "" {
		return "", ""
	}
	lt := strings.Index(item, "<")
	gt := strings.Index(item, ">")
	if lt >= 0 && gt > lt {
		addr = TrimSpaceASCII(item[lt+1 : gt])
		name = TrimSpaceASCII(item[:lt])
	} else {
		addr = TrimSpaceASCII(strings.Trim(item, "<>"))
		name = addr
	}
	if name == "" {
		name = addr
	}
	return name, addr
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

// EntryURL is the absolute URL of an entry (what the notification mail and the
// hooks print). baseURL may be "", in which case a page-relative URL is
// returned.
func (s *Server) EntryURL(baseURL, logbook string, id int) string {
	rel := s.entryURL(logbook, id)
	if baseURL == "" {
		return rel
	}
	return strings.TrimSuffix(baseURL, "/") + rel
}

// EntryLink is the page-relative URL of an entry, exported for the tests.
func (s *Server) EntryLink(logbook string, id int) string { return s.entryURL(logbook, id) }
