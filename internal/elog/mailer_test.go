// ELOG rewritten in Go - tests for the e-mail construction rules that the
// upstream/local patches to the C daemon established.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func countHeaderLine(msg, header string) int {
	n := 0
	for _, l := range strings.Split(msg, "\r\n") {
		if len(l) >= len(header) && EqualFold(l[:len(header)], header) {
			n++
		}
	}
	return n
}

func TestRenderPlainASCII(t *testing.T) {
	m := &mailMessage{}
	m.Set("To", "someone@example.org")
	m.Set("From", "elog@example.org")
	m.Set("Subject", "run 1234 finished")
	m.Body = "all fine\n"
	s := m.render()
	if n := countHeaderLine(s, "MIME-Version:"); n != 1 {
		t.Errorf("MIME-Version appears %d times, want exactly 1\n%s", n, s)
	}
	if n := countHeaderLine(s, "Content-Type:"); n != 1 {
		t.Errorf("Content-Type appears %d times, want exactly 1\n%s", n, s)
	}
	if !strings.Contains(s, "Content-Transfer-Encoding: 7bit\r\n") {
		t.Errorf("a pure ASCII body must be announced 7bit:\n%s", s)
	}
	if strings.Contains(s, "multipart") {
		t.Errorf("a message without attachments must not be multipart:\n%s", s)
	}
	if !strings.Contains(s, "\r\n\r\nall fine\n") {
		t.Errorf("body must follow the header block:\n%q", s)
	}
}

func TestRenderUTF8Is8bit(t *testing.T) {
	m := &mailMessage{}
	m.Set("To", "someone@example.org")
	m.Set("Subject", "kWh")
	m.Body = "Teplota kolíku 20 °C – stabilní\n"
	s := m.render()
	if !strings.Contains(s, "Content-Transfer-Encoding: 8bit\r\n") {
		t.Errorf("a UTF-8 body must be announced 8bit:\n%s", s)
	}
	if strings.Contains(s, "Content-Transfer-Encoding: 7bit") {
		t.Errorf("a UTF-8 body must never be announced 7bit:\n%s", s)
	}
	if !strings.Contains(s, `charset=utf-8`) {
		t.Errorf("charset must be declared:\n%s", s)
	}
	if !strings.Contains(s, "20 °C") {
		t.Errorf("the body must be passed through unmodified:\n%s", s)
	}
}

func TestRenderMultipartClosesBoundary(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "note.txt")
	f2 := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(f1, []byte("hello\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte{0, 1, 2, 3}, 0644); err != nil {
		t.Fatal(err)
	}
	m := &mailMessage{}
	m.Set("To", "someone@example.org")
	m.Set("Subject", "with attachments")
	m.Set("Content-Type", "text/plain; charset=utf-8") // must be replaced, not duplicated
	m.Body = "see attached\n"
	m.Files = []string{f1, f2}
	s := m.render()
	// multipart header + text part + two attachment parts
	if n := countHeaderLine(s, "Content-Type:"); n != 4 {
		t.Errorf("want 4 Content-Type headers (multipart + 3 parts), got %d\n%s", n, s)
	}
	if n := countHeaderLine(s, "MIME-Version:"); n != 1 {
		t.Errorf("MIME-Version must appear exactly once, got %d", n)
	}
	if !strings.Contains(s, "multipart/") {
		t.Errorf("message with attachments must be multipart:\n%s", s)
	}
	if !strings.HasSuffix(s, "--\r\n") {
		t.Errorf("the multipart must end with the closing '--boundary--' line, got %q",
			s[len(s)-30:])
	}
	if !strings.Contains(s, "Content-Transfer-Encoding: base64") {
		t.Errorf("attachments must be base64 encoded:\n%s", s)
	}
	if strings.Contains(s, "note.txt") == false {
		t.Errorf("attachment file name must appear in the part header:\n%s", s)
	}
}

func TestRenderDropsMissingAttachments(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m := &mailMessage{}
	m.Set("To", "someone@example.org")
	m.Body = "body\n"
	m.Files = []string{filepath.Join(dir, "gone.txt"), good}
	s := m.render()
	if n := countHeaderLine(s, "Content-Type:"); n != 3 {
		t.Errorf("the vanished attachment must be skipped, got %d Content-Type headers\n%s", n, s)
	}
	if !strings.HasSuffix(s, "--\r\n") {
		t.Errorf("closing boundary missing")
	}
}

func TestEncodeWordKeepsUTF8Intact(t *testing.T) {
	for _, s := range []string{
		"Teplota kolíku 20 °C – stabilní",
		"日本語のタイトル",
		strings.Repeat("é", 200),
		"emoji 🚀 in subject",
		"Muj kůň", // the quoted-printable branch
	} {
		enc := EncodeWord(s)
		for _, w := range strings.Fields(enc) {
			if len(w) > 75 {
				t.Errorf("encoded word longer than 75 characters for %q: %q", s, w)
			}
			if !utf8.ValidString(w) {
				t.Errorf("encoded word %q is not valid UTF-8 text", w)
			}
			if strings.HasPrefix(w, "=?") && !strings.HasSuffix(w, "?=") {
				t.Errorf("truncated encoded word %q", w)
			}
		}
		// The whole point of the patch: decoding the encoded words must give the
		// original string back, with no replacement characters.
		if got := DecodeMIMEHeader(enc); got != s {
			t.Errorf("round trip failed: %q -> %q -> %q", s, enc, got)
		}
	}
}

func TestEncodeWordLeavesASCIIAlone(t *testing.T) {
	for _, s := range []string{"run 1234 finished", "Plain Subject"} {
		if got := EncodeWord(s); got != s {
			t.Errorf("ASCII must not be encoded: %q -> %q", s, got)
		}
	}
}

func TestHeaderPhraseKeepsAddress(t *testing.T) {
	got := EncodeHeaderPhrase("Jan Novák <novak@example.org>")
	if !strings.HasSuffix(got, "<novak@example.org>") {
		t.Errorf("address must survive encoding, got %q", got)
	}
	name := strings.TrimSuffix(got, " <novak@example.org>")
	if DecodeMIMEHeader(name) != "Jan Novák" {
		t.Errorf("display name must round trip, got %q", name)
	}
}

func TestShortenUTF8NeverSplitsARune(t *testing.T) {
	s := "Těhotná byvše – 日本語"
	for n := 0; n <= len(s); n++ {
		got := ShortenUTF8(s, n)
		if len(got) > n {
			t.Errorf("ShortenUTF8(_, %d) returned %d bytes", n, len(got))
		}
		if !utf8.ValidString(got) {
			t.Errorf("ShortenUTF8(_, %d) split a rune: %q", n, got)
		}
	}
}
