// Decoding of RFC 2047 encoded words, the inverse of EncodeWord.
//
// The C daemon only encodes headers on the way out, but the local patch series
// that fixed the UTF-8 handling was verified by round-tripping subjects through
// the encoder, and inbound subjects (the Subject of a notification e-mail,
// which elogd echoes back) can arrive encoded, so the decoder belongs next to
// the encoder.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"encoding/base64"
	"strings"
)

// DecodeMIMEHeader returns the value of a header with every RFC 2047 encoded
// word ("=?UTF-8?B?...?=" or "=?UTF-8?Q?...?=") replaced by the characters it
// stands for. Text that is not an encoded word is copied through unchanged, so
// the function is safe on a header that was never encoded, and
// DecodeMIMEHeader(EncodeWord(s)) == s for every s that EncodeWord encodes.
//
// As the RFC requires, one white space between two adjacent encoded words is
// dropped: EncodeWord splits a long phrase at a white space into several
// encoded words and that joining space is not part of the text.
//
// Only UTF-8 payloads are decoded; a word announced with another charset is
// inserted verbatim, which is the best guess available without dragging in a
// charset library.
func DecodeMIMEHeader(s string) string {
	if !strings.Contains(s, "=?") {
		return s
	}
	var out strings.Builder
	prevWord := false
	for {
		i := strings.Index(s, "=?")
		if i < 0 {
			out.WriteString(s)
			return out.String()
		}
		between := s[:i]
		if !(prevWord && between == " ") {
			out.WriteString(between)
		}
		s = s[i+2:]

		// charset
		j := strings.IndexByte(s, '?')
		if j < 0 {
			out.WriteString("=?" + s)
			return out.String()
		}
		charset := strings.ToLower(TrimSpaceASCII(s[:j]))
		s = s[j+1:]

		// encoding
		k := strings.IndexByte(s, '?')
		if k < 0 {
			out.WriteString("=?" + charset + "?" + s)
			return out.String()
		}
		enc := strings.ToUpper(TrimSpaceASCII(s[:k]))
		s = s[k+1:]

		// payload, up to the closing "?="
		e := strings.Index(s, "?=")
		if e < 0 {
			out.WriteString("=?" + charset + "?" + enc + "?" + s)
			return out.String()
		}
		data := s[:e]
		s = s[e+2:]

		switch enc {
		case "B":
			if b, err := base64.StdEncoding.DecodeString(data); err == nil {
				out.Write(b)
			} else if b, err := base64.URLEncoding.DecodeString(data); err == nil {
				out.Write(b)
			} else {
				out.WriteString(data)
			}
		case "Q":
			out.WriteString(decodeQPayload(data))
		default:
			out.WriteString(data)
		}
		prevWord = true
	}
}

// decodeQPayload expands the quoted-printable form used inside an encoded word:
// '_' stands for a space and "=XX" for one byte.
func decodeQPayload(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '_':
			b.WriteByte(' ')
		case '=':
			if i+2 < len(s) {
				if v, ok := hexByte(s[i+1], s[i+2]); ok {
					b.WriteByte(v)
					i += 2
					continue
				}
			}
			b.WriteByte('=')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// hexByte decodes two hexadecimal characters.
func hexByte(hi, lo byte) (byte, bool) {
	a, ok1 := hexDigit(hi)
	b, ok2 := hexDigit(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return a<<4 | b, true
}

// hexDigit is the value of one hexadecimal character.
func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
