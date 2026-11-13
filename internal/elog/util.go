// ELOG rewritten in Go - small generic helpers.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Small helpers the port needs in more than one place.
//
// Note on names: the C program has one global namespace, so ideas that show up
// under two spellings in elogd.cxx (strcasestr vs strieq, getcfg vs
// GetParameter) are given ONE implementation here and an alias where a call site
// reads better with the other name. The aliases live in compat.go; the primary
// implementations of the string helpers are in text.go.
// ---------------------------------------------------------------------------

// parseInt is strconv.Atoi with C atoi() semantics as a fallback, so "10
// entries" still yields 10 the way sscanf("%d") in the C code would.
func parseInt(s string) int {
	n, err := strconv.Atoi(TrimSpaceASCII(s))
	if err != nil {
		return Atoi(s)
	}
	return n
}

// toInt is Atoi under the name the request parser uses.
func toInt(s string) int { return Atoi(s) }

// parseFloat is strconv.ParseFloat with a 0-on-garbage result (C atof()).
func parseFloat(s string) (float64, bool) {
	f, err := strconv.ParseFloat(TrimSpaceASCII(s), 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// parseFloatOr is parseFloat with an explicit default.
func parseFloatOr(s string, def float64) float64 {
	if f, ok := parseFloat(s); ok {
		return f
	}
	return def
}

// splitHostPort splits "host:port" and falls back to defPort (a string, so the
// SMTP code can pass "25" or "465" without converting). An IPv6 address in
// brackets and a bare host are handled; the ok result says whether an explicit
// port was present. The C code did strchr(":") on a fixed buffer and silently
// kept a truncated host when the value overflowed; Go strings make that
// impossible, so the only failure mode is "no port given".
func splitHostPort(hostport string, defPort string) (host, port string, ok bool) {
	hostport = TrimSpaceASCII(hostport)
	if hostport == "" {
		return "localhost", defPort, false
	}
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if Atoi(p) <= 0 {
			return h, defPort, false
		}
		return h, p, true
	}
	return hostport, defPort, false
}

// joinHostPort is net.JoinHostPort for an integer port.
func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// JoinHostPort is net.JoinHostPort for a port that came from a configuration
// value; the default SMTP port is not written out, because elogd's own client
// connects to "localhost" (port 25 implied) and mirroring that behaviour is
// friendlier to a local MSA.
func JoinHostPort(host, port string) string {
	if port == "" || port == "25" {
		return host
	}
	return net.JoinHostPort(host, port)
}

// MaxDate is the later of two times (the "last change" computation of the list
// page); the zero time means "unknown".
func MaxDate(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// dateToFileName is the lowercase spelling used by the storage layer.
func dateToFileName(t time.Time) string { return DateToFileName(t) }

// shortOf truncates a string for a log line without ever cutting a UTF-8
// character in half (the same rule the RSS and list pages follow).
func shortOf(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return ShortenUTF8(s, n) + "..."
}

// fileExists is the stat() idiom of elogd ("does this file exist and is it not
// a directory").
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// sprintf is fmt.Sprintf under the short name the transcribed code uses.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// fmtSprintf is the name the localization helpers call.
func fmtSprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
//
// elogd builds every path by concatenating into a char[PATH_MAX]; that is the
// single largest source of the fixed-buffer class of bug this port does not have
// to reproduce. The two helpers below are the only path primitives this package
// declares, so "how are paths built here?" has one grep answer, and both are
// thin wrappers over path/filepath (which returns a freshly sized string).

func isAbs(p string) bool        { return filepath.IsAbs(p) }
func isAbsPath(p string) bool    { return filepath.IsAbs(p) }
func joinPath(parts ...string) string { return filepath.Join(parts...) }

// collapseBlanks turns every run of white space into one space, which is how the
// user-name comparison of the password file ignores the typing differences
// between "J.  Doe" and "J. Doe".
func collapseBlanks(s string) string {
	var b strings.Builder
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f' {
			if !prevSpace && b.Len() > 0 {
				b.WriteByte(' ')
			}
			prevSpace = true
			continue
		}
		prevSpace = false
		b.WriteByte(c)
	}
	return b.String()
}
