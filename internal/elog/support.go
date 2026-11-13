// ELOG rewritten in Go - the few generic helpers that have no better home.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

// This file used to hold the "grab bag" of the first transcription pass: a
// second set of configuration accessors (getParam/boolParam/intParam/...), a
// second Atoi, a second logging function and thin wrappers around the storage
// and mail layers. All of those turned out to be duplicates of what the real
// implementations already provide:
//
//	configuration accessors  -> (*Config).Get/GetString/GetInt/GetBool/...
//	                            (config.go), reached through a ConfigScope;
//	                            a request uses q.Cfg, code outside a request
//	                            uses currentServerConfig() (state.go)
//	logging                  -> (*Server).Logf (server.go) and the file log of
//	                            hitlog.go
//	entry lookups            -> (*Logbook).Message / (*Logbook).Path (storage.go)
//	mail                     -> (*Server).notify / (*Server).sendMail (mailer.go)
//
// They were removed rather than kept as aliases, because a second spelling of
// every operation is exactly how the first pass acquired two Atoi functions with
// different overflow behaviour and two log writers with different formats. What
// remains here is only what is genuinely general.

import (
	"fmt"
	"strconv"
	"strings"
)

// Itoa is strconv.Itoa under the name the transcribed C code uses (every
// "%d" of elogd.cxx became an Itoa here so that the conversion points are
// greppable in one place).
func Itoa(n int) string { return strconv.Itoa(n) }

// humanBytes is the size printed next to an attachment. elogd formats it with
// "%5.1f kB"/"%d Bytes" style conversions; the strings are reproduced because
// they appear in the HTML of every attachment row.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1000:
		return fmt.Sprintf("%.1f kB", float64(n)/1000.0)
	default:
		return fmt.Sprintf("%d Bytes", n)
	}
}

// firstErrorLine is the first line of the standard error of a failed
// subprocess, which is what goes to the daemon log and to the configuration
// page. Truncating at the first line keeps a stack-trace-producing hook from
// filling the log; it is a display choice, not a buffer limit.
func firstErrorLine(s string) string {
	s = TrimSpaceASCII(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
