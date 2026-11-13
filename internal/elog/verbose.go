// ELOG rewritten in Go - the verbosity of the daemon's own diagnostics.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

// ---------------------------------------------------------------------------
// -v <n> / -S
// ---------------------------------------------------------------------------
//
// elogd keeps one global verbosity level (set_verbose()/get_verbose()) with the
// levels VERBOSE_URL=1, VERBOSE_INFO=2, VERBOSE_DEBUG=3, and -S (silent) clears
// the flag that says whether anything may be printed at all. The same two knobs
// are here: the level decides how much the subsystems that were transcribed from
// eprintf() calls print, and silent() is what -S sets.
//
// What the level does NOT control is the per-request URL log of -v 1: this port
// writes one line per *request* only when the HTTP layer was wrapped by the
// caller (cmd/elogd does that, see its logRequests middleware), because
// net/http owns the connection handling here. Per-entry hit logging - which is
// what an operator usually wants - is driven by the configuration keys "Logging"
// and "Record hit file" and is implemented in hitlog.go / hitlog_glue.go.

var (
	verboseLevel = 2 // the C default once the daemon is up
	verboseSet   bool
)

// SetVerbose sets the verbosity of the daemon log. It is the port of
// set_verbose(); -S is -v 0.
func SetVerbose(n int) {
	verboseLevel = n
	verboseSet = true
}

// Verbose is the port of get_verbose().
func Verbose() int { return verboseLevel }

// Debugf logs at the VERBOSE_DEBUG level only.
func Debugf(format string, args ...any) {
	if verboseLevel >= 3 {
		Logf(format, args...)
	}
}

// Infof logs at the VERBOSE_INFO level and above; -S and -v 1 silence it, which
// is what the C code's silent flag does to its informational eprintf() lines.
func Infof(format string, args ...any) {
	if verboseLevel >= 2 && !silent() {
		Logf(format, args...)
	}
}

// silent is -S: no diagnostics at all.
func silent() bool { return verboseSet && verboseLevel < 1 }

// Silent reports the -S state for callers that want to skip work whose only
// purpose is a log line (building a long parameter dump, for instance).
func Silent() bool { return silent() }
