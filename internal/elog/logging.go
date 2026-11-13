// ELOG rewritten in Go - the daemon's own log output.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"fmt"
	"io"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
// The daemon log
// ---------------------------------------------------------------------------
//
// elogd writes its diagnostics with fprintf(stderr, ...) and, with "Logging"
// set, mirrors them into the logbook's mlog.log (see hitlog_glue.go's
// recordConfigLog) and, with -l, redirects its whole standard error into a file.
// The equivalent here is one writer, chosen by logWriter(): the -l file when
// Server.SetOutput opened one, stderr otherwise.
//
// Code that has a *Server uses (*Server).Logf, which timestamps through the
// standard log package. Code that does not (the storage layer while a logbook is
// being opened, the start-up checks in cmd/elogd) uses the package-level Logf
// below, so there is exactly one destination and one timestamp format.

// logWriter is where the daemon log goes.
func logWriter() io.Writer {
	if s := currentServer(); s != nil && s.Log != nil {
		return s.Log
	}
	return os.Stderr
}

// Logf writes one line to the daemon log with a timestamp.
func Logf(format string, args ...any) {
	fmt.Fprintf(logWriter(), "%s: %s\n", time.Now().Format("2006-01-02 15:04:05"),
		fmt.Sprintf(format, args...))
}

// logf is the package-level short form, used by the helpers that were
// transcribed from the C code's bare fprintf() calls and have no *Server in
// hand. (It does not collide with (*Server).logf: methods live in the type's
// namespace.)
func logf(format string, args ...any) { Logf(format, args...) }
