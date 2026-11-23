// ELOG rewritten in Go - missing package-level API.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"path/filepath"
)

// ---------------------------------------------------------------------------
// Verbosity levels
// ---------------------------------------------------------------------------
//
// The levels of elogd's verbose.h: VERBOSE_SILENT/VERBOSE_URL/VERBOSE_INFO/
// VERBOSE_DEBUG. verbose.go keeps the state, these are the names the command
// line works with.

const (
	// VerboseSilent is -S: no diagnostics at all.
	VerboseSilent = 0
	// VerboseURL is -v 1: one line per requested URL.
	VerboseURL = 1
	// VerboseInfo is -v 2 (the default): informational start-up messages.
	VerboseInfo = 2
	// VerboseDebug is -v 3.
	VerboseDebug = 3
)

// ---------------------------------------------------------------------------
// File names
// ---------------------------------------------------------------------------

// ConfigFileName is the compiled-in CFGFILE of the C program.
const ConfigFileName = "elogd.cfg"

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

// Abs makes a path taken from the configuration absolute. A relative path is
// resolved against the directory of the configuration file, which is what the C
// program does for the SSL certificates and for the resource directory; when no
// configuration is loaded it falls back to the process working directory.
func Abs(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if c := currentServerConfig(); c != nil {
		if d := c.ConfigDir(); d != "" {
			return filepath.Join(d, p)
		}
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// Abs is the method form of the package function Abs(), used where a server is
// at hand. It resolves against the logbook data directory first (Server.abs),
// which is the rule for every other path in a logbook configuration.
func (s *Server) Abs(p string) string {
	if s == nil {
		return Abs(p)
	}
	return s.abs(p)
}

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

// Crypt is the port of the C crypt() call used by the password file: it returns
// the stored form of a clear-text password. DoCrypt is the same function under
// the name that says what it does; Crypt is the spelling the transcribed call
// sites use.
func Crypt(password string) string { return DoCrypt(password) }
