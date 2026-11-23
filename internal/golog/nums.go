// ELOG rewritten in Go - small numeric/boolean conversions shared by the form
// and the configuration code, plus the one column-list helper the mailer and the
// pages ask the server for.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"strconv"
	"strings"
)

// orBool is the value of a configuration key with the elogd default. The
// spelling of "true" follows the configuration file: "true", "yes" and "1" are
// true, everything else (including "") is the default.
func orBool(v string, def bool) bool {
	switch strings.ToLower(TrimSpaceASCII(v)) {
	case "":
		return def
	case "true", "yes", "1", "on":
		return true
	case "false", "no", "0", "off":
		return false
	}
	return def
}

// orBoolDef is the spelling used by the transcribed configuration code.
func orBoolDef(v string, def bool) bool { return orBool(v, def) }

// orInt is the value of a configuration key with the elogd default; an empty
// value yields the default, garbage yields 0 through Atoi(), which is what
// atoi() of the C code returns for garbage too.
func orInt(v string, def int) int {
	if TrimSpaceASCII(v) == "" {
		return def
	}
	return Atoi(v)
}

// orIntDef is the spelling used by the transcribed configuration code.
func orIntDef(v string, def int) int { return orInt(v, def) }

// orFloat is the value of a configuration key with the elogd default.
func orFloat(v string, def float64) float64 {
	if TrimSpaceASCII(v) == "" {
		return def
	}
	f, err := strconv.ParseFloat(TrimSpaceASCII(v), 64)
	if err != nil {
		return def
	}
	return f
}

// displayedAttrs is the column list of one configuration scope: the "Display in
// List" key when it is set, otherwise every attribute of the logbook (the
// fallback Config.DisplayedAttrs implements). The notification body and the list
// page both ask the server rather than the configuration directly, so the
// fallback stays in one place and a server without a configuration - which is
// what a unit test builds - does not panic.
func (s *Server) displayedAttrs(scope ConfigScope) []string {
	if s == nil || s.Config == nil {
		return nil
	}
	return s.Config.DisplayedAttrs(scope)
}
