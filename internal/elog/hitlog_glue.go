// ELOG rewritten in Go - the daemon-side glue that wraps the hit log.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"os"
	"time"
)

// ---------------------------------------------------------------------------
// What elogd's logging configuration actually selects
// ---------------------------------------------------------------------------
//
// elogd has one key, "Logging", whose value selects a mode (LOG_NONE / LOG_TEXT
// / LOG_XML / LOG_STDOUT in elogd.cxx) and a second key, "Record hit file", that
// decides whether a display of a message is counted at all. The modes differ in
// the record format and in where it goes:
//
//	file    id|logbook|YYYY-MM-DD HH:MM:SS|user|ip|user agent   into mlog.hit
//	xml     <message id=".." logbook=".." time=".." user=".." .../> into mlog.hit
//	stdout  the plain line, additionally mirrored on the daemon's own log
//	other   nothing
//
// hitlog.go owns the file itself (its hitLoggingMode() decides whether a record
// is appended, and its logbookNamesVisible() lists the logbooks whose files are
// consulted); this file owns the mode name, the view-counter accessors the pages
// call, the daemon-side mirror line, and elogd's log_message() equivalent - so
// that "where is a view counted, and where is a daemon message printed" each has
// exactly one answer.

// loggingMode is the "Logging" key normalised to ""|file|xml|stdout.
func loggingMode(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	switch TrimSpaceASCII(cfg.GetString(ConfigScope{Group: "global"}, "Logging", "")) {
	case "xml", "XML":
		return "xml"
	case "file", "FILE":
		return "file"
	case "stdout", "STDOUT":
		return "stdout"
	default:
		return ""
	}
}

// recordHit notes one display of a message: the counter in the hit file (when
// "Record hit file" is on) plus, in "Logging = stdout" mode, the mirror line on
// the daemon's own log. user is the login name when one is known, which is what
// elogd passes from its per-request "user" global.
func (s *Server) recordHit(lb *Logbook, id int, ip, user, userAgent string) {
	if s == nil || lb == nil || id <= 0 {
		return
	}
	mode := loggingMode(s.Config)
	if mode == "" {
		return
	}
	s.RecordHitAs(lb, id, ip, user, userAgent)
	if mode == "stdout" {
		Logf("%s", stdoutHitLine(lb.Name, id, user, ip))
	}
}

// stdoutHitLine is the one-line record of the "Logging = stdout" mode.
func stdoutHitLine(logbook string, id int, user, ip string) string {
	return "displayed " + logbook + "/" + Itoa(id) + " by " + orText(user, "anonymous") +
		" from " + ip
}

// recordConfigLog is elogd's log_message(): when "Logging" is on, the daemon
// mirrors its informational messages into the logbook's mlog.log as well as onto
// its own log. A failure to open the file is ignored - a read-only data directory
// must not break browsing (the C code does not even check its fopen()).
func (s *Server) recordConfigLog(entry string) {
	if s == nil || s.Config == nil {
		return
	}
	mode := loggingMode(s.Config)
	if mode == "" {
		return
	}
	name := s.Config.GetString(ConfigScope{Group: "global"}, "Logging file", "mlog.log")
	dir := s.firstLogbookDir()
	if dir == "" {
		dir = s.DataDir
	}
	if dir == "" {
		return
	}
	path := name
	if !isAbsPath(path) {
		path = joinPath(dir, name)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if mode == "xml" {
		f.WriteString("<event time=\"" + time.Now().Format("2006-01-02 15:04:05") + "\">" +
			xmlEscapeText(entry) + "</event>\n")
		return
	}
	f.WriteString(time.Now().Format("2006-01-02 15:04:05") + " " + entry + "\n")
}

// xmlEscapeText is the escaping the XML log form needs. elogd writes that form
// with a bare fprintf(), so a user agent or user name containing '<' corrupts the
// file; escaping is a deliberate improvement over byte-for-byte fidelity because
// the file is machine read.
func xmlEscapeText(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			b = append(b, "&amp;"...)
		case '<':
			b = append(b, "&lt;"...)
		case '>':
			b = append(b, "&gt;"...)
		case '"':
			b = append(b, "&quot;"...)
		default:
			b = append(b, s[i])
		}
	}
	return string(b)
}

// firstLogbookDir is the data directory of the first logbook, which is where
// elogd's global log file lands when "Logging" is on and no absolute file name is
// configured (the C code uses the directory of whichever logbook was current).
func (s *Server) firstLogbookDir() string {
	if s == nil {
		return ""
	}
	for _, n := range s.Order {
		if lb := s.Logbooks[n]; lb != nil && lb.Dir != "" {
			return lb.Dir
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// View counters
// ---------------------------------------------------------------------------

// ViewsOf is the number of recorded views of one message ("Display views" puts it
// behind each row of the list page).
func (s *Server) ViewsOf(logbook string, id int) int {
	return s.hitLogByName(logbook).count(id)
}

// Views is the number of recorded views of a whole logbook.
func (s *Server) Views(logbook string) int {
	return s.hitLogByName(logbook).total()
}

// ViewsTotal is the number of recorded views across every logbook, the figure the
// status page prints.
func (s *Server) ViewsTotal() int {
	total := 0
	for _, n := range s.logbookNamesVisible("", true) {
		total += s.Views(n)
	}
	return total
}

// RecentHits returns the recorded views of every visible logbook newer than since,
// newest first, at most n of them (n<=0 means all). The hits page renders this.
func (s *Server) RecentHits(user string, since time.Time, n int) []hit {
	var all []hit
	for _, name := range s.logbookNamesVisible(user, true) {
		h := s.hitLogByName(name)
		if h == nil {
			continue
		}
		h.mu.Lock()
		h.loadLocked()
		for _, x := range h.hits {
			if !since.IsZero() && x.when.Before(since) {
				continue
			}
			all = append(all, x)
		}
		h.mu.Unlock()
	}
	sortHitsDesc(all)
	if n > 0 && len(all) > n {
		all = all[:n]
	}
	return all
}
