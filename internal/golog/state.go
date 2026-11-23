// ELOG rewritten in Go - process-wide state that the transcribed call sites
// reach without a parameter: "the current server", "the current configuration",
// "the current request".
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"encoding/base64"
	"sync"
)

// The C daemon has one select() loop and keeps its state in file-scope statics
// (current_server, _cfg, the current logbook ...). A Go daemon serves requests
// on several goroutines, so the same three ideas exist here behind a mutex, and
// every helper that was transcribed without a parameter reads them here. New
// code takes the *Server (or the *Request) as an argument instead.

var (
	currentMu     sync.RWMutex
	currentSrv    *Server
	currentSrvCfg *Config
)

// setCurrentServer records the server whose requests are being served. Only the
// start-up code and the request pipeline call it.
func setCurrentServer(s *Server) {
	currentMu.Lock()
	currentSrv = s
	if s != nil {
		currentSrvCfg = s.Config
	} else {
		currentSrvCfg = nil
	}
	currentMu.Unlock()
}

// SetCurrentServer is the exported form, for cmd/elogd.
func SetCurrentServer(s *Server) { setCurrentServer(s) }

// currentServer is the server of the running daemon, nil before New() finished.
func currentServer() *Server {
	currentMu.RLock()
	defer currentMu.RUnlock()
	return currentSrv
}

// CurrentServer is the exported form of currentServer.
func CurrentServer() *Server { return currentServer() }

// currentServerConfig is the configuration of the running daemon: the one the
// server was built from, refreshed when the configuration was re-read. A helper
// that has neither a server nor a request (Abs, the notification address list)
// reads it here; it returns nil before the configuration file was parsed, and
// every caller has to cope with that.
func currentServerConfig() *Config {
	currentMu.RLock()
	s, c := currentSrv, currentSrvCfg
	currentMu.RUnlock()
	if c != nil {
		return c
	}
	if s != nil {
		return s.Config
	}
	return nil
}

// ---------------------------------------------------------------------------
// Configuration scopes
// ---------------------------------------------------------------------------

// ScopeFor builds the lookup scope of a logbook name: the group itself plus the
// top group of the hierarchy, which is what makes "[global Midas]" apply to the
// logbook "Midas/Run1".
func (s *Server) ScopeFor(logbook string) ConfigScope {
	sc := ConfigScope{Group: logbook}
	if logbook == "" || EqualFold(logbook, "global") {
		sc.Group = "global"
		return sc
	}
	if i := indexByteFold(logbook, '/'); i > 0 {
		sc.TopGroup = logbook[:i]
	}
	if s != nil && s.Config != nil {
		if v, ok := s.Config.Get(sc, "Condition"); ok {
			sc.Condition = TrimSpaceASCII(v)
		}
	}
	return sc
}

// ScopeOf is the request-side spelling of ScopeFor; a request always knows the
// logbook it belongs to, so the argument is only needed when a page renders a
// link into another logbook.
func (q *Request) ScopeOf(logbook string) ConfigScope {
	if q == nil {
		return ConfigScopeForLogbook(logbook)
	}
	if logbook == "" || logbook == q.Cfg.Group {
		return q.Cfg
	}
	if s := currentServer(); s != nil {
		return s.ScopeFor(logbook)
	}
	return ConfigScopeForLogbook(logbook)
}

// ConfigScopeForLogbook is the scope of a logbook without a server at hand, used
// by package-level helpers (Abs, the password-file lookup).
func ConfigScopeForLogbook(logbook string) ConfigScope {
	sc := ConfigScope{Group: logbook}
	if logbook == "" {
		sc.Group = "global"
		return sc
	}
	if i := indexByteFold(logbook, '/'); i > 0 {
		sc.TopGroup = logbook[:i]
	}
	return sc
}

// indexByteFold is the position of the first occurrence of the byte c, or -1. It
// exists so that the hierarchy split reads like the C code it replaces.
func indexByteFold(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// The request in flight
// ---------------------------------------------------------------------------

// currentRequest is the request Server.serve is handling. It exists for the
// handful of helpers that were transcribed from C statics and have no *Request
// parameter; everything else takes the request explicitly.
func (s *Server) currentRequest() *Request {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight
}

// setCurrentRequest records the request being served. serve sets it on entry and
// clears it on the way out, so a helper cannot see a stale request.
func (s *Server) setCurrentRequest(q *Request) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.inflight = q
	s.mu.Unlock()
	if q != nil {
		setCurrentServer(s)
	}
}

// ---------------------------------------------------------------------------
// Shell substitution in configuration values
// ---------------------------------------------------------------------------

// ShellSubstFor expands the $shell(...) constructs of a configuration value in
// the given scope. The substitution only happens when the operator switched it
// on ("Config shell" in elogd, gated by -x here), because a value in a config
// file that can start a program is a privilege boundary: the configuration file
// must stay more trusted than the entries.
func (s *Server) ShellSubstFor(scope ConfigScope, text string) string {
	if s == nil || !s.Exec {
		return text
	}
	if s.Config != nil {
		if v := s.Config.GetString(scope, "Config shell", ""); v != "" && Atoi(v) == 0 {
			return text
		}
	}
	return shellSubst(s, text)
}

// ---------------------------------------------------------------------------
// base64
// ---------------------------------------------------------------------------

// base64Std is the encoding the attachment tokens, the login token and the
// password file use. It lives here because all three need it and none owns it.
var base64Std = base64.StdEncoding

// base64Encode is base64Std.EncodeToString, named so that a reader can grep for
// the places where a value becomes transport-safe.
func base64Encode(b []byte) string { return base64Std.EncodeToString(b) }

// base64Decode is base64Std.DecodeString, tolerant of the unpadded spelling the
// original's login token uses.
func base64Decode(s string) ([]byte, error) {
	for len(s)%4 != 0 {
		s += "="
	}
	return base64Std.DecodeString(s)
}
