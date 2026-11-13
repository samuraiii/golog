// ELOG rewritten in Go - the process-wide state and the small bridges between
// subsystems that need it.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"encoding/base64"
	"sync"
)

// ---------------------------------------------------------------------------
// The one server instance
// ---------------------------------------------------------------------------
//
// elogd is a single-process, single-purpose daemon with one global
// configuration array (log_cfg_t) and one global logbook list, and every helper
// in elogd.cxx reaches for them directly. The equivalent here is one *Server
// published at start-up. It is guarded by a mutex rather than being a plain
// global because this port serves requests on goroutines and because
// ReloadIfChanged() swaps the *Config in place; reading it through these
// accessors keeps that race out of every helper.

var (
	currentMu     sync.RWMutex
	currentSrv    *Server
	currentSrvCfg *Config
)

// setCurrentServer publishes the server for the helpers that have no request at
// hand (the start-up log lines, the configuration re-read check, tests).
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

// SetCurrentServer is the exported form, called by cmd/elogd right after the
// server is built.
func SetCurrentServer(s *Server) { setCurrentServer(s) }

// currentServer is the published server, nil before start-up.
func currentServer() *Server {
	currentMu.RLock()
	defer currentMu.RUnlock()
	return currentSrv
}

// CurrentServer is the exported form of currentServer().
func CurrentServer() *Server { return currentServer() }

// currentServerConfig is the configuration the helpers should read. During a
// configuration reload the server briefly holds a new *Config; helpers that run
// inside a request use q.Cfg with q.S.Config directly, so this accessor only
// serves the code paths outside a request.
func currentServerConfig() *Config {
	currentMu.RLock()
	s := currentSrv
	c := currentSrvCfg
	currentMu.RUnlock()
	if s != nil && s.Config != nil {
		return s.Config
	}
	return c
}

// ---------------------------------------------------------------------------
// Configuration scope
// ---------------------------------------------------------------------------

// ScopeFor is the lookup scope of a logbook section: the [global] defaults plus
// the logbook's own section, which is the two-level lookup getcfg() performs.
func (s *Server) ScopeFor(logbook string) ConfigScope {
	sc := ConfigScope{Group: "global"}
	if logbook == "" {
		return sc
	}
	sc.Group = logbook
	if s == nil || s.Config == nil {
		return sc
	}
	// The top group of a logbook hierarchy ("[phys / slow control]" style
	// sections and the "Top group" key) contributes a third level in elogd.
	if top := s.Config.GetStringDefault(ConfigScope{Group: logbook}, "Top group", ""); top != "" {
		sc.TopGroup = top
	}
	return sc
}

// ScopeOf is the scope a request works in.
func (q *Request) ScopeOf(logbook string) ConfigScope {
	if q != nil && q.S != nil {
		return q.S.ScopeFor(logbook)
	}
	return ConfigScope{Group: logbook}
}

// ConfigScopeForLogbook is the package-level form used where no server is
// reachable (tests, the mail queue).
func ConfigScopeForLogbook(logbook string) ConfigScope {
	if s := currentServer(); s != nil {
		return s.ScopeFor(logbook)
	}
	return ConfigScope{Group: logbook}
}

// ---------------------------------------------------------------------------
// The request in flight
// ---------------------------------------------------------------------------
//
// elogd knows "the current request" implicitly (one request at a time, one
// select() loop). Helpers that were transcribed without a Request parameter read
// it here, which is why the Server.inflight field exists.

// currentRequest returns the request that is being served, nil outside a
// request.
func (s *Server) currentRequest() *Request {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight
}

// setCurrentRequest is called from serve() around the dispatch.
func (s *Server) setCurrentRequest(q *Request) {
	s.mu.Lock()
	s.inflight = q
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Shell substitution with an explicit scope
// ---------------------------------------------------------------------------

// ShellSubstFor expands $(shell ...) / $shell(...) in one configuration value of
// one logbook. The scope decides the working directory the command runs in, which
// is what the "Pre display"/"Post display" texts of a logbook expect when they
// call a script that reads relative files. ShellSubst in server.go is the plain
// spelling.
func (s *Server) ShellSubstFor(scope ConfigScope, text string) string {
	if s == nil {
		return text
	}
	if s.LB(scope.Group) != nil {
		return shellSubstInDir(s, text, s.logbookDir(scope.Group))
	}
	return s.ShellSubst(text)
}

// ---------------------------------------------------------------------------
// Base 64
// ---------------------------------------------------------------------------

// base64Std is the standard alphabet, used for encoded-words, attachments and the
// password-file plumbing. Nothing here needs the URL-safe variant.
var base64Std = base64.StdEncoding
