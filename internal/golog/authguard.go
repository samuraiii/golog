// ELOG rewritten in Go - the login guards: the two layers that answer a login
// attempt before any password is compared.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// why this file exists
// ---------------------------------------------------------------------------
//
// Two layers stand in front of every back end, and both must answer before a
// password is compared, before a directory is bound and before a helper process
// is started - a refused attempt must cost nothing, otherwise the guard itself is
// the denial of service an attacker wanted:
//
//	LoginThrottle (throttle.go)  in memory, on by default, makes the login form
//	                             slow and then refuses one address or account for
//	                             a while; it forgets everything on a restart;
//
//	fail ban (failban.go)        off by default, remembers bans across a restart
//	                             and writes the machine-readable lines an external
//	                             fail2ban reacts to.
//
// The two stay separate on purpose. The throttle protects a service that must stay
// usable and is safe to have always on; a ban is a sharper instrument that can lock
// a whole office out behind one NAT address, so it is opt-in and it keeps a
// paper trail. authiface.go calls LoginGuardBlocked before the chain and the two
// record functions after it; nothing else decides who may reach a back end.

// ---------------------------------------------------------------------------
// the error a blocked attempt gets
// ---------------------------------------------------------------------------

// ErrAuthBlocked is the sentinel every "come back later" answer unwraps to. It is
// deliberately distinct from ErrBadPassword: a caller who is blocked is not wrong,
// he is early, and a handler that confuses the two either tells him his password is
// bad (he keeps trying) or counts the refusal as a failure (the block never ends).
var ErrAuthBlocked = errors.New("golog: login temporarily blocked")

// BlockedError says the attempt was refused by a guard rather than by a back end.
// A login handler turns it into "429 Too Many Requests" with Retry-After, never
// into another password prompt.
type BlockedError struct {
	// Reason is the text the login page shows; it says what to do and nothing
	// about the counter behind it.
	Reason string
	// Secs is what goes into the Retry-After header, always at least 1.
	Secs int
	// Layer names the guard that answered, "login throttle" or "fail ban"; it is
	// logged, not shown, so that an operator can tell which of the two to look at.
	Layer string
	// User and IP are what the guard keyed on. They are already in the daemon log;
	// carrying them here keeps an audit line from having to recompute them.
	User string
	IP   string
}

// Error names the layer, so a log line says which guard produced it. The reason is
// repeated here rather than left to the page, because the error also ends up in the
// daemon log and in a JSON status answer.
func (e *BlockedError) Error() string {
	layer := orText(e.Layer, "login guard")
	if e.Reason == "" {
		return "golog: " + layer + " refused this login attempt (retry in " +
			strconv.Itoa(e.Secs) + " s)"
	}
	return "golog: " + layer + " refused this login attempt: " + e.Reason
}

// Is lets errors.Is(err, ErrAuthBlocked) match any blocking answer.
func (e *BlockedError) Is(target error) bool { return target == ErrAuthBlocked }

// Unwrap points at the sentinel, for callers that prefer Unwrap chains over Is.
func (e *BlockedError) Unwrap() error { return ErrAuthBlocked }

// RetryAfter is the Retry-After header value.
func (e *BlockedError) RetryAfter() string { return strconv.Itoa(e.Secs) }

// newBlockedError builds a blocking answer. A duration of zero would make
// Retry-After meaningless and tell the client to retry immediately, which is the one
// thing a guard must not encourage, so it becomes one second.
func newBlockedError(reason string, secs int, layer string) *BlockedError {
	if secs < 1 {
		secs = 1
	}
	if layer == "" {
		layer = "login guard"
	}
	if reason == "" {
		reason = "Too many failed logins. Try again later."
	}
	return &BlockedError{Reason: reason, Secs: secs, Layer: layer}
}

// blockedSeconds turns a remaining duration into the whole seconds of a
// Retry-After value: rounding down would advertise "retry in 0", so it rounds up.
func blockedSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	n := int((d + time.Second - 1) / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}

// LoginThrottleDelay is the fixed pause the throttle wants on a failed login, in
// milliseconds from "Login throttle fixed delay". It is applied to the failure path
// only and is 0 by default, so that a wrong password stays as quick to answer as it
// always was unless the operator buys time for a cost.
func LoginThrottleDelay(s *Server) time.Duration {
	cfg := LoginThrottleLayer(s).Config()
	if !cfg.Enabled || cfg.FixedDelay <= 0 {
		return 0
	}
	return time.Duration(cfg.FixedDelay) * time.Millisecond
}

// ---------------------------------------------------------------------------
// the gate
// ---------------------------------------------------------------------------

// LoginGuardBlocked is the pre-backend gate authiface.go asks. It consults the
// throttle first and the fail ban second, and reports:
//
//	blocked whether the attempt may reach a back end at all;
//	secs    the Retry-After value to advertise;
//	why     the browser-visible reason;
//	key     which layer answered, for the daemon log.
//
// The order is not arbitrary: the throttle is the layer that is on by default and
// has a message already worded for a browser, so it gets to answer first when both
// would. FailBanCheck writes its own refusal line to the log, so the caller does
// not have to.
func (s *Server) LoginGuardBlocked(user, ip string) (blocked bool, secs int, why, key string) {
	if d := LoginThrottleCheck(s, user, ip); d.Blocked {
		msg := loginThrottleMessage(d)
		if msg == "" {
			msg = "Too many failed logins. Try again later."
		}
		logS(s, "golog auth: login throttle refused an attempt for %q from %s, retry in %ds",
			user, failBanToken(ip), blockedSeconds(d.RetryIn))
		return true, blockedSeconds(d.RetryIn), msg, "login throttle"
	}
	if banned, wait := s.FailBanCheck(user, ip); banned {
		return true, blockedSeconds(wait), "Too many failed logins. Try again later.", "fail ban"
	}
	return false, 0, "", ""
}

// ---------------------------------------------------------------------------
// the record side, in the shape authiface.go calls
// ---------------------------------------------------------------------------
//
// The two layers keep their own Server methods (a caller who wants only one layer
// can still call it); these three functions are the one place that knows the order
// and the nil-server rules.

// FailBanLogFailure writes the line the fail2ban filter counts, once per failed
// login and in exactly one spelling, whatever layer or handler rejected the caller.
func FailBanLogFailure(s *Server, user, ip string) {
	if s == nil {
		return
	}
	s.FailBanLogFailedLogin(user, ip)
}

// FailBanFailure records the failure in the ban table; it reports whether this very
// failure produced a ban, which the login page does not show (the next attempt gets
// the 429) but a status command may want.
func FailBanFailure(s *Server, user, ip string) (bool, time.Duration) {
	if s == nil {
		return false, 0
	}
	return s.FailBanFailure(user, ip)
}

// FailBanSuccess clears the counted failures of a caller who proved who he is.
func FailBanSuccess(s *Server, user, ip string) {
	if s == nil {
		return
	}
	s.FailBanSuccess(user, ip)
}

// ---------------------------------------------------------------------------
// the administrative surface
// ---------------------------------------------------------------------------
//
// An operator who locked himself out needs to see and empty both layers from one
// place; keeping the three functions below identical in shape means a status page or
// a command-line flag only has to know about "the login guards".

// LoginGuardStats is the one-line summary of both layers for a status page.
func LoginGuardStats(s *Server) string {
	return LoginThrottleStats(s) + "; " + s.FailBanStats()
}

// LoginGuardList is every live counter and every ban, throttle first (it is the
// layer that is on by default) and each layer sorted by key, as printable lines.
func LoginGuardList(s *Server) []string {
	var out []string
	if rows := LoginThrottleList(s); len(rows) > 0 {
		out = append(out, "login throttle:")
		for _, e := range rows {
			out = append(out, "  "+e.String())
		}
	}
	if bans := s.FailBanList(); len(bans) > 0 {
		out = append(out, "fail ban:")
		for _, e := range bans {
			out = append(out, "  "+e.String())
		}
	}
	return out
}

// LoginGuardClear lifts the counters and bans matching a key (an address, a user
// name or "" for everything), across both layers, and reports how many rows went
// away. It is the panic button for "I locked myself out", so it is deliberately not
// reachable from any page by default - whoever can call it can unban an attacker
// (see MERGE-NOTES.md for where to wire it).
func LoginGuardClear(s *Server, key string) int {
	if TrimSpaceASCII(key) == "" {
		n := LoginThrottleClear(s, "")
		if s != nil {
			n += s.FailBanClearAll()
		}
		logS(s, "golog auth: login guards cleared by an operator (%d %s)", n, plural(n))
		return n
	}
	n := LoginThrottleClear(s, key)
	if s != nil {
		n += s.FailBanClear(key)
	}
	logS(s, "golog auth: login guards for %s cleared by an operator (%d %s)",
		failBanToken(key), n, plural(n))
	return n
}

// LoginGuardFailureKeys is what a guard refused, as a compact list for a status
// line: the keys of the throttled counters and of the live bans, sorted. Empty in
// normal operation, which is the point of printing it.
func LoginGuardFailureKeys(s *Server) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range LoginThrottleList(s) {
		if !e.Blocked || seen[e.Key] {
			continue
		}
		seen[e.Key] = true
		out = append(out, e.Key)
	}
	if s != nil {
		now := time.Now()
		for _, e := range s.FailBanList() {
			k := string(e.Kind) + ":" + e.Key
			if !e.active(now) || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// BlockedLayerNames is the pair of layer labels, exported so that a status page and
// the documentation use the same two words as the log lines.
func BlockedLayerNames() []string {
	return []string{"login throttle", "fail ban"}
}

// BlockedErrorFromStrings rebuilds a blocking answer from the two strings a status
// page shows again (an administrative path that read them out of a log). It exists
// so that nothing outside this package has to build a BlockedError literal.
func BlockedErrorFromStrings(reason, layer string, secs int) *BlockedError {
	return newBlockedError(strings.TrimSpace(reason), secs, layer)
}
