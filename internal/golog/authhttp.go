// ELOG rewritten in Go - the login path of the HTTP layer, against the
// authentication interface.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// why this file exists
// ---------------------------------------------------------------------------
//
// The login and logout handlers, the "?cmd=Login" form on every page and the
// per-logbook password all live in request.go, a file this batch does not own.
// The integration is a one-line redirect in each of three places (see
// MERGE-NOTES.md) that lands here, where the whole authentication interface can
// be used: the guard in front of the back ends, the chain itself, the session
// start, and the answers 429/503 that did not exist before.
//
// The old path was:
//
//	if !s.checkPassword(user, pass) { ... show the login page again ... }
//
// which meant "the XML password file said no" was the whole of authentication.
// After the redirect it means "no configured back end accepted this caller",
// which is the sentence the login page has always claimed.
//
// Nothing in here compares a password: (*Server).AuthenticateLogin does, through
// the chain.

// ---------------------------------------------------------------------------
// the login form
// ---------------------------------------------------------------------------

// LoginHandler is the "?cmd=Login" entry point (request.go's s.login).
//
//	user, pass := q.Param("unm"), q.Param("upwd")
//	if user == "" || pass == "" {
//		s.LoginHandler(q)   // no credentials: show the form
//	}
//	...
//	s.LoginHandler(q)      // the real login attempt
//
// The two call shapes are the same on purpose: with no credentials there is
// nothing to ask a back end about, so the handler shows the form, and the
// "failed" flag from the old handler's caller is not needed any more - this
// function knows whether the attempt failed because it made the attempt.
func (s *Server) LoginHandler(q *Request) {
	if q == nil || q.W == nil || q.R == nil {
		return
	}
	user := TrimSpaceASCII(q.Param("unm"))
	pass := q.Param("upwd")
	if user == "" || pass == "" {
		s.showLoginPage(q, q.redirParam(), false)
		return
	}

	id, err := s.AuthenticateLogin(q.R, user, pass)
	if err == nil {
		s.finishLogin(q, id)
		return
	}

	// The failure decides both the status and what the page says. The detail
	// goes to the log (AuthenticateLogin already wrote it); the browser gets one
	// of three sentences, so a probe cannot tell "no such user" from "the
	// directory is down" from "you are banned".
	ip := s.LoginSourceIP(q.R)
	switch {
	case LoginBlocked(err):
		s.loginDenied(q, LoginErrorMessage(err), time.Duration(LoginWait(err))*time.Second)
		return
	case IsAuthUnavailable(err):
		s.loginUnavailable(q, LoginErrorMessage(err))
		return
	}
	logS(s, "golog auth: login for %q from %s refused: %v", user, ip, err)
	FailBanLogFailure(s, user, ip)
	s.showLoginPage(q, q.redirParam(), true)
}

// finishLogin is the second half of a successful login: the identity lands on
// the request, the local user record is created when a back end brought a user
// golog did not know, a session is started, and the browser is sent where the
// form said to go.
func (s *Server) finishLogin(q *Request, id Identity) {
	if TrimSpaceASCII(id.Name) == "" {
		// A back end that accepted nobody. Treat it as a refusal rather than
		// letting an anonymous request through with a session cookie.
		logS(s, "golog auth: a back end accepted an empty user name; ignoring")
		s.showLoginPage(q, q.redirParam(), true)
		return
	}
	q.User = id.Name
	if s.Pwd != nil {
		// The directory, the proxy or the helper brought this user; the user
		// page, the subscription list and the notification code all read the
		// password file, so the record has to exist. The generated password is
		// unguessable, so the record cannot become a second way in.
		created := s.ensurePwdUser(id.Name, id.FullName, id.Email, true, true)
		id.Created = id.Created || created
	}
	q.fillIdentity()
	q.newSession()
	s.logLoginOK(q, id)
	s.redirect(q, orText(q.redirParam(), s.BasePath+"/"+q.Cfg.Group+"/"))
}

// logLoginOK is the audit line of a successful login. The address is the one the
// guards key on, so that "who logged in from where" in the log matches what a
// ban would have blocked.
func (s *Server) logLoginOK(q *Request, id Identity) {
	ip := s.LoginSourceIP(q.R)
	what := sprintf("golog auth: login ok for %s from %s via %s", id.Name, ip, id.AuthType)
	if id.Principal != "" && !EqualFold(id.Principal, id.Name) {
		what += " as " + id.Principal
	}
	if id.Created {
		what += " (local user record created)"
	}
	logS(s, "%s", what)
}

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------

// LogoutHandler is the "?cmd=Logout" entry point. The session is dropped
// server-side first - deleting the cookie alone leaves a stolen id valid until
// its expiry - and then the cookie is expired in the browser. Logging out when
// there is no session is not an error and says nothing.
func (s *Server) LogoutHandler(q *Request) {
	if q == nil || q.W == nil || q.R == nil {
		return
	}
	if c, err := q.R.Cookie(s.LoginCookieName()); err == nil && c.Value != "" {
		if s.Sessions != nil {
			s.Sessions.Remove(c.Value)
		}
		logS(s, "golog auth: session of %s ended at logout", q.User)
	}
	s.ClearLoginCookie(q.W, q.R)
	q.User, q.FullName, q.Email = "", "", ""
	if q.LB != nil {
		s.showListPage(q)
		return
	}
	s.redirect(q, orText(q.redirParam(), s.BasePath+"/"))
}

// ---------------------------------------------------------------------------
// the password on the post form
// ---------------------------------------------------------------------------

// CheckFormPassword is the wpwd check of the submit and edit forms: elogd puts a
// "wpwd" field into the post form and compares it against the logbook's "User
// password" before it accepts an entry, which is a second, per-logbook secret
// rather than a login.
//
// The comparison is the constant-time one, the value is never logged, and the
// failure is counted against the source address exactly like a failed login: the
// field is a password, it sits in a form an anonymous visitor sees, and it used
// to be compared with "==" in request.go.
//
// It returns true when the request may go on: no password configured (nothing to
// check), no password submitted (the caller is anonymous or already logged in,
// and the permission check downstream decides), or a correct password.
func (s *Server) CheckFormPassword(q *Request) bool {
	if q == nil || s == nil {
		return false
	}
	given := q.Param("wpwd")
	want := s.Config.GetString(q.Cfg, "User password", "")
	if want == "" {
		return true // this logbook puts no password on its form
	}
	if given == "" {
		return false
	}
	ip := s.LoginSourceIP(q.R)
	if ok, why := s.loginBlocked("", ip); why != "" {
		Infof("golog auth: form password attempt refused from %s: %s", ip, why)
		_ = ok
		return false
	}
	if !constantTimeEqualString(given, want) {
		FailBanLogFailure(s, formPasswordUser(q), ip)
		FailBanFailure(s, formPasswordUser(q), ip)
		LoginThrottleFailure(s, formPasswordUser(q), ip)
		logS(s, "golog auth: wrong form password from %s for logbook %s", ip, q.Cfg.Group)
		return false
	}
	FailBanSuccess(s, formPasswordUser(q), ip)
	LoginThrottleSuccess(s, formPasswordUser(q), ip)
	return true
}

// formPasswordUser is the name the guards key a form-password failure under: the
// form carries no login of its own, so it is the identity on the request, or a
// fixed label for the anonymous poster.
func formPasswordUser(q *Request) string {
	if q != nil && q.User != "" {
		return q.User
	}
	return "(form-password)"
}

// ---------------------------------------------------------------------------
// the header identity of an already-authenticated request
// ---------------------------------------------------------------------------

// TrustedProxyUser is the name a trusted reverse proxy asserts for this request,
// or "" when the request is not from a trusted proxy or asserts nothing. It is
// the header back end's check, exposed for the request pipeline: a site that
// runs SSO through a proxy wants the identity on every request, not only on the
// one that posted a login form, and the session cookie then carries it through.
//
// Reading an assertion is not authentication. This function returns a name, and
// the caller must still decide what to do with it; the authentication decision
// is (*Server).AuthenticateLogin, which applies the group requirement, the
// optional password and the guards. A caller that simply trusts this value on a
// port reachable from clients has built a way in for anybody who can open a TCP
// connection: that is why the peer-address test is inside this function and
// cannot be left out by the caller.
func (s *Server) TrustedProxyUser(r *http.Request) string {
	if r == nil || s == nil {
		return ""
	}
	peer := hostOnly(r.RemoteAddr)
	if ipInNets(peer, trustedProxyNets(s)...) == "" {
		return ""
	}
	o := readHeaderOptions(s.Config, s.ScopeFor(""))
	if why := headerBadName(o.userHeader); why != "" {
		return ""
	}
	got, present, err := o.readHeaderAsserted(r.Header)
	if !present || err != nil {
		return ""
	}
	return o.normalise(got.user)
}

// ---------------------------------------------------------------------------
// the authentication state of the current request, for the pages
// ---------------------------------------------------------------------------

// LoginMethodInfo is what a status or configuration page shows about the login
// setup: enough for an operator to see what the daemon would do, and nothing an
// attacker can use (no bind password, no helper secret, no password file path).
type LoginMethodInfo struct {
	// Chain is the back ends in order, e.g. "LDAP+File".
	Chain string
	// Method is the guard and source-address summary.
	Guards string
	// Proxies is the trusted proxy list in force.
	Proxies string
	// Details is one line per back end.
	Details []string
}

// LoginMethod describes the login setup of this server for an operator.
func (s *Server) LoginMethod() LoginMethodInfo {
	var m LoginMethodInfo
	if s == nil {
		m.Chain = "none"
		m.Guards = "no server"
		m.Proxies = defaultTrustedProxyList
		return m
	}
	m.Chain = AuthenticationSummary(s)
	m.Guards = LoginGuardStats(s)
	m.Proxies = TrustedProxyList(s)
	for _, st := range s.AuthStatus() {
		if st.Details == "" {
			m.Details = append(m.Details, string(st.Name))
			continue
		}
		m.Details = append(m.Details, string(st.Name)+": "+st.Details)
	}
	return m
}

// WriteLoginMethod renders LoginMethod into w. A status page can call it rather
// than repeat the escaping.
func (s *Server) WriteLoginMethod(w http.ResponseWriter) {
	if w == nil {
		return
	}
	m := s.LoginMethod()
	var sb strings.Builder
	fmt.Fprintf(&sb, "login method: %s\n", HTMLEscape(m.Chain))
	fmt.Fprintf(&sb, "guards: %s\n", HTMLEscape(m.Guards))
	fmt.Fprintf(&sb, "trusted proxies: %s\n", HTMLEscape(m.Proxies))
	for _, d := range m.Details {
		fmt.Fprintf(&sb, "  %s\n", HTMLEscape(d))
	}
	_, _ = w.Write([]byte(sb.String()))
}

// loginDenied answers a refused-for-now login (ban or throttle) with 429 and a
// Retry-After header.
func (s *Server) loginDenied(q *Request, msg string, wait time.Duration) {
	if wait > 0 {
		q.W.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)))
	}
	s.errorf(q, http.StatusTooManyRequests, "%s", msg)
}

// loginUnavailable answers a login that could not be decided (directory down).
func (s *Server) loginUnavailable(q *Request, msg string) {
	s.errorf(q, http.StatusServiceUnavailable, "%s", msg)
}

// safeLocalTarget returns v when it is a path on this server ("/demo/12?x=1")
// and "" otherwise. A scheme, a host ("//evil.example", "/\evil.example") or a
// control character makes it unsafe: the value comes from a form field and ends
// up in a Location header after a login, where an off-site target would be an
// open redirect.
func safeLocalTarget(v string) string {
	v = strings.TrimSpace(v)
	if len(v) == 0 || '/' != v[0] {
		return ""
	}
	if len(v) > 1 && ('/' == v[1] || '\\' == v[1]) {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || 0x7f == v[i] || '\\' == v[i] {
			return ""
		}
	}
	return v
}

// redirParam is the "redir" form value, reduced to a local path.
func (q *Request) redirParam() string { return safeLocalTarget(q.Param("redir")) }
