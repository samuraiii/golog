// ELOG rewritten in Go - the authentication front end: one interface, one
// configuration-driven selector, one entry point.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// why this file exists
// ---------------------------------------------------------------------------
//
// The C daemon grew its authentication as a chain of tests inside one function:
// check_loginput() (elogd.cxx) compares the typed password against the XML
// password file, and when "Auth type" says "ldap"/"KRB5" it calls the matching
// library instead (src/auth.cxx authenticate_user_ldap()). Only one method can be
// configured, a broken directory means "nobody can log in", and the same
// comparison code is repeated in check_editinput() and in the e-mail confirmation
// path.
//
// This file is the seam this batch introduces:
//
//	Authenticator       one way of proving an identity (file, directory, proxy,
//	                    helper binary)
//	AuthChain           several of them, tried in order
//	NewAuthenticators   the table-driven selector driven by "Authentication"
//	(*Server).AuthenticateLogin
//	                    the single entry point that consults the login throttle
//	                    and the fail ban BEFORE any back end is asked
//
// Nothing else in the package should compare a password again; the call sites in
// request.go/handlers.go go through AuthenticateLogin (see MERGE-NOTES.md).

// ---------------------------------------------------------------------------
// identity and context
// ---------------------------------------------------------------------------

// Identity is what a back end reports about a caller who proved who he claimed to
// be.
type Identity struct {
	// Name is the account name to record in the session, the log and the
	// "Author" field. A back end may normalise the spelling the caller typed: a
	// directory entry has its own case, and "JDOE" and "jdoe" must not become two
	// identities in the logbook.
	Name string
	// FullName and Email are the display name and the address to seed a new user
	// record with; either may be empty.
	FullName string
	Email    string
	// Groups are the groups the back end knows the caller belongs to: the
	// directory's membership, the groups a proxy asserted, or the groups named in
	// the configuration. accessors.go maps them onto logbook rights.
	Groups []string
	// AuthType goes into the session record ("file", "ldap", "header",
	// "external").
	AuthType string
	// Admin says the back end knows this caller is an administrator (a member of
	// the configured admin group), which the caller may use to grant the
	// configuration editor and the user page.
	Admin bool
	// Created says the back end also created the local user record on the way,
	// which the login page reports and the mailer may use.
	Created bool
	// Principal is the directory identity behind the login (the user DN or the
	// UPN that was bound). It is not shown to the user; it is what a
	// re-authentication or an audit line needs. Empty for the file back end.
	Principal string
}

// AuthContext is the input of one authentication attempt.
type AuthContext struct {
	// User is the claimed name, trimmed by the caller.
	User string
	// Password is the secret. This package never logs it and never puts it in an
	// error message.
	Password string
	// RemoteIP is the address the attempt is attributed to: the peer address, or
	// the client behind a trusted reverse proxy (see trustedproxy.go).
	RemoteIP string
	// Header carries the request headers for the back ends that read them (the
	// trusted-proxy header path). It may be nil.
	Header http.Header
	// S is the server the attempt belongs to; nil only in tests, where the
	// configuration-dependent parts fall back to defaults.
	S *Server
	// Req is the request behind the attempt, when there is one. It is not used by
	// the front end; a back end that needs more than Header may use it. It is
	// never used to decide whether a login is accepted.
	Req *http.Request
}

// scope is the configuration scope the back ends read their options from.
// Authentication is configured globally in practice (the password file and the
// directory are process-wide), so the global scope is the base; a logbook that
// repeats the keys wins because Config.Get falls back to global, not the other
// way round - which is why the server's own scope is used when there is a server.
func (ctx AuthContext) scope() ConfigScope {
	if ctx.S != nil {
		return ctx.S.ScopeFor("")
	}
	return ConfigScope{Group: "global"}
}

// config is the configuration behind the context, or an empty one, so that a back
// end reads its options through the same helpers without a nil check.
func (ctx AuthContext) config() *Config {
	if ctx.S != nil && ctx.S.Config != nil {
		return ctx.S.Config
	}
	return ParseConfig("")
}

// pwdFile is the password file of the server, nil when there is none. The
// directory and helper back ends use it for the optional "create the user on first
// login" behaviour and for the "then try the password file too" fallback.
func (ctx AuthContext) pwdFile() *PwdFile {
	if ctx.S != nil {
		return ctx.S.Pwd
	}
	return nil
}

// ---------------------------------------------------------------------------
// the answers
// ---------------------------------------------------------------------------

// The three answers a back end gives about the caller himself.
var (
	// ErrUnknownUser is "no such account here".
	ErrUnknownUser = errors.New("golog: unknown user")
	// ErrBadPassword is "the account exists, the secret is wrong".
	ErrBadPassword = errors.New("golog: wrong password")
	// ErrAuthUnavailable is "this back end could not be consulted"; the message
	// ends up in the daemon log and, stripped of detail, in the login page - so it
	// must name the failing component, never a secret.
	ErrAuthUnavailable = errors.New("golog: authentication service unavailable")
	// ErrNoAuthenticator is "no back end is configured at all": it is reported
	// with 503 rather than 401, because it is the daemon that cannot answer.
	ErrNoAuthenticator = errors.New("golog: no authentication method is configured")
)

// AuthUnavailablef builds an ErrAuthUnavailable carrying a reason.
func AuthUnavailablef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAuthUnavailable, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// the interface
// ---------------------------------------------------------------------------

// Authenticator is one way of proving an identity.
//
// A back end answers with ErrUnknownUser or ErrBadPassword when the caller is
// rejected, and with an error wrapping ErrAuthUnavailable when it could not be
// consulted at all (directory down, helper missing, KDC unreachable). The
// distinction is not cosmetic: a refused login is counted by the throttle and the
// ban list, an unavailable back end must not be, or one dead directory locks every
// operator out.
//
// A back end must never log the password and must not write to the response.
type Authenticator interface {
	// Name is the label used in logs and messages; it is the canonical spelling
	// of the "Authentication" configuration value that selects it.
	Name() string
	// Authenticate is called with the claimed name and the secret.
	Authenticate(ctx AuthContext) (Identity, error)
}

// ---------------------------------------------------------------------------
// the chain
// ---------------------------------------------------------------------------

// AuthChain tries its members in order; the first success wins.
type AuthChain []Authenticator

// NewAuthChain returns the chain over the given back ends.
func NewAuthChain(a ...Authenticator) AuthChain { return AuthChain(a) }

// List is the chain as a slice, for the status page and for a caller that wants
// to describe or close the members without running them.
func (ch AuthChain) List() []Authenticator { return []Authenticator(ch) }

// Len is the number of back ends, so that a caller can test for "no method at
// all" without naming the type.
func (ch AuthChain) Len() int { return len(ch) }

// Name is the chain's label, e.g. "LDAP+File".
func (ch AuthChain) Name() string {
	if len(ch) == 0 {
		return "none"
	}
	var sb strings.Builder
	for i, a := range ch {
		if i != 0 {
			sb.WriteString("+")
		}
		if a != nil {
			sb.WriteString(a.Name())
		}
	}
	return sb.String()
}

// Authenticate asks every back end in turn. A back end that answers "unavailable"
// is logged and skipped; if every back end was unavailable the caller learns that
// login is impossible right now (503), which is honest and does not invite him to
// keep typing. Otherwise the error of the back end that actually rejected the
// caller is returned, so that a "wrong password" from the second method is not
// hidden behind an "unknown user" from the first.
func (ch AuthChain) Authenticate(ctx AuthContext) (Identity, error) {
	var id Identity
	var last error
	asked, unavailable := 0, 0
	for _, a := range ch {
		if a == nil {
			continue
		}
		asked++
		got, err := a.Authenticate(ctx)
		switch {
		case err == nil:
			if TrimSpaceASCII(got.Name) == "" {
				got.Name = TrimSpaceASCII(ctx.User)
			}
			if got.AuthType == "" {
				got.AuthType = strings.ToLower(a.Name())
			}
			return got, nil
		case errors.Is(err, ErrAuthUnavailable):
			unavailable++
			logS(ctx.S, "golog auth: %s not usable, trying the next method: %v", a.Name(), err)
		case errors.Is(err, ErrBadPassword), errors.Is(err, ErrUnknownUser):
			last = err
		default:
			last = err
		}
	}
	switch {
	case last != nil:
		return id, last
	case asked > 0 && unavailable == asked:
		return id, AuthUnavailablef("every configured method (%s) was unreachable", ch.Name())
	case asked == 0:
		return id, ErrNoAuthenticator
	}
	return id, ErrUnknownUser
}

// ---------------------------------------------------------------------------
// the selector
// ---------------------------------------------------------------------------

// The canonical names are what a session records and what the "Authentication"
// configuration value is normalised to.
const (
	AuthFile     = "File"
	AuthLDAP     = "LDAP"
	AuthNTLM     = "NTLM"
	AuthHeader   = "Header"
	AuthExternal = "External"
)

// newAuthenticator maps a canonical name onto its constructor. Each back end file
// adds its entry in its own init(), so this file does not need to know the
// constructors and a back end stays self-contained.
var (
	authenticatorRegisterMu sync.Mutex
	newAuthenticator        = map[string]func(ctx AuthContext) Authenticator{}
)

// registerAuthenticator adds one back end to the selector.
func registerAuthenticator(canonicalName string, f func(ctx AuthContext) Authenticator) {
	authenticatorRegisterMu.Lock()
	defer authenticatorRegisterMu.Unlock()
	newAuthenticator[canonicalName] = f
}

// RegisteredAuthenticators is the sorted list of the canonical names the selector
// knows about, for an error message and for the status page.
func RegisteredAuthenticators() []string {
	authenticatorRegisterMu.Lock()
	defer authenticatorRegisterMu.Unlock()
	out := make([]string, 0, len(newAuthenticator))
	for n := range newAuthenticator {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// authTypeAliases maps one configuration value onto the canonical name of the back
// end it selects. The C daemon spells its choices "Basic", "LDAP" and "KRB5" (the
// "Auth type" key), so the historical spellings keep working.
//
// "Kerberos"/"Negotiate"/"SSO" deliberately land on the trusted-header back end:
// native Kerberos/SPNEGO is NOT implemented (see authheader.go for the reason and
// for what to configure instead).
func authTypeAliases(name string) string {
	switch strings.ToLower(TrimSpaceASCII(name)) {
	case "file", "basic", "password", "xml", "local":
		return AuthFile
	case "ldap", "ad", "activedirectory", "active directory", "active-directory":
		return AuthLDAP
	case "ntlm", "windows", "ntlmssp":
		return AuthNTLM
	case "header", "proxy", "negotiate", "spnego", "sso", "krb5", "kerberos":
		return AuthHeader
	case "external", "helper", "pam":
		return AuthExternal
	default:
		return ""
	}
}

// authenticationValue returns the raw value of the key that selects the back ends:
// the new "Authentication" (a list, tried in order) or the C daemon's "Auth type"
// (a single value), so an existing elogd.cfg keeps working.
func authenticationValue(c *Config, cfg ConfigScope) string {
	if c == nil {
		return ""
	}
	if v, ok := c.Get(cfg, "Authentication"); ok && TrimSpaceASCII(v) != "" {
		return TrimSpaceASCII(v)
	}
	if v, ok := c.Get(cfg, "Auth type"); ok && TrimSpaceASCII(v) != "" {
		return TrimSpaceASCII(v)
	}
	return ""
}

// authTypeIsOff reports the value that switches authentication off entirely.
// Spelled as a function rather than a map so that the negative spellings cannot
// disagree with each other.
func authTypeIsOff(name string) bool {
	switch strings.ToLower(TrimSpaceASCII(name)) {
	case "none", "off", "disabled", "no", "false", "0":
		return true
	}
	return false
}

// NewAuthenticators builds the chain named by the "Authentication" key, which may
// be a comma separated list tried in order ("LDAP, File").
//
// Four rules shape the result:
//
//   - An absent key gives the file back end alone, which is what the C daemon does
//     when "Auth type" is unset.
//   - Unless the key names it explicitly, the file back end is appended last: the
//     local emergency account and the service accounts that only exist in the
//     password file must keep working when a directory is configured, because that
//     is how every site that ran elogd with "Auth type = ldap" got back in after
//     the directory broke.
//   - An unknown value is reported and skipped rather than quietly treated as the
//     file back end, so a typo shows up in the log instead of silently changing who
//     may log in.
//   - "Authentication = none" is reported in the log and still leaves the file
//     back end: authentication cannot be switched off by a configuration typo,
//     because the daemon serves the logbooks either way and a chain that accepts
//     nobody is the only safe reading of an empty chain.
func NewAuthenticators(s *Server, cfg ConfigScope) (AuthChain, error) {
	var c *Config
	if s != nil {
		c = s.Config
	}
	ctx := AuthContext{S: s}
	value := authenticationValue(c, cfg)
	names := SplitList(value, ",", false)
	if len(names) == 0 {
		return AuthChain{newFileAuthenticator(ctx)}, nil
	}
	var out AuthChain
	var unknown []string
	seen := map[string]bool{}
	for _, n := range names {
		if authTypeIsOff(n) {
			continue
		}
		canon := authTypeAliases(n)
		if canon == "" {
			unknown = append(unknown, n)
			continue
		}
		if seen[canon] {
			continue
		}
		authenticatorRegisterMu.Lock()
		f := newAuthenticator[canon]
		authenticatorRegisterMu.Unlock()
		if f == nil {
			// Named but not built into this binary: say so, because the
			// operator believes he configured something.
			unknown = append(unknown, n)
			continue
		}
		seen[canon] = true
		if a := f(ctx); a != nil {
			out = append(out, a)
		}
	}
	if len(unknown) > 0 {
		Logf("golog auth: unknown Authentication value %q (known: %s, none)",
			strings.Join(unknown, ", "), strings.Join(RegisteredAuthenticators(), ", "))
	}
	if len(out) == 0 {
		if allOff(names) {
			Logf("golog auth: Authentication = none is not honoured: log-in stays on the " +
				"password file, so a typo cannot open or close the whole server")
		}
		return AuthChain{newFileAuthenticator(ctx)}, nil
	}
	if !seen[AuthFile] {
		out = append(out, newFileAuthenticator(ctx))
	}
	return out, nil
}

// allOff reports a value that names nothing but "none"/"off".
func allOff(names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if !authTypeIsOff(n) {
			return false
		}
	}
	return true
}

// AuthenticationSummary is a one-line description of the configured chain for the
// status page and the start-up log.
func AuthenticationSummary(s *Server) string {
	ch := s.Authenticators()
	if len(ch) == 0 {
		return "none"
	}
	return ch.Name()
}

// ---------------------------------------------------------------------------
// the chain cache
// ---------------------------------------------------------------------------

// authChainCache holds one chain per server. The back ends keep a connection pool
// and an already-issued helper configuration, so they must not be rebuilt per
// request; ResetAuthenticators drops the entry.
var (
	authChainMu    sync.Mutex
	authChainCache = map[*Server]AuthChain{}
)

// Authenticators returns the authentication chain of the server, building it on
// first use. A nil server gets the file back end alone, so that a test or a
// command-line check has something to call.
func (s *Server) Authenticators() AuthChain {
	if s == nil {
		return AuthChain{newFileAuthenticator(AuthContext{})}
	}
	authChainMu.Lock()
	defer authChainMu.Unlock()
	if ch, ok := authChainCache[s]; ok {
		return ch
	}
	ch, err := NewAuthenticators(s, s.ScopeFor(""))
	if err != nil {
		logS(s, "golog auth: %v", err)
	}
	if len(ch) == 0 {
		// Never an empty chain: see NewAuthenticators. An empty chain would make
		// every login an "unavailable" and hide the configuration error behind a
		// 503 that says "authentication is disabled on this server".
		ch = AuthChain{newFileAuthenticator(AuthContext{S: s})}
	}
	authChainCache[s] = ch
	return ch
}

// ResetAuthenticators drops the cached chain so the next request rebuilds it from
// the re-read configuration, and closes the pools of the old one. Call it wherever
// SIGHUP / ReloadConfig is handled (one line, see MERGE-NOTES.md).
func (s *Server) ResetAuthenticators() {
	if s == nil {
		return
	}
	authChainMu.Lock()
	old := authChainCache[s]
	delete(authChainCache, s)
	authChainMu.Unlock()
	InvalidateTrustedProxyCache(s)
	for _, a := range old {
		if c, ok := a.(interface{ Close() error }); ok {
			if err := c.Close(); err != nil {
				logS(s, "golog auth: closing %s: %v", a.Name(), err)
			}
		}
	}
	ReloadLoginGuards(s)
}

// ---------------------------------------------------------------------------
// the entry point
// ---------------------------------------------------------------------------

// AuthenticateLogin is what a login handler calls. It consults the login throttle
// and the fail ban BEFORE any back end is asked, runs the chain, and records the
// outcome in both guards.
//
// The order is the reason the function exists: a throttled or banned caller causes
// no password comparison, no directory round trip, no helper process.
//
// The error tells the caller what to answer:
//
//	LoginBlocked(err)                   -> 429 with Retry-After: LoginWait(err)
//	ErrBadPassword / ErrUnknownUser     -> 401, redraw the login page
//	ErrAuthUnavailable                  -> 503 "login is not possible right now"
func (s *Server) AuthenticateLogin(r *http.Request, user, password string) (Identity, error) {
	var id Identity
	user = TrimSpaceASCII(user)
	if user == "" {
		return id, ErrUnknownUser
	}
	ip := s.loginSourceIPFor(r)
	if wait, why := s.loginBlocked(user, ip); why != "" {
		return id, newAuthBlockedError(why, wait)
	}
	ch := s.Authenticators()
	if len(ch) == 0 {
		return id, ErrNoAuthenticator
	}
	ctx := AuthContext{User: user, Password: password, RemoteIP: ip, S: s, Req: r}
	if r != nil {
		ctx.Header = r.Header
	}
	id, err := ch.Authenticate(ctx)
	if err != nil {
		if IsAuthUnavailable(err) || LoginBlocked(err) {
			// A broken back end must not burn the caller's allowance and must not
			// be reported to him as "wrong password". A blocked error came out of
			// the guards and is already counted.
			logS(s, "golog auth: login for %q from %s failed: %v", user, ip, err)
			return id, err
		}
		s.recordLoginFailure(user, ip)
		if delay := LoginThrottleDelay(s); delay > 0 {
			// Only on the failure path: a correct login is never slowed down.
			time.Sleep(delay)
		}
		return id, err
	}
	s.recordLoginSuccess(user, ip)
	logS(s, "golog auth: login ok for %s from %s via %s", user, ip, id.AuthType)
	return id, nil
}

// loginSourceIPFor is LoginSourceIP with a nil-server fallback: a test or a
// command-line check has no server, and "no server" must not read as
// "the whole internet".
func (s *Server) loginSourceIPFor(r *http.Request) string {
	if s == nil {
		if r == nil {
			return ""
		}
		return hostOnly(r.RemoteAddr)
	}
	return s.LoginSourceIP(r)
}

// loginBlocked is the pre-backend gate: the login throttle first, then the fail
// ban. Both layers and their answer live in authguard.go; this is the shape this
// file's entry point wants: the seconds to advertise in Retry-After and the
// browser-visible reason, with an empty reason meaning "let him through".
func (s *Server) loginBlocked(user, ip string) (int, string) {
	blocked, secs, why, key := s.LoginGuardBlocked(user, ip)
	if !blocked {
		return 0, ""
	}
	logS(s, "golog auth: login refused before any back end (%s)", key)
	if why == "" {
		why = "Too many failed logins. Try again later."
	}
	return secs, why
}

// recordLoginFailure tells both guards that one login attempt failed and writes the
// line the fail2ban filter matches. The order matters only for the log: the audit
// line comes first, so an operator (and fail2ban) sees the attempt even when the
// ban bookkeeping then fails to write its state file.
func (s *Server) recordLoginFailure(user, ip string) {
	FailBanLogFailure(s, user, ip)
	FailBanFailure(s, user, ip)
	LoginThrottleFailure(s, user, ip)
}

// recordLoginSuccess tells both guards that the caller proved who he is.
func (s *Server) recordLoginSuccess(user, ip string) {
	FailBanSuccess(s, user, ip)
	LoginThrottleSuccess(s, user, ip)
}

// LoginAuditLog writes the line an external fail2ban jail counts. It is called for
// every rejected login (including the ones refused before a back end ran) and for
// every ban; see docs/fail2ban/.
func (s *Server) LoginAuditLog(format string, args ...any) {
	logS(s, format, args...)
}

// ---------------------------------------------------------------------------
// the errors a login handler branches on
// ---------------------------------------------------------------------------

// newAuthBlockedError builds the "come back later" error of a throttled or banned
// client. The type itself, its Error/Is/Unwrap methods and the Retry-After
// arithmetic are in authguard.go, where the guards live.
func newAuthBlockedError(why string, wait int) error {
	return newBlockedError(why, wait, "")
}

// LoginBlocked reports whether err means "come back later"; a handler answers
// those with 429 and Retry-After instead of another wrong-password message.
func LoginBlocked(err error) bool {
	var g *BlockedError
	return errors.As(err, &g)
}

// LoginWait is the Retry-After value of a blocked login (0 when err is not a
// blocking error).
func LoginWait(err error) int {
	var g *BlockedError
	if errors.As(err, &g) {
		return g.Secs
	}
	return 0
}

// IsAuthUnavailable reports whether err means "a back end could not be consulted",
// which is never counted against the caller and is answered 503 rather than 401.
// Login refusals are not in here: those are a deliberate answer to the caller.
func IsAuthUnavailable(err error) bool {
	return err != nil && errors.Is(err, ErrAuthUnavailable)
}

// LoginErrorMessage is what a login page shows for err: the caller must learn that
// the service is down (otherwise he keeps typing his password at a directory that
// is not answering) but must not learn anything that helps an attacker probe the
// infrastructure.
func LoginErrorMessage(err error) string {
	switch {
	case err == nil:
		return ""
	case LoginBlocked(err):
		return "Too many failed logins. Try again later."
	case IsAuthUnavailable(err), errors.Is(err, ErrNoAuthenticator):
		return "Login is not possible at the moment; please try again shortly."
	case errors.Is(err, ErrBadPassword), errors.Is(err, ErrUnknownUser):
		return "Wrong user name or password."
	default:
		return "Login failed."
	}
}

// ---------------------------------------------------------------------------
// where a login attempt came from
// ---------------------------------------------------------------------------
//
// The address a login is attributed to and the "Trusted proxy" list behind it are
// declared once, in trustedproxy.go: (*Server).LoginSourceIP, trustedProxyNets,
// ParseTrustedProxies, leftmostForwarded, hostOnly and ipInNets. This file only
// adds the exported predicate the header back end and the status page ask for.

// IsTrustedProxy reports whether an address came from a declared proxy. The
// address may carry a port.
func (s *Server) IsTrustedProxy(addr string) bool {
	return ipInNets(hostOnly(addr), trustedProxyNets(s)...) != ""
}

// ---------------------------------------------------------------------------
// identity -> rights
// ---------------------------------------------------------------------------

// GroupsForUser is the group list of a logged-in user as far as golog can see it:
// what the back end asserted (a directory's memberOf, a proxy header) plus the
// groups the configuration assigns to that name, so that a site can keep its
// group assignments in the configuration file and let the directory supply the
// identity.
//
// The local password file cannot carry groups: elogd's <user> record has no group
// element (auth.go's PwdUser has Name, Password, FullName, LastLogout,
// LastActivity, Email, EmailNotify and Inactive and nothing else), so inventing
// one here would change the on-disk format this batch must keep. Group membership
// therefore comes from the back end, and the configuration keys "Login user",
// "Admin user" and "Write user access" keep matching on the name.
func (s *Server) GroupsForUser(name string, asserted []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(g string) {
		g = TrimSpaceASCII(g)
		if g == "" || seen[strings.ToLower(g)] {
			return
		}
		seen[strings.ToLower(g)] = true
		out = append(out, g)
	}
	for _, g := range asserted {
		add(g)
	}
	if s != nil && s.Config != nil {
		// "User groups = <group list>" repeated per name is not an elogd key, so
		// this reads only what a golog site can configure today: the two group
		// names that carry meaning, granted by name below.
		g := ConfigScope{Group: "global"}
		for _, e := range SplitList(s.Config.GetString(g, "Group map", ""), ";", false) {
			// "Group map = GroupA = jdoe, jsmith; GroupB = *@corp.example"
			group, members, found := strings.Cut(e, "=")
			if !found {
				continue
			}
			group = TrimSpaceASCII(group)
			for _, m := range SplitList(members, ",", false) {
				if EqualFold(m, name) || (strings.HasSuffix(m, "*") &&
					HasPrefixFold(name, strings.TrimSuffix(m, "*"))) {
					add(group)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// IdentityIsAdmin reports the administrator flag of an identity: what the back end
// said, or membership of one of the groups named by "Super admin group" in the
// global configuration.
func (s *Server) IdentityIsAdmin(id Identity) bool {
	if id.Admin {
		return true
	}
	if s == nil || s.Config == nil {
		return false
	}
	g := ConfigScope{Group: "global"}
	want := SplitList(s.Config.GetString(g, "Super admin group", ""), ",", false)
	if len(want) == 0 {
		return false
	}
	for _, have := range id.Groups {
		for _, w := range want {
			if EqualFold(have, w) {
				return true
			}
		}
	}
	return false
}
