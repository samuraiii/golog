// ELOG rewritten in Go - single sign-on through a trusted reverse proxy.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.
//
// Why there is no Kerberos in golog
// ---------------------------------
//
// This batch was asked for HTTP Negotiate (Kerberos/SPNEGO) single sign-on, and
// asked to check first whether a pure-Go implementation is possible with what is
// vendored. It is not, and the reason determines what an operator has to deploy,
// so it is recorded here:
//
//   * vendor/modules.txt contains github.com/go-ldap/ldap/v3 (plus asn1-ber and
//     google/uuid), golang.org/x/{net,sys,text} and golang.org/x/crypto holding
//     only md4, and github.com/Azure/go-ntlmssp. There is no Kerberos library:
//     no jcmturner/gokrb5, no SPNEGO or GSS-API package. Adding a module is not
//     allowed for this batch.
//   * Writing SPNEGO from scratch means ASN.1/DER for NegotiationToken
//     (NegTokenInit/NegTokenResp) plus the mechanism OIDs, then the GSS-API
//     per-message token wrapping of the Kerberos checksum (a 16-byte header plus
//     an RC4-HMAC or AES key-usage-recognised MIC, keyed from the session key of
//     the service ticket), then keytab parsing, then an AS-REQ/TGS-REQ client
//     with pre-authentication and enctype negotiation for the gologd service
//     principal, then NTLM as the fallback mechanism. That is several thousand
//     lines of security-critical protocol code, and this batch has no compiler
//     and no test request to check it with. It would be the least reviewable
//     authentication path in the program.
//   * The vendored github.com/Azure/go-ntlmssp is a client-side NTLM
//     implementation: it builds type 1 and type 3 messages and consumes type 2.
//     A server needs the opposite - to issue the type 2 challenge and to verify
//     the type 3 response against a stored password hash - which the package
//     does not export. So it is not a shortcut to a server either.
//
// What this file implements instead is the arrangement production ELOG and golog
// installations in an Active Directory forest actually use: a web server that
// already speaks Kerberos sits in front and tells gologd who the caller is, over
// a header, on a connection whose peer address is a known proxy.
//
//	IIS, Windows Authentication          ->  RequestHeader set X-Remote-User "%LOGON_USER%"
//	Apache + mod_auth_gssapi             ->  RequestHeader set X-Remote-User "%{REMOTE_USER}s"
//	nginx  + a Kerberos auth module      ->  proxy_set_header  X-Remote-User $remote_user
//
// gologd reads that header only from a peer in its trusted proxy list, so a
// client that reaches gologd directly and sends
//
//	GET / HTTP/1.1
//	X-Remote-User: admin
//
// gets nothing: the header is ignored, not "believed with a warning", because
// "believe it a little" is not a setting that survives contact with an attacker.
// The same mechanism also covers smart-card, OIDC-after-proxy and SAML-after-
// proxy front ends: the front end does whatever strong authentication it does
// and asserts the name.
//
// Configuration (global section; the C daemon has no equivalent, this is new):
//
//	Authentication          = Header         (also accepts Negotiate/SPNEGO/SSO/Kerberos/KRB5)
//	Header user header      = X-Remote-User  (header carrying the asserted name)
//	Header trusted proxies  = 10.0.0.5, 127.0.0.0/8
//	Header groups header    = X-Groups        (optional, comma separated)
//	Header fullname header  = X-Display-Name  (optional)
//	Header email header     = X-Email         (optional)
//	Header strip domain     = 1               (DOMAIN\user and user@dom -> user)
//	Header lowercase user   = 0
//	Header login group      = logbook-users   (optional: required group)
//	Header admin group      = logbook-admins  (optional: sets the admin flag)
//	Header create user      = 1               (write the local user record)
//	Header require password = 0               (also demand the local password)
//	Header max length       = 256

package golog

import (
	"fmt"
	"strings"
)

// headerOptions is the resolved configuration of the header back end.
type headerOptions struct {
	// userHeader names the header carrying the asserted login name.
	userHeader string
	// groupsHeader, nameHeader and mailHeader carry the optional extras; ""
	// means "not read".
	groupsHeader string
	nameHeader   string
	mailHeader   string
	// proxyList is the raw list from the configuration. The parsed networks come
	// from trustedproxy.go, which reads these keys plus the generic "Trusted
	// proxy" key so that one list can serve both features; this copy exists only
	// so that AuthDescription can print what was configured.
	proxyList []string
	// stripDomain turns "CORP\jdoe" and "jdoe@corp.example" into "jdoe". The
	// logbook access lists name plain accounts, and the front ends hand over all
	// three spellings depending on which module asserted the name.
	stripDomain bool
	lowercase   bool
	// loginGroup, when set, must appear among the asserted groups.
	loginGroup string
	adminGroup string
	// createUser writes the local password-file record on first login.
	createUser bool
	// requirePassword asks the local password file for a password after the proxy
	// asserted the name - a second factor as seen by somebody who bypassed the
	// proxy. Off by default: off is what makes single sign-on usable.
	requirePassword bool
	// maxHeaderLen bounds what a proxy may assert; a page-sized user name is an
	// attack, not a user, and the value lands in a log line, a session record and
	// possibly the password file.
	maxHeaderLen int
}

// readHeaderOptions reads the header back end's configuration. The options are
// read per attempt rather than once: the header name and the proxy list are the
// two things an operator edits while the daemon runs, and the cost is a few map
// lookups per login.
func readHeaderOptions(c *Config, scope ConfigScope) headerOptions {
	o := headerOptions{
		userHeader:      TrimSpaceASCII(c.GetStringDefault(scope, "Header user header", "X-Remote-User")),
		groupsHeader:    TrimSpaceASCII(c.GetStringDefault(scope, "Header groups header", "")),
		nameHeader:      TrimSpaceASCII(c.GetStringDefault(scope, "Header fullname header", c.GetStringDefault(scope, "Header name header", ""))),
		mailHeader:      TrimSpaceASCII(c.GetStringDefault(scope, "Header email header", c.GetStringDefault(scope, "Header mail header", ""))),
		stripDomain:     c.GetFlagDefault(scope, "Header strip domain", true),
		lowercase:       c.GetFlag(scope, "Header lowercase user"),
		loginGroup:      TrimSpaceASCII(c.GetStringDefault(scope, "Header login group", "")),
		adminGroup:      TrimSpaceASCII(c.GetStringDefault(scope, "Header admin group", "")),
		createUser:      c.GetFlagDefault(scope, "Header create user", true),
		requirePassword: c.GetFlag(scope, "Header require password"),
		proxyList:       c.GetList(scope, "Header trusted proxies"),
		maxHeaderLen:    c.GetInt(scope, "Header max length", 256),
	}
	if o.userHeader == "" {
		o.userHeader = "X-Remote-User"
	}
	if o.maxHeaderLen < 16 {
		o.maxHeaderLen = 16
	}
	return o
}

// headerAuthenticator is the Authenticator of this file.
type headerAuthenticator struct {
	// s is the server whose configuration, trusted proxy list and password file
	// are used. nil falls back to the running daemon through currentServer(),
	// like the file back end.
	s *Server
}

// newHeaderAuthenticator builds the back end for the selector.
func newHeaderAuthenticator(ctx AuthContext) Authenticator {
	return &headerAuthenticator{s: ctx.S}
}

// init registers this back end with the selector.
func init() {
	registerAuthenticator(AuthHeader, newHeaderAuthenticator)
}

// Name is the label used in the log and in a session record.
func (a *headerAuthenticator) Name() string { return AuthHeader }

// server resolves the server behind this back end.
func (a *headerAuthenticator) server() *Server {
	if a != nil && a.s != nil {
		return a.s
	}
	return currentServer()
}

// headerNameCanonical is the canonical MIME spelling of a header name, used in
// log lines so that "x-remote-user" and "X-Remote-User" are visibly one header.
func headerNameCanonical(name string) string {
	out := make([]byte, 0, len(name))
	upper := true
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch == '-':
			upper = true
			out = append(out, ch)
		case upper && ch >= 'a' && ch <= 'z':
			out = append(out, ch-32)
			upper = false
		default:
			upper = false
			out = append(out, ch)
		}
	}
	return string(out)
}

// headerBadName rejects a header name that Go's own header setter would refuse,
// so that a typo in the configuration shows up at the first login instead of
// silently never matching. "" means the name is usable.
func headerBadName(name string) string {
	if name == "" {
		return "the header name is empty"
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x21 || ch > 0x7e || ch == ':' {
			return fmt.Sprintf("the header name %q is not a valid HTTP field name", name)
		}
	}
	return ""
}

// headerAsserted is what a proxy claimed, before anything is trusted.
type headerAsserted struct {
	user   string
	groups []string
	full   string
	mail   string
}

// readHeaderAsserted pulls the assertion out of the headers without trusting it.
// The second result says that the user header was present at all: without it the
// back end abstains, which is what lets a login form still work on a server that
// is normally behind the proxy (the next back end in the chain, usually the
// password file, then gets its chance).
func (o headerOptions) readHeaderAsserted(h map[string][]string) (headerAsserted, bool, error) {
	var got headerAsserted
	if h == nil {
		return got, false, nil
	}
	vals := h[headerCanonicalKey(o.userHeader)]
	if len(vals) == 0 {
		return got, false, nil
	}
	// The same header twice: the proxy did not mean that, and choosing one
	// silently would let an attacker append his own assertion to a legitimate
	// request that a front end already signed.
	if len(vals) > 1 {
		return got, true, fmt.Errorf("%w: the %s header was sent %d times",
			ErrUnknownUser, headerNameCanonical(o.userHeader), len(vals))
	}
	raw := TrimSpaceASCII(vals[0])
	if len(raw) > o.maxHeaderLen {
		return got, true, fmt.Errorf("%w: the asserted name is too long", ErrUnknownUser)
	}
	// A control character in the value is either a broken front end or an
	// attempt to smuggle a second header, or a second log line, into the value.
	if strings.ContainsAny(raw, "\r\n\x00") {
		return got, true, fmt.Errorf("%w: the asserted name contains a control character", ErrUnknownUser)
	}
	if raw == "" {
		return got, false, nil
	}
	got.user = raw
	if o.groupsHeader != "" {
		gv := TrimSpaceASCII(firstHeaderValue(h[headerCanonicalKey(o.groupsHeader)]))
		// A group list is longer than a name by nature, but it is still bounded.
		if len(gv) <= 32*o.maxHeaderLen {
			for _, g := range SplitList(gv, ",", false) {
				if g != "" && !strings.ContainsAny(g, "\r\n\x00") {
					got.groups = append(got.groups, g)
				}
			}
		}
	}
	if o.nameHeader != "" {
		if v := TrimSpaceASCII(firstHeaderValue(h[headerCanonicalKey(o.nameHeader)])); len(v) <= o.maxHeaderLen {
			got.full = strings.ReplaceAll(v, "\t", " ")
		}
	}
	if o.mailHeader != "" {
		if v := TrimSpaceASCII(firstHeaderValue(h[headerCanonicalKey(o.mailHeader)])); len(v) <= o.maxHeaderLen {
			if !strings.ContainsAny(v, "\t \x00") && strings.Contains(v, "@") {
				got.mail = v
			}
		}
	}
	return got, true, nil
}

// firstHeaderValue is the first element of a header value slice, "" when empty.
func firstHeaderValue(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// headerCanonicalKey is http.CanonicalHeaderKey without importing net/textproto
// for one call: both implement the RFC 7230 rule "upper case the first letter of
// each dash-separated word, leave the rest as sent", and the keys of an
// http.Header are in that form.
func headerCanonicalKey(k string) string {
	b := []byte(k)
	upper := true
	for i := 0; i < len(b); i++ {
		ch := b[i]
		switch {
		case ch == '-':
			upper = true
		case upper && ch >= 'a' && ch <= 'z':
			b[i] = ch - 32
			upper = false
		default:
			upper = false
		}
	}
	return string(b)
}

// normalise applies the configured name normalisation.
func (o headerOptions) normalise(raw string) string {
	u := TrimSpaceASCII(raw)
	if o.stripDomain {
		// DOMAIN\user, the form IIS and some Apache modules assert.
		if i := strings.LastIndexByte(u, '\\'); i >= 0 && i+1 < len(u) {
			u = u[i+1:]
		}
		// user@domain, the UPN form and the usual REMOTE_USER.
		if i := strings.IndexByte(u, '@'); i > 0 {
			u = u[:i]
		}
	}
	if o.lowercase {
		u = strings.ToLower(u)
	}
	return u
}

// Authenticate accepts the caller that a trusted proxy asserted.
//
// The order of the checks IS the security of the arrangement, so it is spelled
// out in this order in the code as well:
//
//  1. Is the peer address one of the trusted proxies? If not, the header is
//     ignored completely and the attempt is logged, because it is worth knowing
//     that somebody tried. Nothing else is examined.
//  2. Is there an assertion at all? Without one this back end abstains.
//  3. Does the asserted name survive the sanity checks (repeated header, length,
//     control characters)?
//  4. Does the caller belong to the group "Header login group" requires?
//  5. Optionally: does he also know the local password?
//
// A rejected caller gets ErrUnknownUser or ErrBadPassword, which the chain counts
// against the login throttle, and never a detail saying which check failed; the
// log line carries that for the operator, and the login page must not tell an
// attacker whether the name or the group was wrong.
func (a *headerAuthenticator) Authenticate(ctx AuthContext) (Identity, error) {
	var id Identity
	s := a.server()
	c := ctx.config()
	o := readHeaderOptions(c, ctx.scope())

	if why := headerBadName(o.userHeader); why != "" {
		logS(s, "golog auth: header back end is unusable: %s", why)
		return id, AuthUnavailablef("header back end: %s", why)
	}

	// (1) Is this connection from a proxy we believe? PeerIP is the address of
	// the TCP peer; RemoteIP is the address the attempt is attributed to, which
	// is the peer unless a trusted proxy told us otherwise. A call site that
	// fills in only the latter still works: in a chain run from a login handler
	// the two are equal whenever no proxy is involved.
	peer := TrimSpaceASCII(ctx.RemoteIP)
	if peer == "" {
		peer = TrimSpaceASCII(ctx.RemoteIP)
	}
	if ipInNets(peer, trustedProxyNets(s)...) == "" {
		have := ""
		if len(ctx.Header[headerCanonicalKey(o.userHeader)]) > 0 {
			have = ", which carried an asserted name that was ignored"
		}
		logS(s, "golog auth: header back end ignored a request from %s: the peer is not a trusted proxy%s",
			orUnknownPeer(peer), have)
		return id, fmt.Errorf("%w: no assertion from a trusted proxy", ErrUnknownUser)
	}

	// (2) and (3) the assertion itself.
	asserted, present, err := o.readHeaderAsserted(ctx.Header)
	if err != nil {
		logS(s, "golog auth: %v (peer %s)", err, orUnknownPeer(peer))
		return id, err
	}
	if !present {
		return id, fmt.Errorf("%w: the trusted proxy did not assert a user", ErrUnknownUser)
	}
	name := o.normalise(asserted.user)
	if name == "" {
		return id, fmt.Errorf("%w: the asserted name is empty after normalisation", ErrUnknownUser)
	}

	// (4) the group requirement, then the identity.
	id.Name = name
	id.Groups = asserted.groups
	id.FullName = asserted.full
	id.Email = asserted.mail
	id.AuthType = strings.ToLower(AuthHeader)
	id.Principal = asserted.user
	if o.loginGroup != "" && !headerHasGroup(id.Groups, o.loginGroup) {
		// The proxy vouched for the identity; the configuration says this
		// identity may not use the logbook. A refusal, not an unavailability, so
		// it is counted like a wrong password.
		logS(s, "golog auth: %s is not a member of the group %q asserted by the proxy", name, o.loginGroup)
		return id, fmt.Errorf("%w: %s", ErrUnknownUser, name)
	}
	if o.adminGroup != "" && headerHasGroup(id.Groups, o.adminGroup) {
		id.Admin = true
	}

	// (5) the optional second factor.
	if o.requirePassword {
		pf := ctx.pwdFile()
		if pf == nil {
			return id, AuthUnavailablef("\"Header require password\" is set but this server has no password file")
		}
		u := pf.User(name)
		if u == nil {
			u = pwdUserFold(pf, name)
		}
		if u == nil {
			return id, fmt.Errorf("%w: %s", ErrUnknownUser, name)
		}
		if u.IsInactive() {
			return id, fmt.Errorf("%w: %s is expired", ErrBadPassword, u.Name)
		}
		if ctx.Password == "" || !VerifyStoredPassword(ctx.Password, u.Password) {
			return id, fmt.Errorf("%w: %s", ErrBadPassword, u.Name)
		}
		// The local record wins for the display name and the address: those are
		// the two fields the user may edit himself on the user page, and an
		// asserted value would silently overwrite his own setting on every login.
		if u.FullName != "" {
			id.FullName = u.FullName
		}
		if u.Email != "" {
			id.Email = u.Email
		}
	}

	// The local record that the user page, the subscription list and the mail
	// notification need.
	if o.createUser && s != nil && s.Pwd != nil {
		id.Created = s.ensurePwdUser(name, id.FullName, id.Email, true, true)
	}
	return id, nil
}

// headerHasGroup is the membership test of an asserted group list. Front ends
// differ wildly in how they spell a group (a full DN, the bare name,
// DOMAIN\name), so besides the exact case-insensitive comparison the test
// accepts the first RDN of a DN and the part after DOMAIN\. It deliberately does
// NOT do a substring match: "logbook-admins" must not be satisfied by
// "not-logbook-admins-x".
func headerHasGroup(have []string, want string) bool {
	want = TrimSpaceASCII(want)
	if want == "" {
		return true
	}
	for _, h := range have {
		h = TrimSpaceASCII(h)
		if h == "" {
			continue
		}
		if EqualFold(h, want) {
			return true
		}
		// DN form: the first RDN of "CN=logbook-admins,OU=Groups,DC=corp".
		first := h
		if i := strings.IndexByte(first, ','); i >= 0 {
			first = first[:i]
		}
		if i := strings.IndexByte(first, '='); i >= 0 && i+1 < len(first) {
			first = first[i+1:]
		}
		if EqualFold(TrimSpaceASCII(first), want) {
			return true
		}
		// DOMAIN\group.
		if i := strings.LastIndexByte(h, '\\'); i >= 0 && EqualFold(h[i+1:], want) {
			return true
		}
	}
	return false
}

// orUnknownPeer keeps a missing address readable in a log line.
func orUnknownPeer(ip string) string {
	if TrimSpaceASCII(ip) == "" {
		return "(unknown)"
	}
	return TrimSpaceASCII(ip)
}

// AuthDescription is this back end's line of (*Server).AuthStatus.
func (a *headerAuthenticator) AuthDescription() string {
	s := a.server()
	var c *Config
	if s != nil {
		c = s.Config
	}
	if c == nil {
		c = ParseConfig("")
	}
	o := readHeaderOptions(c, ConfigScope{Group: "global"})
	list := o.proxyList
	if len(list) == 0 {
		list = []string{defaultTrustedProxyList}
	}
	parts := []string{
		"a reverse proxy asserts the name in " + headerNameCanonical(o.userHeader),
		"trusted proxies " + strings.Join(list, ", "),
	}
	if o.createUser {
		parts = append(parts, "creates the local user record")
	}
	if o.requirePassword {
		parts = append(parts, "also requires the local password")
	} else {
		parts = append(parts, "checks no password: whoever reaches this port directly and sends the header is in, so keep the port closed")
	}
	return strings.Join(parts, "; ")
}
