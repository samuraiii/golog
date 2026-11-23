package golog

// HTTP plumbing for the authentication interface: the two log helpers that every
// authentication file uses, the session/cookie half of a login, the mapping of an
// authentication error onto an HTTP status, and a status summary of the active
// authentication back ends.
//
// Nothing in here decides whether a login is accepted: that is
// (*Server).AuthenticateLogin in authiface.go together with the back ends.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// logS writes one log line through the server when there is one and through the
// package logger when there is not, so that no authentication path can lose a
// message because a *Server happens to be nil (unit tests, background jobs).
// The server's own Logf holds its log mutex, so the line cannot be interleaved
// with another goroutine's line. It never takes a password: pass the user name
// and the reason, and keep the secret out of the arguments.
func logS(s *Server, format string, args ...any) {
	if s != nil {
		s.Logf(format, args...)
		return
	}
	Logf(format, args...)
}

// logSBool logs a configuration flag as yes/no instead of 1/0 so that the log
// reads as English ("secure cookie on login: yes").
func logSBool(s *Server, what string, on bool) {
	yes := "no"
	if on {
		yes = "yes"
	}
	logS(s, "golog auth: %s: %s", what, yes)
}

// epochCookieDate is the date that expires a cookie: not every client honours
// Max-Age alone, so the clear-the-cookie path sets both Max-Age and Expires, and
// this is the value of the second one. It is the same instant the pre-existing
// logout handler uses.
func epochCookieDate() time.Time { return time.Unix(0, 0).UTC() }

// ---------------------------------------------------------------------------
// which connection the browser is really on
// ---------------------------------------------------------------------------

// LoginCookieSecure reports whether the login cookie may carry the Secure flag:
// true for a request that arrived over TLS, directly or through a trusted
// reverse proxy that set X-Forwarded-Proto (or the RFC 7239 Forwarded "proto"
// parameter) to https. Proxies that are not in the trusted list are ignored, so
// a client cannot ask for a cookie that is only safe on HTTPS by sending its own
// header, and it cannot lock itself out either: a request that claims https but
// arrived in clear text simply gets a cookie without the flag, which the
// attacker who injected the header already had.
func (s *Server) LoginCookieSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	proto := ""
	if s != nil && s.IsTrustedProxy(r.RemoteAddr) {
		proto = r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = forwardedProto(r.Header.Get("Forwarded"))
		}
	}
	proto = TrimSpaceASCII(proto)
	if i := strings.LastIndexByte(proto, ','); i >= 0 {
		proto = TrimSpaceASCII(proto[i+1:])
	}
	return EqualFold(proto, "https")
}

// forwardedProto picks the "proto=" value out of one RFC 7239 Forwarded element.
// It is deliberately simple: the parameter is a token or a quoted string without
// '=', ';' or ','. Anything odd is treated as absent.
func forwardedProto(value string) string {
	for _, part := range strings.Split(value, ";") {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		if !EqualFold(TrimSpaceASCII(k), "proto") {
			continue
		}
		v = TrimSpaceASCII(v)
		v = strings.Trim(v, `"'`)
		if i := strings.IndexAny(v, ";, \t"); i >= 0 {
			v = v[:i]
		}
		return v
	}
	return ""
}

// ---------------------------------------------------------------------------
// the session half of a login
// ---------------------------------------------------------------------------

// LoginCookieName returns the name of the log-in cookie: the configured
// SessionCookie value (from "Password file cookie") with a usable fallback,
// because a server built without a configuration - a test, a tool - has no name
// otherwise.
func (s *Server) LoginCookieName() string {
	name := ""
	if s != nil {
		name = s.SessionCookie
	}
	if name == "" {
		name = "gologlsid"
	}
	return name
}

// StartLoginSession records a successful login in the session store and returns
// the cookie name and value to send. hostIP must be the same value the request
// path passes to SessionStore.Check - the code base uses q.ClientIP()
// throughout, so pass q.ClientIP() here too: the session store ties a session to
// the address it was created from, and a login stored under one address is
// rejected from another.
func (s *Server) StartLoginSession(r *http.Request, user, hostIP string) (string, string, error) {
	if s == nil {
		return "", "", fmt.Errorf("golog: no server: cannot start a session")
	}
	if s.Sessions == nil {
		return "", "", fmt.Errorf("golog: the session store is not set up")
	}
	if TrimSpaceASCII(user) == "" {
		return "", "", fmt.Errorf("golog: cannot start a session without a user name")
	}
	ip := hostIP
	if ip == "" && r != nil {
		ip = r.RemoteAddr
	}
	id := s.Sessions.New(user, ip)
	if id == "" {
		return "", "", fmt.Errorf("golog: the session store returned an empty session id")
	}
	return s.LoginCookieName(), id, nil
}

// SetLoginCookie sends the log-in cookie: HttpOnly always, SameSite=Lax always,
// Secure when the connection is actually TLS (see LoginCookieSecure). The expiry
// is left to the session store, which enforces it server-side anyway, so a copied
// cookie is useless once the store has forgotten it.
func (s *Server) SetLoginCookie(w http.ResponseWriter, r *http.Request, value string) {
	if w == nil {
		return
	}
	name := s.LoginCookieName()
	if name == "" || value == "" {
		return
	}
	path := s.CookiePath()
	if path == "" {
		path = "/"
	}
	secure := r != nil && s.LoginCookieSecure(r)
	logSBool(s, "secure cookie on login", secure)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearLoginCookie expires the log-in cookie on this path, which is what logout
// needs in addition to dropping the session from the store.
func (s *Server) ClearLoginCookie(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	name := s.LoginCookieName()
	if name == "" {
		return
	}
	path := s.CookiePath()
	if path == "" {
		path = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		Expires:  epochCookieDate(),
		HttpOnly: true,
		Secure:   r != nil && s.LoginCookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// Logout ends a session: the id is removed from the store (so the cookie is dead
// server-side, not merely absent from the browser) and the cookie is expired. An
// unknown or already expired id is not an error: logout is idempotent.
func (s *Server) Logout(r *http.Request) {
	if s == nil || r == nil {
		return
	}
	c, err := r.Cookie(s.LoginCookieName())
	if err != nil || c.Value == "" {
		return
	}
	if s.Sessions != nil {
		s.Sessions.Remove(c.Value)
	}
	logS(s, "golog auth: session ended at logout (%s)", hostOnlyOrAll(c.Value))
}

// hostOnlyOrAll keeps a session id out of the log while still saying that there
// was one: session ids are bearer credentials.
func hostOnlyOrAll(id string) string {
	if id == "" {
		return "(no session)"
	}
	return "presented session (id not logged)"
}

// ---------------------------------------------------------------------------
// errors to HTTP
// ---------------------------------------------------------------------------

// LoginHTTPStatus maps an authentication error onto the status a login handler
// should answer with. The three cases the caller must not confuse are: a blocked
// caller (429 with a Retry-After), a wrong credential (401, the same answer for
// unknown user and wrong password so that no attacker learns which names exist)
// and a back end that could not be reached (503, because that is a server-side
// fault and not the user's mistake, and answering 401 would tell him to try a
// different password).
func LoginHTTPStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case LoginBlocked(err):
		return http.StatusTooManyRequests
	case IsAuthUnavailable(err):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrNoAuthenticator):
		return http.StatusServiceUnavailable
	default:
		return http.StatusUnauthorized
	}
}

// SendLoginFailure answers a rejected login: the same short page for every reason
// so that nothing leaks (the detail goes to the log, not to the browser), the
// right status, and the Retry-After header when the caller is throttled or
// banned. Handlers that would rather redirect back to the login form can use
// LoginHTTPStatus, LoginErrorMessage and LoginWait themselves.
func (s *Server) SendLoginFailure(w http.ResponseWriter, r *http.Request, err error) {
	if w == nil {
		return
	}
	if err == nil {
		err = ErrBadPassword
	}
	code := LoginHTTPStatus(err)
	if secs := LoginWait(err); secs > 0 {
		w.Header().Set("Retry-After", Itoa(secs))
	}
	// The user sees one generic sentence; the reason goes to the log with the
	// source address, so an operator can tell a wrong password from an LDAP
	// server that is down without the browser being told.
	user := ""
	if r != nil {
		user = TrimSpaceASCII(r.Form.Get("uname"))
	}
	logS(s, "golog auth: login for %q refused from %s: %v", safeUserForLog(user), sourceIPOfRequest(s, r), err)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, "<html><head><title>Logbook - login</title></head><body bgcolor=\"#ffffff\">\n"+
		"<h3>Login not accepted</h3>\nThe user name or password is not correct.\n"+
		"<p><a href=\"/logbooks\">Logbooks</a> | <a href=\"/login\">try again</a></p>\n"+
		"</body></html>\n")
}

// safeUserForLog keeps a value typed into a form from adding a line to the daemon
// log, which is the file the fail2ban jail reads.
func safeUserForLog(user string) string { return safeLine(user) }

// sourceIPOfRequest is the address used in log lines: the client behind a
// trusted proxy, never an attacker-supplied header from an untrusted peer.
func sourceIPOfRequest(s *Server, r *http.Request) string {
	if s == nil || r == nil {
		return "(unknown)"
	}
	return s.LoginSourceIP(r)
}

// ---------------------------------------------------------------------------
// status of the authentication setup
// ---------------------------------------------------------------------------

// describable is implemented by back ends that can summarise their own
// configuration; the summary never contains a password, a keytab path's secret
// contents or a bind password.
type describable interface {
	AuthDescription() string
}

// AuthBackendStatus is one line of the authentication status summary.
type AuthBackendStatus struct {
	Name    string
	Details string
}

// AuthStatus describes the authentication back ends this server would use, in
// the order they are tried. It is what an operator reads when a login does not
// work: which settings line is in force, which directory and user filter an LDAP
// line resolved to, whether the local password file is readable, whether a
// helper is configured, and which header a header back end trusts. Passwords are
// never included.
func (s *Server) AuthStatus() []AuthBackendStatus {
	out := []AuthBackendStatus{}
	if s == nil {
		return out
	}
	for _, a := range s.Authenticators().List() {
		st := AuthBackendStatus{Name: a.Name()}
		if d, ok := a.(describable); ok {
			st.Details = d.AuthDescription()
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		out = append(out, AuthBackendStatus{
			Name:    "none",
			Details: `"Authentication" has no usable entry, so log-in is refused`,
		})
	}
	return out
}

// AuthStatusLine renders the status as one loggable line.
func (s *Server) AuthStatusLine() string {
	var sb strings.Builder
	for i, st := range s.AuthStatus() {
		if i > 0 {
			sb.WriteString(" | ")
		}
		sb.WriteString(st.Name)
		if st.Details != "" {
			sb.WriteString(": ")
			sb.WriteString(st.Details)
		}
	}
	return sb.String()
}
