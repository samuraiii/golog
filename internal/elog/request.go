package elog

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------
//
// elogd parses the HTTP request itself (lshttp.cxx) and then walks a long
// if/else-if chain over the "cmd" parameter in show_single_page() /
// process_command(). What has to match for a drop-in replacement is the URL
// scheme, the parameter names and the page behaviour; this file is where all
// three are defined.
//
//	/                                    selection page (list of logbooks)
//	/<logbook>/                          list page
//	/<logbook>/<id>                      display one entry (short form)
//	/<logbook>/<id>/<n>                  attachment n (1-based) of entry id
//	/<logbook>?cmd=Display&message_id=N  display one entry
//	/<logbook>?cmd=Edit&message_id=N     edit page (N=0 -> new entry)
//	/<logbook>?cmd=New                   post a new entry
//	/<logbook>?cmd=Submit                submit handler
//	/<logbook>?cmd=Reply&message_id=N    reply form
//	/<logbook>?cmd=Login&unm=&upwd=      login
//	/<logbook>?cmd=Main                  "home"
//	/<logbook>?cmd=Find&subtext=...      search
//	/<logbook>?cmd=Display as Thread     threaded view
//	/<logbook>?cmd=Raw|XML|JSON|CSV      machine readable output
//	/<logbook>?cmd=RSS | RSSfull         RSS feeds
//	/<logbook>?cmd=Setup                 configuration page (administrators)
//
// Form fields the server reads (POST body or query string; the POST body wins
// because elogd parses the query string first and then folds the body into the
// same table):
//
//	cmd, message_id, edit_id, reply_to, in_reply_to, entry_date, Encoding,
//	user_email, unm, upwd, wpwd, redir, attachment0..N, attdelete,
//	y0 m0 d0 h0 n0 (the date and time fragments of the date widget) and one
//	field per attribute name.
//
// The value "<keep>" is significant: the "extend entry" form resubmits the
// fields it must not change as "<keep>" and the server carries the old value
// over.

// keepValue is the "<keep>" placeholder described above.
const keepValue = "<keep>"

// CookieName is the session cookie name used unless the configuration has a
// "Session cookie" key. Upstream elogd calls it "sessionid" and the value
// format is identical, so a deployment that must keep existing cookies alive
// sets that key; Server.SessionCookie is what the code actually uses.
const CookieName = "sessionid"

// Request is one HTTP request being served, with the parsed parameters and the
// authentication result attached.
type Request struct {
	W        http.ResponseWriter
	R        *http.Request
	S        *Server
	LB       *Logbook
	Cfg      ConfigScope
	User     string // login name, "" for anonymous
	FullName string
	Email    string

	params    url.Values
	body      url.Values
	path      string // path after the BasePath
	rel       string // path after the logbook name
	lbName    string
	msgID     int
	attachIx  int // 1-based attachment index, 0 unless this is an attachment URL
	searchIDs []string
	listTitle string

	parseFailed bool
	parseErr    string
}

// Param returns a request parameter (POST body wins over query string, as in
// elogd, which parses the body after the query string into one flat list).
func (q *Request) Param(name string) string {
	if v := q.body.Get(name); v != "" {
		return v
	}
	return q.params.Get(name)
}

// ParamAll returns every value of a repeated field (multi-select attributes).
func (q *Request) ParamAll(name string) []string {
	if v := q.body[name]; len(v) > 0 {
		return v
	}
	return q.params[name]
}

// HasParam is elogd's isparam(): the parameter is present and not empty.
func (q *Request) HasParam(name string) bool {
	for _, v := range q.ParamAll(name) {
		if v != "" {
			return true
		}
	}
	return false
}

// IntParam is elogd's atoi(getparam(...)).
func (q *Request) IntParam(name string) int { return Atoi(q.Param(name)) }

// anyOf returns the first non-empty parameter among names.
func (q *Request) anyOf(names ...string) (string, bool) {
	for _, n := range names {
		if v := q.Param(n); v != "" {
			return v, true
		}
	}
	return "", false
}

// attrs are the form values of the logbook's attributes, keyed by attribute
// name; used by the preview page and by the mail notification of a new entry.
func (q *Request) attrs() map[string]string {
	out := map[string]string{}
	for _, a := range q.S.Config.AttributeNames(q.Cfg) {
		out[a] = q.Param(a)
	}
	return out
}

// requestURL is the absolute URL of the current request, used as a fallback
// redirect target.
func (q *Request) requestURL() string {
	return q.S.requestBaseURL(q.R) + q.R.URL.RequestURI()
}

// ClientIP is the remote address used as the session key. elogd compares
// against inet_ntoa(rem_addr); behind a reverse proxy that is the proxy's
// address, so Server.RealIP (-f) enables the X-Forwarded-For rewrite. It is off
// by default: trusting that header lets any client hijack somebody else's
// session.
func (q *Request) ClientIP() string { return clientIP(q.R, q.S.RealIP) }

// displayName is what the pages and the edit lock show as "who".
func (q *Request) displayName() string {
	if q.FullName != "" {
		return q.FullName
	}
	if q.User != "" {
		return q.User
	}
	return q.S.Config.GetString(q.Cfg, "Anonymous nickname", "Anonymous")
}

// dumpParams renders the request parameters for the status page, with the
// passwords masked.
func (q *Request) dumpParams() string {
	seen := map[string]bool{}
	var keys []string
	for k := range q.params {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range q.body {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := q.Param(k)
		if EqualFold(k, "upwd") || EqualFold(k, "wpwd") || EqualFold(k, "password") {
			v = "***"
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

// serve is the single HTTP entry point.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if err := s.reloadIfChanged(); err != nil {
		s.logf("config reload: %v", err)
	}

	if s.httpsRedirect(r) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusFound)
		return
	}

	q := &Request{W: w, R: r, S: s, params: url.Values{}, body: url.Values{}}
	q.decodePath()

	if q.rel == "/robots.txt" {
		s.robotsTxt(w)
		return
	}
	if q.rel == "/favicon.ico" {
		if p, ok := s.findResource("favicon.ico"); ok {
			s.serveResourceFile(w, r, p)
			return
		}
	}

	lbName := q.lbName
	if lbName == "" {
		if lb := r.URL.Query().Get("lb"); lb != "" {
			lbName = lb
		}
	}

	if lbName != "" && !s.hasLogbookSection(lbName) {
		// Not a logbook: maybe a static resource (style sheet, logo, ...).
		name := strings.TrimPrefix(q.rel, "/")
		if name == "" {
			name = lbName
		}
		if p, ok := s.findResource(name); ok {
			s.serveResourceFile(w, r, p)
			return
		}
		if p, ok := s.staticFile(name); ok {
			s.serveResourceFile(w, r, p)
			return
		}
		s.errorf(q, http.StatusNotFound, "Logbook \"<b>%s</b>\" does not exist", HTMLEscape(lbName))
		return
	}

	q.Cfg = ConfigScope{Group: lbName, TopGroup: lbName}
	if lbName == "" {
		q.Cfg = ConfigScope{Group: "global"}
	} else {
		q.LB = s.LB(lbName)
	}

	q.parseParams()
	q.authenticate()

	if q.LB == nil {
		// The selection page and the logbook-independent commands.
		switch strings.ToLower(strings.TrimSpace(q.Param("cmd"))) {
		case "logout":
			s.logout(q)
		case "login":
			s.login(q)
		case "status":
			s.showStatusPage(q)
		case "help":
			s.help(q)
		default:
			s.showSelectionPage(q)
		}
		return
	}

	if q.attachIx > 0 {
		s.serveAttachment(q)
		return
	}

	// Two gates, in the original's order so the error pages match:
	// is_user_allowed() (the per-user permission lists) and
	// is_command_allowed() (the logbook's "Allowed commands" menu).
	cmd := strings.TrimSpace(q.Param("cmd"))
	if cmd != "" && !s.userAllowed(q, cmd) {
		s.errorf(q, http.StatusForbidden,
			"Error: Command \"<b>%s</b>\" is not allowed for user \"<b>%s</b>\"",
			HTMLEscape(cmd), HTMLEscape(q.displayName()))
		return
	}
	if cmd != "" && !s.commandAllowed(q, cmd) {
		if s.sameCommand(strings.ToLower(cmd), "New") && !q.HasParam("unm") {
			s.showLoginPage(q, q.R.URL.RequestURI(), false)
			return
		}
		s.errorf(q, http.StatusForbidden, "Error: Command \"<b>%s</b>\" not allowed", HTMLEscape(cmd))
		return
	}

	s.dispatch(q)
}

// hasLogbookSection is the cheap pre-check of serve(): a first path element is
// treated as a logbook only when the configuration has such a section.
func (s *Server) hasLogbookSection(name string) bool {
	if name == "" || !IsLogbookName(name) {
		return false
	}
	return s.Config.Section(name) != nil
}

// decodePath splits the URL into "logbook / remainder" and, for an attachment
// URL, extracts the message id and the attachment index.
func (q *Request) decodePath() {
	p := q.R.URL.Path
	if q.S.BasePath != "" {
		p = strings.TrimPrefix(p, q.S.BasePath)
	}
	q.path = p
	if p == "" {
		p = "/"
	}
	inner := strings.Trim(p, "/")
	parts := strings.Split(inner, "/")
	q.lbName = parts[0]
	if len(parts) > 1 {
		q.rel = "/" + strings.Join(parts[1:], "/")
	} else {
		q.rel = ""
	}
	if len(parts) >= 3 {
		id, err1 := strconv.Atoi(parts[1])
		n, err2 := strconv.Atoi(parts[2])
		if err1 == nil && err2 == nil && id > 0 && n > 0 {
			q.msgID, q.attachIx = id, n
			q.rel = ""
			return
		}
	}
	if len(parts) == 2 {
		if id, err := strconv.Atoi(parts[1]); err == nil && id > 0 {
			q.msgID = id
			q.rel = ""
		}
	}
}

// parseParams fills q.params (query string) and q.body (POST form). Multipart
// bodies are handled by net/http rather than by a hand-rolled reader like
// elogd's, which is exactly where several of the local patches had to go.
func (q *Request) parseParams() {
	for k, v := range q.R.URL.Query() {
		q.params[k] = v
	}
	if q.R.Method != http.MethodPost && q.R.Method != http.MethodPut {
		return
	}
	ct := strings.ToLower(q.R.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "multipart/form-data") {
		limit := q.S.MaxUpload
		if limit <= 0 {
			limit = 32 << 20
		}
		if err := q.R.ParseMultipartForm(limit); err != nil {
			q.S.logf("multipart parse: %v (upload larger than Max total size?)", err)
			q.parseFailed = true
			q.parseErr = err.Error()
			return
		}
		if q.R.MultipartForm != nil {
			for k, v := range q.R.MultipartForm.Value {
				q.body[k] = v
			}
		}
		return
	}
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || q.R.ContentLength > 0 {
		data, err := io.ReadAll(io.LimitReader(q.R.Body, 16<<20))
		if err != nil {
			q.parseFailed = true
			q.parseErr = err.Error()
			return
		}
		for k, v := range splitForm(string(data)) {
			q.body[k] = v
		}
	}
}

// splitForm parses an application/x-www-form-urlencoded body.
func splitForm(s string) map[string][]string {
	out := map[string][]string{}
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		k = URLDecode(k)
		if k == "" {
			continue
		}
		out[k] = append(out[k], URLDecode(v))
	}
	return out
}

// authenticate resolves q.User from, in the original's order: the session
// cookie, HTTP Basic, the unm/upwd form fields, the "wpwd" logbook password and
// finally an SSL client certificate.
func (q *Request) authenticate() {
	ip := q.ClientIP()
	if c, err := q.R.Cookie(q.S.SessionCookie); err == nil {
		if u, ok := q.S.Sessions.Check(c.Value, ip); ok {
			q.User = u
			q.fillIdentity()
			return
		}
	}
	if u, p, ok := q.R.BasicAuth(); ok {
		if q.S.checkPassword(u, p) {
			q.User = u
			q.newSession()
			q.fillIdentity()
			return
		}
	}
	if u, p := q.Param("unm"), q.Param("upwd"); u != "" && p != "" {
		if q.S.checkPassword(u, p) {
			q.User = u
			q.newSession()
			q.fillIdentity()
			return
		}
	}
	if wp := q.Param("wpwd"); wp != "" {
		if m := q.S.Config.GetString(q.Cfg, "User password", ""); m != "" && wp == m {
			q.User = q.Param("unm")
			if q.User == "" {
				q.User = "master"
			}
			q.newSession()
			q.fillIdentity()
			return
		}
	}
	if q.R.TLS != nil && len(q.R.TLS.PeerCertificates) > 0 {
		q.User = q.R.TLS.PeerCertificates[0].Subject.CommonName
		q.fillIdentity()
	}
}

// newSession registers a session and hands the browser the cookie.
func (q *Request) newSession() {
	if q.User == "" {
		return
	}
	id := q.S.Sessions.New(q.User, q.ClientIP())
	http.SetCookie(q.W, &http.Cookie{
		Name:     q.S.SessionCookie,
		Value:    id,
		Path:     q.S.CookiePath(),
		MaxAge:   int(q.S.Sessions.expiry.Seconds()),
		HttpOnly: true,
		Secure:   q.R.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// fillIdentity looks up the full name and e-mail in the password file. For an
// anonymous visitor they come from the cookies the original sets from the post
// page, so an anonymous poster keeps his identity across entries.
func (q *Request) fillIdentity() {
	if q.User != "" && q.S.Pwd != nil {
		if u := q.S.Pwd.User(q.User); u != nil {
			if u.IsInactive() {
				q.User, q.FullName, q.Email = "", "", ""
				return
			}
			q.FullName, q.Email = u.FullName, u.Email
			if q.Email == "" {
				q.Email = u.Name + "@unknown"
			}
			_ = q.S.Pwd.TouchActivity(q.User)
			return
		}
		if q.S.Config.GetBool(ConfigScope{Group: "global"}, "Expire") {
			q.User = ""
			return
		}
	}
	if c, err := q.R.Cookie("elog_author"); err == nil {
		q.FullName = URLDecode(c.Value)
	}
	if c, err := q.R.Cookie("elog_email"); err == nil {
		q.Email = URLDecode(c.Value)
	}
}

// ---------------------------------------------------------------------------
// Permission checks
// ---------------------------------------------------------------------------

// userAllowed is is_user_allowed(): the read-only switch plus the
// Read/Edit/Delete/Admin user lists.
func (s *Server) userAllowed(q *Request, cmd string) bool {
	switch strings.ToLower(cmd) {
	case "login", "logout", "main", "home", "help", "status", "":
		return true
	}
	if !s.IsLogbookAllowed(q.Cfg.Group, q.User) {
		return false
	}
	if s.Config.GetBool(q.Cfg, "Read-only") {
		for _, w := range []string{"submit", "delete", "save", "lock", "unlock", "suppress", "edit", "new", "reply"} {
			if strings.Contains(strings.ToLower(cmd), w) {
				return false
			}
		}
	}
	switch s.commandClass(cmd) {
	case classRead:
		return s.userIn(q.Cfg, "Read", q.User)
	case classWrite:
		return s.userIn(q.Cfg, "Edit", q.User)
	case classDelete:
		return s.userIn(q.Cfg, "Delete", q.User)
	case classAdmin:
		return s.userIn(q.Cfg, "Admin", q.User)
	}
	return s.userIn(q.Cfg, "Read", q.User)
}

type cmdClass int

const (
	classRead cmdClass = iota
	classWrite
	classDelete
	classAdmin
)

// commandClass groups the commands by the permission they need. The C code has
// this knowledge spread over the individual handlers; concentrating it here is
// the only way to keep it checkable.
func (s *Server) commandClass(cmd string) cmdClass {
	c := strings.ToLower(cmd)
	for _, x := range []string{"admin", "config", "setup", "save user", "saveuser", "reset hits", "resethits", "expire"} {
		if strings.Contains(c, x) {
			return classAdmin
		}
	}
	for _, x := range []string{"delete", "suppress", "revert"} {
		if strings.Contains(c, x) {
			return classDelete
		}
	}
	for _, x := range []string{"submit", "edit", "save", "new", "reply", "lock", "unlock", "preview", "post", "signup"} {
		if strings.Contains(c, x) {
			return classWrite
		}
	}
	return classRead
}

// userIn is the membership test against a "<Verb> users" list. An absent or
// empty list means "everybody"; a list that starts with a comma
// ("Edit = , alice, bob") is elogd's idiom for "anonymous plus these users".
func (s *Server) userIn(scope ConfigScope, verb, user string) bool {
	raw, ok := s.Config.Get(scope, verb+" users")
	if !ok {
		raw, ok = s.Config.Get(scope, verb+" allow")
		if !ok {
			raw, ok = s.Config.Get(scope, verb+" user")
			if !ok {
				return true
			}
		}
	}
	list := SplitList(raw, ",", false)
	if len(list) == 0 {
		return true
	}
	anonymousAllowed := strings.HasPrefix(TrimSpaceASCII(raw), ",")
	if user == "" {
		for _, u := range list {
			if EqualFold(u, "anonymous") || u == "*" {
				return true
			}
		}
		return anonymousAllowed
	}
	for _, u := range list {
		if EqualFold(u, user) || u == "*" {
			return true
		}
	}
	return false
}

// commandAllowed is is_command_allowed(): membership in the logbook's "Allowed
// commands" menu, with the internal commands the pages always emit
// whitelisted (the original does the same, otherwise a restricted menu could
// not submit the form it shows).
func (s *Server) commandAllowed(q *Request, cmd string) bool {
	allowed := s.Config.GetList(q.Cfg, "Allowed commands")
	if len(allowed) == 0 {
		allowed = DefaultAllowedCommands
	}
	for _, a := range allowed {
		if EqualFold(a, cmd) {
			return true
		}
	}
	switch strings.ToLower(cmd) {
	case "", "main", "home", "login", "logout", "help", "status", "display",
		"displaylist", "display config", "setup", "summary", "preview", "submit",
		"save", "confirm delete", "find", "post message":
		return true
	}
	return false
}

// DefaultAllowedCommands is the menu the original builds when the configuration
// has no "Allowed commands" key.
var DefaultAllowedCommands = []string{
	"New", "Display", "DisplayList", "Display as Thread", "Find",
	"Next", "Previous", "First", "Last", "Reply", "Edit", "Delete", "Logout",
}

// IsLogbookAllowed is the gate for a whole logbook (selection page and every
// command inside it).
func (s *Server) IsLogbookAllowed(logbook, user string) bool {
	if logbook == "" {
		return true
	}
	scope := ConfigScope{Group: logbook, TopGroup: logbook}
	if s.Config.GetBool(scope, "Hidden") {
		return false
	}
	return s.userIn(scope, "Read", user)
}

// CanEdit reports whether the user may write to a logbook; the pages use it to
// hide buttons the visitor cannot use.
func (s *Server) CanEdit(scope ConfigScope, user string) bool {
	if s.Config.GetBool(scope, "Read-only") {
		return false
	}
	return s.userIn(scope, "Edit", user)
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

// dispatch is process_command(): the command word is matched against the
// English name and against the translated name, because the pages post the
// translated value of the submit button.
func (s *Server) dispatch(q *Request) {
	cmd := strings.TrimSpace(q.Param("cmd"))
	c := strings.ToLower(cmd)

	// Machine-readable output first: those commands are ASCII-only and must
// 	not be affected by a translation.
	switch c {
	case "raw":
		s.showRaw(q, "raw")
		return
	case "xml":
		s.showRaw(q, "xml")
		return
	case "json":
		s.showRaw(q, "json")
		return
	case "csv":
		s.showRaw(q, "csv")
		return
	case "rss":
		s.showRSS(q, false)
		return
	case "rssfull", "rss full":
		s.showRSS(q, true)
		return
	}

	switch {
	case c == "":
		if id := q.msgID; id > 0 {
			s.showDisplayPage(q, id)
			return
		}
		if q.HasParam("message_id") && q.IntParam("message_id") > 0 {
			s.showDisplayPage(q, q.IntParam("message_id"))
			return
		}
		s.showListPage(q)
	case s.sameCommand(c, "Main"), s.sameCommand(c, "Home"), s.sameCommand(c, "DisplayList"),
		s.sameCommand(c, "Display as List"):
		s.showListPage(q)
	case s.sameCommand(c, "Display"):
		id := q.msgID
		if id == 0 {
			id = q.IntParam("message_id")
		}
		if id == 0 {
			s.showListPage(q)
			return
		}
		s.showDisplayPage(q, id)
	case s.sameCommand(c, "Display as Thread"), s.sameCommand(c, "DisplayThread"),
		s.sameCommand(c, "Thread"):
		s.showThreadPage(q)
	case s.sameCommand(c, "New"), s.sameCommand(c, "Post message"):
		s.showEditPage(q, 0, "")
	case s.sameCommand(c, "Reply"):
		s.showEditPage(q, q.IntParam("message_id"), "Reply")
	case s.sameCommand(c, "Edit"), s.sameCommand(c, "Extend"):
		id := q.msgID
		if id == 0 {
			id = q.IntParam("message_id")
		}
		if v := q.IntParam("edit_id"); v > 0 {
			id = v
		}
		s.showEditPage(q, id, "")
	case s.sameCommand(c, "Submit"), s.sameCommand(c, "Save"), s.sameCommand(c, "Post"):
		s.submit(q)
	case s.sameCommand(c, "Preview"):
		s.showPreviewPage(q)
	case s.sameCommand(c, "Delete"), s.sameCommand(c, "Suppress"):
		s.confirmDeletePage(q)
	case s.sameCommand(c, "Confirm Delete"), s.sameCommand(c, "Confirm delete"):
		s.deleteMessage(q)
	case s.sameCommand(c, "Revert"):
		if q.R.Method == http.MethodPost && q.HasParam("version") {
			s.revertTo(q)
			return
		}
		s.showRevertPage(q)
	case s.sameCommand(c, "Find"), s.sameCommand(c, "Search"):
		s.searchPage(q)
	case s.sameCommand(c, "Logout"):
		s.logout(q)
	case s.sameCommand(c, "Login"):
		s.login(q)
	case s.sameCommand(c, "Signup"):
		s.signup(q)
	case s.sameCommand(c, "Edit user"), s.sameCommand(c, "Edituser"), s.sameCommand(c, "User"):
		s.showUserPage(q)
	case s.sameCommand(c, "Save user"), s.sameCommand(c, "Saveuser"):
		s.saveUser(q)
	case s.sameCommand(c, "Subscription"), s.sameCommand(c, "Subscribe"),
		s.sameCommand(c, "Subscribers"):
		s.showSubscriptionPage(q)
	case s.sameCommand(c, "Save subscription"):
		s.saveSubscription(q)
	case s.sameCommand(c, "First"), s.sameCommand(c, "Last"),
		s.sameCommand(c, "Next"), s.sameCommand(c, "Previous"):
		s.showListPage(q)
	case s.sameCommand(c, "Setup"), s.sameCommand(c, "Config"),
		s.sameCommand(c, "Display Config"), s.sameCommand(c, "Display config"):
		s.showConfigPage(q)
	case s.sameCommand(c, "Save config"):
		s.saveConfig(q)
	case s.sameCommand(c, "Status"):
		s.showStatusPage(q)
	case s.sameCommand(c, "Summary"):
		s.showSummaryPage(q)
	case s.sameCommand(c, "Calendar"):
		s.showCalendarPage(q)
	case s.sameCommand(c, "Hits"), s.sameCommand(c, "Views"):
		s.hitsPage(q)
	case s.sameCommand(c, "Reset hits"), s.sameCommand(c, "Resethits"):
		if err := s.ResetHits(q.LB); err != nil {
			s.errorf(q, http.StatusInternalServerError, "Cannot reset the hit list: %s", HTMLEscape(err.Error()))
			return
		}
		s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/")
	case s.sameCommand(c, "Expire"):
		s.showExpirePage(q)
	case s.sameCommand(c, "Do expire"), s.sameCommand(c, "Expire users"):
		s.expireUsers(q)
	case s.sameCommand(c, "Help"):
		s.help(q)
	case s.sameCommand(c, "Post msg"), s.sameCommand(c, "POST"):
		s.servePost(q)
	default:
		s.errorf(q, http.StatusForbidden, "Error: Command \"<b>%s</b>\" not allowed", HTMLEscape(cmd))
	}
}

// sameCommand compares a lower-cased command with a (possibly translated)
// command name: the pages post the translated caption of the button, so both
// spellings must work.
func (s *Server) sameCommand(lower, name string) bool {
	if lower == strings.ToLower(name) {
		return true
	}
	tr := s.loc(name)
	return tr != "" && lower == strings.ToLower(tr)
}

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

func (s *Server) login(q *Request) {
	user, pass := q.Param("unm"), q.Param("upwd")
	if user == "" || pass == "" {
		s.showLoginPage(q, q.Param("redir"), false)
		return
	}
	if !s.checkPassword(user, pass) {
		s.Logf("failed login %q from %s", user, q.ClientIP())
		s.showLoginPage(q, q.Param("redir"), true)
		return
	}
	q.User = user
	q.newSession()
	q.fillIdentity()
	s.redirect(q, orText(q.Param("redir"), s.BasePath+"/"+q.Cfg.Group+"/"))
}

func (s *Server) logout(q *Request) {
	if c, err := q.R.Cookie(s.SessionCookie); err == nil {
		s.Sessions.Remove(c.Value)
	}
	http.SetCookie(q.W, &http.Cookie{
		Name: s.SessionCookie, Value: "", Path: s.CookiePath(),
		MaxAge: -1, Expires: time.Unix(0, 0),
	})
	q.User, q.FullName, q.Email = "", "", ""
	if q.LB != nil {
		s.showListPage(q)
		return
	}
	s.redirect(q, orText(q.Param("redir"), s.BasePath+"/"))
}

// checkPassword verifies a login against the password file.
func (s *Server) checkPassword(user, pass string) bool {
	if s.Pwd == nil {
		return false
	}
	u := s.Pwd.User(user)
	if u == nil || u.IsInactive() {
		return false
	}
	return VerifyStoredPassword(pass, u.Password)
}

// ---------------------------------------------------------------------------
// Machine readable output
// ---------------------------------------------------------------------------

// showRaw implements ?cmd=Raw|XML|JSON|CSV. The shapes are the ones elogd emits,
// because external tooling (mirroring, site scripts) parses them: XML is
// <logbook><entry><Attr>..</Attr><text>..</text></entry></logbook>, JSON is an
// object keyed by message id whose values are flat objects of the header fields
// plus "text", CSV is ';'-separated with a header line.
func (s *Server) showRaw(q *Request, mode string) {
	id := q.msgID
	if id == 0 {
		id = q.IntParam("message_id")
	}
	attrs := s.Config.AttributeNames(q.Cfg)
	if id > 0 {
		e, err := q.LB.Message(id)
		if err != nil {
			s.errorf(q, http.StatusNotFound, "Message %d does not exist", id)
			return
		}
		s.RecordHit(q.LB, id, q.ClientIP())
		switch mode {
		case "raw":
			q.W.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(q.W, e.Marshal())
		case "xml":
			q.W.Header().Set("Content-Type", "text/xml; charset=utf-8")
			io.WriteString(q.W, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
			io.WriteString(q.W, EntryXML(e))
		case "json":
			q.W.Header().Set("Content-Type", "application/json; charset=utf-8")
			io.WriteString(q.W, EntryJSON(e))
		case "csv":
			q.W.Header().Set("Content-Type", "text/csv; charset=utf-8")
			io.WriteString(q.W, EntriesCSV(q.LB, []string{strconv.Itoa(id)}, attrs))
		}
		return
	}

	// ?cmd=JSON&since=N is the polling API the original offers: the reply is
	// the list of newer message ids.
	if mode == "json" && q.Param("since") != "" {
		since := Atoi(q.Param("since"))
		var ids []int
		for _, e := range q.LB.Messages() {
			if e.ID() > since {
				ids = append(ids, e.ID())
			}
		}
		q.W.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprintf(q.W, "{\"count\":%d,\"messages\":[", len(ids))
		for i, m := range ids {
			if i > 0 {
				fmt.Fprint(q.W, ",")
			}
			fmt.Fprintf(q.W, "%d", m)
		}
		fmt.Fprint(q.W, "]}")
		return
	}

	n := s.Config.GetInt(q.Cfg, "Display", 50)
	if v := q.Param("n"); v != "" {
		n = Atoi(v)
	}
	ids := q.searchIDs
	if ids == nil {
		ids = s.pageIDs(q, n)
	}
	switch mode {
	case "raw":
		q.W.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, id := range ids {
			if e, err := q.LB.Message(Atoi(id)); err == nil {
				io.WriteString(q.W, e.Marshal())
				io.WriteString(q.W, "\n")
			}
		}
	case "xml":
		q.W.Header().Set("Content-Type", "text/xml; charset=utf-8")
		io.WriteString(q.W, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<logbook name=\""+
			HTMLEscape(q.Cfg.Group)+"\">\n")
		for _, id := range ids {
			if e, err := q.LB.Message(Atoi(id)); err == nil {
				io.WriteString(q.W, EntryXML(e))
			}
		}
		io.WriteString(q.W, "</logbook>\n")
	case "json":
		q.W.Header().Set("Content-Type", "application/json; charset=utf-8")
		io.WriteString(q.W, EntriesJSON(q.LB, ids))
	case "csv":
		q.W.Header().Set("Content-Type", "text/csv; charset=utf-8")
		io.WriteString(q.W, EntriesCSV(q.LB, ids, attrs))
	}
}

// ShowRaw is the exported form of showRaw (tests).
func (s *Server) ShowRaw(q *Request, mode string) { s.showRaw(q, mode) }

// pageIDs is the id list of the current page of the list view, newest first, so
// that ?cmd=XML returns what the browser shows.
func (s *Server) pageIDs(q *Request, n int) []string {
	all := q.LB.Messages()
	if n <= 0 {
		n = 50
	}
	ids := make([]string, 0, n)
	for i := len(all) - 1; i >= 0 && len(ids) < n; i-- {
		ids = append(ids, strconv.Itoa(all[i].ID()))
	}
	return ids
}

// EntryXML renders one message.
func EntryXML(e *Entry) string {
	var b strings.Builder
	b.WriteString("<entry id=\"" + strconv.Itoa(e.ID()) + "\">\n")
	for _, h := range e.Header {
		if h.Key == MsgMarker || h.Key == "" {
			continue
		}
		n := xmlName(h.Key)
		b.WriteString("  <" + n + ">" + HTMLEscape(h.Value) + "</" + n + ">\n")
	}
	b.WriteString("  <text>" + HTMLEscape(e.Text) + "</text>\n")
	b.WriteString("</entry>\n")
	return b.String()
}

// xmlName maps an attribute name onto something that is a legal XML element
// name. The original writes the raw name, which breaks XML parsers as soon as a
// logbook has an attribute with a space or an accent in it.
func xmlName(k string) string {
	var b strings.Builder
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "attr"
	}
	return b.String()
}

// EntryJSON renders one message as the flat object the JSON API returns.
func EntryJSON(e *Entry) string {
	var b strings.Builder
	b.WriteString("{")
	fmt.Fprintf(&b, "%q:%d,", MsgMarker, e.ID())
	for _, h := range e.Header {
		if h.Key == MsgMarker || h.Key == "" {
			continue
		}
		fmt.Fprintf(&b, "%q:%q,", h.Key, h.Value)
	}
	fmt.Fprintf(&b, "%q:%q", "text", e.Text)
	b.WriteString("}")
	return b.String()
}

// EntriesJSON renders the list form: an object keyed by message ID.
func EntriesJSON(lb *Logbook, ids []string) string {
	var b strings.Builder
	b.WriteString("{")
	sep := ""
	for _, id := range ids {
		e, err := lb.Message(Atoi(id))
		if err != nil {
			continue
		}
		b.WriteString(sep)
		sep = ","
		fmt.Fprintf(&b, "%q:%s", id, EntryJSON(e))
	}
	b.WriteString("}")
	return b.String()
}

// EntriesCSV renders the CSV export (';'-separated, quoted when needed), the
// format elogd's "Save as CSV" produces.
func EntriesCSV(lb *Logbook, ids []string, attrs []string) string {
	cols := append([]string{"ID", "Date", "Title", "Author"}, attrs...)
	cols = append(cols, "Text")
	var b strings.Builder
	for i, c := range cols {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(csvField(c))
	}
	b.WriteByte('\n')
	for _, id := range ids {
		e, err := lb.Message(Atoi(id))
		if err != nil {
			continue
		}
		vals := []string{strconv.Itoa(e.ID()), e.Get2("Date"), e.Title(), e.Author()}
		for _, a := range attrs {
			vals = append(vals, strings.ReplaceAll(e.Get2(a), "\n", " "))
		}
		vals = append(vals, e.Text)
		for i, v := range vals {
			if i > 0 {
				b.WriteByte(';')
			}
			b.WriteString(csvField(v))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func csvField(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if strings.ContainsAny(s, ";\n\"") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

// searchPage is ?cmd=Find: every word of "subtext" must appear
// case-insensitively in the entry (any attribute or the text) unless an "attr"
// filter narrows the search to one attribute; "datefrom"/"dateto" bound the
// date range and "near"/"ndays" the window around a date. The result is
// rendered through the normal list page, so the search result page looks like
// the list page (that is what elogd users expect).
func (s *Server) searchPage(q *Request) {
	words := SplitList(q.Param("subtext"), " ", false)
	attr := q.Param("attr")
	var tfrom, tto time.Time
	if t, ok := ParseDate(q.Param("datefrom")); ok {
		tfrom = t
	}
	if t, ok := ParseDate(q.Param("dateto")); ok {
		tto = t.Add(24 * time.Hour)
	}
	near := q.Param("near")
	nearDays := Atoi(q.Param("ndays"))
	if nearDays == 0 {
		nearDays = 1
	}

	var ids []string
	for _, e := range q.LB.Messages() {
		if !tfrom.IsZero() && e.DateValue().Before(tfrom) {
			continue
		}
		if !tto.IsZero() && !e.DateValue().Before(tto) {
			continue
		}
		if near != "" {
			t, ok := ParseDate(near)
			if !ok {
				continue
			}
			d := e.DateValue().Sub(t)
			if d < 0 {
				d = -d
			}
			if d > time.Duration(nearDays)*24*time.Hour {
				continue
			}
		}
		if attr != "" {
			if !matchWord(e.Get2(attr), words) {
				continue
			}
		} else if !entryMatches(e, words) {
			continue
		}
		ids = append(ids, strconv.Itoa(e.ID()))
	}
	q.searchIDs = ids
	q.listTitle = fmt.Sprintf("Search results for %q (%d entries)", q.Param("subtext"), len(ids))
	s.showListPage(q)
}

func matchWord(hay string, words []string) bool {
	for _, w := range words {
		if !ContainsFold(hay, w) {
			return false
		}
	}
	return true
}

func entryMatches(e *Entry, words []string) bool {
	if len(words) == 0 {
		return true
	}
	var b strings.Builder
	for _, h := range e.Header {
		b.WriteString(h.Key)
		b.WriteByte(' ')
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	b.WriteString(e.Text)
	return matchWord(b.String(), words)
}

// ---------------------------------------------------------------------------
// Static files, attachments, error pages
// ---------------------------------------------------------------------------

// staticFile looks a bare file name up in the resource directories. Only a
// small allow-list of extensions is served and the name must be a bare file
// name, so neither the configuration file nor the password file can be pulled
// out with "../" even though the password file normally sits inside the data
// directory.
func (s *Server) staticFile(name string) (string, bool) {
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		return "", false
	}
	base := filepath.Base(filepath.FromSlash(name))
	if base == "" || base == "." || base == ".." || base != filepath.FromSlash(name) {
		return "", false
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".css", ".js", ".gif", ".png", ".jpg", ".jpeg", ".ico", ".svg",
		".txt", ".map", ".woff", ".woff2", ".html", ".htm":
	default:
		return "", false
	}
	for _, dir := range s.StaticDirs("") {
		p := filepath.Join(dir, base)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

// StaticDirs is where static resources are looked for: the resource directory
// (the elogd installation directory or "Resource dir"), the style-sheet
// directory and the logbook's own data directory.
func (s *Server) StaticDirs(logbook string) []string {
	var out []string
	if s.ResourceDir != "" {
		out = append(out, s.ResourceDir)
	}
	if v, ok := s.Config.Get(ConfigScope{Group: "global"}, "Stylesheet dir"); ok && v != "" {
		out = append(out, s.abs(v))
	}
	if logbook == "" {
		for _, name := range s.Order {
			if lb := s.LB(name); lb != nil {
				out = append(out, lb.Dir)
			}
		}
		return out
	}
	if lb := s.LB(logbook); lb != nil {
		out = append(out, lb.Dir)
	}
	return out
}

// robotsTxt keeps crawlers out of the state-changing commands. The original
// ships no robots.txt at all, so this only ever adds safety.
func (s *Server) robotsTxt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "User-agent: *\nDisallow: /*cmd=Submit\nDisallow: /*cmd=Edit\nDisallow: /*cmd=Delete\n")
}

// serveAttachment is the /<logbook>/<id>/<n> handler. The original looks the
// name up in the entry (el_retrieve_attachment()) and then serves the file; the
// file is served directly here, which keeps every URL a client may have
// bookmarked while saving a round trip.
func (s *Server) serveAttachment(q *Request) {
	e, err := q.LB.Message(q.msgID)
	if err != nil {
		s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", q.msgID)
		return
	}
	ref, err := q.LB.AttachmentByIndex(e, q.attachIx)
	if err != nil {
		s.errorf(q, http.StatusNotFound, "Attachment #%d of entry #%d not found", q.attachIx, q.msgID)
		return
	}
	full, err := q.LB.Path(e.Subdir, ref.Name)
	if err != nil || !fileExists(full) {
		s.errorf(q, http.StatusNotFound, "Attachment #%d of entry #%d not found", q.attachIx, q.msgID)
		return
	}
	if q.HasParam("thumb") {
		if p, ok := s.Thumbnail(q.LB.DataDirFor(e.Subdir), ref.Name,
			s.Config.GetInt(q.Cfg, "Thumbnail width", 100),
			s.Config.GetInt(q.Cfg, "Thumbnail height", 100)); ok {
			full = p
		}
	}
	s.RecordHit(q.LB, q.msgID, q.ClientIP())
	ServeAttachment(q.W, q.R, full, ref.Display, q.HasParam("thumb"))
}

// Help is the exported form of the help page (tests).
func (s *Server) Help(q *Request) { s.help(q) }

// ServeStatic is the exported form of the static file lookup (tests).
func (s *Server) ServeStatic(q *Request, name string) bool {
	p, ok := s.staticFile(name)
	if !ok {
		return false
	}
	s.serveResourceFile(q.W, q.R, p)
	return true
}
