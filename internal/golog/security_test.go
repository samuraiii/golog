package golog

import (
	"bytes"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A poster-controlled .html/.svg attachment must never be served as active
// content of this origin.
func TestAttachmentActiveContentIsDownloadOnly(t *testing.T) {
	dir := t.TempDir()
	for name, want := range map[string]bool{"x.html": true, "x.svg": true, "x.xml": true, "x.txt": false, "x.png": false} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("<script>alert(1)</script>"), 0o644)
		w := httptest.NewRecorder()
		ServeAttachment(w, httptest.NewRequest("GET", "/x", nil), p, name, false)
		h := w.Header()
		if "nosniff" != h.Get("X-Content-Type-Options") || !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
			t.Errorf("%s: missing nosniff or sandbox policy: %v", name, h)
		}
		if want && (!strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || "application/octet-stream" != h.Get("Content-Type")) {
			t.Errorf("%s served as active content: type=%q disp=%q", name, h.Get("Content-Type"), h.Get("Content-Disposition"))
		}
	}
}

// Values substituted into a command line are one word each, whatever they hold.
func TestCommandSubstitutionCannotAddWords(t *testing.T) {
	s := New(ParseConfig("[global]\n"), "")
	e := &Entry{}
	e.SetID(7)
	e.Set("Title", `x" --config=/tmp/evil "y`)
	e.Set("Foo", "a b; rm -rf / 'q'")
	cmd := s.substituteEntryWith("/usr/bin/notify &title &attrFoo", e, "demo", "", cmdQuote)
	argv := SplitCommand(cmd)
	want := []string{"/usr/bin/notify", `x" --config=/tmp/evil "y`, "a b; rm -rf / 'q'"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
}

// CR/LF in a poster-controlled value must not start a new mail header or add an
// envelope recipient.
func TestMailHeaderInjection(t *testing.T) {
	m := &mailMessage{}
	m.Set("Subject", "hi\r\nBcc: victim@example.org")
	m.Set("From", "a@example.org\r\nX-Evil: 1")
	m.Set("To", "ok@example.org")
	raw := m.render()
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") || strings.HasPrefix(line, "X-Evil:") {
			t.Errorf("injected header line %q in:\n%s", line, raw)
		}
	}
	for _, bad := range []string{"a@b.c>\r\nRCPT TO:<x@y.z", "a b@c.d", "-oQ/tmp@x", "a@b.c,d@e.f", "x@y.z;z@y.z"} {
		if got := emailAddress(bad); got != "" {
			t.Errorf("emailAddress(%q) = %q, want it refused", bad, got)
		}
	}
	if got := emailAddress("Jan <jan@example.org>"); "jan@example.org" != got {
		t.Errorf("emailAddress of a normal address = %q", got)
	}
}

func TestProtectedConfigKeys(t *testing.T) {
	for _, k := range []string{"Password file", "Authentication", "Admin user", "SSL cert", "Execute new", "Sendmail", "OIDC issuer", "Port", "Header trusted proxies"} {
		if !protectedConfigKey(k) {
			t.Errorf("%q can be written through the web editor", k)
		}
	}
	for _, k := range []string{"Comment", "Attributes", "Options Type", "Menu commands", "Page Title", "Allowed commands", "Reverse sort"} {
		if protectedConfigKey(k) {
			t.Errorf("%q is wrongly protected", k)
		}
	}
}

func postAs(s *Server, target, body string, hdr map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", target, strings.NewReader(body))
	r.Host = "logbooks.example"
	r.RemoteAddr = "192.0.2.7:4000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestCSRF(t *testing.T) {
	s := accessServer(t, "Read users = alice\nAdmin user = alice")
	alice := sessionFor(s, "alice")
	del := "cmd=Confirm+delete&message_id=1"
	// a cross-site or header-less POST with the session cookie is refused
	for name, hdr := range map[string]map[string]string{
		"no origin":        nil,
		"foreign origin":   {"Origin": "https://evil.example"},
		"fetch cross-site": {"Sec-Fetch-Site": "cross-site"},
		"foreign referer":  {"Referer": "https://evil.example/x"},
		"null origin":      {"Origin": "null"},
	} {
		w := postAs(s, "/secret/", del, hdr, alice)
		if 403 != w.Code || !strings.Contains(w.Body.String(), "Cross-site") {
			t.Errorf("%s: %d %q", name, w.Code, w.Body.String())
		}
	}
	// the same request from this site is not refused for that reason
	w := postAs(s, "/secret/", del, map[string]string{"Origin": "https://logbooks.example"}, alice)
	if strings.Contains(w.Body.String(), "Cross-site") {
		t.Errorf("same-origin POST refused as cross-site: %d", w.Code)
	}
	// a state-changing command is never accepted as GET
	if g := do(s, "GET", "/secret/?cmd=Confirm+delete&message_id=1", alice); 405 != g.Code {
		t.Errorf("GET Confirm delete: %d, want 405", g.Code)
	}
	if g := do(s, "GET", "/secret/?cmd=Save+config&param=Comment&value=x", alice); 405 != g.Code {
		t.Errorf("GET Save config: %d, want 405", g.Code)
	}
	// reading is still GET
	if g := do(s, "GET", "/secret/1", alice); !strings.Contains(g.Body.String(), "TOP-SECRET-BODY") {
		t.Errorf("GET display: %d", g.Code)
	}
}

func TestMutatingCommands(t *testing.T) {
	for _, c := range []string{"Submit", "Confirm delete", "Save config", "Save user", "Expire users", "Reset hits", "Suppress"} {
		if !mutatingCommand(c) {
			t.Errorf("%q should be POST-only", c)
		}
	}
	for _, c := range []string{"", "Display", "List", "Find", "Edit", "New", "Reply", "Delete", "Setup", "Login", "Logout"} {
		if mutatingCommand(c) {
			t.Errorf("%q should be allowed as GET", c)
		}
	}
}

func TestProtectedConfigKeyNormalisation(t *testing.T) {
	for _, k := range []string{"  Password   file ", "PASSWORD FILE", "ssl\tcert", "Authentication"} {
		if !protectedConfigKey(k) {
			t.Errorf("%q slips past the protected-key list", k)
		}
	}
}

func TestFooterOnlySafeTags(t *testing.T) {
	cases := map[string]string{
		`<b>bold</b> <i>i</i> <u>u</u>`:                                  `<b>bold</b> <i>i</i> <u>u</u>`,
		`<a href="https://x.org/a?b=1&c=2" title="t">link</a>`:           `<a href="https://x.org/a?b=1&amp;c=2" title="t">link</a>`,
		`<a href="/local/page">l</a>`:                                    `<a href="/local/page">l</a>`,
		`<img src="/logo.png" alt="logo" width="40">`:                    `<img src="/logo.png" alt="logo" width="40">`,
		`<script>alert(1)</script>`:                                      `&lt;script&gt;alert(1)&lt;/script&gt;`,
		`<a href="javascript:alert(1)">x</a>`:                            `<a>x</a>`,
		`<a href=" JaVaScRiPt:alert(1)">x</a>`:                           `<a>x</a>`,
		`<a href="java&#115;cript:alert(1)">x</a>`:                       `<a>x</a>`,
		`<a href="//evil.example/x">x</a>`:                               `<a>x</a>`,
		`<a href="data:text/html,x">x</a>`:                               `<a>x</a>`,
		`<img src=x onerror=alert(1)>`:                                   `<img src="x">`,
		`<img src="javascript:alert(1)" onerror="x">`:                    `<img>`,
		`<b onclick="x()">b</b>`:                                         `<b>b</b>`,
		`<iframe src="https://evil.example"></iframe>`:                   `&lt;iframe src=&quot;https://evil.example&quot;&gt;&lt;/iframe&gt;`,
		`<style>body{display:none}</style>`:                              `&lt;style&gt;body{display:none}&lt;/style&gt;`,
		`1 < 2 and <b>ok`:                                                `1 &lt; 2 and <b>ok`,
		`<a href="https://x.org" onmouseover="alert(1)" style="x">a</a>`: `<a href="https://x.org">a</a>`,
	}
	for in, want := range cases {
		if got := sanitizeFooterHTML(in); got != want {
			t.Errorf("footer %q\n got %q\nwant %q", in, got, want)
		}
	}
}

// A signup creates an account that cannot log in until an administrator
// approves it.
func TestSignupNeedsApproval(t *testing.T) {
	s := accessServer(t, "Admin user = alice")
	s.Config.Set("global", "Enable signup", "1")
	pw := s.Config.GetString(ConfigScope{Group: "secret"}, "Password file", "")
	pf, err := LoadPwdFile(pw)
	if err != nil {
		t.Fatal(err)
	}
	s.Pwd = pf
	hdr := map[string]string{"Origin": "https://logbooks.example"}

	// the form carries a captcha; a wrong answer creates nothing
	form := do(s, "GET", "/secret/?cmd=Signup")
	if !strings.Contains(form.Body.String(), "/captcha?t=") {
		t.Fatalf("the signup form has no captcha: %d", form.Code)
	}
	signup := func(user string, answerRight bool) *httptest.ResponseRecorder {
		f := do(s, "GET", "/secret/?cmd=Signup").Body.String()
		i := strings.Index(f, `name="captcha_token" value="`)
		tok := f[i+len(`name="captcha_token" value="`):]
		tok = tok[:strings.IndexByte(tok, '"')]
		nonce, _, ok := parseCaptchaToken(tok, time.Now())
		if !ok {
			t.Fatal("bad token in the form")
		}
		ans := captchaAnswer(nonce)
		if !answerRight {
			ans = "ZZZZZ"
		}
		return postAs(s, "/secret/", "cmd=Signup&unm="+user+"&upwd=a-good-password&email=n@example.org&captcha_token="+tok+"&captcha_answer="+strings.ToLower(ans), hdr, nil)
	}
	if signup("robot", false); pf.User("robot") != nil {
		t.Fatal("an account was created with a wrong captcha")
	}
	w := signup("newbie", true)
	if !strings.Contains(w.Body.String(), "approve") {
		t.Fatalf("signup answer: %d %s", w.Code, w.Body.String())
	}
	login := func() bool {
		w := postAs(s, "/secret/", "cmd=Login&unm=newbie&upwd=a-good-password", hdr, nil)
		for _, c := range w.Result().Cookies() {
			if c.Name == s.SessionCookie && "" != c.Value {
				return true
			}
		}
		return false
	}
	if login() {
		t.Fatal("a pending account could log in")
	}
	if 1 != len(pf.PendingUsers()) {
		t.Fatal("the account is not pending")
	}
	// the pending state survives a reload of the file
	if back, err := LoadPwdFile(pw); err != nil || 1 != len(back.PendingUsers()) {
		t.Fatalf("pending state lost on reload: %v", err)
	}
	bob := sessionFor(s, "bob")
	// only an administrator sees the page or may decide
	if g := do(s, "GET", "/secret/?cmd=Approve+users", bob); strings.Contains(g.Body.String(), "newbie") {
		t.Error("a non-administrator sees the pending list")
	}
	if w := postAs(s, "/secret/", "cmd=Approve+user&user=newbie", hdr, bob); login() || 403 != w.Code {
		t.Errorf("a non-administrator approved an account: %d", w.Code)
	}
	alice := sessionFor(s, "alice")
	if g := do(s, "GET", "/secret/?cmd=Approve+users", alice); !strings.Contains(g.Body.String(), "newbie") {
		t.Errorf("the administrator does not see the pending account: %d", g.Code)
	}
	if g := do(s, "GET", "/secret/?cmd=Approve+user&user=newbie", alice); 405 != g.Code || login() {
		t.Errorf("approval by GET: %d", g.Code)
	}
	postAs(s, "/secret/", "cmd=Approve+user&user=newbie", hdr, alice)
	if !login() {
		t.Error("the approved account cannot log in")
	}
	// rejecting removes the account
	signup("spammer", true)
	postAs(s, "/secret/", "cmd=Reject+user&user=spammer", hdr, alice)
	if pf.User("spammer") != nil {
		t.Error("a rejected account still exists")
	}
	// the editor tells the administrator about the footer rule
	s.Config.Set("secret", "Footer", "<b>x</b>")
	s.Config.Set("global", "Allow config edit", "1")
	if g := do(s, "GET", "/secret/?cmd=Setup", alice); !strings.Contains(g.Body.String(), "only the tags") {
		t.Error("the configuration page does not mention the footer rule")
	}
}

func TestCaptcha(t *testing.T) {
	now := time.Now()
	tok := NewCaptchaToken(now)
	nonce, _, ok := parseCaptchaToken(tok, now)
	if !ok {
		t.Fatal("a fresh token is refused")
	}
	answer := captchaAnswer(nonce)
	if 5 != len(answer) || strings.Trim(answer, captchaAlphabet) != "" {
		t.Errorf("answer %q", answer)
	}
	// the picture is a PNG of the documented size and is the same every time
	img1, ok1 := CaptchaPNG(tok, now)
	img2, _ := CaptchaPNG(tok, now)
	cfg, err := png.DecodeConfig(bytes.NewReader(img1))
	if !ok1 || err != nil || 190 != cfg.Width || 64 != cfg.Height || !bytes.Equal(img1, img2) {
		t.Errorf("picture: ok=%v err=%v %dx%d same=%v", ok1, err, cfg.Width, cfg.Height, bytes.Equal(img1, img2))
	}
	// the token does not contain the answer
	if strings.Contains(strings.ToUpper(tok), answer) {
		t.Error("the answer is readable in the token")
	}
	// a wrong answer burns the token: the right one afterwards fails
	if CheckCaptcha(tok, "WRONG", now) || CheckCaptcha(tok, answer, now) {
		t.Error("a token survived a wrong attempt")
	}
	// right answer once, in any case and with spaces; never twice
	tok = NewCaptchaToken(now)
	nonce, _, _ = parseCaptchaToken(tok, now)
	ans := captchaAnswer(nonce)
	if !CheckCaptcha(tok, " "+strings.ToLower(ans)+" ", now) {
		t.Error("the right answer was refused")
	}
	if CheckCaptcha(tok, ans, now) {
		t.Error("a token was accepted twice")
	}
	// expired and tampered tokens
	old := NewCaptchaToken(now.Add(-captchaTTL - time.Minute))
	oldNonce, _, _ := parseCaptchaToken(old, now.Add(-captchaTTL-time.Minute))
	if CheckCaptcha(old, captchaAnswer(oldNonce), now) {
		t.Error("an expired token was accepted")
	}
	bad := NewCaptchaToken(now)
	flipped := []byte(bad)
	flipped[3] ^= 1
	if _, _, ok := parseCaptchaToken(string(flipped), now); ok {
		t.Error("a modified token was accepted")
	}
	if _, ok := CaptchaPNG("garbage", now); ok {
		t.Error("a picture for a garbage token")
	}
	// the image endpoint is rate limited
	resetCaptchaRate()
	s := accessServer(t, "")
	tk := NewCaptchaToken(time.Now())
	if g := do(s, "GET", "/captcha?t="+tk); 200 != g.Code || "image/png" != g.Header().Get("Content-Type") {
		t.Errorf("captcha endpoint: %d %q", g.Code, g.Header().Get("Content-Type"))
	}
	limited := false
	for i := 0; i < 60; i++ {
		if do(s, "GET", "/captcha?t="+tk).Code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Error("the captcha image is not rate limited")
	}
}

func newPolicyServer(t *testing.T, extra string) (*Server, *PwdFile) {
	t.Helper()
	s := accessServer(t, extra)
	pf, err := LoadPwdFile(s.Config.GetString(ConfigScope{Group: "secret"}, "Password file", ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := pf.AddUser("dora", "first-password-1", "Dora", "d@example.org"); err != nil {
		t.Fatal(err)
	}
	s.Pwd = pf
	return s, pf
}

// The rules are optional: without them nothing expires and anything long
// enough can be reused.
func TestPasswordRulesAreOptional(t *testing.T) {
	s, pf := newPolicyServer(t, "")
	pol := s.passwordPolicy(ConfigScope{Group: "secret"})
	if pol.MaxAgeDays != 0 || pol.History != 0 {
		t.Fatalf("defaults: %+v", pol)
	}
	if pf.PasswordExpired("dora", pol.MaxAgeDays, time.Now().AddDate(10, 0, 0)) {
		t.Error("a password expired with no lifetime configured")
	}
	if err := pf.ChangePassword("dora", "first-password-1", pol, false, time.Now()); err != nil {
		t.Errorf("reuse refused with no history configured: %v", err)
	}
	if err := pf.ChangePassword("dora", "short", pol, false, time.Now()); err == nil {
		t.Error("a 5-character password was accepted")
	}
}

func TestPasswordHistory(t *testing.T) {
	s, pf := newPolicyServer(t, "Password history = 3")
	pol := s.passwordPolicy(ConfigScope{Group: "secret"})
	now := time.Now()
	for _, pw := range []string{"second-password-2", "third-password-3", "fourth-password-4"} {
		if err := pf.ChangePassword("dora", pw, pol, false, now); err != nil {
			t.Fatalf("changing to %q: %v", pw, err)
		}
	}
	// the current one and the two before it are refused; the oldest is free again
	for _, pw := range []string{"fourth-password-4", "third-password-3", "second-password-2"} {
		if err := pf.ChangePassword("dora", pw, pol, false, now); err == nil {
			t.Errorf("%q was reused", pw)
		}
	}
	if err := pf.ChangePassword("dora", "first-password-1", pol, false, now); err != nil {
		t.Errorf("a password older than the history was refused: %v", err)
	}
	if n := len(pf.User("dora").History); n > 2 {
		t.Errorf("%d hashes remembered, want at most 2 (the current one is the third)", n)
	}
	// only hashes are stored
	for _, h := range pf.User("dora").History {
		if strings.Contains(h, "password") {
			t.Error("a plain password is stored in the history")
		}
	}
	// the history survives a reload
	back, _ := LoadPwdFile(pf.path)
	if len(back.User("dora").History) == 0 {
		t.Error("history lost on reload")
	}
}

func TestPasswordLifetime(t *testing.T) {
	s, pf := newPolicyServer(t, "Password max age = 30")
	pol := s.passwordPolicy(ConfigScope{Group: "secret"})
	now := time.Now()
	if pf.PasswordExpired("dora", pol.MaxAgeDays, now) || !pf.PasswordExpired("dora", pol.MaxAgeDays, now.AddDate(0, 0, 31)) {
		t.Error("lifetime of 30 days not applied")
	}
	// an account with no date starts its lifetime when the rule is first applied
	pf.User("dora").PasswordChanged = ""
	if pf.PasswordExpired("dora", 30, now.AddDate(1, 0, 0)) {
		t.Error("an account with no recorded date was locked out at once")
	}
	if pf.User("dora").PasswordChanged == "" {
		t.Error("no date was recorded")
	}
	// external accounts are exempt
	pf.User("dora").External = true
	if pf.PasswordExpired("dora", 30, now.AddDate(5, 0, 0)) {
		t.Error("an external account expired")
	}
	pf.User("dora").External = false
	// a password set by an administrator is expired at once
	if err := pf.ChangePassword("dora", "set-by-admin-9", pol, true, now); err != nil {
		t.Fatal(err)
	}
	if !pf.PasswordExpired("dora", 30, now) {
		t.Error("an administrator-set password is not expired")
	}
}

// An expired password sends every page to the change form; changing it needs the
// old one, and then everything works again.
func TestExpiredPasswordForcesChange(t *testing.T) {
	s, pf := newPolicyServer(t, "Password max age = 30\nPassword history = 2")
	pf.User("dora").PasswordChanged = time.Now().AddDate(0, 0, -45).UTC().Format(time.RFC3339)
	dora := sessionFor(s, "dora")
	hdr := map[string]string{"Origin": "https://logbooks.example"}

	g := do(s, "GET", "/secret/1", dora)
	if 302 != g.Code || !strings.Contains(g.Header().Get("Location"), "Edit+user") && !strings.Contains(g.Header().Get("Location"), "Edit%20user") {
		t.Fatalf("an expired password did not lead to the change form: %d %q", g.Code, g.Header().Get("Location"))
	}
	if f := do(s, "GET", "/secret/?cmd=Edit+user", dora); !strings.Contains(f.Body.String(), "has expired") || !strings.Contains(f.Body.String(), "oldpassword") {
		t.Error("the change form does not explain or ask for the old password")
	}
	change := func(old, nw string) *httptest.ResponseRecorder {
		return postAs(s, "/secret/", "cmd=Save+user&user=dora&oldpassword="+old+"&password="+nw, hdr, dora)
	}
	if w := change("wrong-old-password", "brand-new-password-5"); 403 != w.Code {
		t.Errorf("a wrong old password was accepted: %d", w.Code)
	}
	if w := change("first-password-1", "first-password-1"); 400 != w.Code {
		t.Errorf("reusing the current password: %d", w.Code)
	}
	if w := change("first-password-1", "brand-new-password-5"); 302 != w.Code {
		t.Fatalf("a valid change failed: %d %s", w.Code, w.Body.String())
	}
	if g := do(s, "GET", "/secret/1", dora); strings.Contains(g.Header().Get("Location"), "Edit") {
		t.Error("still sent to the change form after changing the password")
	}
	if !VerifyStoredPassword("brand-new-password-5", pf.User("dora").Password) {
		t.Error("the new password is not stored")
	}
}

// With "Base path" every page, link, form, redirect and cookie carries the prefix;
// requests outside it are 404; and a proxy that strips the prefix works too.
func TestBasePath(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		s := accessServer(t, "Read users = alice")
		s.Config.Set("global", "Enable signup", "1")
		s.Config.Set("global", "Base path", "/golog")
		s.BasePath = "/golog"
		if proxy {
			s.Config.Set("global", "Base path proxy", "1")
		}
		alice := sessionFor(s, "alice")
		alice.Path = "/golog"
		prefixed := func(u string) string {
			if proxy {
				return strings.TrimPrefix(u, "/golog")
			}
			return u
		}
		re := regexp.MustCompile(`(?:href|src|action)="(/[^"]*)"`)
		for _, u := range []string{"/golog/secret/", "/golog/secret/1", "/golog/secret/?cmd=Find", "/golog/", "/golog/secret/?cmd=Signup", "/golog/secret/?cmd=Login"} {
			w := do(s, "GET", prefixed(u), alice)
			if w.Code != 200 {
				t.Errorf("proxy=%v GET %s: %d", proxy, u, w.Code)
			}
			for _, m := range re.FindAllStringSubmatch(w.Body.String(), -1) {
				if !strings.HasPrefix(m[1], "/golog/") {
					t.Errorf("proxy=%v %s links to %q outside the prefix", proxy, u, m[1])
				}
			}
		}
		if !proxy {
			if w := do(s, "GET", "/secret/", alice); w.Code != 404 {
				t.Errorf("a request outside the prefix: %d", w.Code)
			}
			if w := do(s, "GET", "/golog"); w.Code != 301 || w.Header().Get("Location") != "/golog/" {
				t.Errorf("/golog: %d %q", w.Code, w.Header().Get("Location"))
			}
		}
		// the session cookie is scoped to the prefix, and a login redirects inside it
		pf, _ := LoadPwdFile(s.Config.GetString(ConfigScope{Group: "secret"}, "Password file", ""))
		pf.AddUser("carol", "correct horse battery", "C", "c@example.org")
		s.Pwd = pf
		w := postAs(s, prefixed("/golog/secret/"), "cmd=Login&unm=carol&upwd=correct+horse+battery", map[string]string{"Origin": "https://logbooks.example"}, nil)
		var cookie *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == s.SessionCookie {
				cookie = c
			}
		}
		if nil == cookie || "/golog" != cookie.Path {
			t.Errorf("proxy=%v session cookie: %+v", proxy, cookie)
		}
		if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/golog/") {
			t.Errorf("proxy=%v login redirects to %q", proxy, loc)
		}
		// attachment and captcha URLs
		e, _ := s.LB("secret").Message(1)
		if u := s.AttachmentURL("secret", e, AttachmentRefs(e)[0]); !strings.HasPrefix(u, "/golog/") {
			t.Errorf("attachment URL %q", u)
		}
		f := do(s, "GET", prefixed("/golog/secret/?cmd=Signup")).Body.String()
		if !strings.Contains(f, `src="/golog/captcha?t=`) {
			t.Errorf("proxy=%v captcha image URL is not under the prefix", proxy)
		}
		resetCaptchaRate()
		tk := NewCaptchaToken(time.Now())
		if g := do(s, "GET", prefixed("/golog/captcha?t="+tk)); 200 != g.Code {
			t.Errorf("proxy=%v captcha endpoint: %d", proxy, g.Code)
		}
	}
}
