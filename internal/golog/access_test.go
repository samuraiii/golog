package golog

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// accessServer builds a server with one private logbook: it has a password file,
// "Read users = alice", an entry with an attachment and a password store in its
// data directory.
func accessServer(t *testing.T, logbookExtra string) *Server {
	t.Helper()
	dir := t.TempDir()
	lbDir := filepath.Join(dir, "lb", "secret")
	if err := os.MkdirAll(lbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entry := "$@MID@$: 1\nDate: Mon, 02 Jan 2023 10:00:00 +0100\nAuthor: alice\nEncoding: plain\n" +
		"Attachment: 230102_000000_secret.txt\n========================================\nTOP-SECRET-BODY\n"
	os.WriteFile(filepath.Join(lbDir, "230102a.log"), []byte(entry), 0o644)
	os.WriteFile(filepath.Join(lbDir, "230102_000000_secret.txt"), []byte("ATTACHMENT-SECRET"), 0o644)
	pw := filepath.Join(dir, "pw.xml")
	os.WriteFile(pw, []byte(`<?xml version="1.0"?><list><user><name>alice</name><password>x</password></user><user><name>bob</name><password>y</password></user></list>`), 0o600)
	os.WriteFile(filepath.Join(lbDir, "password.xml"), []byte("PASSWORD-STORE"), 0o644)
	cfg := ParseConfig(fmt.Sprintf(`[global]
logbook dir = %s
[secret]
attributes = Author
Password file = %s
%s
`, filepath.Join(dir, "lb"), pw, logbookExtra))
	s := New(cfg, filepath.Join(dir, "golog.cfg"))
	s.DataDir = filepath.Join(dir, "lb")
	if err := s.OpenAll(); err != nil {
		t.Fatal(err)
	}
	return s
}

func sessionFor(s *Server, user string) *http.Cookie {
	return &http.Cookie{Name: s.SessionCookie, Value: s.Sessions.New(user, "192.0.2.7")}
}

func TestAnonymousCannotReadPrivateLogbook(t *testing.T) {
	s := accessServer(t, "Read users = alice")
	for _, target := range []string{
		"/secret/", "/secret/1", "/secret/?cmd=Display&message_id=1", "/secret/?cmd=Raw", "/secret/?cmd=XML",
		"/secret/?cmd=CSV", "/secret/?cmd=RSS", "/secret/1/1", "/secret/?cmd=Setup", "/secret/?cmd=Config",
		"/secret/password.xml", "/secret/230102_000000_secret.txt", "/secret/230102a.log",
	} {
		w := do(s, "GET", target)
		body := w.Body.String()
		for _, leak := range []string{"TOP-SECRET-BODY", "ATTACHMENT-SECRET", "PASSWORD-STORE", "attributes = Author", "Password file"} {
			if strings.Contains(body, leak) {
				t.Errorf("anonymous GET %s leaked %q (HTTP %d)", target, leak, w.Code)
			}
		}
	}
	// the visitor is sent to the login form instead
	if w := do(s, "GET", "/secret/"); !strings.Contains(w.Body.String(), `name="upwd"`) {
		t.Errorf("anonymous GET /secret/ did not show the login form: %d", w.Code)
	}
}

func TestListedUserReadsOthersDoNot(t *testing.T) {
	s := accessServer(t, "Read users = alice")
	if w := do(s, "GET", "/secret/1", sessionFor(s, "alice")); !strings.Contains(w.Body.String(), "TOP-SECRET-BODY") {
		t.Errorf("alice cannot read: %d", w.Code)
	}
	if w := do(s, "GET", "/secret/1/1", sessionFor(s, "alice")); !strings.Contains(w.Body.String(), "ATTACHMENT-SECRET") {
		t.Errorf("alice cannot fetch the attachment: %d", w.Code)
	}
	for _, target := range []string{"/secret/", "/secret/1", "/secret/1/1", "/secret/?cmd=Raw"} {
		w := do(s, "GET", target, sessionFor(s, "bob"))
		if strings.Contains(w.Body.String(), "TOP-SECRET-BODY") || strings.Contains(w.Body.String(), "ATTACHMENT-SECRET") {
			t.Errorf("bob (not in Read users) got content from %s", target)
		}
	}
}

func TestSetupNeedsAnAdministrator(t *testing.T) {
	// no "Admin user" list: any logged-in user of a password-protected logbook
	// is an administrator (elogd), an anonymous visitor never is.
	s := accessServer(t, "")
	if w := do(s, "GET", "/secret/?cmd=Setup"); strings.Contains(w.Body.String(), "Password file") {
		t.Error("anonymous Setup shows the configuration")
	}
	s = accessServer(t, "Admin user = alice")
	if w := do(s, "GET", "/secret/?cmd=Setup", sessionFor(s, "bob")); strings.Contains(w.Body.String(), "Password file") || w.Code != 403 {
		t.Errorf("non-admin Setup: %d", w.Code)
	}
	if w := do(s, "GET", "/secret/?cmd=Setup", sessionFor(s, "alice")); 200 != w.Code {
		t.Errorf("admin Setup: %d", w.Code)
	}
}

func TestLoginUserList(t *testing.T) {
	s := accessServer(t, "Login user = alice")
	if w := do(s, "GET", "/secret/1", sessionFor(s, "bob")); strings.Contains(w.Body.String(), "TOP-SECRET-BODY") || 403 != w.Code {
		t.Errorf("bob passed the Login user list: %d", w.Code)
	}
	if w := do(s, "GET", "/secret/1", sessionFor(s, "alice")); !strings.Contains(w.Body.String(), "TOP-SECRET-BODY") {
		t.Errorf("alice blocked: %d", w.Code)
	}
}

func TestGuestMenuCommands(t *testing.T) {
	s := accessServer(t, "Guest menu commands = Display, List, Find")
	if w := do(s, "GET", "/secret/"); !strings.Contains(w.Body.String(), "TOP-SECRET-BODY") && 200 != w.Code {
		t.Errorf("guest list: %d", w.Code)
	}
	if w := do(s, "GET", "/secret/?cmd=Setup"); strings.Contains(w.Body.String(), "Password file") {
		t.Error("guest got Setup")
	}
	if w := do(s, "GET", "/secret/?cmd=Edit&message_id=1"); strings.Contains(w.Body.String(), "TOP-SECRET-BODY") {
		t.Error("guest got the edit form")
	}
}
