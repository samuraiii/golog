package golog

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Thousands of accounts and sessions: a lookup is an index access, not a scan.
func TestManyUsersAndSessions(t *testing.T) {
	const nUsers, nSessions = 5000, 20000
	pf := &PwdFile{path: filepath.Join(t.TempDir(), "pw.xml")}
	for i := 0; i < nUsers; i++ {
		pf.Users = append(pf.Users, &PwdUser{Name: fmt.Sprintf("user%05d", i), Password: "x", Encoding: "SHA256",
			Email: fmt.Sprintf("u%d@example.org", i), LastActivity: "0", LastLogout: "0", Inactive: "0"})
	}
	if err := pf.Save(); err != nil {
		t.Fatal(err)
	}
	back, err := LoadPwdFile(pf.path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(back.Users) != nUsers {
		t.Fatalf("reload: %d users", len(back.Users))
	}

	start := time.Now()
	for i := 0; i < 200000; i++ {
		if back.User(fmt.Sprintf("user%05d", i%nUsers)) == nil {
			t.Fatal("user missing")
		}
	}
	if back.User("nobody") != nil {
		t.Error("found a user that does not exist")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("200000 lookups among %d users took %v: not indexed", nUsers, d)
	}

	ss := NewSessionStore(24)
	ids := make([]string, nSessions)
	start = time.Now()
	for i := range ids {
		ids[i] = ss.New(fmt.Sprintf("user%05d", i%nUsers), "192.0.2.1")
	}
	for r := 0; r < 5; r++ {
		for i, id := range ids {
			if u, ok := ss.Check(id, "192.0.2.1"); !ok || u != fmt.Sprintf("user%05d", i%nUsers) {
				t.Fatalf("session %d: %q %v", i, u, ok)
			}
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("%d sessions took %v: not a map", nSessions, d)
	}
	if _, ok := ss.Check(ids[0], "203.0.113.9"); ok {
		t.Error("a session was accepted from another address")
	}
	if ss.Count() != nSessions {
		t.Errorf("count = %d", ss.Count())
	}
	ss.Remove(ids[0])
	if _, ok := ss.Check(ids[0], "192.0.2.1"); ok {
		t.Error("a removed session still works")
	}

	// activity time stamps from many users at once end in one write
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			back.TouchActivity(fmt.Sprintf("user%05d", i))
		}(i)
	}
	wg.Wait()
	if u := back.User("user00001"); "0" == u.LastActivity {
		t.Error("last activity not recorded")
	}
}

// A browser login against a real password file: the file loads, the password
// is checked through the chain, a session starts and the cookie works.
func TestLoginAgainstPasswordFile(t *testing.T) {
	s := accessServer(t, "Read users = alice")
	pw := s.Config.GetString(ConfigScope{Group: "secret"}, "Password file", "")
	pf, err := LoadPwdFile(pw)
	if err != nil {
		t.Fatalf("the password file does not load: %v", err)
	}
	if err := pf.AddUser("carol", "correct horse battery", "Carol", "carol@example.org"); err != nil {
		t.Fatal(err)
	}
	s.Pwd = pf
	post := func(user, pass string) *http.Cookie {
		w := postAs(s, "/secret/", "cmd=Login&unm="+user+"&upwd="+pass, map[string]string{"Origin": "https://logbooks.example"}, nil)
		for _, c := range w.Result().Cookies() {
			if c.Name == s.SessionCookie && "" != c.Value {
				return c
			}
		}
		return nil
	}
	if c := post("carol", "wrong password"); nil != c {
		t.Error("a wrong password started a session")
	}
	c := post("carol", "correct horse battery")
	if nil == c {
		t.Fatal("the right password did not start a session")
	}
	if len(c.Value) != 32 || !c.HttpOnly {
		t.Errorf("session cookie %q httponly=%v", c.Value, c.HttpOnly)
	}
	if u, ok := s.Sessions.Check(c.Value, "192.0.2.7"); !ok || "carol" != u {
		t.Errorf("session user %q %v", u, ok)
	}
}
