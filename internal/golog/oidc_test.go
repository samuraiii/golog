package golog

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIdP is a minimal OpenID provider: discovery, JWKS, token endpoint. The
// token endpoint answers with an ID token for whatever the test put in claims.
type fakeIdP struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	kid     string
	claims  func(nonce string) map[string]any
	nonce   atomic.Value
	tokens  atomic.Int32
	gotAuth atomic.Value
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: k, kid: "k1"}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(k.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": f.kid, "use": "sig", "n": b64(k.N.Bytes()), "e": b64(e),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.gotAuth.Store(r.Header.Get("Authorization") + "|" + r.PostForm.Get("code_verifier") + "|" + r.PostForm.Get("grant_type"))
		f.tokens.Add(1)
		n, _ := f.nonce.Load().(string)
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.sign(f.claims(n)), "token_type": "Bearer"})
	})
	return f
}

func (f *fakeIdP) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": f.kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	return in + "." + b64(sig)
}

func newOIDCServer(t *testing.T, idp *fakeIdP, extra string) *Server {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "lb"), 0o755)
	cfg := ParseConfig(fmt.Sprintf(`[global]
logbook dir = %s
OIDC issuer = %s
OIDC client id = golog
OIDC client secret = s3cret
OIDC redirect uri = http://127.0.0.1/oidc/callback
%s
SSO mode = button
[demo]
attributes = Author
`, filepath.Join(dir, "lb"), idp.srv.URL, extra))
	s := New(cfg, filepath.Join(dir, "golog.cfg"))
	return s
}

// do runs one request through the server's handler.
func do(s *Server, method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "192.0.2.7:4000"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// loginStart returns the state, nonce parameters and the flow cookie.
func loginStart(t *testing.T, s *Server, idp *fakeIdP) (state string, ck *http.Cookie) {
	t.Helper()
	w := do(s, "GET", "/oidc/login?redir=/demo/3")
	if 302 != w.Code {
		t.Fatalf("login start: %d %s", w.Code, w.Body.String())
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	q := loc.Query()
	if "S256" != q.Get("code_challenge_method") || "" == q.Get("code_challenge") || "code" != q.Get("response_type") ||
		"golog" != q.Get("client_id") || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("bad authorization request: %v", q)
	}
	idp.nonce.Store(q.Get("nonce"))
	for _, c := range w.Result().Cookies() {
		if oidcFlowCookie == c.Name {
			ck = c
		}
	}
	if nil == ck || ck.Value != q.Get("state") || !ck.HttpOnly {
		t.Fatalf("flow cookie missing or unbound: %v", ck)
	}
	return q.Get("state"), ck
}

func goodClaims(idp *fakeIdP) func(string) map[string]any {
	return func(nonce string) map[string]any {
		return map[string]any{
			"iss": idp.srv.URL, "aud": "golog", "sub": "u-1", "nonce": nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"preferred_username": "JDoe@Corp.Example", "name": "Jan Doe", "email": "jdoe@corp.example",
			"groups": []string{"users", "admins"},
		}
	}
}

func TestOIDCLoginFlow(t *testing.T) {
	idp := newFakeIdP(t)
	idp.claims = goodClaims(idp)
	s := newOIDCServer(t, idp, "OIDC strip domain = 1\nOIDC login group = users")

	state, ck := loginStart(t, s, idp)
	w := do(s, "GET", "/oidc/callback?code=abc&state="+url.QueryEscape(state), ck)
	if 302 != w.Code || "/demo/3" != w.Header().Get("Location") {
		t.Fatalf("callback: %d loc=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.SessionCookie {
			session = c
		}
	}
	if nil == session || "" == session.Value {
		t.Fatal("no session cookie after a successful OIDC login")
	}
	if u, ok := s.Sessions.Check(session.Value, "192.0.2.7"); !ok || "jdoe" != u {
		t.Errorf("session user = %q, %v; want jdoe (domain stripped, lower-cased)", u, ok)
	}
	got, _ := idp.gotAuth.Load().(string)
	if !strings.HasPrefix(got, "Basic ") || !strings.HasSuffix(got, "|authorization_code") || strings.Count(got, "|") != 2 {
		t.Errorf("token request = %q", got)
	}
	// the flow is single use
	w = do(s, "GET", "/oidc/callback?code=abc&state="+url.QueryEscape(state), ck)
	if 302 == w.Code {
		t.Error("a state value was accepted twice")
	}
}

func TestOIDCRejections(t *testing.T) {
	idp := newFakeIdP(t)
	s := newOIDCServer(t, idp, "OIDC login group = staff")
	for name, mod := range map[string]func(map[string]any){
		"wrong audience": func(c map[string]any) { c["aud"] = "other" },
		"wrong issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
		"expired":        func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"wrong nonce":    func(c map[string]any) { c["nonce"] = "not-the-nonce" },
		"not in group":   func(c map[string]any) {},
		"multi aud foreign azp": func(c map[string]any) {
			c["aud"] = []string{"golog", "other"}
			c["azp"] = "other"
		},
	} {
		mod := mod
		idp.claims = func(n string) map[string]any {
			c := goodClaims(idp)(n)
			mod(c)
			return c
		}
		state, ck := loginStart(t, s, idp)
		w := do(s, "GET", "/oidc/callback?code=abc&state="+url.QueryEscape(state), ck)
		if 302 == w.Code {
			t.Errorf("%s: login accepted", name)
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == s.SessionCookie && "" != c.Value {
				t.Errorf("%s: a session was started", name)
			}
		}
	}
	// state without the browser cookie (login CSRF), and an unknown state
	idp.claims = goodClaims(idp)
	state, _ := loginStart(t, s, idp)
	if w := do(s, "GET", "/oidc/callback?code=abc&state="+url.QueryEscape(state)); 302 == w.Code {
		t.Error("callback without the flow cookie accepted")
	}
	if w := do(s, "GET", "/oidc/callback?code=abc&state=nope"); 302 == w.Code {
		t.Error("unknown state accepted")
	}
}

func TestOIDCBadSignatureAndAlg(t *testing.T) {
	idp := newFakeIdP(t)
	idp.claims = goodClaims(idp)
	s := newOIDCServer(t, idp, "")
	p, set, err := s.oidcFor()
	if err != nil || nil == p {
		t.Fatal(err)
	}
	tok := idp.sign(goodClaims(idp)("n"))
	if _, err := p.verifyJWT(tok, set); err != nil {
		t.Fatalf("good token refused: %v", err)
	}
	parts := strings.Split(tok, ".")
	// flipped payload byte: signature no longer matches
	pl, _ := b64u(parts[1])
	pl[len(pl)/2] ^= 1
	if _, err := p.verifyJWT(parts[0]+"."+b64(pl)+"."+parts[2], set); err == nil {
		t.Error("tampered payload accepted")
	}
	// alg none and HS256 are never accepted
	for _, alg := range []string{"none", "HS256"} {
		h, _ := json.Marshal(map[string]string{"alg": alg, "kid": "k1"})
		if _, err := p.verifyJWT(b64(h)+"."+parts[1]+"."+parts[2], set); err == nil {
			t.Errorf("alg %s accepted", alg)
		}
	}
}

func TestOIDCSettingsErrors(t *testing.T) {
	s := New(ParseConfig("[global]\nOIDC issuer = https://x.example\n"), "")
	if _, err := s.oidcSettings(); err == nil {
		t.Error("missing client id accepted")
	}
	s = New(ParseConfig("[global]\nOIDC issuer = https://x.example\nOIDC client id = a\nOIDC redirect uri = https://h/oidc/callback\nOIDC algorithms = none\n"), "")
	if _, err := s.oidcSettings(); err == nil {
		t.Error("alg none accepted in the allow-list")
	}
}

func TestOIDCForcedModeRedirects(t *testing.T) {
	idp := newFakeIdP(t)
	s := newOIDCServer(t, idp, "SSO mode = forced")
	w := do(s, "GET", "/?cmd=Login")
	if 302 != w.Code || !strings.Contains(w.Header().Get("Location"), "/oidc/login") {
		t.Errorf("forced mode: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = do(s, "GET", "/?cmd=Login&local=1")
	if 200 != w.Code || !strings.Contains(w.Body.String(), `name="upwd"`) {
		t.Errorf("break-glass local form not shown: %d", w.Code)
	}
}

// A second login under the same account name with another provider subject is
// refused, and an existing unlinked local account is not taken over.
func TestOIDCAccountLinking(t *testing.T) {
	idp := newFakeIdP(t)
	s := newOIDCServer(t, idp, "OIDC strip domain = 1")
	login := func(sub string) int {
		idp.claims = func(n string) map[string]any {
			c := goodClaims(idp)(n)
			c["sub"] = sub
			return c
		}
		state, ck := loginStart(t, s, idp)
		return do(s, "GET", "/oidc/callback?code=abc&state="+url.QueryEscape(state), ck).Code
	}
	if 302 != login("sub-A") {
		t.Fatal("first login refused")
	}
	if 302 != login("sub-A") {
		t.Error("same subject refused")
	}
	if 302 == login("sub-B") {
		t.Error("another subject took over the linked account")
	}
}
