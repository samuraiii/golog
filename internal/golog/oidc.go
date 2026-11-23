// golog - OpenID Connect relying party (authorization code flow with PKCE).
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// Design: docs/SSO-DESIGN.md (section 2). This file is the protocol half: the
// settings, discovery, the key set, ID-token validation. oidchttp.go is the
// browser half: /oidc/login, /oidc/callback and the login-page button.
//
// Configuration, [global] (all keys optional except the first three):
//
//	OIDC issuer = https://login.example/realms/x     iss, also the discovery base
//	OIDC client id = golog
//	OIDC client secret file = /etc/golog/oidc-secret (or "OIDC client secret")
//	OIDC redirect uri = https://logbooks.example/golog/oidc/callback
//	OIDC external url = https://logbooks.example/golog   (derives the redirect uri)
//	OIDC name = Corporate SSO                button label / log prefix
//	OIDC scopes = openid profile email       "groups" is added when a group
//	                                         claim is mapped
//	OIDC algorithms = RS256 ES256            allow-list; none and HS* never
//	OIDC clock skew = 120                    seconds, at most 300
//	OIDC claim user = preferred_username, email, sub
//	OIDC claim fullname = name
//	OIDC claim email = email
//	OIDC claim groups = groups
//	OIDC strip domain = 0                    jdoe@corp -> jdoe
//	OIDC lowercase user = 1
//	OIDC login group = <group>               required membership, if set
//	OIDC admin group = <group>               members become administrators
//	OIDC create user = 1                     create the local user record
//	OIDC auth style = basic|post             client authentication at the token
//	                                         endpoint (default basic)
//	OIDC ca file = <pem>                     extra CA for the provider's TLS
//	OIDC http timeout = 10                   seconds
//	OIDC flow ttl = 300                      seconds a login may take
//	SSO mode = off|button|forced             (default off)
//	SSO local login = 1                      forced mode: keep ?local=1 reachable
package golog

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// oidcSettings is the OIDC configuration read from the global section.
type oidcSettings struct {
	Issuer, ClientID, Secret, RedirectURI string
	Name                                  string
	Scopes                                []string
	Algs                                  map[string]bool
	Skew                                  time.Duration
	ClaimUser, ClaimName, ClaimEmail      []string
	ClaimGroups                           string
	StripDomain, Lower, CreateUser        bool
	LoginGroup, AdminGroup                string
	PostAuth                              bool
	CAFile                                string
	HTTPTimeout, FlowTTL                  time.Duration
}

func cfgList(s *Server, key, def string) []string {
	v := strings.TrimSpace(s.Config.GetString(ConfigScope{Group: "global"}, key, def))
	var out []string
	for _, f := range strings.FieldsFunc(v, func(r rune) bool { return ',' == r || ' ' == r || ';' == r }) {
		out = append(out, f)
	}
	return out
}

func cfgSeconds(s *Server, key string, def, max int) time.Duration {
	n := s.Config.GetInt(ConfigScope{Group: "global"}, key, def)
	if n <= 0 {
		n = def
	}
	if max > 0 && n > max {
		n = max
	}
	return time.Duration(n) * time.Second
}

// oidcConfigured reads the settings; nil means "no OIDC provider configured".
func (s *Server) oidcSettings() (*oidcSettings, error) {
	g := ConfigScope{Group: "global"}
	iss := strings.TrimRight(strings.TrimSpace(s.Config.GetString(g, "OIDC issuer", "")), "/")
	if "" == iss {
		return nil, nil
	}
	o := &oidcSettings{Issuer: iss}
	o.ClientID = strings.TrimSpace(s.Config.GetString(g, "OIDC client id", ""))
	if "" == o.ClientID {
		return nil, errors.New(`"OIDC client id" is not set`)
	}
	o.Secret = strings.TrimSpace(s.Config.GetString(g, "OIDC client secret", ""))
	if f := strings.TrimSpace(s.Config.GetString(g, "OIDC client secret file", "")); "" != f {
		b, err := os.ReadFile(s.Abs(f))
		if err != nil {
			return nil, fmt.Errorf("OIDC client secret file: %w", err)
		}
		o.Secret = strings.TrimSpace(string(b))
	}
	o.RedirectURI = strings.TrimSpace(s.Config.GetString(g, "OIDC redirect uri", ""))
	if "" == o.RedirectURI {
		ext := strings.TrimRight(strings.TrimSpace(s.Config.GetString(g, "OIDC external url", "")), "/")
		if "" == ext {
			return nil, errors.New(`set "OIDC redirect uri" or "OIDC external url"`)
		}
		o.RedirectURI = ext + "/oidc/callback"
	}
	o.Name = s.Config.GetString(g, "OIDC name", "Single sign-on")
	o.Scopes = cfgList(s, "OIDC scopes", "openid profile email")
	o.ClaimUser = cfgList(s, "OIDC claim user", "preferred_username, email, sub")
	o.ClaimName = cfgList(s, "OIDC claim fullname", "name")
	o.ClaimEmail = cfgList(s, "OIDC claim email", "email")
	o.ClaimGroups = strings.TrimSpace(s.Config.GetString(g, "OIDC claim groups", "groups"))
	hasOpenID := false
	for _, sc := range o.Scopes {
		if "openid" == sc {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		o.Scopes = append([]string{"openid"}, o.Scopes...)
	}
	o.Algs = map[string]bool{}
	for _, a := range cfgList(s, "OIDC algorithms", "RS256 ES256") {
		switch a {
		case "RS256", "RS384", "RS512", "ES256", "ES384":
			o.Algs[a] = true
		default:
			return nil, fmt.Errorf("OIDC algorithms: %q is not supported (RS256/384/512, ES256/384)", a)
		}
	}
	o.Skew = cfgSeconds(s, "OIDC clock skew", 120, 300)
	o.StripDomain = s.Config.GetBool(g, "OIDC strip domain")
	o.Lower = "0" != strings.TrimSpace(s.Config.GetString(g, "OIDC lowercase user", "1"))
	o.CreateUser = "0" != strings.TrimSpace(s.Config.GetString(g, "OIDC create user", "1"))
	o.LoginGroup = strings.TrimSpace(s.Config.GetString(g, "OIDC login group", ""))
	o.AdminGroup = strings.TrimSpace(s.Config.GetString(g, "OIDC admin group", ""))
	o.PostAuth = "post" == strings.ToLower(strings.TrimSpace(s.Config.GetString(g, "OIDC auth style", "basic")))
	o.CAFile = strings.TrimSpace(s.Config.GetString(g, "OIDC ca file", ""))
	if "" != o.CAFile {
		o.CAFile = s.Abs(o.CAFile)
	}
	o.HTTPTimeout = cfgSeconds(s, "OIDC http timeout", 10, 120)
	o.FlowTTL = cfgSeconds(s, "OIDC flow ttl", 300, 1800)
	return o, nil
}

// ---------------------------------------------------------------------------
// provider: discovery and keys
// ---------------------------------------------------------------------------

type oidcMeta struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURI  string `json:"jwks_uri"`
}

type oidcProvider struct {
	mu       sync.Mutex
	set      *oidcSettings
	client   *http.Client
	meta     *oidcMeta
	metaAt   time.Time
	keys     map[string]crypto.PublicKey
	jwksAt   time.Time
	lastMiss time.Time // last forced refetch because of an unknown kid
	flows    map[string]*oidcFlow
}

var (
	oidcMu   sync.Mutex
	oidcProv *oidcProvider
)

// oidcFor returns the provider for the current settings, rebuilding it when the
// issuer, client or CA changed in the configuration.
func (s *Server) oidcFor() (*oidcProvider, *oidcSettings, error) {
	set, err := s.oidcSettings()
	if err != nil || nil == set {
		return nil, nil, err
	}
	oidcMu.Lock()
	defer oidcMu.Unlock()
	if oidcProv != nil && oidcProv.set.Issuer == set.Issuer && oidcProv.set.ClientID == set.ClientID && oidcProv.set.CAFile == set.CAFile {
		oidcProv.mu.Lock()
		oidcProv.set = set
		oidcProv.mu.Unlock()
		return oidcProv, set, nil
	}
	cl, err := newOIDCClient(set)
	if err != nil {
		return nil, nil, err
	}
	oidcProv = &oidcProvider{set: set, client: cl, flows: map[string]*oidcFlow{}}
	return oidcProv, set, nil
}

func newOIDCClient(set *oidcSettings) (*http.Client, error) {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: set.HTTPTimeout,
		MaxIdleConns:        4,
		IdleConnTimeout:     60 * time.Second,
	}
	if "" != set.CAFile {
		pool, err := x509.SystemCertPool()
		if err != nil || nil == pool {
			pool = x509.NewCertPool()
		}
		b, err := os.ReadFile(set.CAFile)
		if err != nil {
			return nil, fmt.Errorf("OIDC ca file: %w", err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("OIDC ca file: no certificate found")
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{
		Transport: tr,
		Timeout:   set.HTTPTimeout,
		// The provider's endpoints do not redirect; a redirect is an attack or a
		// misconfiguration, not something to follow with a client secret.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func (p *oidcProvider) getJSON(u string, into any, limit int64) error {
	resp, err := p.client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if 200 != resp.StatusCode {
		return fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(into)
}

// metadata returns the discovery document, refreshed once a day.
func (p *oidcProvider) metadata() (*oidcMeta, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meta != nil && time.Since(p.metaAt) < 24*time.Hour {
		return p.meta, nil
	}
	var m oidcMeta
	if err := p.getJSON(p.set.Issuer+"/.well-known/openid-configuration", &m, 1<<20); err != nil {
		if p.meta != nil {
			return p.meta, nil // keep the old one while the provider is down
		}
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	if m.Issuer != p.set.Issuer {
		return nil, fmt.Errorf("OIDC discovery: issuer %q does not match the configured %q", m.Issuer, p.set.Issuer)
	}
	for _, e := range []string{m.AuthURL, m.TokenURL, m.JWKSURI} {
		u, err := url.Parse(e)
		if err != nil || "https" != u.Scheme && !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("OIDC discovery: endpoint %q is not https", e)
		}
	}
	p.meta, p.metaAt = &m, time.Now()
	return p.meta, nil
}

func isLoopbackHost(h string) bool {
	return "localhost" == h || "127.0.0.1" == h || "::1" == h
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64u(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (k jwk) public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err1 := b64u(k.N)
		e, err2 := b64u(k.E)
		if err1 != nil || err2 != nil || 0 == len(n) || 0 == len(e) || len(e) > 4 {
			return nil, errors.New("bad RSA key")
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n)}
		for _, b := range e {
			pk.E = pk.E<<8 | int(b)
		}
		if pk.N.BitLen() < 2048 || pk.E < 3 {
			return nil, errors.New("RSA key too small")
		}
		return pk, nil
	case "EC":
		var c elliptic.Curve
		switch k.Crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		default:
			return nil, errors.New("unsupported curve " + k.Crv)
		}
		x, err1 := b64u(k.X)
		y, err2 := b64u(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad EC key")
		}
		pk := &ecdsa.PublicKey{Curve: c, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !c.IsOnCurve(pk.X, pk.Y) {
			return nil, errors.New("EC point is not on the curve")
		}
		return pk, nil
	}
	return nil, errors.New("unsupported key type " + k.Kty)
}

// fetchKeys replaces the key set from the JWKS document.
func (p *oidcProvider) fetchKeys(m *oidcMeta) error {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(m.JWKSURI, &doc, 256<<10); err != nil {
		return fmt.Errorf("OIDC jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for i, k := range doc.Keys {
		if "" != k.Use && "sig" != k.Use {
			continue
		}
		pk, err := k.public()
		if err != nil {
			continue
		}
		id := k.Kid
		if "" == id {
			id = fmt.Sprintf("#%d", i)
		}
		keys[id] = pk
	}
	if 0 == len(keys) {
		return errors.New("OIDC jwks: no usable signing key")
	}
	p.keys, p.jwksAt = keys, time.Now()
	return nil
}

// key finds the verification key for a kid. The set is refreshed every 6 hours
// and, for an unknown kid, at most once a minute (key rotation without letting a
// forged kid make golog hammer the provider).
func (p *oidcProvider) key(kid string) (crypto.PublicKey, error) {
	m, err := p.metadata()
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if nil == p.keys || time.Since(p.jwksAt) > 6*time.Hour {
		if err := p.fetchKeys(m); err != nil && nil == p.keys {
			return nil, err
		}
	}
	find := func() (crypto.PublicKey, bool) {
		if k, ok := p.keys[kid]; ok && "" != kid {
			return k, true
		}
		if "" == kid && 1 == len(p.keys) {
			for _, k := range p.keys {
				return k, true
			}
		}
		return nil, false
	}
	if k, ok := find(); ok {
		return k, nil
	}
	if time.Since(p.lastMiss) > time.Minute {
		p.lastMiss = time.Now()
		if err := p.fetchKeys(m); err == nil {
			if k, ok := find(); ok {
				return k, nil
			}
		}
	}
	return nil, fmt.Errorf("no key %q in the provider's key set", kid)
}

// ---------------------------------------------------------------------------
// ID token validation
// ---------------------------------------------------------------------------

var hashFor = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"ES256": crypto.SHA256, "ES384": crypto.SHA384,
}

// verifyJWT checks the signature of a compact JWS against the allowed
// algorithms and the provider's keys and returns the claims.
func (p *oidcProvider) verifyJWT(tok string, set *oidcSettings) (map[string]any, error) {
	if len(tok) > 16384 {
		return nil, errors.New("token too large")
	}
	parts := strings.Split(tok, ".")
	if 3 != len(parts) {
		return nil, errors.New("not a compact JWS")
	}
	hb, err1 := b64u(parts[0])
	pb, err2 := b64u(parts[1])
	sig, err3 := b64u(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("bad base64 in token")
	}
	var hdr struct {
		Alg  string   `json:"alg"`
		Kid  string   `json:"kid"`
		Crit []string `json:"crit"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errors.New("bad token header")
	}
	if len(hdr.Crit) > 0 {
		return nil, errors.New("token has critical header extensions")
	}
	h, known := hashFor[hdr.Alg]
	if !known || !set.Algs[hdr.Alg] {
		return nil, fmt.Errorf("algorithm %q is not allowed", hdr.Alg)
	}
	key, err := p.key(hdr.Kid)
	if err != nil {
		return nil, err
	}
	hh := h.New()
	hh.Write([]byte(parts[0] + "." + parts[1]))
	digest := hh.Sum(nil)
	switch k := key.(type) {
	case *rsa.PublicKey:
		if !strings.HasPrefix(hdr.Alg, "RS") {
			return nil, errors.New("key type does not match the algorithm")
		}
		if err := rsa.VerifyPKCS1v15(k, h, digest, sig); err != nil {
			return nil, errors.New("bad signature")
		}
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(hdr.Alg, "ES") {
			return nil, errors.New("key type does not match the algorithm")
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return nil, errors.New("bad signature length")
		}
		r := new(big.Int).SetBytes(sig[:size])
		sg := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, sg) {
			return nil, errors.New("bad signature")
		}
	default:
		return nil, errors.New("unsupported key")
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, errors.New("bad token payload")
	}
	return claims, nil
}

func claimNum(c map[string]any, k string) (time.Time, bool) {
	n, ok := c[k].(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// checkClaims applies the ID-token rules of OpenID Connect Core 3.1.3.7.
func checkClaims(c map[string]any, set *oidcSettings, nonce string, now time.Time) error {
	if iss, _ := c["iss"].(string); iss != set.Issuer {
		return fmt.Errorf("issuer %q is not the configured one", iss)
	}
	switch a := c["aud"].(type) {
	case string:
		if a != set.ClientID {
			return errors.New("token is for another audience")
		}
	case []any:
		found := false
		for _, x := range a {
			if s, _ := x.(string); s == set.ClientID {
				found = true
			}
		}
		if !found {
			return errors.New("token is for another audience")
		}
		if len(a) > 1 {
			if azp, _ := c["azp"].(string); azp != set.ClientID {
				return errors.New("token has several audiences and a foreign azp")
			}
		}
	default:
		return errors.New("token has no audience")
	}
	exp, ok := claimNum(c, "exp")
	if !ok || !now.Before(exp.Add(set.Skew)) {
		return errors.New("token is expired or has no exp")
	}
	if iat, ok := claimNum(c, "iat"); ok && iat.After(now.Add(set.Skew)) {
		return errors.New("token was issued in the future")
	}
	if nbf, ok := claimNum(c, "nbf"); ok && nbf.After(now.Add(set.Skew)) {
		return errors.New("token is not valid yet")
	}
	if n, _ := c["nonce"].(string); "" == nonce || n != nonce {
		return errors.New("nonce mismatch")
	}
	if sub, _ := c["sub"].(string); "" == sub {
		return errors.New("token has no subject")
	}
	return nil
}

func claimStrings(c map[string]any, names []string) string {
	for _, n := range names {
		if s, ok := c[n].(string); ok && "" != strings.TrimSpace(s) {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func claimGroups(c map[string]any, name string) []string {
	var out []string
	switch v := c[name].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && len(out) < 256 {
				out = append(out, s)
			}
		}
	case string:
		out = SplitList(v, ",", false)
	}
	return out
}

// identityFromClaims maps validated claims to a golog identity. A name with a
// control character or a length above 256 is refused.
func identityFromClaims(c map[string]any, set *oidcSettings) (Identity, error) {
	name := claimStrings(c, set.ClaimUser)
	if "" == name {
		return Identity{}, errors.New("the token carries no user name claim")
	}
	if set.StripDomain {
		if i := strings.IndexByte(name, '@'); i > 0 {
			name = name[:i]
		}
	}
	if set.Lower {
		name = strings.ToLower(name)
	}
	if len(name) > 256 {
		return Identity{}, errors.New("user name too long")
	}
	for _, r := range name {
		if r < 0x20 || 0x7f == r {
			return Identity{}, errors.New("user name has a control character")
		}
	}
	id := Identity{
		Name:     name,
		FullName: claimStrings(c, set.ClaimName),
		Email:    claimStrings(c, set.ClaimEmail),
		AuthType: "oidc",
		Groups:   claimGroups(c, set.ClaimGroups),
	}
	id.Principal, _ = c["sub"].(string)
	in := func(g string) bool {
		for _, x := range id.Groups {
			if x == g {
				return true
			}
		}
		return false
	}
	if "" != set.LoginGroup && !in(set.LoginGroup) {
		return Identity{}, errors.New("the user is not in the required group")
	}
	id.Admin = "" != set.AdminGroup && in(set.AdminGroup)
	return id, nil
}
