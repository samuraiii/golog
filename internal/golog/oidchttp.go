// golog - OpenID Connect: the browser half (login redirect, callback, button).
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// Routes (relative to the base path): /oidc/login starts the flow,
// /oidc/callback is the redirect URI to register at the provider. A logbook
// named "oidc" would be shadowed by them, which is the price of a callback URL
// without a query string (providers such as Entra ID do not accept one).
package golog

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	oidcFlowCookie = "golog_oidc_flow"
	oidcMaxFlows   = 10000
)

// oidcFlow is one login in progress, kept server side under its state value.
type oidcFlow struct {
	nonce, verifier, redir, ip string
	created                    time.Time
}

// cryptoToken returns n random bytes base64url encoded; unlike RandomToken it
// fails instead of falling back to the clock.
func cryptoToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// oidcMode is "off", "button" or "forced".
func (s *Server) oidcMode() string {
	if "" == strings.TrimSpace(s.Config.GetString(ConfigScope{Group: "global"}, "OIDC issuer", "")) {
		return "off"
	}
	switch m := strings.ToLower(strings.TrimSpace(s.Config.GetString(ConfigScope{Group: "global"}, "SSO mode", "off"))); m {
	case "button", "forced":
		return m
	}
	return "off"
}

// oidcRoute handles /oidc/login and /oidc/callback; it reports whether the
// request was one of them.
func (s *Server) oidcRoute(q *Request) bool {
	p := strings.TrimRight(q.path, "/")
	if "/oidc/login" != p && "/oidc/callback" != p {
		return false
	}
	q.Cfg = ConfigScope{Group: "global", TopGroup: "global"}
	q.parseParams()
	q.authenticate()
	if "off" == s.oidcMode() {
		s.errorf(q, http.StatusNotFound, "Single sign-on is not enabled")
		return true
	}
	if "/oidc/login" == p {
		s.oidcLogin(q)
	} else {
		s.oidcCallback(q)
	}
	return true
}

func (s *Server) oidcFail(q *Request, code int, user string, format string, a ...any) {
	ip := s.LoginSourceIP(q.R)
	logS(s, "golog auth: OIDC login refused for %s from %s: %s", orText(user, "-"), ip, fmt.Sprintf(format, a...))
	FailBanLogFailure(s, user, ip)
	// The browser gets one generic sentence; the reason is in the log.
	s.errorf(q, code, "Single sign-on failed. Please try again, or ask the administrator.")
}

// oidcLogin starts the authorization code flow with PKCE.
func (s *Server) oidcLogin(q *Request) {
	p, set, err := s.oidcFor()
	if err != nil || nil == p {
		logS(s, "golog auth: OIDC configuration: %v", err)
		s.errorf(q, http.StatusServiceUnavailable, "Single sign-on is not available")
		return
	}
	if blocked, secs, why, _ := s.LoginGuardBlocked("", s.LoginSourceIP(q.R)); blocked {
		q.W.Header().Set("Retry-After", fmt.Sprint(secs))
		s.errorf(q, http.StatusTooManyRequests, "%s", why)
		return
	}
	meta, err := p.metadata()
	if err != nil {
		logS(s, "golog auth: %v", err)
		s.errorf(q, http.StatusServiceUnavailable, "Single sign-on is not available")
		return
	}
	state, e1 := cryptoToken(32)
	nonce, e2 := cryptoToken(32)
	verifier, e3 := cryptoToken(48)
	if e1 != nil || e2 != nil || e3 != nil {
		s.errorf(q, http.StatusInternalServerError, "Single sign-on is not available")
		return
	}
	now := time.Now()
	p.mu.Lock()
	for k, f := range p.flows { // drop stale flows
		if now.Sub(f.created) > set.FlowTTL {
			delete(p.flows, k)
		}
	}
	if len(p.flows) >= oidcMaxFlows {
		p.mu.Unlock()
		s.errorf(q, http.StatusServiceUnavailable, "Too many logins in progress, try again in a minute")
		return
	}
	p.flows[state] = &oidcFlow{nonce: nonce, verifier: verifier, redir: q.redirParam(), ip: s.LoginSourceIP(q.R), created: now}
	p.mu.Unlock()

	sum := sha256.Sum256([]byte(verifier))
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", set.ClientID)
	v.Set("redirect_uri", set.RedirectURI)
	scopes := append([]string(nil), set.Scopes...)
	v.Set("scope", strings.Join(scopes, " "))
	v.Set("state", state)
	v.Set("nonce", nonce)
	v.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	v.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(meta.AuthURL, "?") {
		sep = "&"
	}
	http.SetCookie(q.W, &http.Cookie{
		Name: oidcFlowCookie, Value: state, Path: s.CookiePath(), MaxAge: int(set.FlowTTL.Seconds()),
		HttpOnly: true, Secure: q.R.TLS != nil || set.RedirectURI[:5] == "https", SameSite: http.SameSiteLaxMode,
	})
	q.W.Header().Set("Cache-Control", "no-store")
	q.W.Header().Set("Location", meta.AuthURL+sep+v.Encode())
	q.W.WriteHeader(http.StatusFound)
}

// oidcCallback completes the flow: state check, code exchange, ID-token
// validation, identity mapping, session.
func (s *Server) oidcCallback(q *Request) {
	p, set, err := s.oidcFor()
	if err != nil || nil == p {
		s.errorf(q, http.StatusServiceUnavailable, "Single sign-on is not available")
		return
	}
	q.W.Header().Set("Cache-Control", "no-store")
	state := q.Param("state")
	// The flow is single use: take it out of the table first.
	p.mu.Lock()
	flow := p.flows[state]
	delete(p.flows, state)
	p.mu.Unlock()
	clear := func() {
		http.SetCookie(q.W, &http.Cookie{Name: oidcFlowCookie, Value: "", Path: s.CookiePath(), MaxAge: -1, HttpOnly: true})
	}
	ck, cerr := q.R.Cookie(oidcFlowCookie)
	if "" == state || nil == flow || cerr != nil || 1 != subtle.ConstantTimeCompare([]byte(ck.Value), []byte(state)) {
		clear()
		s.oidcFail(q, http.StatusBadRequest, "", "unknown or unbound state")
		return
	}
	clear()
	if time.Since(flow.created) > set.FlowTTL {
		s.oidcFail(q, http.StatusBadRequest, "", "login took longer than %s", set.FlowTTL)
		return
	}
	if e := q.Param("error"); "" != e {
		s.oidcFail(q, http.StatusForbidden, "", "provider answered error=%q", truncate(e, 60))
		return
	}
	code := q.Param("code")
	if "" == code || len(code) > 4096 {
		s.oidcFail(q, http.StatusBadRequest, "", "no authorization code")
		return
	}
	meta, err := p.metadata()
	if err != nil {
		s.oidcFail(q, http.StatusServiceUnavailable, "", "%v", err)
		return
	}
	idToken, err := p.exchange(meta, set, code, flow.verifier)
	if err != nil {
		s.oidcFail(q, http.StatusForbidden, "", "token exchange: %v", err)
		return
	}
	claims, err := p.verifyJWT(idToken, set)
	if err == nil {
		err = checkClaims(claims, set, flow.nonce, time.Now())
	}
	if err != nil {
		s.oidcFail(q, http.StatusForbidden, "", "ID token: %v", err)
		return
	}
	id, err := identityFromClaims(claims, set)
	if err != nil {
		s.oidcFail(q, http.StatusForbidden, "", "%v", err)
		return
	}
	if err := s.oidcCheckLink(set, id.Name, id.Principal); err != nil {
		s.oidcFail(q, http.StatusForbidden, id.Name, "%v", err)
		return
	}
	if !set.CreateUser && (nil == s.Pwd || nil == s.Pwd.User(id.Name)) {
		s.oidcFail(q, http.StatusForbidden, id.Name, "no local user record and OIDC create user = 0")
		return
	}
	q.params.Set("redir", flow.redir)
	s.finishLogin(q, id)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// exchange trades the code for tokens and returns the ID token.
func (p *oidcProvider) exchange(meta *oidcMeta, set *oidcSettings, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", set.RedirectURI)
	form.Set("code_verifier", verifier)
	if set.PostAuth || "" == set.Secret {
		form.Set("client_id", set.ClientID)
		if "" != set.Secret {
			form.Set("client_secret", set.Secret)
		}
	}
	req, err := http.NewRequest(http.MethodPost, meta.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if !set.PostAuth && "" != set.Secret {
		req.SetBasicAuth(url.QueryEscape(set.ClientID), url.QueryEscape(set.Secret))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if 200 != resp.StatusCode {
		return "", fmt.Errorf("token endpoint answered HTTP %d", resp.StatusCode)
	}
	var tr struct {
		IDToken string `json:"id_token"`
		Type    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || "" == tr.IDToken {
		return "", fmt.Errorf("token response has no id_token")
	}
	return tr.IDToken, nil
}

// ssoButtonHTML is the "Sign in with ..." block of the login page ("" when SSO
// is off).
func (s *Server) ssoButtonHTML(q *Request) string {
	if "off" == s.oidcMode() {
		return ""
	}
	g := ConfigScope{Group: "global"}
	label := s.Config.GetString(g, "SSO button label", "Sign in with "+s.Config.GetString(g, "OIDC name", "single sign-on"))
	target := s.BasePath + "/oidc/login"
	if r := q.redirParam(); "" != r {
		target += "?redir=" + url.QueryEscape(r)
	}
	return fmt.Sprintf("<p><a class=\"navbar\" href=\"%s\"><b>%s</b></a></p>\n", HTMLEscape(target), HTMLEscape(label))
}

// ssoForced reports that the login page must send the browser to the provider:
// forced mode, and the break-glass local form not asked for (or not allowed).
func (s *Server) ssoForced(q *Request) bool {
	if "forced" != s.oidcMode() {
		return false
	}
	local := "0" != strings.TrimSpace(s.Config.GetString(ConfigScope{Group: "global"}, "SSO local login", "1"))
	return !(local && "1" == q.Param("local"))
}
