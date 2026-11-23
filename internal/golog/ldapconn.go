package golog

// The directory behind the LDAP back end, and the real client.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.
//
// LdapDir is the whole surface the LDAP back end needs: search, bind as somebody,
// bind as somebody on a connection that is thrown away, close. That is enough to
// authenticate anybody and little enough that a test can carry a directory in a
// map - no server, no network, no port 389 - while production runs the same code
// against the vendored github.com/go-ldap/ldap/v3.
//
// Two rules fall out of the interface and are worth stating where they are born:
//
//   - Bind changes the identity of a connection, so the connection it is used on
//     belongs to one caller at a time. The pool hands out one connection per bind
//     identity and never lets two logins share a connection that is bound.
//   - BindFresh exists because the caller's password must not end up on a shared
//     connection: a failed bind on a pooled connection can leave the server with
//     an unexpected security buffer (which is a real error the library reports),
//     and a successful one would leave the caller's credentials in force on a
//     connection that later serves somebody else. So BindFresh dials, binds, and
//     hands over a connection the caller must Close.
//
// Reuse, kept as simple as it can be
// ----------------------------------
//
// A login costs two round trips (look the account up, bind as it) on top of the
// TCP and TLS handshake. Opening a connection per login is what the C daemon does
// - authenticate_user_ldap() calls ldap_initialize() and ldap_unbind_ext_s()
// around every attempt - and against a domain controller that means a fresh TLS
// handshake per login attempt, which is exactly the CPU an attacker brute-forcing
// accounts wants the server to spend.
//
// So connections are kept, as a slice of idle connections under a mutex with
// three rules and nothing else: a connection is only handed to a caller that wants
// the same bind identity; a connection idle for longer than "Ldap idle timeout" is
// closed instead of reused (a directory or a firewall drops an idle session, and
// finding that out during a user's login is worse than dialling again); and a
// connection that produced an error is closed, never returned. There is no
// background sweeper and no wait queue - the idle timeout is applied when a
// connection is taken out, which is the only moment it matters.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LdapDir is one directory the back end can talk to. Everything takes the URL: a
// pooled implementation borrows a connection for that URL, a single-connection
// implementation ignores it, a fake answers from a table.
type LdapDir interface {
	// Search runs one search. Referrals are never followed.
	Search(baseDN, filter string, scope int, attributes []string) ([]*ldap.Entry, error)
	// Bind changes the identity of a connection held by the caller.
	Bind(dn, password string) error
	// BindFresh dials url, binds as dn with password and returns the connection.
	// The caller must Close it; nothing about the secret is kept.
	BindFresh(url, dn, password string) (LdapDir, error)
	// Close releases what this directory holds.
	Close() error
}

// brokenDir is the LdapDir of a back end whose configuration is unusable: every
// operation returns the reason, so a broken "Ldap url" produces the same clear
// message on every login instead of a different surprise on every code path.
type brokenDir struct{ err error }

func (b brokenDir) Search(string, string, int, []string) ([]*ldap.Entry, error) {
	return nil, b.err
}

func (b brokenDir) Bind(string, string) error { return b.err }

func (b brokenDir) BindFresh(string, string, string) (LdapDir, error) { return nil, b.err }

func (b brokenDir) Close() error { return b.err }

// ---------------------------------------------------------------------------
// one connection
// ---------------------------------------------------------------------------

// ldapDirConn adapts *ldap.Conn to LdapDir.
type ldapDirConn struct {
	c *ldap.Conn
	// searchScope, searchSize and searchSeconds are the search request's limits;
	// they live here because they belong to the request the pool builds, not to
	// the protocol object.
	searchSize    int
	searchSeconds int
}

// Search runs one search with the alias dereference policy set to never, which is
// what stops a wrong base DN from sending the service account's credentials to a
// server the configuration does not name. It is also the reason a referral is
// reported rather than followed: ldap.Conn has no referral-chasing option, so a
// referral would be an error here even if the search request asked for it.
func (d *ldapDirConn) Search(baseDN, filter string, scope int, attributes []string) ([]*ldap.Entry, error) {
	if d == nil || d.c == nil {
		return nil, AuthUnavailablef("the ldap connection is closed")
	}
	req := ldap.NewSearchRequest(baseDN, scope, ldap.NeverDerefAliases,
		d.searchSize, d.searchSeconds, false, filter, attributes, nil)
	res, err := d.c.Search(req)
	if err != nil {
		return nil, ldapError(err)
	}
	if res == nil {
		return nil, nil
	}
	if len(res.Referrals) > 0 {
		// Named in the log, then ignored: chasing it would mean handing the
		// service account to another server.
		logS(currentServer(), "golog auth: ldap server referred to %d server(s), not followed: %s",
			len(res.Referrals), ldapLogToken(strings.Join(res.Referrals, " ")))
	}
	return res.Entries, nil
}

// Bind performs a simple bind. The library also offers DialWithBind, an NTLM bind
// and an unauthenticated bind; simple bind is the one that works against Active
// Directory, OpenLDAP and Samba alike, and the only one that keeps the caller's
// secret out of any challenge-response the daemon would then have to implement.
func (d *ldapDirConn) Bind(dn, password string) error {
	if d == nil || d.c == nil {
		return AuthUnavailablef("the ldap connection is closed")
	}
	return ldapError(d.c.Bind(dn, password))
}

// BindFresh on a connection dials a new one: a caller that asks for a fresh
// connection must not get the one it is holding.
func (d *ldapDirConn) BindFresh(url, dn, password string) (LdapDir, error) {
	return ldapDialURL(url, ldapOptions{}, dn, password)
}

// Close unbinds and closes.
func (d *ldapDirConn) Close() error {
	if d == nil || d.c == nil {
		return nil
	}
	return d.c.Close()
}

// ldapDialFunc opens one directory connection and performs the bind. A test
// replaces it through ldapOptions.dial; production uses ldapDialURL.
type ldapDialFunc func(rawURL string, o ldapOptions, bindDN, bindPassword string) (LdapDir, error)

// ldapDialURL is the production dial: connect, transport security, timeouts, bind.
//
// The timeouts matter: the C client sets none at all, so a directory that stops
// answering hangs the login, the goroutine and the connection forever.
func ldapDialURL(rawURL string, o ldapOptions, bindDN, bindPassword string) (LdapDir, error) {
	info, err := parseLDAPURL(rawURL)
	if err != nil {
		return nil, err
	}
	dialTimeout := orDuration(o.dialTimeout, 10*time.Second)
	ioTimeout := orDuration(o.ioTimeout, 15*time.Second)
	tlsCfg, err := ldapTLSConfig(o)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	var conn *ldap.Conn
	if info.tls {
		conn, err = ldap.DialURL(rawURL, ldap.DialWithTLSConfig(tlsCfg), ldap.DialWithDialer(dialer))
	} else {
		conn, err = ldap.DialURL(rawURL, ldap.DialWithDialer(dialer))
	}
	if err != nil {
		return nil, AuthUnavailablef("cannot connect to %s: %v", ldapLogToken(rawURL), err)
	}
	if conn == nil {
		return nil, AuthUnavailablef("cannot connect to %s", ldapLogToken(rawURL))
	}
	conn.SetTimeout(ioTimeout)

	if !info.tls && o.startTLS {
		cfg := ldapTLSStartConfig(o, tlsCfg)
		if err := conn.StartTLS(cfg); err != nil {
			_ = conn.Close()
			return nil, AuthUnavailablef("ldap starttls %s: %v", ldapLogToken(rawURL), err)
		}
	}
	d := &ldapDirConn{c: conn, searchSize: 0, searchSeconds: int(ioTimeout / time.Second)}
	if TrimSpaceASCII(bindDN) != "" {
		if err := conn.Bind(bindDN, bindPassword); err != nil {
			_ = conn.Close()
			if isLdapBadCreds(err) {
				// The service account's own secret is wrong. That is not
				// "unavailable" - the operator has to fix it - and counting it
				// against the caller's login allowance would be wrong as well, so
				// it is ErrBadPassword wrapped in a way that names the account.
				return nil, fmt.Errorf("golog: ldap service account %s: %w", ldapLogToken(bindDN), ErrBadPassword)
			}
			return nil, ldapError(err)
		}
	}
	return d, nil
}

// ldapTLSStartConfig prepares the StartTLS options. StartTLS takes the TLS
// configuration from the caller and fills ServerName in from the connection when
// it is empty; clearing it keeps a custom RootCAs pool from being paired with the
// name of a different server.
func ldapTLSStartConfig(o ldapOptions, base *tls.Config) *tls.Config {
	cfg := base
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg = cfg.Clone()
	if o.serverName != "" {
		cfg.ServerName = o.serverName
	} else {
		cfg.ServerName = ""
	}
	return cfg
}

// ldapURLInfo is what the dial needs to know about a URL: whether it is TLS from
// the start and whether it is a local socket.
type ldapURLInfo struct {
	tls   bool
	local bool
}

// parseLDAPURL validates the scheme. The library accepts "ldapi://" and would then
// read the host as a socket path - a confusing failure on Windows - and a URL
// without a scheme is a typo worth naming.
func parseLDAPURL(rawURL string) (ldapURLInfo, error) {
	var info ldapURLInfo
	switch {
	case HasPrefixFold(rawURL, "ldaps://"):
		info.tls = true
	case HasPrefixFold(rawURL, "ldap://"):
	case HasPrefixFold(rawURL, "ldapi://"):
		info.local = true
		return info, AuthUnavailablef("ldap url %s: a local socket (ldapi) is not supported", ldapLogToken(rawURL))
	default:
		return info, AuthUnavailablef("ldap url %s has no ldap:// or ldaps:// scheme", ldapLogToken(rawURL))
	}
	return info, nil
}

// ldapTLSConfig builds the TLS options from "Ldap ca file", "Ldap insecure skip
// verify" and "Ldap tls server name". The default is the system trust store with
// verification on and TLS 1.2 as the floor, which both a Windows Server 2016
// domain controller and any current OpenLDAP server speak.
func ldapTLSConfig(o ldapOptions) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.caFile != "" {
		pem, err := os.ReadFile(o.caFile)
		if err != nil {
			return nil, AuthUnavailablef("ldap ca file %s: %v", o.caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, AuthUnavailablef("ldap ca file %s holds no certificate", o.caFile)
		}
		cfg.RootCAs = pool
	}
	if o.serverName != "" {
		cfg.ServerName = o.serverName
	}
	if o.skipVerify {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

// isLDAPTransportError reports the errors that mean "this socket is unusable"
// rather than "the directory said no". The library wraps a protocol problem in
// *ldap.Error; a broken pipe or a deadline arrives as the network error itself, so
// anything that is not an LDAP result counts as transport.
func isLDAPTransportError(err error) bool {
	if err == nil {
		return false
	}
	var le *ldap.Error
	if !errors.As(err, &le) || le == nil {
		return true
	}
	switch le.ResultCode {
	case ldap.LDAPResultOperationsError, ldap.LDAPResultUnavailable,
		ldap.LDAPResultServerDown, ldap.LDAPResultTimeout,
		ldap.LDAPResultLocalError, ldap.LDAPResultEncodingError,
		ldap.LDAPResultDecodingError, ldap.LDAPResultBusy,
		ldap.LDAPResultUnavailableCriticalExtension,
		ldap.LDAPResultAdminLimitExceeded, ldap.LDAPResultConnectError:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// the pool
// ---------------------------------------------------------------------------

// ldapPool is the LdapDir a back end uses in production. It satisfies LdapDir
// itself, so the back end does not know whether it holds a pool, a single
// connection or, in a test, a fake.
type ldapPool struct {
	opts ldapOptions

	mu      sync.Mutex
	idle    []*ldapLease
	closed  bool
	dialled int // for the description line

	// dial replaces the real dialer; nil means ldapDialURL.
	dial ldapDialFunc
}

// ldapLease is one pooled connection plus the bookkeeping the pool needs.
type ldapLease struct {
	conn LdapDir
	who  string    // bind identity in force, "" = anonymous
	used time.Time // when it went back into the pool
	url  string
}

// acquire returns a healthy connection bound as dn. The caller must give it back
// with release (it worked) or discard (it failed), and must not hand it to
// anybody else while holding it.
func (p *ldapPool) acquire(dn string) (*ldapLease, error) {
	want := TrimSpaceASCII(dn)
	now := time.Now()
	idleTimeout := orDuration(p.opts.idleTimeout, time.Minute)

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, AuthUnavailablef("the ldap connection pool is closed")
	}
	var picked *ldapLease
	var keep []*ldapLease
	var expired []LdapDir
	for _, l := range p.idle {
		switch {
		case picked == nil && l != nil && l.who == want && now.Sub(l.used) <= idleTimeout:
			picked = l
		case l != nil && now.Sub(l.used) > idleTimeout:
			expired = append(expired, l.conn)
		case l != nil:
			keep = append(keep, l)
		}
	}
	p.idle = keep
	p.mu.Unlock()

	for _, c := range expired {
		_ = c.Close()
	}
	if picked != nil {
		return picked, nil
	}
	return p.dialAny(want, p.opts.bindPassword)
}

// dialAny tries every configured URL in order and returns the first connection
// that works with the given identity.
func (p *ldapPool) dialAny(dn, password string) (*ldapLease, error) {
	dial := p.dial
	if dial == nil {
		dial = ldapDialURL
	}
	var last error
	for _, raw := range p.opts.urls {
		conn, err := dial(raw, p.opts, dn, password)
		if err == nil {
			if conn == nil {
				last = AuthUnavailablef("cannot connect to %s", ldapLogToken(raw))
				continue
			}
			p.mu.Lock()
			p.dialled++
			p.mu.Unlock()
			return &ldapLease{conn: conn, who: TrimSpaceASCII(dn), used: time.Now(), url: raw}, nil
		}
		last = err
		if !IsAuthUnavailable(err) {
			// A wrong service-account password is the same on every server of the
			// forest; trying the next one only hides the reason.
			return nil, err
		}
	}
	if last == nil {
		return nil, AuthUnavailablef("no ldap url is configured")
	}
	return nil, last
}

// release puts a healthy connection back.
func (p *ldapPool) release(l *ldapLease) {
	if l == nil || l.conn == nil {
		return
	}
	l.used = time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	size := orRange(p.opts.poolSize, 1, 64)
	if p.closed || len(p.idle) >= size {
		_ = l.conn.Close()
		return
	}
	p.idle = append(p.idle, l)
}

// discard throws away a connection that failed.
func (p *ldapPool) discard(l *ldapLease) {
	if l == nil || l.conn == nil {
		return
	}
	_ = l.conn.Close()
}

// Search implements LdapDir: borrow the service-account connection, search, put it
// back. A transport error closes the connection; a directory-level error (bad
// filter, no such base) keeps it, because the connection itself is fine.
func (p *ldapPool) Search(baseDN, filter string, scope int, attributes []string) ([]*ldap.Entry, error) {
	lease, err := p.acquire(p.opts.bindDN)
	if err != nil {
		return nil, err
	}
	entries, err := lease.conn.Search(baseDN, filter, scope, attributes)
	if err != nil {
		if IsAuthUnavailable(err) && !isBadPasswordError(err) || isLDAPTransportError(err) {
			p.discard(lease)
			return nil, err
		}
		p.release(lease)
		return nil, err
	}
	p.release(lease)
	return entries, nil
}

// Bind implements LdapDir. Binding as the service identity reuses a pooled
// connection (that is what the pool is for); binding as anybody else must not, so
// it goes through BindFresh and is closed by the caller.
func (p *ldapPool) Bind(dn, password string) error {
	if TrimSpaceASCII(dn) != TrimSpaceASCII(p.opts.bindDN) {
		c, err := p.BindFresh("", dn, password)
		if err != nil {
			return err
		}
		return c.Close()
	}
	lease, err := p.acquire(dn)
	if err != nil {
		return err
	}
	err = lease.conn.Bind(dn, password)
	if err != nil {
		p.discard(lease)
		return err
	}
	p.release(lease)
	return nil
}

// BindFresh implements LdapDir: a dedicated connection, bound as dn, that the
// caller closes. Nothing here keeps the secret: the connection carries the bind
// result, and Close drops it.
func (p *ldapPool) BindFresh(url, dn, password string) (LdapDir, error) {
	if TrimSpaceASCII(url) == "" {
		if len(p.opts.urls) > 0 {
			url = p.opts.urls[0]
		}
	}
	dial := p.dial
	if dial == nil {
		dial = ldapDialURL
	}
	conn, err := dial(url, p.opts, dn, password)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, AuthUnavailablef("cannot connect to %s", ldapLogToken(url))
	}
	return conn, nil
}

// Close closes the idle connections. A connection a login is holding is closed by
// that login on the way out, so nothing leaks.
func (p *ldapPool) Close() error {
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.closed = true
	p.mu.Unlock()
	for _, l := range idle {
		if l != nil && l.conn != nil {
			_ = l.conn.Close()
		}
	}
	return nil
}

// description is the pool's one-line summary for the status page: URLs, identity,
// how many connections were dialled. No password.
func (p *ldapPool) description() string {
	p.mu.Lock()
	idle, dialled := len(p.idle), p.dialled
	p.mu.Unlock()
	return fmt.Sprintf("%d connection(s) dialled, %d idle", dialled, idle)
}

// ---------------------------------------------------------------------------
// the shared pools
// ---------------------------------------------------------------------------

// ldapPools holds one pool per directory configuration. Two logbook scopes that
// name the same directory and the same service account share it, because that is
// the whole point of keeping connections; a different service account is a
// different pool, because a pooled connection carries that identity.
var (
	ldapPoolsMu sync.Mutex
	ldapPools   = map[string]*ldapPool{}
)

// getLdapPool returns the pool of a configuration, dialling it on first use.
//
// A directory that is down right now must not keep the daemon from starting, so a
// dial failure here is not fatal: the pool is returned anyway and every login
// retries (and reports the reason) until the directory answers again. nil is
// returned only for a configuration that can never work.
func getLdapPool(o ldapOptions) (LdapDir, error) {
	if len(o.urls) == 0 {
		return brokenDir{err: AuthUnavailablef("ldap is not configured")}, nil
	}
	key := ldapPoolCacheKey(o)
	ldapPoolsMu.Lock()
	defer ldapPoolsMu.Unlock()
	if p, ok := ldapPools[key]; ok && p != nil {
		return p, nil
	}
	p := &ldapPool{opts: o, dial: o.dial}
	// Probe once so that the first user does not wait for two timeouts before the
	// operator sees a message; the result is not kept.
	if lease, err := p.dialAny(o.bindDN, o.bindPassword); err != nil {
		logS(currentServer(), "golog auth: ldap %v (will retry on every login)", err)
	} else {
		p.release(lease)
	}
	ldapPools[key] = p
	return p, nil
}

// CloseLdapPools closes every pool. A configuration reload calls it, because the
// new configuration may name a different directory, a different service account or
// no LDAP at all, and an idle TLS connection to the old one has no reason to stay
// open.
func CloseLdapPools() {
	ldapPoolsMu.Lock()
	old := ldapPools
	ldapPools = map[string]*ldapPool{}
	ldapPoolsMu.Unlock()
	for _, p := range old {
		_ = p.Close()
	}
}

// LdapPoolStatus describes the pools for the status page: one line per directory,
// with the service account's DN (which is not a secret) and without its password
// (which is).
func LdapPoolStatus() string {
	ldapPoolsMu.Lock()
	keys := make([]string, 0, len(ldapPools))
	for k := range ldapPools {
		keys = append(keys, k)
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		p := ldapPools[k]
		out = append(out, p.description())
	}
	ldapPoolsMu.Unlock()
	if len(out) == 0 {
		return "no ldap connection is open"
	}
	return joinLines(out)
}

// joinLines joins a slice with "; " so that a status line stays one line.
func joinLines(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
