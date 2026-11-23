// ELOG rewritten in Go - which source address a login is attributed to, and
// which proxies are trusted enough to be believed.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.
//
// Why this is a separate file
// ---------------------------
//
// Both guards (the login throttle and the fail ban) and the trusted-header back
// end need the same answer to one question: "which address do I blame, and which
// proxy may tell me that answer?". Getting it wrong in one direction makes the
// ban useless (the attacker spoofs his source), getting it wrong in the other
// makes it a denial of service tool (an attacker points the ban at a colleague's
// address, or the whole office is locked out because the proxy was not listed).
//
// So the rule is deliberately strict, and it is in ONE place:
//
//   - The peer address of the TCP connection is always trusted.
//   - X-Forwarded-For / X-Real-IP / Forwarded are read ONLY when the peer is in
//     the trusted proxy list; then the LEFTMOST forwarded address is used, which
//     is the client as the first proxy saw it.
//   - The default list is loopback only. Loopback is safe because a remote
//     attacker cannot open a connection from 127.0.0.1. It is also what the
//     common setups need: stunnel, nginx and Apache on the same host.
//
// The configuration keys are "Trusted proxy" (the same name for every layer, so
// one list decides who is believed) and, for the header back end only,
// "Header trusted proxies" as an extra list.

package golog

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// defaultTrustedProxyList is the loopback list, in the spelling the
// configuration file uses.
const defaultTrustedProxyList = "127.0.0.0/8, ::1/128"

// ParseTrustedProxies turns configuration entries into networks. An entry may be
// a CIDR ("10.0.0.0/8"), a plain address ("192.168.1.5", which means that one
// host) or the name of a network interface ("eth0" or "em0" style: every address
// the interface currently holds - a convenience for a machine whose proxy sits on
// a fixed link). The second return value lists the entries that meant nothing,
// so the caller can log them once instead of silently ignoring a typo in a
// security setting.
func ParseTrustedProxies(entries []string) ([]*net.IPNet, []string) {
	var nets []*net.IPNet
	var bad []string
	for _, raw := range entries {
		e := TrimSpaceASCII(raw)
		if e == "" {
			continue
		}
		if strings.ContainsRune(e, '/') {
			_, n, err := net.ParseCIDR(e)
			if err != nil || n == nil {
				bad = append(bad, e)
				continue
			}
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 8 * len(ip) // 32 for a 4-byte IP, 128 for the 16-byte form
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if ifNets := interfaceNetworks(e); len(ifNets) > 0 {
			nets = append(nets, ifNets...)
			continue
		}
		bad = append(bad, e)
	}
	return nets, bad
}

// interfaceNetworks lists the networks of a named interface as /32 and /128
// entries, so "192.168.1.20" and "fe80::1" both match exactly. A link-local
// address is only useful when it came from the interface itself, which is the
// only reason this helper exists at all.
func interfaceNetworks(name string) []*net.IPNet {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []*net.IPNet
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		bits := 8 * len(ip)
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out
}

// ipInNets returns the first network that contains the address, or "" when none
// does. An unparseable address never matches, and that is the right way round: a
// source we cannot parse is not a trusted proxy.
func ipInNets(ip string, nets ...*net.IPNet) string {
	if len(nets) == 0 {
		return ""
	}
	parsed := net.ParseIP(hostOnly(ip))
	if parsed == nil {
		return ""
	}
	for _, n := range nets {
		if n == nil {
			continue
		}
		if n.Contains(parsed) {
			return n.String()
		}
	}
	return ""
}

// hostOnly strips the port of "1.2.3.4:5678" and the brackets of
// "[::1]:8080", leaving a bare address. It leaves an address without a port
// alone.
func hostOnly(addr string) string {
	a := TrimSpaceASCII(addr)
	if a == "" {
		return a
	}
	if a[0] == '[' {
		if i := strings.IndexByte(a, ']'); i > 0 {
			return a[1:i]
		}
		return strings.Trim(a, "[]")
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// trustedProxyCache memoises the parsed list per server. The cache is keyed on
// the *Server and invalidated when the configuration object changes (which is
// what a reload does), so the lookup is one map hit per login.
var trustedProxyCache sync.Map // *Server -> *trustedProxyEntry

type trustedProxyEntry struct {
	cfg  *Config
	nets []*net.IPNet
	list []string
}

// trustedProxyNets is the network list of a server from "Trusted proxy" (plus
// "Header trusted proxies", so that one list can be shared by the two features
// that need it). An unset key means loopback only.
func trustedProxyNets(s *Server) []*net.IPNet {
	if s == nil || s.Config == nil {
		nets, _ := ParseTrustedProxies(strings.Split(defaultTrustedProxyList, ","))
		return nets
	}
	cfg := s.Config
	if v, ok := trustedProxyCache.Load(s); ok {
		if e, ok := v.(*trustedProxyEntry); ok && e != nil && e.cfg == cfg {
			return e.nets
		}
	}
	list := proxyEntries(cfg)
	nets, bad := ParseTrustedProxies(list)
	if len(nets) == 0 {
		nets, _ = ParseTrustedProxies(strings.Split(defaultTrustedProxyList, ","))
	}
	if len(bad) > 0 {
		logf("golog auth: ignoring unusable Trusted proxy entries: %s", strings.Join(bad, ", "))
	}
	trustedProxyCache.Store(s, &trustedProxyEntry{cfg: cfg, nets: nets, list: list})
	return nets
}

// proxyEntries collects the proxy lists of the configuration.
func proxyEntries(cfg *Config) []string {
	g := ConfigScope{Group: "global"}
	var out []string
	for _, key := range []string{"Trusted proxy", "Trusted proxies", "Header trusted proxies"} {
		out = append(out, SplitList(TrimSpaceASCII(cfg.GetString(g, key, "")), ",", false)...)
	}
	return out
}

// InvalidateTrustedProxyCache drops the memoised proxy list of a server. A
// configuration reload calls it through ResetAuthenticators; tests use it too.
func InvalidateTrustedProxyCache(s *Server) {
	if s != nil {
		trustedProxyCache.Delete(s)
	}
}

// TrustedProxyList is the configured list as text, for the status page and the
// start-up log.
func TrustedProxyList(s *Server) string {
	if s == nil || s.Config == nil {
		return defaultTrustedProxyList
	}
	list := proxyEntries(s.Config)
	if len(list) == 0 {
		return defaultTrustedProxyList
	}
	return strings.Join(list, ", ")
}

// ---------------------------------------------------------------------------
// the source address of a login
// ---------------------------------------------------------------------------

// LoginSourceIP is the address a login attempt is attributed to. It is stricter
// than the address the pages show on purpose:
//
//   - the peer address of the connection, unless
//   - the peer is a trusted proxy, in which case the leftmost address of
//     X-Forwarded-For (or of Forwarded: for=..., or X-Real-IP).
//
// The result never carries a port or brackets, and it may be "" when nothing
// usable is known; callers treat "" as an unknown source, which the throttle
// counts under its own "unknown" key rather than not at all.
func (s *Server) LoginSourceIP(r *http.Request) string {
	peer := ""
	if r != nil {
		peer = hostOnly(r.RemoteAddr)
	}
	if peer == "" {
		// No peer at all (a request built by hand in a test, a Unix socket with
		// no peer name): fall back to the -f machinery the rest of the code uses,
		// which at least looks at X-Forwarded-For when the operator asked for it.
		// Without -f that fallback is the peer address too, so it stays "" here.
		if r != nil {
			return hostOnly(clientIP(r, s != nil && s.RealIP))
		}
		return ""
	}
	nets := trustedProxyNets(s)
	if len(nets) == 0 || ipInNets(peer, nets...) == "" {
		// An unlisted peer may not name somebody else's address.
		return peer
	}
	if fwd := leftmostForwarded(r); fwd != "" {
		return fwd
	}
	return peer
}

// leftmostForwarded is the client address behind a chain of proxies: the
// LEFTMOST entry of X-Forwarded-For, which is the address the first proxy saw.
// The rightmost entry is the previous proxy, which the peer address already
// tells us, and the entries in between are whatever the proxies in front chose
// to write. Taking the rightmost one instead would blame the outermost proxy for
// what its client did - which, with a CDN or a corporate gateway in front, is
// exactly the denial of service this list is meant to avoid.
func leftmostForwarded(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		for _, part := range strings.Split(v, ",") {
			if host := hostOnly(part); host != "" && host != "unknown" {
				return host
			}
		}
	}
	if v := r.Header.Get("Forwarded"); v != "" {
		// RFC 7239: Forwarded: for=1.2.3.4;by=..., for="[2001:db8::1]"
		for _, part := range strings.Split(v, ",") {
			for _, kv := range strings.Split(part, ";") {
				kv = TrimSpaceASCII(kv)
				if !HasPrefixFold(kv, "for=") {
					continue
				}
				val := strings.Trim(TrimSpaceASCII(kv[len("for="):]), "\"")
				if i := strings.Index(val, "%"); i >= 0 { // strip the proto= prefix of RFC 7239bis
					val = val[i+1:]
				}
				if host := hostOnly(val); host != "" && host != "unknown" {
					return host
				}
			}
		}
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return hostOnly(v)
	}
	return ""
}
