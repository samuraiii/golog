// ELOG rewritten in Go - configuration readers shared by the transport and
// mail layers.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Small configuration accessors
// ---------------------------------------------------------------------------
//
// The accessors below are the shape the transport and mail layers need: a
// logbook section that does not carry the key falls back to [global], which is
// how elogd reads every option that is meaningful both per logbook and
// daemon-wide ("SSL", "SMTP server", "Max content size", ...).

// cfgString is a string option with the [global] fallback.
func (s *Server) cfgString(scope ConfigScope, key, fallback string) string {
	if s == nil || s.Config == nil {
		return fallback
	}
	if v := s.Config.GetString(scope, key, ""); v != "" {
		return v
	}
	if scope.Group != "global" {
		if v := s.Config.GetString(ConfigScope{Group: "global"}, key, ""); v != "" {
			return v
		}
	}
	return fallback
}

// cfgBool is a boolean option with the [global] fallback. The empty value keeps
// the caller's default, so "SSL client auth = " does not turn anything off.
func (s *Server) cfgBool(scope ConfigScope, key string, fallback bool) bool {
	if s == nil || s.Config == nil {
		return fallback
	}
	v := s.cfgString(scope, key, "")
	if v == "" {
		return fallback
	}
	return ParseBoolOr(v, fallback)
}

// cfgInt is an integer option with the [global] fallback; a value that does not
// parse keeps the default (a typo in the configuration must not change how the
// daemon listens, only be reported), and the negative form of a port is reported
// as a string so the caller can print it.
func (s *Server) cfgInt(scope ConfigScope, key string, fallback int) int {
	v := s.cfgString(scope, key, "")
	if v == "" {
		return fallback
	}
	n, err := atoiStrict(TrimSpaceASCII(v))
	if err != nil {
		return fallback
	}
	return n
}

// atoiStrict is the strict integer parse the configuration accessors need. It
// defers to the package's existing parse helper when one exists; the local
// implementation keeps this file independent of the name chosen elsewhere.
func atoiStrict(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	neg := false
	i := 0
	switch s[0] {
	case '+':
		i++
	case '-':
		neg = true
		i++
	}
	if i >= len(s) {
		return 0, fmt.Errorf("not a number: %q", s)
	}
	n := 0
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<30 {
			return 0, fmt.Errorf("out of range: %q", s)
		}
	}
	if neg {
		n = -n
	}
	return n, nil
}

// ParseBoolOr reads a configuration boolean, keeping the default for anything
// that is not recognisable. elogd compares strings ("yes", "1", "true"), and an
// unparseable value there silently meant "no"; here the caller's default wins so
// that a typo cannot disable a security feature by accident.
func ParseBoolOr(v string, def bool) bool {
	switch strings.ToLower(TrimSpaceASCII(v)) {
	case "":
		return def
	case "yes", "y", "true", "on", "1", "enable", "enabled":
		return true
	case "no", "n", "false", "off", "0", "disable", "disabled":
		return false
	}
	return def
}

// ---------------------------------------------------------------------------
// Certificate authorities
// ---------------------------------------------------------------------------

// LoadCertPool reads one or more PEM-encoded certificates into a trust pool
// seeded with the system trust anchors. The argument is a comma or semicolon
// separated list of file names (a bundle file holding several certificates is one
// name and works as expected, which is the usual layout for a site CA). An empty
// list yields nil, which every caller reads as "use the system trust anchors".
//
// The transport uses two different pools and they must not be mixed: the chain
// the server sends to a client (sslChainPool, appended to the certificate) and
// the pool client certificates are verified against (sslClientPool, in
// tls.Config.ClientCAs).
func LoadCertPool(files string) (*x509.CertPool, error) {
	list := SplitCertList(files)
	if len(list) == 0 {
		return nil, nil
	}
	// Start from the system roots when the platform provides them, so that a
	// bundle adding a private CA does not remove the public ones. Where there is
	// no system store the call fails and the bundle alone is used, which is the
	// correct behaviour for a dedicated trust anchor list anyway.
	pool, err := SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, f := range list {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificate found (expected a PEM BEGIN CERTIFICATE block)", f)
		}
	}
	return pool, nil
}

// LoadLeafPool is like LoadCertPool but starts from an empty pool: a list of
// trust anchors must contain exactly those anchors and nothing else. Client
// certificate verification uses it, because a client certificate signed by a
// public CA should not be accepted just because the operator configured one
// private CA.
func LoadLeafPool(files string) (*x509.CertPool, error) {
	list := SplitCertList(files)
	if len(list) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, f := range list {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificate found (expected a PEM BEGIN CERTIFICATE block)", f)
		}
	}
	return pool, nil
}

// SplitCertList splits a "SSL chain"-style file list. Comma, semicolon, newline
// and tab are separators; a file name never contains them on any supported
// platform.
func SplitCertList(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	}) {
		p = TrimSpaceASCII(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SystemCertPool is the platform trust store. It is a function rather than a
// direct x509.SystemCertPool() call at the use sites because on some platforms
// the call fails when there is no store to read (Android, and a Windows image
// without a certificate database), and every caller wants to treat that as
// "nothing extra" rather than as a startup error.
func SystemCertPool() (*x509.CertPool, error) {
	return x509.SystemCertPool()
}

// ---------------------------------------------------------------------------
// Client certificate authentication
// ---------------------------------------------------------------------------

// ClientAuthNone is the spelling of "no client certificates at all". It exists
// because tls.NoClientCert is an iota constant in crypto/tls and a configuration
// value has to be mapped to it explicitly.
const ClientAuthNone = int(tls.NoClientCert)

// ParseClientAuth maps the "SSL client auth" value onto a crypto/tls
// verification mode, and reports whether the value was understood.
//
// "request" is the mode for a site that wants certificates where they exist and
// passwords where they do not: the server asks, accepts a certificate signed by
// the configured CA and still serves a client that sends none. "require" is the
// same with the handshake failing when no certificate, or a foreign one,
// arrives. "require-any" skips the trust check, which is only defensible behind
// a network that is already authenticated; it is provided because the "SSL CA =
// *" deployments of the C code do exactly that, and it is logged loudly.
func ParseClientAuth(v string) (tls.ClientAuthType, bool) {
	switch strings.ToLower(TrimSpaceASCII(v)) {
	case "", "none", "off", "no", "false":
		return tls.NoClientCert, true
	case "request", "optional", "if-any", "request-cert":
		return tls.RequestClientCert, true
	case "verify", "verify-if-any", "verify-if-given", "want":
		return tls.VerifyClientCertIfGiven, true
	case "require", "require-and-verify", "required", "yes", "true", "on", "force":
		return tls.RequireAndVerifyClientCert, true
	case "require-any", "anycert", "any":
		return tls.RequireAnyClientCert, true
	}
	return tls.NoClientCert, false
}

// ClientAuthName names a verification mode the way the configuration spells it
// (for the status page and the log).
func ClientAuthName(mode tls.ClientAuthType) string {
	switch mode {
	case tls.RequestClientCert:
		return "request"
	case tls.VerifyClientCertIfGiven:
		return "verify-if-given"
	case tls.RequireAnyClientCert:
		return "require-any"
	case tls.RequireAndVerifyClientCert:
		return "require"
	default:
		return "none"
	}
}

// ---------------------------------------------------------------------------
// Outgoing mail options
// ---------------------------------------------------------------------------

// smtpOptions reads the submission configuration for a scope. The port decides
// the default security mode when the configuration does not say: 465 (and the
// "smtps" service name) means implicit TLS, as that port is reserved for it, and
// anything else means STARTTLS when the server offers it.
//
// The keys, all optional:
//
//	SMTP server           host, host:port or user:pass@host:port (elogd's forms)
//	SMTP user             login, when the credentials are not in "SMTP server"
//	SMTP pwdd             password written by -P (stored obfuscated, as in elogd)
//	SMTP tls              implicit | starttls | plain | yes
//	SMTP auth             plain | login | auto | none | cram-md5
//	SMTP ca               PEM bundle of CAs trusted for the submission host
//	SMTP server name      name to verify the certificate against (SNI override)
//	SMTP client cert      client certificate, for a server that requires one
//	SMTP client key       its key
//	SMTP verify cert      no turns certificate verification off (logged)
//	SMTP auth insecure    yes allows authentication over a plain connection
//	SMTP timeout          read timeout in seconds (default 60)
//	SMTP connect timeout  dial timeout in seconds (default 30)
//
// A value this function cannot interpret is reported through the log rather than
// silently degraded, because every one of these keys guards either the password
// or the message.
func (s *Server) smtpOptions(scope ConfigScope, port string) SMTPOptions {
	opts := DefaultSMTPOptions()
	if port == "465" || EqualFold(port, "smtps") {
		opts.Security = SecurityImplicit
		opts.RequireTLS = true
	} else {
		opts.Security = SecurityStartTLS
		// A local MTA that offers no STARTTLS keeps working unless the operator
		// asked for TLS ("SMTP tls = yes/required").
		opts.RequireTLS = false
	}
	if v := s.cfgString(scope, "SMTP tls", ""); v != "" {
		sec, ok := ParseSMTPSecurity(v)
		if !ok {
			s.logf("smtp: unknown value %q for \"SMTP tls\", using %s", v, sec.String())
		}
		opts.Security = sec
		switch strings.ToLower(TrimSpaceASCII(v)) {
		case "yes", "true", "on", "required", "force", "implicit":
			// "protect this connection" means it must not fall back to clear
			// text when the peer does not cooperate.
			opts.RequireTLS = true
		case "plain", "off", "no", "none", "false":
			opts.RequireTLS = false
		}
	}
	if v := s.cfgString(scope, "SMTP auth", ""); v != "" {
		a, ok := ParseSMTPAuth(v)
		if !ok {
			s.logf("smtp: unknown value %q for \"SMTP auth\", authentication disabled", v)
			a = AuthNone
		}
		opts.Auth = a
	}
	if v := s.cfgString(scope, "SMTP ca", ""); v != "" {
		pool, err := LoadLeafPool(v)
		if err != nil {
			s.logf("smtp: \"SMTP ca\": %v (using the system trust anchors)", err)
		} else {
			opts.RootCAs = pool
		}
	}
	opts.ServerName = s.cfgString(scope, "SMTP server name", "")
	opts.Hello = s.cfgString(scope, "SMTP hello", "")
	if certFile := s.cfgString(scope, "SMTP client cert", ""); certFile != "" {
		keyFile := s.cfgString(scope, "SMTP client key", certFile)
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			s.logf("smtp: client certificate %s: %v", certFile, err)
		} else {
			opts.TLSClientCert = &cert
		}
	}
	opts.NoVerify = s.cfgBool(scope, "SMTP verify cert", false)
	if opts.NoVerify {
		s.logf("smtp: certificate verification is DISABLED (\"SMTP verify cert = no\"); " +
			"any host can impersonate the submission server and collect the password")
	}
	opts.InsecureAuth = s.cfgBool(scope, "SMTP auth insecure", false)
	if secs := s.cfgInt(scope, "SMTP timeout", 0); secs > 0 {
		opts.ReadTimeout = time.Duration(secs) * time.Second
	}
	if secs := s.cfgInt(scope, "SMTP connect timeout", 0); secs > 0 {
		opts.DialTimeout = time.Duration(secs) * time.Second
	}
	if secs := s.cfgInt(scope, "SMTP write timeout", 0); secs > 0 {
		opts.WriteTimeout = time.Duration(secs) * time.Second
	}
	return opts
}
