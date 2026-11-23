// ELOG rewritten in Go - the SMTP submission client.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// SMTP submission (RFC 5321 with the STARTTLS and AUTH extensions)
// ---------------------------------------------------------------------------
//
// The C client is a hand-rolled state machine over SSL_connect() and raw
// sockets: it dials, reads the greeting, sends EHLO, then picks STARTTLS or
// AUTH LOGIN depending on what the peer offered, and finally walks
// MAIL/RCPT/DATA. Its weaknesses are the ones this port has to avoid: no
// certificate verification at all (the SMTP path never called
// SSL_CTX_set_verify, so any certificate was accepted), no timeouts (a silent
// server hung the daemon, because the notification is sent from the thread that
// served the posting request), fixed buffers in the AUTH path, and a failure to
// notice that a command failed - the error was overwritten by the next read.
//
// Here the protocol is small and explicit (this file), the message is built in
// mailer.go, and the configuration is read in (*Server).smtpOptions. Every
// socket operation carries a deadline, and a command that fails returns
// immediately with the server's reply in the error, so a failed notification
// says which command failed instead of "mail not delivered".

// SMTPSecurity is how the connection to the submission port is protected.
type SMTPSecurity int

// The three settings "SMTP tls" accepts. "implicit" is port 465: TLS from the
// first byte, no greeting in clear text. "starttls" is port 587/25: connect in
// clear text, then upgrade. "plain" is a trusted network (a local MTA).
const (
	SecurityPlain SMTPSecurity = iota
	SecurityStartTLS
	SecurityImplicit
)

// String is the configuration spelling of the mode.
func (s SMTPSecurity) String() string {
	switch s {
	case SecurityImplicit:
		return "implicit"
	case SecurityStartTLS:
		return "starttls"
	default:
		return "plain"
	}
}

// ParseSMTPSecurity maps the "SMTP tls" value. An unrecognised non-empty value
// is reported with ok=false so that a typo ("implict") shows up in the log
// instead of silently turning into a clear-text connection.
func ParseSMTPSecurity(v string) (SMTPSecurity, bool) {
	switch strings.ToLower(TrimSpaceASCII(v)) {
	case "":
		return SecurityPlain, true
	case "implicit", "implied", "ssl", "sslimplicit", "force-ssl":
		return SecurityImplicit, true
	case "starttls", "start-tls", "start_tls", "tls":
		return SecurityStartTLS, true
	case "plain", "off", "no", "none", "false":
		return SecurityPlain, true
	case "yes", "true", "on", "required", "force":
		// "SMTP tls = yes" means "protect the connection"; whether that is
		// STARTTLS or implicit TLS is decided from the port by the caller.
		return SecurityStartTLS, true
	}
	return SecurityPlain, false
}

// SMTPAuth is the authentication mechanism to offer.
type SMTPAuth int

// The mechanisms "SMTP auth" accepts. ELOG implemented LOGIN only; PLAIN is
// just as widely deployed and needs one round trip instead of two, and AuthNone
// turns authentication off (a relay that authenticates by source address).
const (
	AuthNone SMTPAuth = iota
	AuthAuto
	AuthPlain
	AuthLogin
	AuthCRAMMD5
)

// ParseSMTPAuth maps the "SMTP auth" value. "cram-md5" is recognised and
// reported as unsupported: it needs a challenge round trip this client does not
// implement, and silently falling back to LOGIN would send a password where the
// server expected a response to a challenge.
func ParseSMTPAuth(v string) (SMTPAuth, bool) {
	switch strings.ToLower(TrimSpaceASCII(v)) {
	case "":
		return AuthNone, true
	case "auto", "default":
		return AuthAuto, true
	case "plain":
		return AuthPlain, true
	case "login":
		return AuthLogin, true
	case "cram-md5", "crammd5", "cram":
		return AuthCRAMMD5, true
	case "none", "off", "no", "false":
		return AuthNone, true
	}
	return AuthNone, false
}

// String names the mechanism for the log.
func (a SMTPAuth) String() string {
	switch a {
	case AuthAuto:
		return "auto"
	case AuthPlain:
		return "PLAIN"
	case AuthLogin:
		return "LOGIN"
	case AuthCRAMMD5:
		return "CRAM-MD5"
	default:
		return "none"
	}
}

// SMTPOptions is everything the client needs beyond the address. The zero value
// dials a plain connection with default timeouts and no authentication;
// DefaultSMTPOptions is the value the configuration path starts from.
type SMTPOptions struct {
	// Host is the name the connection is made to and the name the certificate
	// is verified against; DialSMTP fills it from its host argument when empty.
	Host string
	// Security selects implicit TLS, STARTTLS or no TLS.
	Security SMTPSecurity
	// Auth selects the mechanism; AuthAuto takes what the server advertises.
	Auth SMTPAuth
	// RequireTLS makes the absence or refusal of STARTTLS an error instead of a
	// silent downgrade to clear text.
	RequireTLS bool
	// TLSConfig is used for implicit TLS and for STARTTLS. When nil a
	// configuration with the system trust anchors is used.
	TLSConfig *tls.Config
	// RootCAs, when not nil, replaces the system trust anchors: the optional CA
	// bundle for a private submission host goes here.
	RootCAs *x509.CertPool
	// ServerName overrides the name used for SNI and verification.
	ServerName string
	// TLSClientCert, when not nil, is offered to servers that require a client
	// certificate.
	TLSClientCert *tls.Certificate
	// Hello is the EHLO argument; empty means the Host value.
	Hello string
	// Timeouts: zero means the default (30 s dial, 30 s write, 60 s read).
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	ReadTimeout  time.Duration
	// HandshakeTimeout bounds the TLS handshake; zero means DialTimeout.
	HandshakeTimeout time.Duration
	// NoVerify disables certificate verification. It exists for the hosts with a
	// self-signed submission certificate and must be set deliberately
	// ("SMTP verify cert = no"); the caller logs that it is on.
	NoVerify bool
	// InsecureAuth allows authentication over a connection that stayed in clear
	// text ("SMTP auth insecure = yes"). Off by default.
	InsecureAuth bool
	// Username and Password are the credentials for Auth; empty means none.
	Username, Password string
}

// The protocol timeouts of a submission. The read timeout is the longest: a
// server that greylists sits on DATA for minutes and a notification is worth
// waiting for - but not forever, because the caller is the thread that served
// the posting request.
const (
	smtpDialTimeout  = 30 * time.Second
	smtpWriteTimeout = 30 * time.Second
	smtpReadTimeout  = 60 * time.Second
)

// DefaultSMTPOptions is the option set implied by an unset configuration: a
// plain connection to port 25 with the standard timeouts, which is what elogd
// does with "SMTP server = localhost".
func DefaultSMTPOptions() SMTPOptions {
	return SMTPOptions{
		Security:     SecurityPlain,
		Auth:         AuthNone,
		DialTimeout:  smtpDialTimeout,
		WriteTimeout: smtpWriteTimeout,
		ReadTimeout:  smtpReadTimeout,
	}
}

// SMTPError is a protocol error: the reply code and the text the server sent.
// The code matters because 4xx means "try again" and 5xx means "the address is
// broken", and the text is the operator's only clue.
type SMTPError struct {
	Code int
	Cmd  string
	Msg  string
}

func (e *SMTPError) Error() string {
	if e.Cmd == "" {
		return fmt.Sprintf("smtp: %d %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("smtp: %s: %d %s", e.Cmd, e.Code, e.Msg)
}

// Temporary reports whether the server asked for a retry (4.x.x).
func (e *SMTPError) Temporary() bool { return e.Code >= 400 && e.Code < 500 }

// smtpReply is one answer from the server: the code and the text of every line,
// with the code and the continuation dashes removed. The lines are kept apart
// because the EHLO extension list is one keyword per line and joining them loses
// where one parameter list ends.
type smtpReply struct {
	Code  int
	Lines []string
}

// Text is the reply as one line (for error messages and logs).
func (r smtpReply) Text() string { return strings.Join(r.Lines, " ") }

// Keywords is the EHLO extension map: every line after the greeting contributes
// "KEYWORD" -> "its parameters".
func (r smtpReply) Keywords() map[string]string {
	out := map[string]string{}
	if len(r.Lines) < 2 {
		return out
	}
	for _, line := range r.Lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out[strings.ToUpper(fields[0])] = strings.Join(fields[1:], " ")
	}
	return out
}

// SMTPClient is one submission session. It is not safe for concurrent use.
type SMTPClient struct {
	op     SMTPOptions
	conn   net.Conn
	r      *bufio.Reader
	w      *bufio.Writer
	ehlo   map[string]string
	tlsOn  bool // the connection is TLS right now
	closed bool
}

// DialSMTP connects to host:port and reads the greeting. Nothing is sent yet:
// the EHLO is sent by Start, so that an implicit-TLS upgrade happens first.
func DialSMTP(host, port string, opts SMTPOptions) (*SMTPClient, error) {
	host = TrimSpaceASCII(host)
	if port == "" {
		port = "25"
	}
	if opts.Host == "" {
		opts.Host = host
	}
	d := net.Dialer{Timeout: opts.dialTimeout()}
	addr := JoinHostPort(host, port)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	c := &SMTPClient{op: opts, conn: conn}
	c.r = bufio.NewReader(conn)
	c.w = bufio.NewWriter(conn)
	if c.op.Security == SecurityImplicit {
		if err := c.upgradeTLS(); err != nil {
			conn.Close()
			return nil, err
		}
	}
	// The greeting: something that is only half a submission service (a port
	// checker, a captive portal) says something other than 220, and that is much
	// clearer here than three commands later.
	rep, err := c.readReply()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if rep.Code != 220 {
		conn.Close()
		return nil, &SMTPError{Code: rep.Code, Cmd: "greeting", Msg: rep.Text()}
	}
	return c, nil
}

// NewSMTPClient dials, sends EHLO and is then ready for MAIL, so the caller
// either gets a usable session or an error saying why it is not.
func NewSMTPClient(host, port string, opts SMTPOptions) (*SMTPClient, error) {
	c, err := DialSMTP(host, port, opts)
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// newSMTPClient is the unexported alias the delivery path in mailer.go uses.
func newSMTPClient(host, port string, opts SMTPOptions) (*SMTPClient, error) {
	return NewSMTPClient(host, port, opts)
}

// Close ends the session. QUIT is attempted, but a silent server must not delay
// a shutdown, so the socket is closed either way.
func (c *SMTPClient) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.w != nil && c.conn != nil {
		_ = c.conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.w.WriteString("QUIT\r\n")
		_ = c.w.Flush()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// TLS reports whether the session is encrypted.
func (c *SMTPClient) TLS() bool { return c.tlsOn }

// ServerName is the name TLS verification uses.
func (c *SMTPClient) ServerName() string {
	if c.op.ServerName != "" {
		return c.op.ServerName
	}
	if c.op.Hello != "" {
		return c.op.Hello
	}
	return c.op.Host
}

// Extension reports whether EHLO advertised a keyword (case-insensitively) and
// returns its parameters.
func (c *SMTPClient) Extension(name string) (string, bool) {
	for k, v := range c.ehlo {
		if EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// Extensions is the EHLO parameter map (AUTH, STARTTLS, PIPELINING, 8BITMIME,
// SIZE, ...).
func (c *SMTPClient) Extensions() map[string]string { return c.ehlo }

// timeout accessors with defaults -------------------------------------------

func (o SMTPOptions) dialTimeout() time.Duration {
	if o.DialTimeout > 0 {
		return o.DialTimeout
	}
	return smtpDialTimeout
}

func (c *SMTPClient) writeTimeout() time.Duration {
	if c.op.WriteTimeout > 0 {
		return c.op.WriteTimeout
	}
	return smtpWriteTimeout
}

func (c *SMTPClient) readTimeout() time.Duration {
	if c.op.ReadTimeout > 0 {
		return c.op.ReadTimeout
	}
	return smtpReadTimeout
}

func (c *SMTPClient) handshakeTimeout() time.Duration {
	if c.op.HandshakeTimeout > 0 {
		return c.op.HandshakeTimeout
	}
	return c.op.dialTimeout()
}

// tlsConfigFor builds the client TLS configuration from the options.
func (c *SMTPClient) tlsConfigFor() *tls.Config {
	cfg := c.op.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		cfg = cfg.Clone()
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS12
		}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = c.ServerName()
	}
	if cfg.RootCAs == nil && c.op.RootCAs != nil {
		cfg.RootCAs = c.op.RootCAs
	}
	if c.op.NoVerify {
		cfg.InsecureSkipVerify = true
	}
	if c.op.TLSClientCert != nil {
		cfg.Certificates = []tls.Certificate{*c.op.TLSClientCert}
	}
	// An SMTP connection must not negotiate an HTTP protocol through ALPN.
	cfg.NextProtos = nil
	return cfg
}

// upgradeTLS turns the connection into TLS (implicit TLS and STARTTLS).
func (c *SMTPClient) upgradeTLS() error {
	if c.tlsOn {
		return nil
	}
	tc := tls.Client(c.conn, c.tlsConfigFor())
	if err := c.conn.SetDeadline(time.Now().Add(c.handshakeTimeout())); err != nil {
		tc.Close()
		return err
	}
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return fmt.Errorf("smtp tls handshake with %s: %w", c.ServerName(), err)
	}
	_ = c.conn.SetDeadline(time.Time{})
	c.conn = tc
	c.r = bufio.NewReader(tc)
	c.w = bufio.NewWriter(tc)
	c.tlsOn = true
	return nil
}

// Start sends EHLO - twice when STARTTLS is used, as RFC 3207 requires - and
// works out what the server can do.
func (c *SMTPClient) Start() error {
	hi := TrimSpaceASCII(c.op.Hello)
	if hi == "" {
		hi = c.op.Host
	}
	if hi == "" {
		hi = "localhost"
	}
	rep, err := c.cmd("EHLO " + hi)
	if err != nil {
		return err
	}
	if rep.Code != 250 {
		if rep.Code != 500 && rep.Code != 502 && rep.Code != 504 {
			return &SMTPError{Code: rep.Code, Cmd: "EHLO", Msg: rep.Text()}
		}
		// A service that does not know EHLO still speaks RFC 821: no STARTTLS,
		// no AUTH, but MAIL/RCPT/DATA work, so fall back to HELO instead of
		// losing the notification. TLS and authentication are impossible then,
		// and that is said rather than tried.
		c.ehlo = nil
		if c.op.Security != SecurityPlain {
			return fmt.Errorf("smtp: %s does not support EHLO, cannot use %s",
				c.ServerName(), c.op.Security.String())
		}
		rep, err = c.cmd("HELO " + hi)
		if err != nil {
			return err
		}
		if rep.Code != 250 {
			return &SMTPError{Code: rep.Code, Cmd: "HELO", Msg: rep.Text()}
		}
		return nil
	}
	c.ehlo = rep.Keywords()

	switch c.op.Security {
	case SecurityImplicit:
		if !c.tlsOn {
			// Port 465 without TLS means something that is not the submission
			// service is answering; authenticating to it is not acceptable.
			return errors.New("smtp: implicit TLS requested but the connection is not encrypted")
		}
	case SecurityStartTLS:
		if !c.tlsOn {
			if _, ok := c.Extension("STARTTLS"); !ok {
				if c.op.RequireTLS {
					return fmt.Errorf("smtp: %s does not offer STARTTLS", c.ServerName())
				}
				break // best effort: stay in clear text, as the C client did
			}
			rep, err = c.cmd("STARTTLS")
			if err != nil {
				return err
			}
			if rep.Code != 220 {
				if c.op.RequireTLS {
					return &SMTPError{Code: rep.Code, Cmd: "STARTTLS", Msg: rep.Text()}
				}
				break
			}
			if err := c.upgradeTLS(); err != nil {
				return err
			}
			// The TLS session starts a new protocol dialogue: EHLO again.
			rep, err = c.cmd("EHLO " + hi)
			if err != nil {
				return err
			}
			if rep.Code != 250 {
				return &SMTPError{Code: rep.Code, Cmd: "EHLO after STARTTLS", Msg: rep.Text()}
			}
			c.ehlo = rep.Keywords()
		}
	case SecurityPlain:
		// The operator asked for a clear-text session (a local MTA): nothing to
		// upgrade.
	}

	if !c.tlsOn && c.op.Auth != AuthNone && !c.op.InsecureAuth {
		// Sending a password in clear text is a leak, not a fallback: refuse and
		// say what to change.
		return fmt.Errorf(
			"smtp: refusing %s authentication over an unencrypted connection to %s "+
				"(use STARTTLS or port 465, or set SMTP auth insecure = yes to allow it)",
			c.op.Auth.String(), c.ServerName())
	}
	return nil
}

// Auth authenticates. With AuthAuto the mechanism is taken from what the server
// advertised (PLAIN preferred, then LOGIN); with an explicit mechanism the
// server must offer it. Empty credentials do nothing.
func (c *SMTPClient) Auth(user, pass string) error {
	if user == "" && pass == "" {
		return nil
	}
	if c.op.Auth == AuthNone {
		return nil
	}
	if c.op.Auth == AuthCRAMMD5 {
		return errors.New("smtp: CRAM-MD5 authentication is recognised but not implemented")
	}
	offer, _ := c.Extension("AUTH")
	mechs := strings.Fields(offer)
	want := c.op.Auth
	if want == AuthAuto {
		want = pickAuthMech(mechs)
		if want == AuthNone {
			// No AUTH in EHLO: a relay that authenticates by source address.
			// Sending AUTH would be a protocol error, so continue unauthenticated.
			return nil
		}
	} else if !authMechanismOffered(mechs, want) {
		return fmt.Errorf("smtp: %s does not offer AUTH %s (offered: %s)",
			c.ServerName(), want.String(), strings.Join(mechs, " "))
	}
	switch want {
	case AuthPlain:
		return c.authPlain(user, pass)
	case AuthLogin:
		return c.authLogin(user, pass)
	}
	return fmt.Errorf("smtp: unsupported authentication mechanism %s", want.String())
}

// pickAuthMech chooses the mechanism both sides support. LOGIN is the only one
// the C client implements, so it has to stay in the list; PLAIN is preferred
// because it is one round trip and is specified by RFC 4616. CRAM-MD5 is never
// picked automatically.
func pickAuthMech(mechs []string) SMTPAuth {
	var login bool
	for _, m := range mechs {
		switch strings.ToUpper(TrimSpaceASCII(m)) {
		case "PLAIN":
			return AuthPlain
		case "LOGIN":
			login = true
		}
	}
	if login {
		return AuthLogin
	}
	return AuthNone
}

func authMechanismOffered(mechs []string, want SMTPAuth) bool {
	name := want.String()
	for _, m := range mechs {
		if EqualFold(TrimSpaceASCII(m), name) {
			return true
		}
	}
	return false
}

// authPlain sends AUTH PLAIN <base64(NUL user NUL pass)> (RFC 4616) in one
// command. The password is not in clear text on the wire, but base64 is not
// encryption, which is why the connection has to be TLS.
func (c *SMTPClient) authPlain(user, pass string) error {
	resp := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
	rep, err := c.cmd("AUTH PLAIN " + resp)
	if err != nil {
		return err
	}
	if rep.Code != 235 {
		return &SMTPError{Code: rep.Code, Cmd: "AUTH PLAIN", Msg: rep.Text()}
	}
	return nil
}

// authLogin sends the AUTH LOGIN dialogue: base64 of the user name, then of the
// password, each on its own line, each announced by 334. The prompts are read
// rather than assumed: a server that rejects the mechanism answers 5xx straight
// away, and continuing would send a password into a connection that is not
// authenticated.
func (c *SMTPClient) authLogin(user, pass string) error {
	rep, err := c.cmd("AUTH LOGIN")
	if err != nil {
		return err
	}
	if rep.Code != 334 {
		return &SMTPError{Code: rep.Code, Cmd: "AUTH LOGIN", Msg: rep.Text()}
	}
	rep, err = c.cmd(base64.StdEncoding.EncodeToString([]byte(user)))
	if err != nil {
		return err
	}
	if rep.Code != 334 {
		return &SMTPError{Code: rep.Code, Cmd: "AUTH LOGIN (user)", Msg: maskBase64(rep.Text())}
	}
	rep, err = c.cmd(base64.StdEncoding.EncodeToString([]byte(pass)))
	if err != nil {
		return err
	}
	if rep.Code != 235 {
		return &SMTPError{Code: rep.Code, Cmd: "AUTH LOGIN (password)", Msg: maskBase64(rep.Text())}
	}
	return nil
}

// maskBase64 keeps a bare base64 run - which in an SMTP dialogue is a credential
// - out of the log and out of an error string that could reach a web page.
func maskBase64(s string) string {
	if base64BlobRe.MatchString(strings.TrimSpace(s)) {
		return "<base64 elided>"
	}
	return s
}

// base64BlobRe matches a bare base64 run long enough to be a credential.
var base64BlobRe = regexp.MustCompile(`^[A-Za-z0-9+/]{12,}={0,2}$`)

// Deliver performs MAIL FROM / RCPT TO / DATA.
func (c *SMTPClient) Deliver(from string, to []string, msg []byte) error {
	if len(to) == 0 {
		return nil // nothing to do; an empty RCPT set would be a protocol error
	}
	if err := c.mailFrom(from, !IsASCIIPrintable(string(msg))); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.rcptTo(rcpt); err != nil {
			return err
		}
	}
	return c.data(msg)
}

// mailFrom announces the envelope sender, with BODY=8BITMIME when the server
// advertised that extension and the message is not pure ASCII: without the
// parameter an MTA that enforces 7-bit SMTP rejects or mangles a UTF-8
// notification.
func (c *SMTPClient) mailFrom(from string, eightBit bool) error {
	cmd := "MAIL FROM:<" + from + ">"
	if eightBit {
		if _, ok := c.Extension("8BITMIME"); ok {
			cmd += " BODY=8BITMIME"
		}
	}
	rep, err := c.cmd(cmd)
	if err != nil {
		return err
	}
	if rep.Code != 250 {
		return &SMTPError{Code: rep.Code, Cmd: "MAIL", Msg: rep.Text()}
	}
	return nil
}

func (c *SMTPClient) rcptTo(rcpt string) error {
	rep, err := c.cmd("RCPT TO:<" + rcpt + ">")
	if err != nil {
		return err
	}
	// 251 "user not local, will forward" is a success.
	if rep.Code != 250 && rep.Code != 251 {
		return &SMTPError{Code: rep.Code, Cmd: "RCPT", Msg: rep.Text()}
	}
	return nil
}

// data sends the message body. Every line is dot-stuffed (a line that starts
// with '.' has to be doubled or the transmission ends early) and the message is
// terminated by "<CRLF>.<CRLF>"; the 5xx answer some servers then give is a
// delivery failure and is reported as one.
func (c *SMTPClient) data(msg []byte) error {
	rep, err := c.cmd("DATA")
	if err != nil {
		return err
	}
	if rep.Code != 354 {
		return &SMTPError{Code: rep.Code, Cmd: "DATA", Msg: rep.Text()}
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout())); err != nil {
		return err
	}
	if err := writeDotStuffed(c.w, msg); err != nil {
		return err
	}
	if err := c.w.Flush(); err != nil {
		return err
	}
	rep, err = c.readReply()
	if err != nil {
		return err
	}
	if rep.Code != 250 {
		return &SMTPError{Code: rep.Code, Cmd: "DATA", Msg: rep.Text()}
	}
	return nil
}

// writeDotStuffed copies msg to w, quoting leading dots and ending the message.
// The terminating sequence is written even for an empty message, which is then a
// legal empty body rather than a truncated one.
func writeDotStuffed(w *bufio.Writer, msg []byte) error {
	for len(msg) > 0 {
		line := msg
		if i := bytes.IndexByte(msg, '\n'); i >= 0 {
			line, msg = msg[:i+1], msg[i+1:]
		} else {
			msg = nil // a last line without the newline: terminated below
		}
		if len(line) > 0 && line[0] == '.' {
			if err := w.WriteByte('.'); err != nil {
				return err
			}
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if len(line) == 0 || line[len(line)-1] != '\n' {
			if err := w.WriteByte('\n'); err != nil {
				return err
			}
		}
	}
	_, err := w.WriteString("\r\n.\r\n")
	return err
}

// cmd writes one command and reads its answer. An I/O or parsing failure is an
// error; a 4xx/5xx answer is returned as a code, because whether it is fatal
// depends on the command (a 500 to an unknown extension is fine, a 550 on RCPT
// is not).
func (c *SMTPClient) cmd(line string) (smtpReply, error) {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout())); err != nil {
		return smtpReply{}, err
	}
	if _, err := c.w.WriteString(line + "\r\n"); err != nil {
		return smtpReply{}, fmt.Errorf("smtp write %s: %w", smtpCmdName(line), err)
	}
	if err := c.w.Flush(); err != nil {
		return smtpReply{}, fmt.Errorf("smtp write %s: %w", smtpCmdName(line), err)
	}
	return c.readReply()
}

// readReply reads one, possibly multi-line, answer.
func (c *SMTPClient) readReply() (smtpReply, error) {
	var rep smtpReply
	for {
		line, err := c.readLine()
		if err != nil {
			return rep, err
		}
		if len(line) < 3 {
			return rep, fmt.Errorf("smtp: malformed reply %q", line)
		}
		code := 0
		for _, ch := range line[:3] {
			if ch < '0' || ch > '9' {
				return rep, fmt.Errorf("smtp: malformed reply %q", line)
			}
			code = code*10 + int(ch-'0')
		}
		if rep.Code == 0 {
			rep.Code = code
		}
		if len(line) > 4 {
			rep.Lines = append(rep.Lines, line[4:])
		} else {
			rep.Lines = append(rep.Lines, "")
		}
		if line[3] != '-' {
			return rep, nil
		}
	}
}

// readLine reads one line with a deadline and a bound on its length: a peer that
// streams bytes forever must not grow the process's memory.
func (c *SMTPClient) readLine() (string, error) {
	if err := c.conn.SetReadDeadline(time.Now().Add(c.readTimeout())); err != nil {
		return "", err
	}
	line, err := c.r.ReadString('\n')
	if len(line) > maxSMTPReplyLine {
		return "", fmt.Errorf("smtp: reply line longer than %d bytes", maxSMTPReplyLine)
	}
	if err != nil {
		if errors.Is(err, io.EOF) && strings.TrimRight(line, "\r\n") != "" {
			return strings.TrimRight(line, "\r\n"), nil // cut off at EOF
		}
		return "", fmt.Errorf("smtp read: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// maxSMTPReplyLine bounds one reply line (a 4xx reply can carry a long text).
const maxSMTPReplyLine = 8192

// smtpCmdName is the command name for an error message - never its arguments,
// which can hold a base64 password.
func smtpCmdName(line string) string {
	if i := strings.IndexAny(line, " \t"); i > 0 {
		return line[:i]
	}
	return line
}

// ---------------------------------------------------------------------------
// Delivery entry point independent of the configuration
// ---------------------------------------------------------------------------

// SendMailMessage submits one rendered message to a submission host with the
// given options. It is the whole client in one call for callers that have no
// Server (tests, the -M password probe, helper commands); the daemon's path is
// (*Server).smtpDeliver in mailer.go, which reads the configuration.
func SendMailMessage(host, port string, opts SMTPOptions, from string, to []string, msg []byte) error {
	c, err := NewSMTPClient(host, port, opts)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Auth(opts.Username, opts.Password); err != nil {
		return err
	}
	return c.Deliver(from, to, msg)
}
