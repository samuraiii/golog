// ELOG rewritten in Go - authentication by an external helper program.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.
//
// What this is
// ------------
//
// "Authentication = External" asks a program of the operator's choosing whether
// a user name and a password go together. It exists because the alternative is
// not available: PAM, the answer on every Linux box, sits behind a C library,
// and this project must cross-compile for linux and windows without cgo, so
// gologd cannot call pam_authenticate itself. Running a helper is the portable
// form of the same thing, and it covers much more than PAM:
//
//   * PAM through any helper (a 20-line C program, a Python script with
//     python-pam, or an existing checkpw-style binary), which brings TOTP,
//     YubiKey, /etc/shadow, LDAP-via-pam_ldap and the site's existing account
//     policy with it;
//   * kerberos "kvno" or "kinit -c FILE" checks without gologd speaking
//     Kerberos;
//   * sudo-style checks against a custom database, a RADIUS client, a
//     certificate check, a script that phones a home-built account system, or a
//     mock used by the test suite.
//
// The contract is deliberately small and deliberately not a shell:
//
//   * the program named by "External program" is executed directly with
//     exec.Command - never through /bin/sh, cmd.exe or any other shell, so no
//     character in a user name or a password can turn into a command;
//   * the arguments come from "External args" (a list), with %u replaced by the
//     user name, %h by the source address and %d by the domain from
//     "Ldap domain". There is deliberately NO placeholder for the password:
//     argv of every process on the machine is readable (ps, /proc, the Windows
//     process list), so a password there is a leaked password, and an attempt to
//     configure one is refused with an error rather than executed;
//   * the password is written to the helper's standard input, followed by a
//     newline, and the pipe is closed. A helper that does not read stdin loses
//     nothing: the write is capped and the pipe is not waited for;
//   * exit code 0 means the credential is correct. Any other exit code means it
//     is not, and is counted against the caller like a wrong password, EXCEPT the
//     code named by "External unavailable exit code" (default 100), which means
//     "I could not decide" - that is reported as a service failure and burns no
//     throttle allowance;
//   * the helper's standard output may carry optional "Key: value" lines that
//     fill in the identity (see the read of the protocol below); anything it
//     writes to standard error is logged with the password redacted, because a
//     helper that prints its own failure reason is how an operator debugs one.
//
// Nothing here logs a password, and nothing here passes one to a shell.
//
// Configuration (global section; new in golog, the C daemon has no equivalent):
//
//	Authentication                 = External
//	External program               = /usr/local/lib/golog/golog-check-pam
//	External args                  = -u %u -h %h        (%u user, %h address, %% literal)
//	External timeout               = 10                 (seconds, killed after this)
//	External max output            = 4096               (bytes of stdout/stderr kept)
//	External unavailable exit code = 100
//	External env                   = PATH=/usr/bin:/bin   (repeatable; the ONLY
//	                                   environment the helper gets, so a
//	                                   "Ldap bind password" cannot leak into it)
//	External create user           = 1                  (write the local record)
//	External pass groups           = 1                  (honour "Group:" lines)
//	External max length            = 256                 (name/address bound)

package golog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// externalOptions is the resolved configuration of the helper back end.
type externalOptions struct {
	program  string
	args     []string
	timeout  time.Duration
	maxOut   int
	unavail  int
	env      []string
	create   bool
	groups   bool
	maxName  int
	maxArgIn int
}

// readExternalOptions reads the helper back end's configuration.
func readExternalOptions(c *Config, scope ConfigScope) externalOptions {
	o := externalOptions{
		program: TrimSpaceASCII(c.GetStringDefault(scope, "External program", "")),
		args:    c.GetList(scope, "External args"),
		timeout: c.GetDuration(scope, "External timeout", 10*time.Second),
		maxOut:  c.GetInt(scope, "External max output", 4096),
		unavail: c.GetInt(scope, "External unavailable exit code", 100),
		env:     c.GetAll(scope, "External env"),
		create:  c.GetFlagDefault(scope, "External create user", true),
		groups:  c.GetFlagDefault(scope, "External pass groups", true),
	}
	if len(o.args) == 0 {
		// The documented default: the name as the only argument, which is what
		// every checkpw-style binary expects.
		o.args = []string{"%u"}
	}
	if o.timeout < time.Second {
		o.timeout = time.Second
	}
	if o.timeout > 10*time.Minute {
		// A helper allowed to hang for an hour is a denial of service on the
		// login path, whatever the operator wrote in the file.
		o.timeout = 10 * time.Minute
	}
	if o.maxOut < 256 {
		o.maxOut = 256
	}
	if o.maxOut > 1<<20 {
		o.maxOut = 1 << 20
	}
	o.maxName = c.GetInt(scope, "External max length", 256)
	if o.maxName < 16 {
		o.maxName = 16
	}
	o.maxArgIn = o.maxName
	if o.maxArgIn > 4096 {
		o.maxArgIn = 4096
	}
	return o
}

// externalError is what a helper reports on its standard error, already made
// safe for the log.
type externalError struct {
	code   int
	output string
}

func (e externalError) Error() string {
	if e.output == "" {
		return sprintf("the authentication helper exited with code %d", e.code)
	}
	return sprintf("the authentication helper exited with code %d: %s", e.code, e.output)
}

// externalAuthenticator is the Authenticator of this file.
type externalAuthenticator struct {
	s *Server
}

// newExternalAuthenticator builds the back end for the selector.
func newExternalAuthenticator(ctx AuthContext) Authenticator {
	return &externalAuthenticator{s: ctx.S}
}

// init registers this back end with the selector.
func init() {
	registerAuthenticator(AuthExternal, newExternalAuthenticator)
}

// Name is the label used in the log and in a session record.
func (a *externalAuthenticator) Name() string { return AuthExternal }

// server resolves the server behind this back end.
func (a *externalAuthenticator) server() *Server {
	if a != nil && a.s != nil {
		return a.s
	}
	return currentServer()
}

// externalPlaceholders expands the placeholders of one configured argument. It
// reports ok=false when the argument asks for the password, which this
// implementation refuses to put on the command line.
func externalPlaceholders(arg, user, ip string, max int) (string, bool, bool) {
	var b strings.Builder
	wantsPassword := false
	for i := 0; i < len(arg); i++ {
		ch := arg[i]
		if ch != '%' || i+1 >= len(arg) {
			b.WriteByte(ch)
			continue
		}
		switch arg[i+1] {
		case '%':
			b.WriteByte('%')
		case 'u':
			b.WriteString(clampForHelper(user, max))
		case 'h':
			b.WriteString(clampForHelper(ip, max))
		case 'p', 'P':
			// Never: argv is world-readable on every operating system.
			wantsPassword = true
		default:
			// An unknown escape is passed through verbatim, so a helper whose
			// own flag happens to be followed by a letter ( "-x%y" ) still
			// receives what the operator typed.
			b.WriteByte('%')
			b.WriteByte(arg[i+1])
		}
		i++
	}
	return b.String(), true, wantsPassword
}

// clampForHelper keeps an attacker-supplied length out of argv and rejects the
// control characters that would let one argument become two log lines. An empty
// result for a non-empty input is a rejection, and the caller reports it.
func clampForHelper(s string, max int) string {
	s = TrimSpaceASCII(s)
	if max > 0 && len(s) > max {
		s = s[:max]
	}
	if strings.ContainsAny(s, "\r\n\x00") {
		return ""
	}
	return s
}

// externalArgv builds the argument vector. The second result explains why the
// vector could not be built; a failure here is a configuration error, so it must
// not be reported to the caller as a wrong password.
func (o externalOptions) externalArgv(user, ip string) ([]string, string) {
	if TrimSpaceASCII(o.program) == "" {
		return nil, "\"External program\" is not set"
	}
	out := make([]string, 0, len(o.args))
	for _, a := range o.args {
		v, _, wantsPassword := externalPlaceholders(a, user, ip, o.maxArgIn)
		if wantsPassword {
			return nil, "the helper must not be given the password on its command line: " +
				"argv is readable by every process on the machine, so use %u and read the " +
				"password from standard input"
		}
		out = append(out, v)
	}
	return out, ""
}

// resolveHelper turns the configured program into something exec can start and
// returns a complaint instead when the answer is not usable. The checks are the
// ones that matter for a program that is started with a user's password on its
// stdin: an absolute path (so a stray "golog-check" cannot be picked up from the
// current directory or from a PATH entry an operator did not mean), a real file,
// not a directory, and a warning when other users may write to it - a helper
// that a local attacker can replace is a helper that collects passwords.
func resolveHelper(name string) (string, string) {
	n := TrimSpaceASCII(name)
	if n == "" {
		return "", "\"External program\" is not set"
	}
	if !strings.ContainsAny(n, `/\`) && !hasDrivePrefix(n) {
		return "", sprintf("\"External program\" must be an absolute path, not the bare name %q: "+
			"a helper that is looked up in PATH depends on who sets PATH", n)
	}
	st, err := os.Stat(n)
	if err != nil {
		return "", sprintf("the authentication helper %q cannot be read: %v", n, firstErrorLine(err.Error()))
	}
	if st.IsDir() {
		return "", sprintf("the authentication helper %q is a directory", n)
	}
	if st.Mode().Perm()&0o022 != 0 {
		logf("golog auth: warning: the authentication helper %q is writable by group or other "+
			"(mode %v): whoever can write it can collect the passwords sent to it", n, st.Mode().Perm())
	}
	return n, ""
}

// hasDrivePrefix reports the "C:\dir\prog.exe" spelling of a Windows path. It is
// done by hand instead of with filepath.IsAbs so that a linux binary reading a
// configuration file written on Windows gives the same answer as the Windows
// binary would (filepath.IsAbs is per-operating-system, which would make the
// error message differ between the two).
func hasDrivePrefix(p string) bool {
	if len(p) < 3 || p[1] != ':' {
		return false
	}
	c := p[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
	return p[2] == '\\' || p[2] == '/'
}

// externalProtocol is the optional attribute part of the helper's output.
type externalProtocol struct {
	user    string
	full    string
	mail    string
	groups  []string
	admin   bool
	reason  string
	created bool
}

// parseExternalOutput reads the "Key: value" lines a helper may write on its
// standard output. Everything it does not understand is ignored, which is what
// makes the protocol optional: a helper that only exits 0 is a complete helper.
// The keys are ASCII case-insensitive, and a value is trimmed but otherwise
// taken as it came, except that control characters are dropped so that one
// output line cannot become a second log line or a second XML element.
func parseExternalOutput(out string, o externalOptions) externalProtocol {
	var p externalProtocol
	for _, line := range strings.Split(out, "\n") {
		line = TrimSpaceASCII(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		val = strings.Trim(TrimSpaceASCII(val), "\r\n\x00")
		val = strings.ReplaceAll(val, "\t", " ")
		switch strings.ToLower(TrimSpaceASCII(key)) {
		case "user", "username", "user name", "login":
			if len(val) <= o.maxName && !strings.ContainsAny(val, "\r\n\x00") {
				p.user = val
			}
		case "fullname", "full name", "name", "displayname":
			if len(val) <= o.maxName {
				p.full = val
			}
		case "email", "e-mail", "mail":
			if len(val) <= o.maxName && strings.Contains(val, "@") && !strings.ContainsAny(val, " \t") {
				p.mail = val
			}
		case "group", "groups":
			if !o.groups {
				continue
			}
			for _, g := range SplitList(val, ",", false) {
				if g != "" && len(g) <= o.maxName && !strings.ContainsAny(g, "\r\n\x00") {
					p.groups = append(p.groups, g)
				}
			}
		case "admin":
			p.admin = Bool(val)
		case "reason", "message":
			if len(val) <= 2*o.maxName {
				p.reason = val
			}
		}
	}
	return p
}

// redactSecret removes a secret from text a helper produced. A helper that
// echoes its own argv, or its stdin, into an error message is common enough that
// the daemon must not put the password into the log through it.
func redactSecret(text, secret string) string {
	if secret == "" || !strings.Contains(text, secret) {
		return text
	}
	return strings.ReplaceAll(text, secret, "***")
}

// Authenticate runs the helper.
func (a *externalAuthenticator) Authenticate(ctx AuthContext) (Identity, error) {
	var id Identity
	s := a.server()
	o := readExternalOptions(ctx.config(), ctx.scope())

	argv, why := o.externalArgv(ctx.User, ctx.RemoteIP)
	if why != "" {
		// A configuration fault, not the caller's mistake: it must not cost him
		// his throttle allowance and it must not look like a wrong password.
		logS(s, "golog auth: external back end is unusable: %s", why)
		return id, AuthUnavailablef("external back end: %s", why)
	}
	prog, why := resolveHelper(o.program)
	if why != "" {
		logS(s, "golog auth: external back end is unusable: %s", why)
		return id, AuthUnavailablef("external back end: %s", why)
	}

	// The context is the kill switch: a helper that hangs must not be able to
	// hold a login worker, and it must not survive to accumulate one per login
	// attempt.
	cctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, prog, argv...)
	// The environment is rebuilt rather than inherited: gologd holds a
	// configuration full of secrets and a helper has no business seeing them.
	cmd.Env = externalEnv(o.env)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = limitWriter{buf: &stdout, left: o.maxOut}
	cmd.Stderr = limitWriter{buf: &stderr, left: o.maxOut}

	// The password goes to stdin and nowhere else. StdinPipe is used rather than
	// a bytes.Reader so that a helper which never reads it is not blocked behind
	// a full pipe on the way out, and so that the write itself is not waited for.
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return id, AuthUnavailablef("external back end: cannot create the standard input pipe: %s",
			firstErrorLine(err.Error()))
	}
	startErr := cmd.Start()
	if startErr == nil {
		// The write is deliberately unchecked: a helper that closes its stdin
		// early (a wrapper that only checks the name) gets EPIPE here, which is
		// its business, and the exit code is what this function reads.
		_, _ = pipe.Write([]byte(ctx.Password))
		_, _ = pipe.Write([]byte("\n"))
		_ = pipe.Close()
	}
	runErr := func() error {
		if startErr != nil {
			return startErr
		}
		return cmd.Wait()
	}()

	out := redactSecret(stdout.String(), ctx.Password)
	errText := redactSecret(firstErrorLine(stderr.String()), ctx.Password)

	if startErr != nil {
		// The program could not be started at all. That is the daemon's or the
		// operator's problem, never the caller's.
		logS(s, "golog auth: cannot run the authentication helper %s: %s", prog, firstErrorLine(startErr.Error()))
		return id, AuthUnavailablef("external back end: cannot run %s: %s",
			prog, firstErrorLine(startErr.Error()))
	}

	code := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			code = ee.ExitCode()
		} else {
			logS(s, "golog auth: the authentication helper %s failed: %v", prog, runErr)
			return id, AuthUnavailablef("external back end: %s", firstErrorLine(runErr.Error()))
		}
		if cctx.Err() == context.DeadlineExceeded {
			// Killed by the timeout: the helper hung, which is a service failure
			// and not an answer about this caller's password.
			logS(s, "golog auth: the authentication helper %s did not finish within %s and was killed",
				prog, o.timeout)
			return id, AuthUnavailablef("external back end: %s timed out after %s", prog, o.timeout)
		}
	}

	if code == o.unavail {
		// The helper's own way of saying "the directory/KDC/database is down".
		logS(s, "golog auth: the authentication helper %s reports that it cannot decide (exit %d): %s",
			prog, code, orNoDetail(errText))
		return id, AuthUnavailablef("external back end: %s reported an unavailable service", prog)
	}
	if code != 0 {
		// A refusal. The caller sees "wrong password" through the chain; this
		// line is for the operator, and it carries the helper's own reason with
		// the password redacted.
		logS(s, "golog auth: the authentication helper refused %q from %s (exit %d): %s",
			ctx.User, orUnknownPeer(ctx.RemoteIP), code, externalError{code: code, output: errText}.output)
		return id, fmt.Errorf("%w: %s", ErrBadPassword, ctx.User)
	}

	// Success. The optional output lines fill in what the helper knows.
	p := parseExternalOutput(out, o)
	id.Name = ctx.User
	if p.user != "" {
		// The helper may canonicalise the name (the directory's spelling).
		id.Name = p.user
	}
	id.FullName = p.full
	id.Email = p.mail
	id.Groups = p.groups
	id.Admin = p.admin
	id.AuthType = strings.ToLower(AuthExternal)
	id.Principal = prog

	if p.reason != "" {
		logS(s, "golog auth: the authentication helper accepted %q from %s: %s",
			id.Name, orUnknownPeer(ctx.RemoteIP), p.reason)
	}
	if o.create && s != nil && s.Pwd != nil {
		id.Created = s.ensurePwdUser(id.Name, id.FullName, id.Email, true, true)
	}
	return id, nil
}

// externalEnv builds the environment of the helper. With no "External env" the
// helper gets only a PATH - enough to exec a helper that resolves its own
// programs, and nothing that could carry a secret out of the daemon.
func externalEnv(configured []string) []string {
	var out []string
	sawPath := false
	for _, e := range configured {
		e = TrimSpaceASCII(e)
		if e == "" {
			continue
		}
		if HasPrefixFold(e, "PATH=") {
			sawPath = true
		}
		out = append(out, e)
	}
	if !sawPath {
		// The system default rather than the daemon's: the daemon's PATH may
		// contain a build directory or a user's home.
		out = append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, out...)
	}
	return out
}

// orNoDetail keeps a log line from ending in an empty detail.
func orNoDetail(s string) string {
	if TrimSpaceASCII(s) == "" {
		return "no output"
	}
	return TrimSpaceASCII(s)
}

// limitWriter collects at most left bytes and throws away the rest, so a helper
// that dumps a megabyte of debugging on standard error cannot grow the daemon's
// memory or its log line beyond a sane size. It never returns an error, so the
// child's write is never interrupted by us: the cap is a reader-side cap.
type limitWriter struct {
	buf  *bytes.Buffer
	left int
}

func (w limitWriter) Write(p []byte) (int, error) {
	if w.buf == nil {
		return len(p), nil
	}
	if w.left <= 0 {
		return len(p), nil
	}
	if len(p) > w.left {
		w.buf.Write(p[:w.left])
		w.left = 0
		return len(p), nil
	}
	w.buf.Write(p)
	w.left -= len(p)
	return len(p), nil
}

// AuthDescription is this back end's line of (*Server).AuthStatus. The program
// path is not a secret (it is in the configuration file, which is); the password
// never appears anywhere near it.
func (a *externalAuthenticator) AuthDescription() string {
	s := a.server()
	c := ParseConfig("")
	if s != nil && s.Config != nil {
		c = s.Config
	}
	o := readExternalOptions(c, ConfigScope{Group: "global"})
	if o.program == "" {
		return "no \"External program\" is configured, so this method cannot accept anybody"
	}
	why := ""
	if _, w := resolveHelper(o.program); w != "" {
		why = " (unusable: " + w + ")"
	}
	return sprintf("%s %s, %d second timeout%s", o.program,
		strings.Join(o.args, " "), int(o.timeout/time.Second), why)
}
