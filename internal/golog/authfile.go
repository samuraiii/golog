// ELOG rewritten in Go - the local password file as one authentication back end.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// what is verified, and how
// ---------------------------------------------------------------------------
//
// The daemon keeps the login names and the password hashes in one XML file -
// <list><user><name>..</name><password encoding="SHA256">..</password>.. (see
// auth.go for the type, the reader and the writer, which this file does not
// touch). auth.go already verifies a secret with subtle.ConstantTimeCompare, so
// this file does not do that a second time; it registers the back end with the
// selector in authiface.go and adds the two things the file lookup was missing:
// a case-insensitive fall-back and a single place where an unknown user and a
// wrong password are told apart.
//
// The one comparison that was NOT constant time anywhere in the port is the
// logbook "User password": a shared secret typed into a configuration file
// ("User password = masterpw") and compared with "==" in request.go's
// authenticate(), which answers after the first differing byte. It is a password
// field of the same login form ("wpwd"), so it is reachable by exactly the same
// attacker who brute-forces user passwords; it now goes through the same
// comparison the user hashes get (see verifyUserPassword).
//
// The on-disk format is unchanged: the three spellings auth.go accepts (the
// elogd form "<salt>$<hash>", the full crypt form "$5$..." and the pre-SHA256
// plaintext) keep working, and nothing here rewrites the file.

// fileBackedAuthenticator is the Authenticator of the XML password file.
type fileBackedAuthenticator struct {
	// s is the server whose password file is consulted; nil means "the running
	// daemon's", resolved through currentServer() on every attempt, so that a
	// test (or a second server in the same process) is not tied to one.
	s *Server
}

// newFileBackedAuthenticator builds the back end. It is the constructor the
// selector uses for the "File" name (and for the C daemon's "Basic"), which is
// why it is a function taking an AuthContext and not a method.
func newFileBackedAuthenticator(ctx AuthContext) Authenticator {
	return &fileBackedAuthenticator{s: ctx.S}
}

// init registers the back end this file owns with the selector. Registration
// next to the implementation is what keeps the selector's table small: adding a
// back end does not require editing authiface.go.
func init() {
	registerAuthenticator(AuthFile, newFileBackedAuthenticator)
}

// Name is the label used in the log and in a session record.
func (a *fileBackedAuthenticator) Name() string { return AuthFile }

// pwdFile is the password file of this back end, or nil when there is none.
func (a *fileBackedAuthenticator) pwdFile() *PwdFile {
	if a != nil && a.s != nil && a.s.Pwd != nil {
		return a.s.Pwd
	}
	if s := currentServer(); s != nil {
		return s.Pwd
	}
	return nil
}

// Authenticate checks the typed secret against the password file.
//
// The name is looked up exactly as the rest of the daemon looks it up - byte for
// byte, because that is what <user><name> holds and what every access list in
// the configuration refers to - and only when nothing matched, a second time
// with the case ignored. Active Directory accounts are case-insensitive and the
// local file is not, so a site that runs both must be able to type its name the
// way the directory spells it; the canonical spelling is returned, so that the
// session, the hit log and the "Author" field carry one name and not two
// spellings of it.
func (a *fileBackedAuthenticator) Authenticate(ctx AuthContext) (Identity, error) {
	var id Identity
	pf := a.pwdFile()
	if pf == nil {
		// No file is not "wrong password": it is a server that cannot
		// authenticate anybody. Counting it against the caller's allowance
		// would lock him out over a configuration mistake.
		return id, AuthUnavailablef("this server has no password file")
	}
	name := TrimSpaceASCII(ctx.User)
	if name == "" {
		return id, AuthUnavailablef("no user name was given")
	}
	if ctx.Password == "" {
		// The empty secret is answered here rather than at the hash, because it
		// is the one case in which the hash comparison would accept an empty
		// stored value (see VerifyStoredPassword): an account with an empty
		// password must never log anybody in, whatever the file says.
		return id, fmt.Errorf("%w: no password was given", ErrBadPassword)
	}
	u := pf.User(name)
	if u == nil {
		u = pwdUserFold(pf, name)
	}
	if u == nil {
		return id, fmt.Errorf("%w: %s", ErrUnknownUser, name)
	}
	if u.IsInactive() {
		// The account exists and is known; it is switched off. Not a bad
		// password (there is nothing to guess) and not "unknown" (which would
		// make the chain try the next back end with the same name).
		return id, fmt.Errorf("%w: %s is expired", ErrBadPassword, u.Name)
	}
	if !VerifyStoredPassword(ctx.Password, u.Password) {
		return id, fmt.Errorf("%w: %s", ErrBadPassword, u.Name)
	}
	id.Name = u.Name
	id.FullName = u.FullName
	id.Email = u.Email
	id.AuthType = strings.ToLower(AuthFile)
	return id, nil
}

// pwdUserFold is PwdFile.User with the case ignored, which is what a directory
// user expects from a local file. It scans the exported slice instead of changing
// that type, so the existing case-sensitive behaviour - which the access lists
// and the "Author" matching rely on - is untouched. The first match wins.
func pwdUserFold(pf *PwdFile, name string) *PwdUser {
	if pf == nil || name == "" {
		return nil
	}
	for _, u := range pf.Users {
		if u != nil && EqualFold(u.Name, name) {
			return u
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// the shared logbook password
// ---------------------------------------------------------------------------

// verifyUserPassword compares the "wpwd" field against the "User password" of
// the scope. It replaces the "wp == m" comparison of request.go's authenticate();
// both the empty-value rule and the constant-time rule are the reason it exists:
//
//   - an empty configuration value means "this logbook has no shared password"
//     and must never match an empty typed field (the original checked m != ""
//     first; that rule is kept);
//   - both values are hashed before they are compared, so the comparison time
//     depends on neither the length nor the common prefix of the secret.
//
// The hash is a plain SHA-256 of the value: this is a timing question, not a
// storage one, and the value sits in the configuration file in clear text
// anyway.
func verifyUserPassword(given, configured string) bool {
	if strings.TrimSpace(configured) == "" {
		return false
	}
	return constantTimeEqualString(given, configured)
}

// constantTimeEqualString compares two strings without leaking their common
// prefix or their length: the length goes into the hash along with the value, so
// a wrong length costs exactly as much time as a wrong byte.
func constantTimeEqualString(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// ---------------------------------------------------------------------------
// the account a directory or a proxy vouched for
// ---------------------------------------------------------------------------

// passwordFileHasUser answers "is there a local record for this name" - case
// sensitively first, then ignoring the case. It never verifies a secret: a back
// end that has already vouched for the caller elsewhere needs exactly this to
// decide whether to create the record ("Ldap create user", "Header create
// user"). It is a function and not a method so that any back end can use it
// without building one.
func passwordFileHasUser(pf *PwdFile, name string) bool {
	if pf == nil {
		return false
	}
	name = TrimSpaceASCII(name)
	if name == "" {
		return false
	}
	return pf.User(name) != nil || pwdUserFold(pf, name) != nil
}

// ensurePwdUser creates the password-file record of a caller a directory or a
// proxy vouched for, so that the pages which insist on a local record - the user
// page, the subscription list, the e-mail notification - have something to point
// at. The LDAP back end ("Ldap create user") and the header back end ("Header
// create user") both use it, which is why it lives next to the file back end
// rather than in either of them.
//
// No usable password is stored: the record gets a random one, so that the file
// alone can never log this user in while the external account is what
// authenticates him. The secret is never logged. It reports whether it created
// anything and stays quiet about a name that already exists (the normal case on
// the second login).
func (s *Server) ensurePwdUser(name, fullName, email string, withFullName, withEmail bool) bool {
	if s == nil || s.Pwd == nil {
		return false
	}
	name = TrimSpaceASCII(name)
	if name == "" {
		return false
	}
	if passwordFileHasUser(s.Pwd, name) {
		return false
	}
	full, mail := "", ""
	if withFullName {
		full = TrimSpaceASCII(fullName)
	}
	if withEmail {
		mail = TrimSpaceASCII(email)
	}
	// AddUser hashes what it is given, so a random 32-byte secret is what lands
	// in the file.
	if err := s.Pwd.AddUser(name, randomSecret(), full, mail); err == nil {
		s.Pwd.MarkExternal(name)
	} else {
		// A concurrent login of the same first-time caller, or a read-only data
		// directory: worth one line, and neither is fatal, because the caller is
		// authenticated either way.
		s.logf("golog auth: could not create the local record for %s: %v", name, err)
		return false
	}
	s.logf("golog auth: created the local record for %s", name)
	return true
}

// randomSecret is a random string from the portable alphabet, used as the
// unusable password of an externally authenticated account.
func randomSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the process cannot get entropy at all. Fall
		// back to a value that contains a NUL, which no password field can
		// submit, rather than to something guessable: this value is a placeholder
		// nobody is meant to know.
		return "\x00golog-unusable-password"
	}
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// wiring to the selector (authiface.go) and to the status page (authext.go)
// ---------------------------------------------------------------------------

// newFileAuthenticator is the name the selector and the chain cache in
// authiface.go call. The two names exist because the constructor is the entry
// point of the selector table (where the long, explicit name reads better) while
// authiface.go builds the fall-back back end in three places (where the short one
// keeps those lines inside the column limit). One implementation, two spellings,
// as with the other aliases in this package.
func newFileAuthenticator(ctx AuthContext) Authenticator { return newFileBackedAuthenticator(ctx) }

// AuthDescription is the file back end's line for (*Server).AuthStatus. A path
// and a user count are not secret; a password hash never appears here, and no
// user name is listed at all.
func (a *fileBackedAuthenticator) AuthDescription() string {
	if a.pwdFile() == nil {
		return "the XML password file of this server (none is open, so this method cannot accept anybody)"
	}
	return "the XML password file of this server"
}
