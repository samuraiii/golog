// golog - optional password rules: lifetime and reuse.
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// Both rules are off unless configured ([global] or one logbook):
//
//	Password max age = 90      days after which a password has to be changed
//	Password history = 5       a new password may not equal the current one or any
//	                           of the last 5 (at most 24 are remembered)
//	Password min length = 8    shortest password accepted when one is set (default 8)
//
// An expired password does not lock the account: the user can log in but every
// page leads to the "change password" form until it is changed. Accounts with no
// recorded date start their lifetime the first time it is checked, so switching
// the rule on does not lock everybody out at once. A password set by an
// administrator for somebody else counts as expired, so the user chooses their
// own at the next login. Accounts of users who sign in through LDAP or OpenID
// Connect are not subject to either rule (their local password is a random secret).
// Only the hashes of old passwords are kept, in the same format as the password.
package golog

import (
	"errors"
	"fmt"
	"time"
)

const maxPasswordHistory = 24

// PasswordPolicy is the optional password rules of a scope.
type PasswordPolicy struct {
	MaxAgeDays int
	History    int
	MinLength  int
}

func (s *Server) passwordPolicy(scope ConfigScope) PasswordPolicy {
	p := PasswordPolicy{
		MaxAgeDays: s.Config.GetInt(scope, "Password max age", 0),
		History:    s.Config.GetInt(scope, "Password history", 0),
		MinLength:  s.Config.GetInt(scope, "Password min length", 8),
	}
	if p.History > maxPasswordHistory {
		p.History = maxPasswordHistory
	}
	if p.MaxAgeDays < 0 {
		p.MaxAgeDays = 0
	}
	if p.History < 0 {
		p.History = 0
	}
	if p.MinLength < 1 {
		p.MinLength = 8
	}
	return p
}

// MarkExternal flags an account whose credentials are managed elsewhere.
func (pf *PwdFile) MarkExternal(name string) {
	pf.mu.Lock()
	if u := pf.lookupLocked(name); nil != u {
		u.External = true
	}
	pf.mu.Unlock()
	pf.saveLater()
}

// PasswordExpired reports whether the user must change the password now. An
// account without a recorded date gets one (today), so the lifetime begins when
// the rule is first applied.
func (pf *PwdFile) PasswordExpired(name string, maxAgeDays int, now time.Time) bool {
	if maxAgeDays <= 0 {
		return false
	}
	pf.mu.Lock()
	u := pf.lookupLocked(name)
	if nil == u || u.External {
		pf.mu.Unlock()
		return false
	}
	if "" == u.PasswordChanged {
		u.PasswordChanged = now.UTC().Format(time.RFC3339)
		pf.mu.Unlock()
		pf.saveLater()
		return false
	}
	changed, err := time.Parse(time.RFC3339, u.PasswordChanged)
	pf.mu.Unlock()
	if err != nil {
		return true // an unreadable date is treated as expired, not as forever
	}
	return now.After(changed.AddDate(0, 0, maxAgeDays))
}

// ChangePassword sets a new password for the account, enforcing the minimum
// length and the history rule. byAdmin is true when somebody else chose it: the
// password is then marked expired so the owner replaces it at the next login.
func (pf *PwdFile) ChangePassword(name, newPassword string, pol PasswordPolicy, byAdmin bool, now time.Time) error {
	if len(newPassword) < pol.MinLength {
		return fmt.Errorf("the password must have at least %d characters", pol.MinLength)
	}
	pf.mu.Lock()
	u := pf.lookupLocked(name)
	if nil == u {
		pf.mu.Unlock()
		return errors.New("user does not exist")
	}
	// "the last N passwords" are the current one and the N-1 before it.
	if pol.History > 0 && !u.External {
		if VerifyStoredPassword(newPassword, u.Password) {
			pf.mu.Unlock()
			return fmt.Errorf("the new password must differ from the last %d passwords", pol.History)
		}
		for i, h := range u.History {
			if i >= pol.History-1 {
				break
			}
			if VerifyStoredPassword(newPassword, h) {
				pf.mu.Unlock()
				return fmt.Errorf("the new password must differ from the last %d passwords", pol.History)
			}
		}
	}
	// the one being replaced becomes the newest history entry
	if pol.History > 1 && "" != u.Password {
		u.History = append([]string{u.Password}, u.History...)
	}
	if limit := maxInt(pol.History-1, 0); len(u.History) > limit {
		u.History = u.History[:limit]
	}
	u.Password = DoCrypt(newPassword)
	u.Encoding = "SHA256"
	if byAdmin {
		u.PasswordChanged = time.Unix(0, 0).UTC().Format(time.RFC3339)
	} else {
		u.PasswordChanged = now.UTC().Format(time.RFC3339)
	}
	pf.mu.Unlock()
	return pf.Save()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// passwordExpiredFor is the gate's question: does this request's user have to
// change the password before doing anything else?
func (s *Server) passwordExpiredFor(q *Request) bool {
	if nil == s.Pwd || "" == q.User {
		return false
	}
	pol := s.passwordPolicy(q.Cfg)
	return s.Pwd.PasswordExpired(q.User, pol.MaxAgeDays, time.Now())
}
