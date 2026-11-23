package golog

// paths.go - the edit-lock questions the pages and the submit path ask.
//
// The lock itself is a "<id>.lock" file in the data directory of the logbook
// (editlock.go), exactly like the original's create_editlock()/check_editlock():
// the file holds the id, the user name and the time, and it is ignored once it is
// older than the "Login expiration" configuration key. What the pages need is the
// three questions below - is it locked, who holds it, and may this user open the
// editor - plus the two writes (place a lock, break a lock).
//
// The low level (AddLock/AddLockFile/DelLock/IsLocked/LockAge) is in
// editlock.go; compat.go keeps the short spellings (lockedBy, setEditLock) that
// the transcribed call sites use, which forward here.

import (
	"time"
)

// EditLockTimeout is the age from which an edit lock is ignored: the
// "Login expiration" key, which is also the session lifetime (elogd uses the same
// value in check_editlock()).
func (s *Server) EditLockTimeout() time.Duration {
	if s == nil {
		return 24 * time.Hour
	}
	return s.LockTimeout(ConfigScope{Group: "global"})
}

// editLocked reports whether the entry has a live edit lock.
func (s *Server) editLocked(lb *Logbook, id int) bool {
	if lb == nil || id <= 0 {
		return false
	}
	_, ok := lb.IsLocked(id, s.EditLockTimeout())
	return ok
}

// EditLockBy is the name written in the lock file, "" when the entry is not
// locked. The pages print it in the "this entry is being edited by ..." notice,
// which is display_edit_page()'s "Locked by" attribute row.
func (s *Server) EditLockBy(lb *Logbook, id int) string {
	if lb == nil || id <= 0 {
		return ""
	}
	info, ok := lb.IsLocked(id, s.EditLockTimeout())
	if !ok {
		return ""
	}
	return info.User
}

// editLockedByOther is the check display_edit_page() and remove_message() do
// before they touch an entry: a locked entry belongs to the user who locked it
// and to the users with the "Edit all"/"Admin" right, which the caller checks.
func (s *Server) editLockedByOther(lb *Logbook, id int, user string) bool {
	if !s.editLocked(lb, id) {
		return false
	}
	if user == "" {
		return true
	}
	return !SamePerson(s.EditLockBy(lb, id), user)
}

// EditLockedByOther is the exported form of editLockedByOther.
func (s *Server) EditLockedByOther(lb *Logbook, id int, user string) bool {
	return s.editLockedByOther(lb, id, user)
}

// editLockActive is the question submit() asks with the request in hand: is this
// entry locked by somebody the submitting user is not? The lock records the
// display name ("John Doe"), while the submitter may be identified by his login
// name as well, so both are compared - elogd does the same with its
// check_editlock(user, name) pair.
func (s *Server) editLockActive(q *Request, id int) bool {
	if q == nil || q.LB == nil {
		return false
	}
	who := s.EditLockBy(q.LB, id)
	if who == "" {
		return false
	}
	return !SamePerson(who, q.displayName()) && !SamePerson(who, q.User)
}

// touchEditLock creates the lock of the entry a user is about to edit and
// answers the name of a user who already holds one. A lock held by somebody else
// is not broken here: the caller refuses the editor in that case unless the user
// may edit everything, which is how the original behaves (it prints "this
// message is being edited by <name>" and offers the force edit).
func (s *Server) touchEditLock(lb *Logbook, id int, user string) (string, error) {
	if lb == nil || id <= 0 {
		return "", nil
	}
	who := s.EditLockBy(lb, id)
	if who != "" && !SamePerson(who, user) {
		return who, nil
	}
	if err := lb.AddLock(id, orText(user, "unknown")); err != nil {
		return who, err
	}
	return who, nil
}

// SetEditLock places the lock of an entry the user is editing. A lock that
// somebody else holds is overwritten only here, which is the "force edit" path
// (elogd's check_editlock() with force_edit set); the ordinary path goes through
// touchEditLock, which refuses to break a lock.
func (s *Server) SetEditLock(lb *Logbook, e *Entry, who string) error {
	if lb == nil || e == nil {
		return nil
	}
	return lb.AddLockFile(e.ID(), orText(who, "unknown"), true)
}

// ClearEditLock removes the lock of an entry, whatever its age. elogd does this
// when the editor is left (submit, cancel) and when an entry is deleted, because
// a dangling lock would keep the entry uneditable until the timeout passes.
func (s *Server) ClearEditLock(lb *Logbook, id int) {
	if lb == nil || id <= 0 {
		return
	}
	lb.DelLock(id)
}

// clearEditLockOnDisk is ClearEditLock under the name submit() uses, which says
// what actually happens: the lock is a file, and removing it is the end of the
// editing session. Keeping the two spellings means the storage layer is called
// from one place.
func (s *Server) clearEditLockOnDisk(lb *Logbook, id int) { s.ClearEditLock(lb, id) }
