package elog

// ---------------------------------------------------------------------------
// Edit locks
// ---------------------------------------------------------------------------
//
// The original guards concurrent editing with a lock FILE per message,
// "<logbook dir>/<id>.lock", written by lock_file() when the edit page is
// opened and removed by unlock_file() when the entry is stored or the page is
// left; ckedit_exist() reports the holder. display_logbook_page() asks
// lock_file() whether a message is in use and prints
//
//	"This log entry is currently edited by <user>. Do you want to edit it
//	anyway (concurrent editing may lead to lost updates)?"
//
// with a Yes/No radio button (the "force" parameter), which this port reproduces
// in entry.go.
//
// The scheme is deliberately kept file-based and identical, so an elogd and a
// Go elogd pointing at the same data directory during a gradual rollout see the
// same locks instead of both believing the entry is free. The name is spelled
// out in one place here because a stray "<id>.lock" left behind by a killed
// daemon is the one failure mode users actually see; the timeout below is what
// makes it recoverable without a manual rm.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LockSuffix is the extension of an edit-lock file: "<id>.lock".
const LockSuffix = ".lock"

// lockBodyFields is the number of lines lockFile writes (user, time, pid);
// lockInfo tolerates fewer (an empty or half-written file means "unknown
// holder", not "not locked").
const lockBodyFields = 3

// lockFileName is lock_file()/unlock_file()'s path for one message.
func (lb *Logbook) lockFileName(id int) string {
	return filepath.Join(lb.Dir, strconv.Itoa(id)+LockSuffix)
}

// AddLockFile is elogd's lock_file(): create <id>.lock, refusing when the entry
// is already locked by somebody else (unless it is the same user, which may
// re-enter its own edit page). force bypasses the check, which is what the
// "edit anyway" answer on the confirmation page does.
func (lb *Logbook) AddLockFile(id int, user string, force bool) error {
	name := lb.lockFileName(id)
	if !force {
		if _, err := os.Stat(name); err == nil {
			if info, ok := lb.lockInfo(id); ok && info.User != "" && !SamePerson(info.User, user) {
				return &LockHeldError{ID: id, User: info.User, When: info.When}
			}
		}
	}
	body := user + "\n" + FormatCTime(time.Now()) + "\n" + strconv.Itoa(os.Getpid()) + "\n"
	for len(strings.Split(strings.TrimRight(body, "\n"), "\n")) < lockBodyFields {
		body += "\n"
	}
	return os.WriteFile(name, []byte(body), 0o664)
}

// AddLock is the force-free form used by the pages that only mark an entry.
func (lb *Logbook) AddLock(id int, user string) error {
	return lb.AddLockFile(id, user, false)
}

// DelLockFile is unlock_file(). A missing file is not an error.
func (lb *Logbook) DelLockFile(id int) error { return os.Remove(lb.lockFileName(id)) }

// DelLock is the form used where the error is not interesting (leaving a page).
func (lb *Logbook) DelLock(id int) { _ = lb.DelLockFile(id) }

// DeleteLock is the historical name kept for call sites that read as "the
// server deletes a lock"; it is DelLockFile.
func (lb *Logbook) DeleteLock(id int) error { return lb.DelLockFile(id) }

// LockInfo is what ckedit_exist() reports.
type LockInfo struct {
	ID   int
	User string
	When time.Time
	PID  string
}

// LockHeldError is returned by AddLockFile when somebody else holds the lock.
type LockHeldError struct {
	ID   int
	User string
	When time.Time
}

func (e *LockHeldError) Error() string {
	return "entry " + strconv.Itoa(e.ID) + " is locked by " + e.User
}

// IsLocked reports whether an edit lock exists and has not timed out.
// "Edit lock timeout" (hours, elogd's default is 24) decides when a lock is
// considered stale, because a browser tab left open for three days must not
// block a logbook forever. The C program compares against the file's mtime; the
// mtime is used here too (the body's ctime string is for the message shown).
func (lb *Logbook) IsLocked(id int, timeout time.Duration) (LockInfo, bool) {
	name := lb.lockFileName(id)
	st, err := os.Stat(name)
	if err != nil {
		return LockInfo{ID: id}, false
	}
	info, _ := lb.lockInfo(id)
	if timeout > 0 && time.Since(st.ModTime()) > timeout {
		return info, false
	}
	return info, true
}

// LockAge is the time an existing lock file was last touched, for the status
// page and the "locked for 3 days" hint.
func (lb *Logbook) LockAge(id int) (time.Duration, bool) {
	st, err := os.Stat(lb.lockFileName(id))
	if err != nil {
		return 0, false
	}
	return time.Since(st.ModTime()), true
}

func (lb *Logbook) lockInfo(id int) (LockInfo, bool) {
	data, err := os.ReadFile(lb.lockFileName(id))
	if err != nil {
		return LockInfo{ID: id}, false
	}
	info := LockInfo{ID: id}
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
	if len(lines) > 0 {
		info.User = TrimSpaceASCII(lines[0])
	}
	if len(lines) > 1 {
		if t, ok := ParseCTime(TrimSpaceASCII(lines[1])); ok {
			info.When = t
		}
	}
	if len(lines) > 2 {
		info.PID = TrimSpaceASCII(lines[2])
	}
	return info, true
}

// LockTimeout reads "Edit lock timeout" (hours) for a scope; 0 means "never
// expires", which is what the original does when the value is 0.
func (s *Server) LockTimeout(scope ConfigScope) time.Duration {
	h := s.Config.Hours(scope, "Edit lock timeout", 24)
	if h <= 0 {
		return 0
	}
	return time.Duration(h * float64(time.Hour))
}
