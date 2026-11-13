package elog

// ---------------------------------------------------------------------------
// compat.go
//
// The C program has one global namespace and several spellings for the same idea
// (getcfg vs GetParameter, strstrip vs strip, system() vs run_command, one
// notification rule reached from three places). Each idea has exactly ONE
// implementation in this package; this file collects
//
//   - the short aliases that let the transcribed call sites keep the name
//     elogd.cxx uses, and
//   - the small subsystem bridges that belong to no single file (localisation,
//     notification addresses, edit-lock and attachment spellings).
//
// Keeping them here means that "redeclared in this block" cannot happen and that
// grepping a concept finds its one implementation. The canonical
// implementations live in: text.go (strings), config.go/config_util.go
// (configuration), dates.go (dates and file names), storage.go (message files
// and index), attachments.go, auth.go, hitlog.go, editlock.go, mailer.go,
// state.go (the process-wide server) and procs.go (the ONE file that starts a
// subprocess).
// ---------------------------------------------------------------------------

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Version of the daemon this binary reports
// ---------------------------------------------------------------------------

const (
	// Version is the version of this Go implementation.
	Version = "1.0.0-go"

	// EmulatedVersion is the elogd release whose behaviour is reproduced. The
	// pages and the status line print it (Server.Version), so that a client or a
	// monitoring script which parses it sees what it expects.
	EmulatedVersion = "V1.1.0 (2022-01/03)"
)

// ---------------------------------------------------------------------------
// Entry accessors used by the pages
// ---------------------------------------------------------------------------
//
// storage.go is the canonical spelling of every accessor (Get, Set, ID, Attrs,
// ...). These are the aliases the transcribed call sites use; they forward, so
// there is still exactly one implementation of each rule.

// Get2 is the one-value accessor under the name the transcribed code uses
// ("value = get2(entry, title)").
func (e *Entry) Get2(key string) string {
	v, _ := e.Get(key)
	return v
}

// SetHeader is Set under the transcribed name (elogd's set_attribute()).
func (e *Entry) SetHeader(key, value string) { e.Set(key, value) }

// Set2 is Set under the transcribed name.
func (e *Entry) Set2(key, value string) { e.Set(key, value) }

// IDnum and IDstr are the message number as a number and as a string, the two
// forms elogd passes around.
func (e *Entry) IDnum() int { return e.ID() }

func (e *Entry) IDstr() string { return strconv.Itoa(e.ID()) }

// AttrValue is the value of one user attribute, "" when unset. The "Attr:"
// header may repeat; the FIRST match wins, which is what get_att_value() in the
// original returns. Attribute names are compared ASCII case insensitively.
func (e *Entry) AttrValue(attr string) string {
	v, _ := e.Attr(attr)
	return v
}

// Attr returns one attribute value and whether it was present.
//
// The attribute name is the header KEY: a message file stores a user attribute
// as a header line "Topic: Run A", so parseBlock() already split it into
// Key="Topic", Value="Run A". A value that itself carries "name: value" (an
// entry written by a tool that put several attributes on one line) is matched on
// the value part too, which costs nothing and keeps such odd entries readable.
func (e *Entry) Attr(name string) (string, bool) {
	for _, h := range e.Header {
		if EqualFold(h.Key, name) {
			return h.Value, true
		}
	}
	for _, h := range e.Header {
		i := strings.IndexByte(h.Value, ':')
		if i < 0 {
			continue
		}
		if EqualFold(strings.TrimSpace(h.Value[:i]), name) {
			return strings.TrimSpace(h.Value[i+1:]), true
		}
	}
	return "", false
}

// Attrs2 is Attrs under the transcribed name.
func (e *Entry) Attrs2() []HeaderLine { return e.Attrs() }

// Date is the entry's date, with the zero time when the "Date:" header is
// missing or unparseable. DateValue() is the same value under the name the
// storage layer uses; both names exist because the page code and the storage
// code grew separate call sites, and the C original likewise reads
// msg->date/parse_date_time() at several places.
func (e *Entry) Date() time.Time { return e.DateValue() }

// parseEntryBytes parses one raw message block.
func parseEntryBytes(b []byte) (*Entry, error) { return parseBlock(b) }

// ---------------------------------------------------------------------------
// Small string aliases
// ---------------------------------------------------------------------------

func trim(s string) string { return TrimSpaceASCII(s) }

func lower(s string) string { return strings.ToLower(s) }

func htmlEscape(s string) string { return HTMLEscape(s) }

func urlEscape(s string) string { return URLEncode(s) }

func formatSize(n int64) string { return humanBytes(n) }

// ---------------------------------------------------------------------------
// Localisation
// ---------------------------------------------------------------------------

// loc is the translation of one string, exactly like the tr() macro of
// elogd.cxx: a logbook without a language file (or with an empty entry) gets the
// English text back, which is also what the shipped English installation does.
func (s *Server) loc(name string) string { return s.locale().Get(name) }

// locT is loc under the transcribed name.
func (s *Server) locT(name string) string { return s.loc(name) }

// locf is a translated printf: the format string is looked up first, so a
// translation can reorder its arguments (%[1]s style).
func (s *Server) locf(format string, args ...any) string {
	return sprintf(s.loc(format), args...)
}

// locale returns the language table of the server, loading it on first use. The
// locale is a process-wide setting in elogd (the -l switch or the global
// "Locale" key), so it is cached here; the cache is guarded by Server.locMu
// because this port serves requests on several goroutines while elogd has one
// select() loop.
func (s *Server) locale() *Locale {
	if s == nil {
		return localeFor("", "English")
	}
	s.locMu.Lock()
	defer s.locMu.Unlock()
	if s.locCache != nil {
		return s.locCache
	}
	name := s.Locale
	if name == "" {
		name = "English"
	}
	s.locCache = LoadLocale(s.ResourceDir, name)
	return s.locCache
}

// locFor translates with the locale of one logbook scope. Every logbook of a
// real deployment shares the server locale; the scope argument exists because
// elogd's tr() reads the locale at the moment it is called and because a
// per-logbook "Locale" key may override the global one.
func (s *Server) locFor(scope ConfigScope, name string) string {
	if s == nil || s.Config == nil {
		return s.loc(name)
	}
	v := TrimSpaceASCII(s.Config.GetString(scope, "Locale", ""))
	if v == "" || EqualFold(v, s.Locale) {
		return s.loc(name)
	}
	return localeFor(s.ResourceDir, v).Get(name)
}

// localeCacheDir caches the .lng files by resource directory and language, so
// that a per-logbook "Locale" does not re-read the file on every string. The
// server's own language goes through Server.locCache instead (see locale()).
var localeCacheDir sync.Map // "dir\x00name" -> *Locale

func localeFor(resourceDir, name string) *Locale {
	if name == "" {
		name = "English"
	}
	key := resourceDir + "\x00" + name
	if v, ok := localeCacheDir.Load(key); ok {
		return v.(*Locale)
	}
	l := LoadLocale(resourceDir, name)
	localeCacheDir.Store(key, l)
	return l
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

// attachmentURL is the lowercase spelling the page code uses.
func (s *Server) attachmentURL(lbName string, e *Entry, ref AttachmentRef) string {
	return s.AttachmentURL(lbName, e, ref)
}

// attachmentURLFrom is the URL of one attachment of a message, from the message
// number and the 1-based index the URL scheme uses.
func (s *Server) attachmentURLFrom(logbook string, id, idx int) string {
	return s.entryURL(logbook, id) + "/" + strconv.Itoa(idx)
}

// deleteAttachmentsFor removes every file of an entry. elogd leaves the files
// behind when the store itself fails; the caller decides, this only deletes.
func (s *Server) deleteAttachmentsFor(lb *Logbook, e *Entry) {
	if lb == nil || e == nil {
		return
	}
	for _, a := range AttachmentRefs(e) {
		lb.DeleteAttachment(e.Subdir, a.Name)
	}
}

// ---------------------------------------------------------------------------
// Notification addresses
// ---------------------------------------------------------------------------

// NotifyAddresses is the To: list of a notification: every user of the password
// file whose "email_notify" entries cover this logbook (and category), in file
// order.
//
// The password file stores one <email_notify> element per logbook the user
// subscribed to (read_password_entry() in auth.cxx), and the subscription page
// writes the literal "all" for a user who wants everything. A value may also
// carry a category list, "logbook:cat1,cat2", which the subscription page of a
// logbook with categories produces; the wildcard "*" matches every category.
// Comparison is ASCII case insensitive, like the rest of the configuration
// handling. The author argument is part of the signature because elogd passes it
// (its "notify about a reply" variant filters on it); this build notifies the
// whole subscription list, see the note in mailer.go.
func (s *Server) NotifyAddresses(logbook, category, author string) []string {
	if s == nil || s.Pwd == nil {
		return nil
	}
	_ = author // reserved, see the comment above
	var out []string
	for _, pu := range s.Pwd.Users {
		if pu == nil || pu.IsInactive() || pu.Email == "" {
			continue
		}
		for _, v := range pu.EmailNotify {
			if matchNotify(v, logbook, category) {
				out = append(out, pu.Email)
				break
			}
		}
	}
	return out
}

// matchNotify is one "email_notify" entry of the password file.
func matchNotify(value, logbook, category string) bool {
	value = TrimSpaceASCII(value)
	if value == "" {
		return false
	}
	if EqualFold(value, "all") || value == "*" {
		return true
	}
	name, cats, has := strings.Cut(value, ":")
	if !EqualFold(TrimSpaceASCII(name), logbook) {
		return false
	}
	if !has || TrimSpaceASCII(cats) == "" {
		return true
	}
	if TrimSpaceASCII(category) == "" {
		return true
	}
	for _, c := range SplitList(cats, ",", false) {
		if c == "*" || EqualFold(c, category) {
			return true
		}
	}
	return false
}

// subscribed reports whether one user wants notifications about a logbook /
// category pair.
func (s *Server) subscribed(u *PwdUser, logbook, category string) bool {
	if u == nil {
		return false
	}
	for _, v := range u.EmailNotify {
		if matchNotify(v, logbook, category) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// View statistics and edit locks: the spellings the page code uses
// ---------------------------------------------------------------------------

// showViews is the "Display views" switch.
func (s *Server) showViews(scope ConfigScope) bool { return s.ShowViews(scope) }

// hitsSince parses the "since" argument of the hits page.
func hitsSince(v string) (time.Time, bool) { return HitsSince(v) }

// setEditLock places the lock for a message that is about to be edited.
func (s *Server) setEditLock(lb *Logbook, id int, user string) {
	if lb == nil {
		return
	}
	e, err := lb.Message(id)
	if err != nil {
		return
	}
	s.SetEditLock(lb, e, user)
}

// lockedBy is who holds the edit lock of a message ("" when nobody).
func (s *Server) lockedBy(lb *Logbook, id int) string { return s.EditLockBy(lb, id) }
