package elog

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// The pieces the request pipeline, the pages and the command hooks reach for but
// which are not a subsystem of their own: entry URLs, the delete command, the
// resource/static file serving, the &-substituted hooks, the "Display views"
// switch and the shell-substitution entry point of configuration values.
//
// Everything here is a thin composition of canonical implementations that live
// in server.go, storage.go, attachments.go, hitlog.go, editlock.go, shell.go and
// procs.go; the reason they sit together is that they are the API surface the
// transcribed C call sites expect, not new behaviour.
// ---------------------------------------------------------------------------

// EntryURL is the bookmark-stable URL of a message: "<base>/<logbook>/<id>", the
// short form elogd has always served and that the "Display" command answers.
// BasePath is "" at the root ("/elog" with -p elog), hence the explicit slash.
func EntryURL(basePath, logbook string, id int) string {
	return basePath + "/" + logbook + "/" + strconv.Itoa(id)
}

// URLFor is the permanent (absolute) link of an entry: what the notification
// mail, RSS and the &url substitution of the external commands use. elogd takes
// it from the "Server" configuration key and falls back to the Host header of
// the current request, which is what ServerBaseURL/requestBaseURL do.
func (s *Server) URLFor(logbook string, e *Entry) string {
	if s == nil || e == nil {
		return ""
	}
	base := s.ServerBaseURL()
	if base == "" {
		if r := s.currentRequest(); r != nil {
			base = s.requestBaseURL(r.R)
		}
	}
	return base + EntryURL(s.BasePath, logbook, e.ID())
}

// entryLink is the in-server relative link to an entry, used in the pages where
// an absolute host name would be wrong behind a proxy.
func (s *Server) entryLink(logbook string, e *Entry) string {
	if e == nil {
		return ""
	}
	return s.entryURL(logbook, e.ID())
}

// ---------------------------------------------------------------------------
// The Delete command
// ---------------------------------------------------------------------------

// deleteMessage is remove_message(): show the confirmation page when the reader
// has only asked, remove the entry (and, unless the logbook keeps them, its
// attachments) when the confirmation was posted.
//
// The original also writes the deleted entry into the "_deleted.log" file of the
// logbook when "Delete reverting" is on; entryHistory()/revertTo() cover the same
// ground for edited entries, and the deletion history is kept here too because a
// logbook that relies on "Display changes"/revert must not lose it.
func (s *Server) deleteMessage(q *Request) {
	id := q.msgID
	if id == 0 {
		id = q.IntParam("message_id")
	}
	e, err := q.LB.Message(id)
	if err != nil {
		s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", id)
		return
	}
	// An entry that somebody else is editing must not vanish under their feet;
	// elogd checks the lock the same way before it removes the file.
	if s.editLocked(q.LB, id) && !s.CanEdit(q.Cfg, q.User) {
		s.errorf(q, http.StatusForbidden, "Entry #%d is locked for editing by %s", id,
			HTMLEscape(orText(s.EditLockBy(q.LB, id), "another user")))
		return
	}
	if !q.HasParam("confirmed") {
		s.confirmDeletePage(q)
		return
	}
	if err := q.LB.Remove(id); err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot delete entry #%d: %v", id, err)
		return
	}
	s.ClearEditLock(q.LB, id)
	if v := s.Config.GetString(q.Cfg, "Execute delete", ""); v != "" {
		if err := s.RunEntryHook(v, q.LB.Dir, e, q.Cfg.Group, "UTF-8"); err != nil {
			s.logf("Execute delete hook for #%d: %v", id, err)
		}
	}
	s.logf("%s deleted entry #%d of logbook %s", orText(q.User, "anonymous"), id, q.Cfg.Group)
	s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/")
}

// deleteEntryFiles removes the attachments of an entry that is being deleted.
// The "Remove attachments" key decides whether the files go with the entry; the
// default keeps them, which is what the original does with its
// remove_attachments flag (a logbook that is deleted outright is a job for rm).
func (s *Server) deleteEntryFiles(lb *Logbook, e *Entry, scope ConfigScope) {
	if s.Config.GetBoolDefault(scope, "Remove attachments", true) {
		s.deleteAttachmentsFor(lb, e)
	}
}

// ---------------------------------------------------------------------------
// Static files, the resource directory and the robots.txt
// ---------------------------------------------------------------------------

// serveResourceFile resolves a requested resource name (a theme CSS file, an
// icon, a .lng file, ...) inside the allowed directories and serves it.
func (s *Server) serveResourceFile(w http.ResponseWriter, r *http.Request, name string) {
	p, ok := s.staticPath(name)
	if !ok {
		s.errorf(&Request{W: w, R: r, S: s}, http.StatusNotFound, "File not found")
		return
	}
	serveFile(w, r, p)
}

// serveFile serves one already-resolved file with the content type that goes with
// its extension. Style sheets are served as UTF-8 because the theme files of a
// multilingual logbook contain non-ASCII text.
func serveFile(w http.ResponseWriter, r *http.Request, p string) {
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	ctype := ContentTypeFor(p)
	if strings.HasSuffix(strings.ToLower(p), ".css") && !strings.Contains(ctype, "charset") {
		ctype = "text/css; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Last-Modified", st.ModTime().UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "public, max-age=300")
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, filepath.Base(p), st.ModTime(), f)
}

// staticPath resolves a requested resource name to a file, searching the
// directories elogd searches: the logbook's own static dir, the resource
// directory and the logbook data directory. The name must be a plain file name
// (or a "theme/x.css" style relative path without "..").
//
// The path comes from a URL, so it is resolved inside the allowed directories
// only: every "." / ".." / empty element and every drive prefix is refused before
// a single system call, and the resolved path is re-checked to sit under the
// directory it came from. elogd has the same intent ("..\" checks in
// display_logbook_page()) but implemented on a fixed buffer.
func (s *Server) staticPath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "/")
	if name == "" || strings.Contains(name, ":") {
		return "", false
	}
	for _, el := range strings.Split(name, "/") {
		if el == "" || el == "." || el == ".." {
			return "", false
		}
	}
	var dirs []string
	if q := s.currentRequest(); q != nil {
		dirs = append(dirs, q.StaticDirs("")...)
	}
	if s.ResourceDir != "" {
		dirs = append(dirs, s.ResourceDir)
	}
	for _, d := range dirs {
		p := filepath.Join(d, filepath.FromSlash(name))
		if !withinDir(p, d) {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

// StaticDirs is the list of directories a request may serve static files from:
// the resource directory plus the logbook's own "static" directory and its data
// directory (elogd looks for the file next to the theme files and in the logbook
// directory).
func (q *Request) StaticDirs(subdir string) []string {
	var out []string
	if q == nil || q.S == nil {
		return out
	}
	if q.S.ResourceDir != "" {
		out = append(out, q.S.ResourceDir)
	}
	if q.LB != nil {
		out = append(out, filepath.Join(q.LB.Dir, "static"), q.LB.Dir)
	}
	if subdir != "" {
		for i, d := range out {
			out[i] = filepath.Join(d, subdir)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Hooks and substitutions
// ---------------------------------------------------------------------------

// RunHook runs one configured external command ("Execute new", "Execute edit",
// "Execute delete") after the &-substitutions were applied. The hook receives the
// entry it refers to, so &num, &title and &attrX expand to its values, and the
// expanded string is split into argv words and started directly - the value of a
// logbook attribute can therefore never become a command, which is the injection
// the local patches addressed by quoting.
//
// Nothing in this path touches a shell: see shell.go and procs.go.
func (s *Server) RunHook(command, logbook, dir string, e *Entry) error {
	charset := "UTF-8"
	if s.Config != nil {
		if v := s.Config.GetString(ConfigScope{Group: logbook}, "Character set", ""); v != "" {
			charset = v
		}
	}
	if e != nil {
		command = strings.ReplaceAll(command, "&url", s.URLFor(logbook, e))
	}
	return s.RunEntryHook(command, dir, e, logbook, charset)
}

// ---------------------------------------------------------------------------
// Configuration helpers used by the pages and the hit page
// ---------------------------------------------------------------------------

// ShowViews is the "Display views" switch of the summary page, which puts the
// number of views behind each entry in the list.
func (s *Server) ShowViews(scope ConfigScope) bool {
	if s == nil || s.Config == nil {
		return false
	}
	return s.Config.GetFlag(scope, "Display views")
}

// ShellSubstValue expands $shell(...) in one configuration value of one scope.
// The scope is part of the signature because elogd reads the value with the
// logbook's group and may run the command in that logbook's directory; the
// expansion itself, including the -x gate, is shell.go's shellSubstInDir.
func (s *Server) ShellSubstValue(scope ConfigScope, value string) string {
	if s == nil {
		return value
	}
	if !strings.Contains(value, "shell(") && !strings.Contains(value, "$(shell") {
		return value
	}
	if s.LB(scope.Group) != nil {
		return shellSubstInDir(s, value, s.logbookDir(scope.Group))
	}
	return s.ShellSubst(value)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

// firstLine is the first non-empty line of a text, trimmed - the subject
// extraction of the mail and the one-line summary of the hooks. The scan is
// rune-safe: ShortenUTF8() is applied by the callers, never a byte slice.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		l = TrimSpaceASCII(strings.TrimSuffix(l, "\r"))
		if l != "" {
			return l
		}
	}
	return ""
}

// personKey is the comparison key of SamePerson: lower case, blanks collapsed.
func personKey(s string) string { return strings.ToLower(collapseBlanks(s)) }

// readAttachmentFile reads one attachment for the notification mail. Missing or
// unreadable files are reported to the caller, which skips the part rather than
// sending a truncated MIME message (that was one of the patched C bugs: a part
// whose file vanished left the multipart unclosed and the rest of the message was
// swallowed by the MTA).
func readAttachmentFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// humanTime is the "3 days ago" spelling the status page uses for the age of a
// session or of the last configuration reload.
func humanTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// copyFileRange is the small file copy the delete/revert history uses. Buffers
// grow as needed; nothing here is a fixed-size buffer.
func copyFileRange(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}
