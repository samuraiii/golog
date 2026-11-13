package elog

import (
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Entry submission - the port of submit_logbook()
// ---------------------------------------------------------------------------
//
// The original's flow (elogd.cxx submit_logbook()):
//
//  1. validate: "You must enter a subject" / "You must specify an author" when
//     "Mandatory subject"/"Mandatory author" is set; an attribute with an option
//     list must contain one of its options.
//  2. if the logbook requires a password and no valid session exists, bounce
//     back to the form with the password box.
//  3. build the header from the attributes; a field whose value is "<keep>" keeps
//     the previous value, and a field the form did not send at all is taken from
//     the old entry (so a hidden attribute survives an edit).
//  4. allocate the id: for a new entry the number the New page pre-filled in
//     "message_id", else next_id; elogd refuses to overwrite an existing message
//     ("Entry #N already exists").
//  5. store the attachments next to the message file, appending the generated
//     names to the "Attachment" header; delete the ones listed in "attdelete".
//  6. el_submit() appends the message block and updates the index.
//  7. run "Execute new"/"Execute edit" - the shell-injection site: the C code
//     built a shell string; here exec.Command with an argv slice, no shell (see
//     shell.go).
//  8. compose and send the notification mail (mailer.go).
//  9. redirect to the display page of the new entry.
//
// One deliberate difference: the C code edits the entry in place, so a validation
// failure late in the sequence can leave the in-memory index modified. Everything
// below works on a copy that is only handed to the storage layer once it is
// complete.

// submit is the ?cmd=Submit handler.
func (s *Server) submit(q *Request) {
	lb := q.LB
	if lb == nil {
		s.errorf(q, http.StatusNotFound, "No such logbook")
		return
	}
	if q.parseFailed {
		s.showFormError(q, "The submission could not be read ("+HTMLEscape(q.parseErr)+
			"). It is probably larger than the \"Max total size\" of this logbook.", q.IntParam("message_id"))
		return
	}
	id := q.IntParam("message_id")
	if id == 0 {
		id = q.IntParam("edit_id")
	}
	var old *Entry
	if id > 0 {
		e, err := lb.Message(id)
		if err != nil {
			s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", id)
			return
		}
		old = e
	}
	if !s.CanEdit(q.Cfg, q.User) {
		s.errorf(q, http.StatusForbidden, "You are not allowed to post to this logbook")
		return
	}
	// The edit lock protects two people editing at once; an administrator may
	// override it, because otherwise a forgotten lock would need a walk to the
	// data directory to clear.
	if old != nil && s.editLockActive(q, id) && !s.userIn(q.Cfg, "Admin", q.User) {
		s.showFormError(q, fmt.Sprintf(
			"Entry <b>#%d</b> is locked for editing by <b>%s</b>. Ask that user to leave the "+
				"edit page, or wait until the lock expires.", id, HTMLEscape(s.lockedBy(lb, id))), id)
		return
	}

	// Work on a copy so a validation failure cannot leave the in-memory index
	// half-updated.
	e := &Entry{}
	if old != nil {
		e.Header = append([]HeaderLine(nil), old.Header...)
		e.Text = old.Text
		e.Subdir = old.Subdir
		e.File = old.File
		e.Offset = old.Offset
	}

	set := func(key, val string) {
		if val == keepValue {
			return
		}
		e.SetHeader(key, StripHeaderInjection(val))
	}

	attrs := s.Config.AttributeNames(q.Cfg)
	for _, a := range attrs {
		if len(q.ParamAll(a)) == 0 && old != nil {
			continue // the form did not carry this field: keep the old value
		}
		set(a, s.joinAttrValue(q, a))
	}
	if v, ok := q.anyOf("Title", "subject", "Subject"); ok {
		set("Title", v)
	}
	if v, ok := q.anyOf("Author", "author"); ok {
		set("Author", v)
	}
	if v, ok := q.anyOf("Email", "email", "user_email"); ok {
		set("Email", v)
	}
	if len(q.ParamAll("Text")) > 0 {
		txt := strings.ReplaceAll(q.Param("Text"), "\r\n", "\n")
		if s.Config.GetBool(q.Cfg, "UseHTML") {
			txt = SanitizeHTML(txt)
		} else {
			txt = EscapeNewlines(txt)
		}
		e.Text = txt
	}
	if rp := q.IntParam("reply_to"); rp > 0 {
		e.SetInReplyTo(rp)
	}
	if rp := q.IntParam("in_reply_to"); rp > 0 {
		e.SetInReplyTo(rp)
	}

	// An anonymous poster's name and e-mail are echoed back as cookies so the
	// next post is pre-filled, which is what the original does.
	if q.User == "" {
		s.setIdentityCookies(q, e.Get2("Author"), e.Get2("Email"))
	}

	if msg := s.validateEntry(q, e, attrs); msg != "" {
		s.showFormError(q, msg, id)
		return
	}

	// Date: the form posts the parts of the date widget, "now" is the default
	// for a new entry and the old value is kept when the form carried no date.
	date := s.formDate(q, old)
	e.SetHeader("Date", FormatRFC2822(date))
	if v := q.Param("Encoding"); v != "" {
		set("Encoding", v)
	}
	if v := q.Param("Charset"); v != "" {
		set("Charset", v)
	}

	// Attachments -----------------------------------------------------------
	var saved, failed []string
	if q.R.MultipartForm != nil {
		var err error
		saved, failed, err = s.saveAttachments(q, lb, e, date)
		if err != nil {
			s.showFormError(q, "Cannot store the attachment: "+HTMLEscape(err.Error()), id)
			return
		}
	}
	s.deleteAttachments(q, lb, e)
	all := mergeAttachments(e, saved)
	e.SetAttachments(all)

	// Thread bookkeeping: a reply points at its parent, a new top-level entry is
	// its own thread. el_submit() does the same in the C code.
	if e.InReplyTo() > 0 && e.Thread() == 0 {
		if parent, err := lb.Message(e.InReplyTo()); err == nil {
			if th := parent.Thread(); th > 0 {
				e.SetThread(th)
			} else {
				e.SetThread(parent.ID())
			}
		}
	}

	// Persist --------------------------------------------------------------
	isNew := old == nil
	if isNew {
		if id <= 0 {
			id = q.IntParam("entry_id")
		}
		if id <= 0 {
			id = lb.NextID()
		}
		if _, err := lb.Message(id); err == nil {
			s.showFormError(q, fmt.Sprintf(
				"Entry <b>#%d</b> already exists - it may have been created while you were "+
					"typing. Please press Back, change the entry and submit it again.", id), 0)
			return
		}
		e.SetID(id)
		e.Del("ID")
		if err := lb.Append(e); err != nil {
			s.showFormError(q, "Cannot store the entry: "+HTMLEscape(err.Error()), 0)
			return
		}
	} else {
		if err := lb.Update(e); err != nil {
			s.showFormError(q, "Cannot store the entry: "+HTMLEscape(err.Error()), id)
			return
		}
	}
	s.clearEditLockOnDisk(lb, id)

	// Hooks and mail -------------------------------------------------------
	url := s.requestBaseURL(q.R) + s.entryURL(q.Cfg.Group, e.ID())
	e.SetHeader("_URL", url) // for &url in the hook and in the display text
	charset := s.Config.GetStringDefault(q.Cfg, "Charset", "utf-8")
	hookKey := "Execute new"
	if !isNew {
		hookKey = "Execute edit"
	}
	if cmd := s.Config.GetString(q.Cfg, hookKey, ""); cmd != "" {
		if err := s.RunEntryHook(cmd, lb.DataDirFor(e.Subdir), e, q.Cfg.Group, charset); err != nil {
			s.logf("%s: %v", hookKey, err)
		}
	}
	if !Bool(s.Config.GetString(q.Cfg, "No mail", "0")) && q.Param("nomail") != "1" {
		if err := s.notify(q, lb, e, old, url); err != nil {
			s.logf("notification mail: %v", err)
		}
	}

	if len(failed) > 0 {
		s.beginPage(q, "Entry submitted", "")
		fmt.Fprintf(q.W, "<p>Entry <a href=%q>#%d</a> was stored, but these attachments could not "+
			"be saved (name not allowed or file too large):</p><ul>", HTMLEscape(url), e.ID())
		for _, f := range failed {
			fmt.Fprintf(q.W, "<li>%s</li>", HTMLEscape(f))
		}
		fmt.Fprint(q.W, "</ul>\n")
		s.endPage(q)
		return
	}
	s.redirect(q, url)
}

// joinAttrValue builds the value of one attribute. A multi-select posts several
// values, which the original joins with ", ".
func (s *Server) joinAttrValue(q *Request, attr string) string {
	vals := q.ParamAll(attr)
	switch len(vals) {
	case 0:
		return ""
	case 1:
		return strings.ReplaceAll(vals[0], "\r\n", "\n")
	}
	return strings.Join(vals, ", ")
}

// validateEntry is the set of checks the original applies before accepting a
// post; the returned string is the message shown to the user ("" == OK).
func (s *Server) validateEntry(q *Request, e *Entry, attrs []string) string {
	if s.Config.GetBool(q.Cfg, "Mandatory subject") && strings.TrimSpace(e.Title()) == "" {
		return "You must enter a subject."
	}
	if s.Config.GetBool(q.Cfg, "Mandatory author") && strings.TrimSpace(e.Author()) == "" {
		return "You must specify the author."
	}
	if s.Config.GetBool(q.Cfg, "Require user password") && q.User == "" {
		return "You must enter the user password for this logbook."
	}
	for _, a := range attrs {
		opts := s.Config.OptionsFor(q.Cfg, a)
		if len(opts) == 0 {
			continue
		}
		v := strings.TrimSpace(e.Get2(a))
		if v == "" {
			continue
		}
		ok := false
		for _, o := range opts {
			if EqualFold(TrimSpaceASCII(o), v) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Sprintf("The value of \"%s\" must be one of %s.",
				HTMLEscape(a), HTMLEscape(strings.Join(opts, ", ")))
		}
	}
	if mx := s.Config.GetInt(q.Cfg, "Max text size", 0); mx > 0 && len(e.Text) > mx*1024 {
		return fmt.Sprintf("The text is too long (limit %d kB).", mx)
	}
	return ""
}

// formDate rebuilds the entry date from the parts the date widget posts
// (y0/m0/d0/h0/n0), falling back to the old value or to now.
func (s *Server) formDate(q *Request, old *Entry) time.Time {
	now := time.Now()
	if v := q.Param("entry_date"); v != "" {
		if t, ok := ParseDate(v); ok {
			return t
		}
	}
	y, mo, d := now.Year(), int(now.Month()), now.Day()
	h, mi := now.Hour(), now.Minute()
	got := false
	if v := q.Param("y0"); v != "" {
		y, got = Atoi(v), true
	}
	if v := q.Param("m0"); v != "" {
		mo, got = Atoi(v), true
	}
	if v := q.Param("d0"); v != "" {
		d, got = Atoi(v), true
	}
	if v := q.Param("h0"); v != "" {
		h = Atoi(v)
	}
	if v := q.Param("n0"); v != "" {
		mi = Atoi(v)
	}
	if !got {
		if old != nil {
			return old.DateValue()
		}
		return now
	}
	return time.Date(y, time.Month(clamp(mo, 1, 12)), clamp(d, 1, 31),
		clamp(h, 0, 23), clamp(mi, 0, 59), 0, 0, time.Local)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// setIdentityCookies reproduces the "remember the anonymous poster" cookies.
func (s *Server) setIdentityCookies(q *Request, author, email string) {
	if author != "" {
		http.SetCookie(q.W, &http.Cookie{Name: "elog_author", Value: URLEncode(author),
			Path: s.CookiePath(), MaxAge: 30 * 24 * 3600})
	}
	if email != "" {
		http.SetCookie(q.W, &http.Cookie{Name: "elog_email", Value: URLEncode(email),
			Path: s.CookiePath(), MaxAge: 30 * 24 * 3600})
	}
}

// mergeAttachments adds the newly stored names to the entry's list without
// duplicating an existing one.
func mergeAttachments(e *Entry, saved []string) []string {
	list := e.Attachments()
	if len(saved) == 0 {
		return list
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(list)+len(saved))
	for _, a := range append(append([]string{}, list...), saved...) {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// ---------------------------------------------------------------------------
// Storing uploads
// ---------------------------------------------------------------------------
//
// Two points from the local patches are carried over explicitly:
//
//   - the stored name is built by MakeFilenamePortable(), which strips the
//     characters Windows forbids, the reserved device names and a trailing
//     dot/space, and never lets the name start with '-' (which would look like an
//     option to convert(1));
//   - the name is only ever handed to a helper as one argv element. Nothing here
//     builds a command line, so a file called "; rm -rf /" is inert. The C
//     original quoted the name after the injection fix - quoting is a workaround,
//     not going through a shell at all is the fix.

// saveAttachments stores the uploads of this request and returns the names to add
// to the entry plus the names that could not be stored.
func (s *Server) saveAttachments(q *Request, lb *Logbook, e *Entry, date time.Time) (saved, failed []string, err error) {
	fm := q.R.MultipartForm
	if fm == nil {
		return nil, nil, nil
	}
	dir := lb.DataDirFor(e.Subdir)
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return nil, nil, err
	}
	maxSize := int64(s.MaxUpload) << 20
	if v := s.Config.GetInt(q.Cfg, "Max attachment size", 0); v > 0 {
		maxSize = int64(v) << 20
	}

	// The form names its inputs attachment0, attachment1, ... Walk them in that
	// order so the stored list matches the order the user picked, and accept the
	// plain "attachment" name used by some themes.
	keys := make([]string, 0, len(fm.File))
	for k := range fm.File {
		if k == "attachment" || strings.HasPrefix(k, "attachment") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, key := range keys {
		for _, fh := range fm.File[key] {
			name, ok := s.storeAttachment(lb, dir, fh, date, maxSize)
			if !ok {
				if fh.Filename != "" {
					failed = append(failed, filepath.Base(filepath.FromSlash(fh.Filename)))
				}
				continue
			}
			if name != "" {
				saved = append(saved, name)
			}
		}
	}
	return saved, failed, nil
}

// storeAttachment writes one upload next to the message file. It returns the
// stored name, or "" with ok=true for an empty file input (not an upload) and ""
// with ok=false for a rejected one.
func (s *Server) storeAttachment(lb *Logbook, dir string, fh *multipart.FileHeader,
	date time.Time, maxSize int64) (string, bool) {
	if fh == nil || fh.Size == 0 {
		return "", true
	}
	if maxSize > 0 && fh.Size > maxSize {
		s.logf("attachment %s rejected: %d bytes over the limit", fh.Filename, fh.Size)
		return "", false
	}
	stem := MakeFilenamePortable(filepath.Base(filepath.FromSlash(fh.Filename)), 120)
	base := AttachmentName(stem, date)

	// el_generate_attachment_filename() builds "<YYMMDD_HHMMSS>_<name>"; the
	// collision loop in el_copy_attachment() then adds "_1" until the name is
	// free, so a re-upload inside the same second cannot overwrite another
	// entry's attachment.
	name := NextAttachmentName(base, func(n string) bool {
		_, err := os.Stat(filepath.Join(dir, n))
		return err == nil
	})
	full := filepath.Join(dir, name)
	// Belt and braces: the name is generated, but verify it stayed inside the
	// logbook directory before writing.
	if !withinDir(full, lb.Dir) {
		return "", false
	}

	src, err := fh.Open()
	if err != nil {
		return "", false
	}
	defer src.Close()
	dst, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o664)
	if err != nil {
		return "", false
	}
	// LimitReader is one byte larger than the limit so an over-long file is
	// detected rather than silently truncated.
	_, cpErr := io.Copy(dst, io.LimitReader(src, maxSize+1))
	stat, _ := dst.Stat()
	clErr := dst.Close()
	if stat != nil && maxSize > 0 && stat.Size() > maxSize {
		cpErr = fmt.Errorf("attachment too large")
	}
	if cpErr != nil || clErr != nil {
		os.Remove(full)
		if cpErr != nil {
			s.logf("attachment %s: %v", name, cpErr)
		}
		return "", false
	}
	// Thumbnails are produced lazily when the entry is displayed, so a submit
	// never waits for ImageMagick.
	return name, true
}

// withinDir reports whether p resolves to a path inside dir. Every path built
// from a stored file name goes through this, so a name that somehow contains
// "../" cannot escape the logbook directory.
func withinDir(p, dir string) bool {
	rel, err := filepath.Rel(dir, filepath.Clean(p))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

// deleteAttachments removes the attachments the edit form ticked ("attdelete"
// holds the 1-based index of the attachment).
func (s *Server) deleteAttachments(q *Request, lb *Logbook, e *Entry) {
	del := map[int]bool{}
	for _, d := range append(q.ParamAll("attdelete"), q.ParamAll("delatt")...) {
		if n := Atoi(d); n > 0 {
			del[n] = true
		}
	}
	if len(del) == 0 {
		return
	}
	list := e.Attachments()
	out := make([]string, 0, len(list))
	for i, name := range list {
		if !del[i+1] {
			out = append(out, name)
			continue
		}
		lb.DeleteAttachment(e.Subdir, name)
	}
	e.SetAttachments(out)
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

// entryURL is the path part of an entry's URL: the short form elogd has served
// since forever and that readers have bookmarked.
func (s *Server) entryURL(logbook string, id int) string {
	return EntryURL(s.BasePath, logbook, id)
}

// ServerBaseURL is the configured "Server" URL without a trailing slash, "" when
// the configuration does not name one.
func (s *Server) ServerBaseURL() string {
	return s.requestBaseURLForConfig()
}

// requestBaseURLForConfig is the "Server" configuration key as a URL.
func (s *Server) requestBaseURLForConfig() string {
	v := TrimSpaceASCII(s.Config.GetString(ConfigScope{Group: "global"}, "Server", ""))
	if v == "" {
		return ""
	}
	v = strings.TrimSuffix(v, "/")
	if !strings.Contains(v, "://") {
		v = "http://" + v
	}
	return v
}

// requestBaseURL is the above with the Host header as a fallback, which is what
// elogd effectively uses when "Server" is unset - so a mirror or a vhost gets
// links that point at itself.
func (s *Server) requestBaseURL(r *http.Request) string {
	if u := s.requestBaseURLForConfig(); u != "" {
		return u
	}
	scheme := "http"
	if r != nil && r.TLS != nil {
		scheme = "https"
	}
	if r != nil && r.Host != "" {
		return scheme + "://" + r.Host
	}
	return ""
}
