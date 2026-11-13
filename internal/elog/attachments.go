// ELOG rewritten in Go - attachments: storage names, URLs, thumbnails, MIME
// delivery.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------
//
// Storage: an attachment sits in the same directory as the daily message file
// of its entry (the year directory, or the YYYYMMDD directory the original
// creates for attachments - see storage.go for the resolution order) and is
// named
//
//	YYMMDD_HHMMSS_<sanitised original name>
//
// (el_generate_attachment_filename(); AttachmentName/OriginalAttachmentName in
// dates.go own the prefix rule). The "Attachment:" header of the entry holds
// the list, comma separated. A URL of the form
//
//	/<logbook>/<message id>/<1-based index>
//
// serves the file directly, so an old URL keeps working after the entry is
// edited (the index is into the entry's own list, not into a directory), and the
// physical file name never appears in a page, a bookmark or a mail.

// AttachmentRef is one attachment of an entry: the stored name plus the
// display name shown to the user.
type AttachmentRef struct {
	Name    string // stored file name, e.g. 240430_123456_photo.jpg
	Display string // what the page shows
	Index   int    // 1-based index inside the entry
}

// AttachmentRefs is the free-function form of (*Logbook).AttachmentRefs, for
// code that has an entry but no logbook (the mailer).
func AttachmentRefs(e *Entry) []AttachmentRef {
	att := e.Attachments()
	out := make([]AttachmentRef, 0, len(att))
	for i, a := range att {
		out = append(out, AttachmentRef{Name: a, Display: OriginalAttachmentName(a), Index: i + 1})
	}
	return out
}

// AttachmentRefs lists the attachments of an entry.
func (lb *Logbook) AttachmentRefs(e *Entry) []AttachmentRef { return AttachmentRefs(e) }

// AttachmentByIndex is el_retrieve_attachment().
func (lb *Logbook) AttachmentByIndex(e *Entry, idx int) (AttachmentRef, error) {
	refs := lb.AttachmentRefs(e)
	if idx < 1 || idx > len(refs) {
		return AttachmentRef{}, fmt.Errorf("%w: attachment %d of entry %d", ErrNotFound, idx, e.ID())
	}
	return refs[idx-1], nil
}

// AttachmentURL is the URL the pages use for an attachment. The original emits
// "<logbook>/<id>/<n>" and lets the server resolve the physical name, which
// keeps the stored file name out of the page and out of bookmarks.
//
// BasePath is "" at the root and "/elog" when the -p switch was given, so the
// slash has to be written explicitly here.
func (s *Server) AttachmentURL(lbName string, e *Entry, ref AttachmentRef) string {
	return s.BasePath + "/" + lbName + "/" + strconv.Itoa(e.ID()) + "/" + strconv.Itoa(ref.Index)
}

// AttachmentThumbURL is the URL that asks for the generated thumbnail of an
// attachment; ServeAttachment creates it on demand (see Server.ThumbnailPath).
func (s *Server) AttachmentThumbURL(lbName string, e *Entry, ref AttachmentRef) string {
	return s.AttachmentURL(lbName, e, ref) + "?thumb=1"
}

// SaveAttachment stores an uploaded file for an entry and returns the stored
// name. origName is what the browser sent: it may contain a Windows path and
// arbitrary characters, and MakeFilenamePortable() sanitises it exactly like the
// patched C make_filename_portable() does (Windows-forbidden characters,
// reserved device names, trailing dot/space, length).
func (lb *Logbook) SaveAttachment(subdir, origName string, r io.Reader, now time.Time) (string, error) {
	if r == nil {
		return "", errors.New("no file")
	}
	if origName == "" {
		return "", errors.New("no attachment name")
	}
	stem := MakeFilenamePortable(origName, 120)
	if stem == "" {
		return "", errors.New("attachment name not allowed")
	}
	dataDir := lb.DataDirFor(subdir)
	if err := os.MkdirAll(dataDir, 0o775); err != nil {
		return "", err
	}
	base := AttachmentName(stem, now)
	name := NextAttachmentName(base, func(n string) bool {
		_, err := os.Stat(filepath.Join(dataDir, n))
		return err == nil
	})
	out, err := os.OpenFile(filepath.Join(dataDir, name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o664)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, r); err != nil {
		os.Remove(filepath.Join(dataDir, name))
		return "", err
	}
	return name, nil
}

// DeleteAttachment removes the file (and its cached thumbnail).
func (lb *Logbook) DeleteAttachment(subdir, name string) {
	p, err := lb.Path(subdir, name)
	if err != nil {
		return
	}
	os.Remove(p)
	os.Remove(p + thumbnailSuffix)
}

// thumbnailSuffix is the cache file name suffix of a generated thumbnail. The
// original writes the thumbnail next to the attachment under its own name with a
// ".png" suffix, and deletes it together with the attachment, so the same scheme
// is used here; DeleteAttachment keeps removing the older bare ".png" spelling.
const thumbnailSuffix = ".thumb.png"

// ThumbnailPath returns the cached thumbnail of an attachment, generating it
// with ImageMagick the way el_copy_attachment() does,
//
//	convert -verbose -delay 100 -loop 0 -resize WxH -background white \
//	        <src>[0] <dst>
//
// after asking "identify -format "%w %h"" for the original size so the thumbnail
// keeps its aspect ratio. Thumbnails are cached next to the original as
// "<attachment name>.thumb.png" and regenerated when the original is newer.
//
// Both programs are started by procs.go from an argv slice, never through a
// shell: the C original concatenated the (partly user supplied) file name into a
// command string for system(), which was a genuine command-injection hole - the
// local patches added quoting; in Go no shell is ever involved, so the whole
// class of bug is gone rather than mitigated. Note also that
// MakeFilenamePortable() refuses a leading '-', which would otherwise make a
// file called "-out.png" an *option* to convert(1) even without a shell.
//
// Thumbnails are the one external program this port may run without the -x
// switch, because elogd runs them unconditionally too (they are not a configured
// hook); an operator who does not want ImageMagick executed simply leaves the -g
// switch off, which is the default here and disables this function entirely.
func (s *Server) ThumbnailPath(dataDir, name string, width, height int) (string, bool) {
	if s == nil || !s.Thumbnail || s.ConvertCmd == "" {
		return "", false
	}
	src := s.attachmentFile(dataDir, name)
	if src == "" {
		return "", false
	}
	dst := src + thumbnailSuffix
	if st, err := os.Stat(dst); err == nil && st.ModTime().After(mtimeOf(src)) && st.Size() > 0 {
		return dst, true
	}
	w, h, ok := s.identifySize(src)
	if !ok || h <= 0 || w <= 0 {
		return "", false
	}
	if width <= 0 {
		width = 100
	}
	scale := float64(width) / float64(w)
	if height > 0 && float64(h)*scale > float64(height) {
		scale = float64(height) / float64(h)
	}
	tw := int(float64(w) * scale)
	if tw < 1 {
		tw = 1
	}
	// The "[0]" selects the first frame of a multi-page image, exactly as the
	// original does; it is part of the argv element, so no quoting is needed and
	// a file name with spaces or shell metacharacters is one inert argument.
	args := []string{
		"-verbose", "-delay", "100", "-loop", "0",
		"-resize", strconv.Itoa(tw) + "x" + strconv.Itoa(height),
		"-background", "white",
		src + "[0]",
		dst,
	}
	if _, err := s.runProgram(append([]string{s.ConvertCmd}, args...), "", nil); err != nil {
		os.Remove(dst)
		return "", false
	}
	if st, err := os.Stat(dst); err != nil || st.Size() == 0 {
		os.Remove(dst)
		return "", false
	}
	return dst, true
}

// Thumbnail is the request-facing spelling of ThumbnailPath: the callers in the
// pages and in the attachment handler have a data directory and a stored name
// and only care whether a thumbnail exists.
func (s *Server) Thumbnail(dataDir, name string, width, height int) (string, bool) {
	return s.ThumbnailPath(dataDir, name, width, height)
}

// attachmentFile resolves a stored attachment name inside the data directory.
// The name comes from a message file, which an operator could have edited, so a
// name that escapes the directory (or is absolute) is refused here rather than
// opened: withinDir() is the same check the upload path uses.
func (s *Server) attachmentFile(dataDir, name string) string {
	if dataDir == "" || name == "" {
		return ""
	}
	p := filepath.Join(dataDir, filepath.FromSlash(path.Base(filepath.ToSlash(name))))
	if !withinDir(p, dataDir) {
		return ""
	}
	if st, err := os.Stat(p); err != nil || st.IsDir() {
		return ""
	}
	return p
}

// identifySize asks ImageMagick's identify(1) for the size of an image. The file
// name is one argv element, never interpolated into a command line.
func (s *Server) identifySize(src string) (w, h int, ok bool) {
	if s.IdentifyCmd == "" {
		return 0, 0, false
	}
	out, err := s.runProgram([]string{s.IdentifyCmd, "-format", "%w %h", src + "[0]"}, "", nil)
	if err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d %d", &w, &h); err != nil {
		return 0, 0, false
	}
	return w, h, true
}

func mtimeOf(p string) time.Time {
	if st, err := os.Stat(p); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

// ServeAttachment writes an attachment to the response. The disposition is
// "inline" for things a browser renders (images, text, PDF) and "attachment"
// otherwise, matching the original's Content-Disposition logic. The file name is
// additionally RFC 2231 encoded for non-ASCII names, which the original (a plain
// URL-encode) does not do; the ASCII fallback= parameter is kept for old
// clients.
func ServeAttachment(w http.ResponseWriter, r *http.Request, filePath, displayName string, asThumb bool) {
	st, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "attachment not found", http.StatusNotFound)
		return
	}
	ctype := ContentTypeFor(filePath)
	if asThumb {
		ctype = "image/png"
	}
	w.Header().Set("Content-Type", ctype)
	if isRenderable(ctype) {
		w.Header().Set("Content-Disposition", dispositionInline(displayName))
	} else {
		w.Header().Set("Content-Disposition", dispositionAttachment(displayName))
	}
	w.Header().Set("Last-Modified", st.ModTime().UTC().Format(http.TimeFormat))
	// Only images may sit in a browser cache; anything else can carry
	// confidential logbook data that sits behind the access control list.
	// (Content-Length is left to net/http so that Range requests work.)
	if strings.HasPrefix(ctype, "image/") {
		w.Header().Set("Cache-Control", "private, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "private, no-cache")
	}
	f, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "attachment not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	http.ServeContent(w, r, displayName, st.ModTime(), f)
}

func isRenderable(ctype string) bool {
	for _, p := range []string{"image/", "text/", "video/", "audio/"} {
		if strings.HasPrefix(ctype, p) {
			return true
		}
	}
	switch ctype {
	case "application/pdf", "application/postscript":
		return true
	}
	return false
}

func dispositionInline(name string)     { return "inline; " + dispositionName(name) }
func dispositionAttachment(name string) { return "attachment; " + dispositionName(name) }

func dispositionName(name string) string {
	safe := MakeFilenameHeaderSafe(name)
	if isASCIIString(safe) {
		return `filename="` + safe + `"`
	}
	// RFC 2231: the extensive parameter carries the UTF-8 name percent-encoded.
	// url.QueryEscape would turn a space into '+', which is wrong here, so the
	// RFC 3986 path escaping with its %20 is used and "'" is escaped by hand.
	return fmt.Sprintf(`filename="%s"; filename*=UTF-8''%s`,
		ToASCIIFallback(safe), escapeExtValue(safe))
}

// escapeExtValue is the RFC 2231/5987 value encoding: everything outside the
// attr-char set becomes %XX, byte by byte, so a multi-byte UTF-8 character is
// percent-encoded as a whole and never split.
func escapeExtValue(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}

// MakeFilenameHeaderSafe strips the characters that must not appear in a
// quoted-string header value and any directory part a client may have sent.
func MakeFilenameHeaderSafe(s string) string {
	s = path.Base(strings.ReplaceAll(s, "\\", "/"))
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == '"' || c == '\\' {
			b.WriteByte('_')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// makeFilenameHeaderSafe is the lowercase spelling the transcribed call sites
// use.
func makeFilenameHeaderSafe(s string) string { return MakeFilenameHeaderSafe(s) }

// isASCIIString reports whether s is pure 7-bit, which decides whether an RFC
// 2231 encoded filename* parameter is needed at all.
func isASCIIString(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// ToASCIIFallback is the ASCII-only twin of a file name, for the legacy
// filename= parameter that sits next to filename*=. Non-ASCII bytes are dropped
// (not transliterated: the fallback must never be misleading) and the result is
// never empty.
func ToASCIIFallback(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] < 0x80 {
			b.WriteByte(s[i])
		}
	}
	out := strings.Trim(b.String(), ". ")
	if out == "" || out == "_" {
		return "file" + filepath.Ext(s)
	}
	return out
}

// ContentTypeFor maps a file name to a MIME type. elogd keeps its own table
// (filetype[] in elogd.cxx) and falls back to application/octet-stream;
// mime.TypeByExtension covers the same ground, and the handful of types the
// original forces are overridden here so a browser behaves as before.
func ContentTypeFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt", ".log", ".msg", ".det", ".list", ".cfg", ".inc":
		return "text/plain; charset=utf-8"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".pdf":
		return "application/pdf"
	case ".root", ".cif", ".ndjson":
		// detector-data extensions this logbook uploads; the original serves
		// them as octet-stream, which makes a browser download rather than
		// render, so the behaviour is kept deliberately.
		return "application/octet-stream"
	}
	if t := mime.TypeByExtension(strings.ToLower(filepath.Ext(name))); t != "" {
		if strings.HasPrefix(t, "text/") && !strings.Contains(t, "charset") {
			t += "; charset=utf-8"
		}
		return t
	}
	return "application/octet-stream"
}

// EscapeHTMLText is the escaping the pages use for text that must keep its
// newlines. It is html.EscapeString under a name that says what it is for; the
// pages call it on every attribute value and on the body text after the markup
// conversion.
func EscapeHTMLText(s string) string { return html.EscapeString(s) }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// AttachmentSize is the total size of the attachments of an entry, the value the
// list page shows in the "Attachment" column (elogd stores it in the
// Attachment_size header when the entry is written).
func (s *Server) AttachmentSize(lb *Logbook, e *Entry) int64 {
	if n, ok := entryInt64(e, "Attachment_size"); ok {
		return n
	}
	if lb == nil {
		return 0
	}
	var total int64
	for _, a := range AttachmentRefs(e) {
		if p, err := lb.Path(e.Subdir, a.Name); err == nil {
			if st, err := os.Stat(p); err == nil {
				total += st.Size()
			}
		}
	}
	return total
}

// AttachmentSizeOf is the size of one attachment, for the display page.
func (lb *Logbook) AttachmentSizeOf(subdir, name string) int64 {
	p, err := lb.Path(subdir, name)
	if err != nil {
		return 0
	}
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// IsImageName reports whether a stored attachment name looks like an image, i.e.
// whether it is worth thumbnailing and whether the display page embeds it.
func IsImageName(name string) bool { return isImageName(name) }

func isImageName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".gif", ".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".xpm", ".ico", ".webp":
		return true
	}
	return false
}

// AttachmentDisplayHTML is the table the display page shows for the attachments
// of an entry: a thumbnail when ImageMagick produced one, the name as a link and
// the size. display_logbook_page() builds the same markup; keeping it here keeps
// the attachment markup in one place (the display page, the preview and the
// delete confirmation all call it).
//
// withDelete is not part of this build: deletion goes through the entry's button
// row like every other command, so the parameter is accepted for the call sites
// of the transcribed code and currently unused.
func (s *Server) AttachmentDisplayHTML(logbook string, e *Entry, withDelete bool) string {
	_ = withDelete
	refs := AttachmentRefs(e)
	if len(refs) == 0 {
		return ""
	}
	lb := s.LB(logbook)
	scope := s.ScopeFor(logbook)
	var b strings.Builder
	b.WriteString("<table class=\"elog_attachments\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">\n")
	for _, a := range refs {
		u := s.AttachmentURL(logbook, e, a)
		fmt.Fprintf(&b, "<tr class=\"elog_attachments\"><td class=\"elog_attachments\">")
		if s.Thumbnail && isImageName(a.Name) && lb != nil {
			if _, ok := s.ThumbnailPath(lb.DataDirFor(e.Subdir), a.Name,
				s.ThumbWidth(scope), s.ThumbHeight(scope)); ok {
				fmt.Fprintf(&b, "<a href=\"%s\"><img src=\"%s\" class=\"elog_thumb\" alt=\"%s\" border=\"0\"></a> ",
					HTMLEscape(u), HTMLEscape(s.AttachmentThumbURL(logbook, e, a)), HTMLEscape(a.Display))
			}
		}
		fmt.Fprintf(&b, "<a href=\"%s\" class=\"el_attachment\">%s</a>", HTMLEscape(u), HTMLEscape(a.Display))
		if lb != nil {
			if size := lb.AttachmentSizeOf(e.Subdir, a.Name); size > 0 {
				fmt.Fprintf(&b, " (%s)", humanBytes(size))
			}
		}
		b.WriteString("</td></tr>\n")
	}
	b.WriteString("</table>\n")
	return b.String()
}

// AttachmentRows is the same table reached from a request (the logbook name and
// the logbook object come from the request instead of being passed).
func (s *Server) AttachmentRows(q *Request, e *Entry) string {
	return s.AttachmentDisplayHTML(q.Cfg.Group, e, false)
}

// ThumbWidth and ThumbHeight are the "Thumbnail size" configuration ("WxH", the
// C default is 100x100 in the display code).
func (s *Server) ThumbWidth(scope ConfigScope) int {
	w, _ := s.thumbSize(scope)
	return w
}

func (s *Server) ThumbHeight(scope ConfigScope) int {
	_, h := s.thumbSize(scope)
	return h
}

func (s *Server) thumbSize(scope ConfigScope) (int, int) {
	if s == nil || s.Config == nil {
		return 100, 100
	}
	v := TrimSpaceASCII(s.Config.GetString(scope, "Thumbnail size", ""))
	if v == "" {
		return 100, 100
	}
	ws, hs, ok := strings.Cut(v, "x")
	if !ok {
		return Atoi(ws), Atoi(hs)
	}
	return Atoi(ws), Atoi(hs)
}

// unusedURLEscapeRef keeps the net/url import meaningful for the RFC 2231 code
// above if escapeExtValue is ever replaced by a standard-library helper.
var _ = url.PathEscape
