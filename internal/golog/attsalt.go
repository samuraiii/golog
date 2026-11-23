// golog - salted attachment names.
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// With "Salt = <secret>" in the configuration ([global] or one logbook), every
// NEW attachment is stored under a name with no extension at all:
//
//	base32(sha256(<file name> + <salt> + <entry id>))
//
// where <file name> is the complete name of the uploaded file, extension
// included, and <entry id> is the number of the entry the file belongs to. The
// URL carries the same name:
//
//	/<logbook>/<name>
//
// so neither the file on disk nor the URL can be derived from the name of the
// file and the entry, and neither reveals the file type. The original name (with
// its extension) is kept in the entry ("Attachment names") and decides what the
// page shows, the Content-Type and the download name; the file content decides
// whether a thumbnail can be made. Attachments stored before the salt was set
// (the "<date>_<time>_<name>" files of ELOG and of older golog) keep their names
// and URLs and are served exactly as before: the salt only changes how new files
// are named.
//
// The digest is written in lower-case base32 (RFC 4648, no padding): 52
// characters from a-z 2-7 carry the 256 bits of SHA-256, where hex needs 64.
// That alphabet is safe in a URL and in a file name on every file system,
// including the case-insensitive ones (Windows, macOS), where a mixed-case
// encoding such as base64 could make two different names the same file; it
// cannot start with '-' and cannot spell a reserved device name. A stored name
// is exactly 52 characters, far below every file system's limit.
//
// The secret is the salt; the hash only has to make the name unguessable and
// collision-free. The salt must be long and random (16+ characters).
package golog

import (
	"crypto/sha256"
	"encoding/base32"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// saltedName matches a stored name made by saltedAttachmentName.
var saltedName = regexp.MustCompile(`^[a-z2-7]{52}$`)

// attachmentSalt is the configured salt of a logbook ("" when not set).
func (s *Server) attachmentSalt(scope ConfigScope) string {
	return strings.TrimSpace(s.Config.GetString(scope, "Salt", ""))
}

// saltedAttachmentName builds the stored name. n > 0 is the collision counter
// (two files of the same name in one entry): it is folded into the hashed name,
// never into the visible part.
func saltedAttachmentName(orig, salt string, mid, n int) string {
	h := sha256.New()
	h.Write([]byte(orig))
	if n > 0 {
		h.Write([]byte("#" + strconv.Itoa(n)))
	}
	h.Write([]byte(salt))
	h.Write([]byte(strconv.Itoa(mid)))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil)))
}

// IsSaltedName reports a stored name of the salted scheme's shape (52 characters
// of a-z2-7, and not a legacy "<date>_<time>_<name>").
func IsSaltedName(name string) bool {
	return saltedName.MatchString(name) && !IsAttachmentName(name)
}

// attachmentOrigNames reads the "Attachment names" header:
// "<stored>=<url-escaped original>, ...".
func attachmentOrigNames(e *Entry) map[string]string {
	out := map[string]string{}
	raw, ok := e.Get("Attachment names")
	if !ok {
		return out
	}
	for _, p := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if 2 != len(kv) {
			continue
		}
		if v, err := url.QueryUnescape(kv[1]); err == nil && "" != v {
			out[kv[0]] = v
		}
	}
	return out
}

// recordOrigName remembers the original name of a salted attachment.
func recordOrigName(e *Entry, stored, orig string) {
	names := attachmentOrigNames(e)
	names[stored] = orig
	var parts []string
	for _, a := range e.Attachments() {
		if o, ok := names[a]; ok {
			parts = append(parts, a+"="+url.QueryEscape(o))
			delete(names, a)
		}
	}
	// the one being stored is not in the Attachment list yet
	if o, ok := names[stored]; ok {
		parts = append(parts, stored+"="+url.QueryEscape(o))
	}
	e.Set("Attachment names", strings.Join(parts, ", "))
}

// FindAttachmentByStoredName returns the entry holding an attachment of that
// stored name and the attachment's reference.
func (lb *Logbook) FindAttachmentByStoredName(name string) (*Entry, AttachmentRef, bool) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	for _, e := range lb.entries {
		for _, ref := range AttachmentRefs(e) {
			if ref.Name == name {
				return e, ref, true
			}
		}
	}
	return nil, AttachmentRef{}, false
}
