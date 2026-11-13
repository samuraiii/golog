// ELOG rewritten in Go - the page-rendering entry points the dispatcher calls.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"fmt"
	"net/http"
)

// ---------------------------------------------------------------------------
// The dispatcher's far half
// ---------------------------------------------------------------------------
//
// elogd.cxx has one giant function per screen - display_list(),
// display_single_page(), display_edit_page(), display_logbooks() - and reaches
// them from a switch on the command. The renderers themselves live in pages.go
// (list and selection), entry.go (single entry, thread, edit form, preview,
// delete confirmation, login form) and submit.go (the store path). This file holds
// only what those do not: the generic error pages and the thread-of-one-entry view
// that "?cmd=Display as Thread" of a single message produces.
//
// Keeping them here means request.go never has to know which file holds which
// renderer, and each screen has exactly one implementation.

// displayEntries renders several messages on one page (the search-results-as-full-
// entries view and the "one entry plus its replies" view).
func (s *Server) displayEntries(q *Request, heading string, list []*Entry) {
	s.beginPage(q, orText(heading, s.logbookTitle(q.Cfg.Group)), "")
	if heading != "" {
		fmt.Fprintf(q.W, "<p><b>%s</b></p>\n", HTMLEscape(heading))
	}
	for _, e := range list {
		s.showDisplayPage(q, e.ID())
	}
	s.endPage(q)
}

// displayThreadOf is "?cmd=Display as Thread" reached with a message number: that
// entry followed by everything that refers back to it, oldest first. Without a
// message number the command means the whole logbook as a tree, which entry.go's
// showThreadPage draws.
func (s *Server) displayThreadOf(q *Request, e *Entry) {
	if e == nil {
		s.notFound(q)
		return
	}
	thread := append([]*Entry{e}, s.threadOf(q.LB, e.ID())...)
	s.displayEntries(q, s.loc("Thread"), thread)
}

// threadOf collects the descendants of a message (replies, replies to replies),
// breadth first. The walk keeps a visited set, so a malformed store in which two
// messages claim each other as their parent cannot loop forever; the original's
// recursion over the same data would run until the stack gave out.
func (s *Server) threadOf(lb *Logbook, id int) []*Entry {
	if lb == nil {
		return nil
	}
	seen := map[int]bool{id: true}
	var out []*Entry
	for frontier := []int{id}; len(frontier) > 0; {
		var next []int
		for _, e := range lb.Messages() {
			if !seen[e.ID()] && containsInt(frontier, e.InReplyTo()) {
				seen[e.ID()] = true
				out = append(out, e)
				next = append(next, e.ID())
			}
		}
		frontier = next
	}
	return out
}

// containsInt is a membership test over a short slice (a reply fan-out is small).
func containsInt(v []int, x int) bool {
	if x <= 0 {
		return false
	}
	for _, y := range v {
		if y == x {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Generic error pages
// ---------------------------------------------------------------------------

// notFound answers 404 with the logbook's own page chrome, so a broken bookmark
// still shows the navigation bar (the original does the same: an unknown URL ends
// in the logbook list rather than in a bare browser error page).
func (s *Server) notFound(q *Request) {
	if q == nil || q.W == nil {
		return
	}
	s.errorf(q, http.StatusNotFound, "%s", s.loc("The requested page does not exist"))
}

// serverError answers 500. The original's failure modes are mostly "cannot create
// the message file" (disk full, read-only directory), for which it prints the
// strerror() text; that text is passed through here because an operator reading
// the page needs to see the reason, not a generic message.
func (s *Server) serverError(q *Request, why string) {
	if q == nil || q.W == nil {
		return
	}
	if !wroteHeader(q.W) {
		q.W.WriteHeader(http.StatusInternalServerError)
	}
	s.beginPage(q, s.loc("Error"), "")
	fmt.Fprintf(q.W, "<h3>%s</h3>\n<p>%s</p>\n", HTMLEscape(s.loc("Error")), HTMLEscape(why))
	s.endPage(q)
}

// notModified answers 304 with no body, which is what the caching path of the
// original does for an attachment whose modification time has not changed. The
// header must be set before the status line, so this cannot go through beginPage.
func (s *Server) notModified(q *Request) {
	q.W.Header().Set("Cache-Control", "no-cache, must-revalidate")
	q.W.WriteHeader(http.StatusNotModified)
}

// showErrorPage is the plain 400 page for callers that only have a message: the
// handlers file uses it for "this feature is not configured" cases.
func (s *Server) showErrorPage(q *Request, msg string) {
	s.errorf(q, http.StatusBadRequest, "%s", msg)
}

// showError is the older spelling of the same thing, used by transcribed call
// sites that pass a format string. The format is applied first, the result is
// escaped by errorf, so a caller cannot inject markup through a %s.
func (s *Server) showError(q *Request, format string, args ...any) {
	s.errorf(q, http.StatusBadRequest, format, args...)
}

// redirectPost is what elogd answers after a successful submit. The original
// actually emits a small HTML page containing a meta refresh plus a form that
// auto-submits (because a 302 after a POST used to lose the message on some
// browsers of 2005); a 303 turns the follow-up into a GET without a body, which is
// the modern equivalent of the same behaviour and is what a browser today renders
// identically.
func (s *Server) redirectPost(q *Request, location string) {
	if location == "" {
		location = s.BasePath + "/" + q.Cfg.Group + "/"
	}
	q.W.Header().Set("Location", location)
	q.W.Header().Set("Cache-Control", "no-cache, must-revalidate")
	q.W.WriteHeader(http.StatusSeeOther)
}
