package elog

import (
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// The entry pages: display, thread, edit/new, preview, delete confirmation and
// the login form.
// ---------------------------------------------------------------------------

// showDisplayPage is display_message(): the entry's attributes in the order of
// the "Attribute" configuration list, then the text, then the attachments, then
// the per-entry command buttons.
func (s *Server) showDisplayPage(q *Request, id int) {
	e, err := q.LB.Message(id)
	if err != nil {
		s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", id)
		return
	}
	s.beginPage(q, orText(e.Title(), s.logbookTitle(q.Cfg.Group)), "")

	df := s.Config.GetString(q.Cfg, "Date format", "%a %b %d %Y")
	tf := s.Config.GetString(q.Cfg, "Time format", "%H:%M")
	d := e.DateValue()

	fmt.Fprint(q.W, "<table class=\"entry\" border=\"0\" cellpadding=\"2\" cellspacing=\"1\" width=\"100%\">\n")
	attrRow := func(name, value string) {
		fmt.Fprintf(q.W, "<tr class=\"attributes\"><td class=\"entry_attrname\" valign=\"top\" nowrap=\"nowrap\">%s</td>"+
			"<td class=\"entry_attr\" valign=\"top\">%s</td></tr>\n",
			HTMLEscape(s.loc(name)), value)
	}

	if s.Config.GetBoolDefault(q.Cfg, "Title", true) {
		fmt.Fprintf(q.W, "<tr class=\"subject\"><td class=\"entry_attrname\">%s</td>"+
			"<td class=\"entry_subject\" valign=\"top\">%s</td></tr>\n",
			HTMLEscape(s.loc("Subject")), HTMLEscape(orText(e.Title(), "(no subject)")))
	}
	attrRow("Date", HTMLEscape(FormatDate(df+" "+tf, d)))
	if a := e.Author(); a != "" {
		attrRow("Author", s.authorHTML(q.Cfg, a, e.Get2("Email")))
	}
	// User attributes in configuration order, then any attribute the
	// configuration does not know about: an old entry may carry attributes that
	// were removed from the config later, and dropping them from the display
	// would hide data.
	seen := map[string]bool{"date": true, "author": true, "title": true,
		"subject": true, "attachment": true, "encoding": true, "msg_id": true,
		"in reply to": true, "lockedby": true}
	for _, a := range s.Config.AttributeNames(q.Cfg) {
		seen[strings.ToLower(a)] = true
		if v := e.Get2(a); v != "" {
			attrRow(a, HTMLEscape(v))
		}
	}
	for _, h := range e.Attrs() {
		if seen[strings.ToLower(h.Key)] {
			continue
		}
		seen[strings.ToLower(h.Key)] = true
		if strings.TrimSpace(h.Value) != "" {
			attrRow(h.Key, HTMLEscape(h.Value))
		}
	}
	refs := q.LB.AttachmentRefs(e)
	if len(refs) > 0 {
		attrRow("Attachment", s.AttachmentDisplayHTML(q.Cfg.Group, e, false))
	}
	if r := e.InReplyTo(); r > 0 {
		attrRow("Reply to", fmt.Sprintf("<a href=\"%s\">#%d</a>",
			HTMLEscape(s.BasePath+"/"+q.Cfg.Group+"/?cmd="+URLEncode(s.loc("Display"))+
				"&message_id="+strconv.Itoa(r)), r))
	}
	if by := s.EditLockBy(q.LB, id); by != "" && s.Config.GetBool(q.Cfg, "Show lock") {
		attrRow("Locked by", HTMLEscape(by))
	}
	fmt.Fprint(q.W, "</table>\n")

	// The text. An entry stored with "Encoding: HTML" is passed through as
	// written (that is the whole point of the feature); plain entries get their
	// blank lines turned into paragraphs.
	fmt.Fprint(q.W, "<div class=\"entry_text\">\n")
	if s.entryIsHTML(q.Cfg, e) {
		fmt.Fprint(q.W, e.Text)
	} else {
		fmt.Fprint(q.W, TextToHTML(e.Text))
	}
	fmt.Fprint(q.W, "\n</div>\n")

	// Inline images: the original shows an <img> for image attachments below the
	// text ("Display inline attachments", default on).
	if s.Config.GetInt(q.Cfg, "Display inline attachments", 1) != 0 {
		for _, ref := range refs {
			if !IsImageName(ref.Name) {
				continue
			}
			u := s.AttachmentURL(q.Cfg.Group, e, ref)
			src := u
			if thumb, ok := s.thumbnailURL(q, e, ref); ok {
				src = thumb
			}
			fmt.Fprintf(q.W, "<p><a href=%q><img src=%q alt=%q border=\"0\"></a></p>\n",
				HTMLEscape(u), HTMLEscape(src), HTMLEscape(ref.Display))
		}
	}

	s.writeEntryButtons(q, e)
	s.endPage(q)
}

// entryIsHTML reports whether the text of an entry is HTML, either because the
// entry says so or because the whole logbook is in HTML mode.
func (s *Server) entryIsHTML(scope ConfigScope, e *Entry) bool {
	if strings.Contains(e.Encoding(), "HTML") {
		return true
	}
	return s.Config.GetBool(scope, "UseHTML")
}

// thumbnailURL is the ?thumb= URL of an image attachment, when thumbnails are
// enabled and the file is an image.
func (s *Server) thumbnailURL(q *Request, e *Entry, ref AttachmentRef) (string, bool) {
	if !s.UseThumbs || !IsImageName(ref.Name) {
		return "", false
	}
	return s.AttachmentURL(q.Cfg.Group, e, ref) + "?thumb=1", true
}

// authorHTML renders the author, linking a known e-mail like the original does.
func (s *Server) authorHTML(scope ConfigScope, author, email string) string {
	if email == "" || !s.Config.GetBoolDefault(scope, "Link mail", true) {
		return HTMLEscape(author)
	}
	return fmt.Sprintf("<a href=\"mailto:%s\">%s</a>", HTMLEscape(email), HTMLEscape(author))
}

// writeEntryButtons is the per-entry button row. The form posts message_id and
// cmd back to the same URL, which is what the dispatch expects.
func (s *Server) writeEntryButtons(q *Request, e *Entry) {
	fmt.Fprintf(q.W, "<form method=\"post\" action=\"%s\">\n", HTMLEscape(q.R.URL.Path))
	fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"message_id\" value=\"%d\">\n", e.ID())
	fmt.Fprint(q.W, "<div class=\"navbar\">")
	any := false
	for _, c := range []string{"Reply", "Edit", "Delete", "DisplayList", "Display as Thread"} {
		if !s.commandAllowed(q, c) || !s.userAllowed(q, c) {
			continue
		}
		if EqualFold(c, "Reply") && !s.CanEdit(q.Cfg, q.User) {
			continue
		}
		if EqualFold(c, "Edit") && !s.CanEdit(q.Cfg, q.User) {
			continue
		}
		any = true
		fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\"> ",
			HTMLEscape(s.loc(c)))
	}
	if q.User == "" && s.Pwd != nil {
		fmt.Fprintf(q.W, "&nbsp;<input type=\"text\" name=\"unm\" size=\"8\"> "+
			"<input type=\"password\" name=\"upwd\" size=\"8\"> "+
			"<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\">",
			HTMLEscape(s.loc("Login")))
		any = true
	}
	fmt.Fprint(q.W, "</div>\n</form>\n")
	_ = any
}

// ---------------------------------------------------------------------------
// Thread page
// ---------------------------------------------------------------------------

// showThreadPage is display_thread(): the logbook as a nested list following the
// "In reply to" links. The children of a message are listed in ascending order
// under their parent, the roots newest first, which is what the original
// produces (its threads are built from the "Thread" attribute plus
// "In reply to").
func (s *Server) showThreadPage(q *Request) {
	all := q.LB.Messages()
	index := map[int]*Entry{}
	for _, e := range all {
		index[e.ID()] = e
	}
	byParent := map[int][]*Entry{}
	var roots []*Entry
	for _, e := range all {
		p := e.InReplyTo()
		if p > 0 && index[p] != nil && p != e.ID() {
			byParent[p] = append(byParent[p], e)
			continue
		}
		roots = append(roots, e)
	}
	s.beginPage(q, s.logbookTitle(q.Cfg.Group), "")
	fmt.Fprint(q.W, "<div class=\"thread\">\n")
	seen := map[int]bool{}
	var walk func(e *Entry, depth int)
	walk = func(e *Entry, depth int) {
		if seen[e.ID()] || depth > 32 {
			return
		}
		seen[e.ID()] = true
		link := s.BasePath + "/" + q.Cfg.Group + "/?cmd=" + URLEncode(s.loc("Display")) +
			"&message_id=" + strconv.Itoa(e.ID())
		fmt.Fprintf(q.W, "%*s&#9642; <a href=\"%s\">#%d %s</a> <span class=\"footer\">%s</span><br>\n",
			depth*2, "", HTMLEscape(link), e.ID(),
			HTMLEscape(orText(e.Title(), "(no subject)")),
			HTMLEscape(FormatDate("%Y-%m-%d %H:%M", e.DateValue())))
		for _, kid := range byParent[e.ID()] {
			walk(kid, depth+1)
		}
	}
	for i := len(roots) - 1; i >= 0; i-- {
		walk(roots[i], 0)
	}
	// Entries whose parent was deleted still belong in the list; the loop above
	// skipped them because they are not roots.
	for _, e := range all {
		if !seen[e.ID()] {
			walk(e, 0)
		}
	}
	fmt.Fprint(q.W, "</div>\n")
	s.endPage(q)
}

// ---------------------------------------------------------------------------
// Edit / new page
// ---------------------------------------------------------------------------

// showEditPage is display_edit_page(). The form is multipart because it can carry
// attachments, and the field names are exactly the attribute names, which is the
// contract submit() relies on. id==0 posts a new entry; mode=="Reply" pre-fills
// the subject and the quote and records reply_to.
func (s *Server) showEditPage(q *Request, id int, mode string) {
	var e *Entry
	if id > 0 {
		got, err := q.LB.Message(id)
		if err != nil {
			s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", id)
			return
		}
		e = got
		if by := s.EditLockBy(q.LB, id); by != "" && !SamePerson(by, q.displayName()) &&
			!s.userIn(q.Cfg, "Admin", q.User) {
			s.errorf(q, http.StatusForbidden,
				"Entry #%d is currently locked for editing by <b>%s</b>", id, HTMLEscape(by))
			return
		}
		if q.User != "" || q.FullName != "" {
			s.SetEditLock(q.LB, e, q.displayName())
		}
	}
	if e == nil {
		e = &Entry{}
		e.SetHeader("Date", FormatRFC2822(time.Now()))
		switch {
		case q.FullName != "":
			e.SetHeader("Author", q.FullName)
		case q.User != "":
			e.SetHeader("Author", q.User)
		default:
			e.SetHeader("Author", s.Config.GetString(q.Cfg, "Anonymous nickname", "Anonymous"))
		}
		if q.Email != "" {
			e.SetHeader("Email", q.Email)
		}
	}

	var replyTo int
	if EqualFold(mode, "Reply") && id > 0 {
		if parent, err := q.LB.Message(id); err == nil {
			replyTo = parent.ID()
			e.SetHeader("Title", "Re: "+orText(parent.Title(), "(no subject)"))
			e.Del("Attachment")
			e.Text = quoteText(parent)
		}
	}

	s.beginPage(q, s.loc("Post message"), "")
	fmt.Fprintf(q.W, "<form enctype=\"multipart/form-data\" method=\"post\" action=\"%s\">\n",
		HTMLEscape(q.R.URL.Path))
	fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"cmd\" value=\"%s\">\n", HTMLEscape(s.loc("Submit")))
	fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"message_id\" value=\"%d\">\n", id)
	if replyTo > 0 {
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"reply_to\" value=\"%d\">\n", replyTo)
	}
	if s.Config.GetBool(q.Cfg, "UseHTML") {
		fmt.Fprint(q.W, "<input type=\"hidden\" name=\"Encoding\" value=\"HTML\">\n")
	}

	natts := s.Config.GetInt(q.Cfg, "N attachments", 1)
	if natts <= 0 {
		natts = 1
	}
	atts := s.Config.GetBoolDefault(q.Cfg, "Attachments", true)
	if atts {
		// MAX_FILE_SIZE is the hint a PHP-era browser used; elogd ignores it and
		// enforces "Max total size" itself, which this port does too. It is kept
		// because old entries' screenshots show it and it costs nothing.
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"%d\">\n",
			s.MaxUpload)
	}

	fmt.Fprint(q.W, "<table class=\"entry\" border=\"0\" cellpadding=\"2\" cellspacing=\"1\">\n")
	row := func(label string, body string) {
		fmt.Fprintf(q.W, "<tr><td class=\"entry_attrname\" valign=\"top\">%s</td>"+
			"<td class=\"entry_attr\">%s</td></tr>\n", HTMLEscape(s.loc(label)), body)
	}

	d := e.DateValue()
	if d.IsZero() {
		d = time.Now()
	}
	if s.Config.GetBool(q.Cfg, "Allow user to set date") || id > 0 {
		row("Date", s.dateWidget(d))
	}
	if s.Config.GetBoolDefault(q.Cfg, "Title", true) {
		row("Subject", fmt.Sprintf("<input type=\"text\" name=\"Title\" size=\"60\" maxlength=\"255\" value=\"%s\">",
			HTMLEscape(e.Title())))
	}
	if s.Config.GetBoolDefault(q.Cfg, "Author", true) {
		row("Author", fmt.Sprintf("<input type=\"text\" name=\"Author\" size=\"40\" value=\"%s\">",
			HTMLEscape(e.Author())))
	}

	for _, a := range s.Config.AttributeNames(q.Cfg) {
		if EqualFold(a, "Title") || EqualFold(a, "Subject") ||
			EqualFold(a, "Author") || EqualFold(a, "Date") {
			continue
		}
		row(a, s.attributeField(q, a, e.Get2(a)))
	}

	rows := s.Config.GetInt(q.Cfg, "Text rows", 15)
	cols := s.Config.GetInt(q.Cfg, "Text columns", 80)
	row("Text", fmt.Sprintf("<textarea name=\"Text\" rows=\"%d\" cols=\"%d\">%s</textarea>",
		rows, cols, html.EscapeString(e.Text)))

	if atts {
		refs := q.LB.AttachmentRefs(e)
		for i := 0; i < natts; i++ {
			body := fmt.Sprintf("<input type=\"file\" name=\"attachment%d\" size=\"40\">", i)
			if i == 0 && len(refs) > 0 {
				body += "<br>" + s.AttachmentDisplayHTML(q.Cfg.Group, e, true)
			}
			row("Attachment", body)
		}
	}
	fmt.Fprint(q.W, "</table>\n")

	fmt.Fprint(q.W, "<div class=\"navbar\">")
	for _, c := range []string{"Submit", "Preview", "DisplayList"} {
		fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\"> ",
			HTMLEscape(s.loc(c)))
	}
	if s.Config.GetString(q.Cfg, "User password", "") != "" {
		fmt.Fprintf(q.W, "&nbsp;%s <input type=\"password\" name=\"wpwd\" size=\"10\">",
			HTMLEscape(s.loc("User password")))
	}
	fmt.Fprint(q.W, "</div>\n</form>\n")
	s.endPage(q)
}

// attributeField renders one attribute of the edit form: a select for an
// attribute with options, a multi-line box for a "large" attribute, a plain text
// field otherwise. The names and the option values are what submit() reads back.
func (s *Server) attributeField(q *Request, attr, val string) string {
	var b strings.Builder
	opts := s.Config.OptionsFor(q.Cfg, attr)
	switch {
	case len(opts) > 1 && s.Config.GetBool(q.Cfg, "Multi-select "+attr):
		fmt.Fprintf(&b, "<select name=\"%s\" multiple size=\"%d\">\n", HTMLEscape(attr), clamp(len(opts), 2, 8))
		for _, o := range opts {
			sel := ""
			for _, v := range SplitList(val, ",", false) {
				if EqualFold(TrimSpaceASCII(v), TrimSpaceASCII(o)) {
					sel = " selected"
				}
			}
			fmt.Fprintf(&b, "<option value=\"%s\"%s>%s</option>\n", HTMLEscape(o), sel, HTMLEscape(o))
		}
		fmt.Fprint(&b, "</select>")
	case len(opts) > 0:
		fmt.Fprintf(&b, "<select name=\"%s\">\n", HTMLEscape(attr))
		fmt.Fprint(&b, "<option value=\"\"></option>\n")
		for _, o := range opts {
			sel := ""
			if EqualFold(TrimSpaceASCII(o), TrimSpaceASCII(val)) {
				sel = " selected"
			}
			fmt.Fprintf(&b, "<option value=\"%s\"%s>%s</option>\n", HTMLEscape(o), sel, HTMLEscape(o))
		}
		fmt.Fprint(&b, "</select>")
	case s.Config.GetBool(q.Cfg, "Large text "+attr):
		fmt.Fprintf(&b, "<textarea name=\"%s\" rows=\"5\" cols=\"60\">%s</textarea>",
			HTMLEscape(attr), html.EscapeString(val))
	default:
		size := 40
		if w := s.Config.GetInt(q.Cfg, "Width "+attr); w > 0 {
			size = clamp(w, 5, 200)
		}
		fmt.Fprintf(&b, "<input type=\"text\" name=\"%s\" size=\"%d\" value=\"%s\">",
			HTMLEscape(attr), size, HTMLEscape(val))
	}
	return b.String()
}

// dateWidget is the y/m/d h:m selector the original posts as y0,m0,d0,h0,n0.
func (s *Server) dateWidget(d time.Time) string {
	var b strings.Builder
	sel := func(name string, v, lo, hi int, label func(int) string) {
		fmt.Fprintf(&b, "<select name=\"%s\">", name)
		for i := lo; i <= hi; i++ {
			selAttr := ""
			if i == v {
				selAttr = " selected"
			}
			text := strconv.Itoa(i)
			if label != nil {
				text = label(i)
			}
			fmt.Fprintf(&b, "<option value=\"%d\"%s>%s</option>", i, selAttr, text)
		}
		fmt.Fprint(&b, "</select>")
	}
	sel("y0", d.Year(), d.Year()-5, d.Year()+1, nil)
	fmt.Fprint(&b, " ")
	sel("m0", int(d.Month()), 1, 12, func(i int) string { return monthNames[i-1] })
	fmt.Fprint(&b, " ")
	sel("d0", d.Day(), 1, 31, nil)
	fmt.Fprint(&b, " ")
	sel("h0", d.Hour(), 0, 23, nil)
	fmt.Fprint(&b, ":")
	sel("n0", d.Minute(), 0, 59, func(i int) string { return fmt.Sprintf("%02d", i) })
	return b.String()
}

// quoteText is the "> " quote of a replied-to entry.
func quoteText(parent *Entry) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.ReplaceAll(parent.Text, "\r\n", "\n"), "\n") {
		b.WriteString("> ")
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

// showPreviewPage re-renders the posted entry without storing it, which is what
// the "Preview" button does.
func (s *Server) showPreviewPage(q *Request) {
	e := &Entry{}
	e.SetHeader("Date", FormatRFC2822(s.formDate(q, nil)))
	for _, a := range append([]string{"Title", "Author"}, s.Config.AttributeNames(q.Cfg)...) {
		if v := q.Param(a); v != "" {
			e.SetHeader(a, v)
		}
	}
	if e.Title() == "" {
		e.SetHeader("Title", q.Param("Subject"))
	}
	e.Text = q.Param("Text")

	s.beginPage(q, s.loc("Preview"), "")
	fmt.Fprintf(q.W, "<p><b>%s</b></p>\n", HTMLEscape(s.loc("Preview")))
	fmt.Fprint(q.W, "<table class=\"entry\" border=\"0\" cellpadding=\"2\" cellspacing=\"1\" width=\"100%\">\n")
	fmt.Fprintf(q.W, "<tr class=\"subject\"><td class=\"entry_attrname\">%s</td>"+
		"<td class=\"entry_subject\">%s</td></tr>\n",
		HTMLEscape(s.loc("Subject")), HTMLEscape(orText(e.Title(), "(no subject)")))
	fmt.Fprintf(q.W, "<tr class=\"attributes\"><td class=\"entry_attrname\">%s</td>"+
		"<td class=\"entry_attr\">%s</td></tr>\n",
		HTMLEscape(s.loc("Date")), HTMLEscape(e.Get2("Date")))
	for _, a := range s.Config.AttributeNames(q.Cfg) {
		if v := e.Get2(a); v != "" {
			fmt.Fprintf(q.W, "<tr class=\"attributes\"><td class=\"entry_attrname\">%s</td>"+
				"<td class=\"entry_attr\">%s</td></tr>\n",
				HTMLEscape(s.loc(a)), HTMLEscape(v))
		}
	}
	fmt.Fprintf(q.W, "</table>\n<div class=\"entry_text\">\n")
	if s.entryIsHTML(q.Cfg, e) {
		fmt.Fprint(q.W, e.Text)
	} else {
		fmt.Fprint(q.W, TextToHTML(e.Text))
	}
	fmt.Fprint(q.W, "</div>\n")
	s.endPage(q)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// confirmDeletePage is the "Delete really?" page of the original.
func (s *Server) confirmDeletePage(q *Request) {
	id := q.msgID
	if id == 0 {
		id = q.IntParam("message_id")
	}
	e, err := q.LB.Message(id)
	if err != nil {
		s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", id)
		return
	}
	s.beginPage(q, s.loc("Delete"), "")
	fmt.Fprintf(q.W, "<p>%s <b>#%d %s</b>?</p>\n<form method=\"post\" action=\"%s\">\n",
		HTMLEscape(s.loc("Do you really want to delete")), e.ID(),
		HTMLEscape(orText(e.Title(), "")), HTMLEscape(q.R.URL.Path))
	fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"message_id\" value=\"%d\">\n", id)
	fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\"> ",
		HTMLEscape(s.loc("Confirm Delete")))
	fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\">\n",
		HTMLEscape(s.loc("DisplayList")))
	fmt.Fprint(q.W, "</form>\n")
	s.endPage(q)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

// showLoginPage is the login form. It posts back to the same URL with the
// "redir" parameter so the user lands where he was going.
func (s *Server) showLoginPage(q *Request, redir string, failed bool) {
	s.beginPage(q, s.loc("Login"), "")
	if failed {
		fmt.Fprintf(q.W, "<p><b>%s</b></p>\n", HTMLEscape(s.loc("Login failed")))
	}
	fmt.Fprintf(q.W, "<form method=\"post\" action=\"%s\">\n", HTMLEscape(q.R.URL.Path))
	fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"cmd\" value=\"%s\">\n", HTMLEscape(s.loc("Login")))
	if redir != "" {
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"redir\" value=\"%s\">\n", HTMLEscape(redir))
	}
	fmt.Fprint(q.W, "<table border=\"0\" cellpadding=\"2\">\n")
	fmt.Fprintf(q.W, "<tr><td>%s</td><td><input type=\"text\" name=\"unm\" size=\"20\"></td></tr>\n",
		HTMLEscape(s.loc("User name")))
	fmt.Fprintf(q.W, "<tr><td>%s</td><td><input type=\"password\" name=\"upwd\" size=\"20\"></td></tr>\n",
		HTMLEscape(s.loc("Password")))
	fmt.Fprint(q.W, "</table>\n")
	fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" value=\"%s\">\n", HTMLEscape(s.loc("Login")))
	if s.Config.GetBool(ConfigScope{Group: "global"}, "Enable signup") {
		fmt.Fprintf(q.W, "<p><a href=\"?cmd=Signup\">%s</a></p>\n", HTMLEscape(s.loc("Signup")))
	}
	fmt.Fprint(q.W, "</form>\n")
	s.endPage(q)
}
