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
// Page furniture
// ---------------------------------------------------------------------------
//
// The C code writes HTML with hundreds of fprintf() calls inside
// display_message(), display_list(), display_single_page() and
// display_edit_page(). The exact markup is part of the protocol only in a few
// places, which are the ones reproduced here:
//
//   - the URLs and form field names (a browser sends back what the page put in,
//     and users have bookmarked the links);
//   - the "cmd" values and their (translated) captions;
//   - the attribute order and the attachment/thumbnail markup, which
//     site-specific CSS files key on;
//   - the class names ("<table class=\"title\">", ".entry_subject",
//     ".entry_attrname", ".entry_attr", ".entry_text", ".navbar"), because the
//     deployed style sheets (the FZU site uses its own elogd.css) restyle those.
//
// Everything else (whitespace, attribute quoting) is free.

// theme holds the configuration keys that change the emitted markup.
type theme struct {
	Title         string
	TitleURL      string
	Logo          string
	LogoWidth     int
	Bgcolor       string
	Textcolor     string
	TableColor    string
	Font          string
	StyleSheet    string
	ExtStyleSheet bool
	PreDisplay    string
	PostDisplay   string
}

func (s *Server) themeFor(scope ConfigScope) theme {
	t := theme{
		Title:         s.Config.GetString(scope, "Title", "ELOG"),
		TitleURL:      s.Config.GetString(scope, "Title URL", ""),
		Logo:          s.Config.GetString(scope, "Logo", ""),
		Bgcolor:       s.Config.GetString(scope, "Bgcolor", ""),
		Textcolor:     s.Config.GetString(scope, "Textcolor", ""),
		TableColor:    s.Config.GetString(scope, "Table color", ""),
		Font:          s.Config.GetString(scope, "Font", "Arial,Helvetica,sans-serif"),
		StyleSheet:    s.Config.GetString(scope, "Stylesheet", ""),
		ExtStyleSheet: s.Config.GetBool(scope, "External stylesheet"),
	}
	if v, ok := s.Config.Get(scope, "Logo Width"); ok {
		t.LogoWidth = Atoi(v)
	}
	// "Pre display" and "Post display" are raw HTML injected around every page
	// (the site banner and the CESNET/FZU footer of the production setup are
	// done with these keys), so they are passed through verbatim like the C code
	// does - which also means they are a trusted-configuration feature, not a
	// user input.
	if raw, ok := s.Config.Get(scope, "Pre display"); ok {
		t.PreDisplay = raw
	}
	if raw, ok := s.Config.Get(scope, "Post display"); ok {
		t.PostDisplay = raw
	}
	return t
}

// beginPage writes <!DOCTYPE> through the opening of <body> plus the title
// banner and the command bar; endPage closes the page. Between them the callers
// emit plain HTML, exactly like the C code writes between its display_start()
// and display_end() calls.
//
// The response headers matter as much as the markup: the Content-Type is set
// exactly once per response (the missing and duplicated Content-Type headers
// were one of the bugs the local patches fixed), the charset is always utf-8
// because the entries are UTF-8 throughout this port, and pages are not
// cacheable because a stale list page would hide a new entry from the next
// reader.
func (s *Server) beginPage(q *Request, title, msgID string) {
	th := s.themeFor(q.Cfg)
	w := q.W
	if !headerSet(w, "Content-Type") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Server", "ELOG/"+Version)

	fmt.Fprint(w, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n")
	fmt.Fprint(w, "<html>\n<head>\n"+
		"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n")
	fmt.Fprintf(w, "<meta name=\"generator\" content=\"elog %s (Go rewrite of elogd %s)\">\n",
		Version, EmulatedVersion)
	fmt.Fprintf(w, "<title>%s</title>\n", HTMLEscape(title))
	if href := s.styleSheetHref(q.Cfg); href != "" {
		fmt.Fprintf(w, "<link rel=\"stylesheet\" type=\"text/css\" href=\"%s\">\n", HTMLEscape(href))
	} else {
		fmt.Fprint(w, "<style type=\"text/css\">\n"+defaultCSS+"</style>\n")
	}
	if _, ok := s.findResource("favicon.ico"); ok {
		fmt.Fprintf(w, "<link rel=\"shortcut icon\" href=\"%s/favicon.ico\" type=\"image/x-icon\">\n",
			HTMLEscape(s.BasePath))
	}
	fmt.Fprint(w, "</head>\n")
	body := ""
	if th.Textcolor != "" {
		body += " text=\"" + html.EscapeString(th.Textcolor) + "\""
	}
	if th.Bgcolor != "" {
		body += " bgcolor=\"" + html.EscapeString(th.Bgcolor) + "\""
	}
	fmt.Fprintf(w, "<body%s>\n", body)
	if th.Font != "" {
		fmt.Fprintf(w, "<font face=\"%s\" size=\"2\">\n", HTMLEscape(th.Font))
	}
	if th.PreDisplay != "" {
		fmt.Fprint(w, th.PreDisplay+"\n")
	}
	s.writeTitleBanner(q, th)
	if msgID == "" {
		s.writeMenu(q)
	}
}

// endPage closes what beginPage opened.
func (s *Server) endPage(q *Request) {
	th := s.themeFor(q.Cfg)
	if th.PostDisplay != "" {
		fmt.Fprint(q.W, th.PostDisplay+"\n")
	}
	s.writeFooter(q)
}

// headerSet reports whether a header key was already set, so a caller that
// already decided on a Content-Type (the raw/XML/JSON/CSV paths) is not
// overridden and the header is never emitted twice.
func headerSet(w http.ResponseWriter, key string) bool {
	return len(w.Header()[key]) > 0
}

// styleSheetHref is the URL of the style sheet: the "Stylesheet" value verbatim
// when set, otherwise the site's styles.css when the logbook asks for an
// external sheet, otherwise "" which means the built-in CSS above.
func (s *Server) styleSheetHref(scope ConfigScope) string {
	if v := s.Config.GetString(scope, "Stylesheet", ""); v != "" {
		return v
	}
	if s.Config.GetBool(scope, "External stylesheet") {
		return s.BasePath + "/styles.css"
	}
	return ""
}

func (s *Server) writeTitleBanner(q *Request, th theme) {
	fmt.Fprint(q.W, "<table class=\"title\" width=\"100%\" border=\"0\" cellpadding=\"2\" cellspacing=\"0\">\n<tr>")
	if th.Logo != "" {
		w := ""
		if th.LogoWidth > 0 {
			w = fmt.Sprintf(" width=\"%d\"", th.LogoWidth)
		}
		fmt.Fprintf(q.W, "<td rowspan=\"2\" valign=\"top\"><img src=\"%s\"%s border=\"0\" alt=\"\"></td>",
			HTMLEscape(th.Logo), w)
	}
	fmt.Fprint(q.W, "<td valign=\"top\"><span class=\"apptitle\">")
	if th.TitleURL != "" {
		fmt.Fprintf(q.W, "<a href=\"%s\">%s</a>", HTMLEscape(th.TitleURL), HTMLEscape(th.Title))
	} else {
		fmt.Fprint(q.W, HTMLEscape(th.Title))
	}
	fmt.Fprint(q.W, "</span></td>\n")
	fmt.Fprintf(q.W, "<td align=\"right\" valign=\"top\">%s</td>\n", HTMLEscape(s.nowString(q.Cfg)))
	fmt.Fprintf(q.W, "</tr>\n<tr><td valign=\"top\">%s</td>", HTMLEscape(s.logbookTitle(q.Cfg.Group)))
	fmt.Fprintf(q.W, "<td align=\"right\" valign=\"top\" class=\"footer\">%s</td></tr>\n", s.userLine(q))
	fmt.Fprint(q.W, "</table>\n")
}

// nowString is the clock shown in the banner, formatted with the logbook's
// "Date format"/"Time format". The C code composed the two strftime() pictures
// into a fixed buffer - one of the local patches was about that overflow; with
// Go strings there is no buffer to overflow.
func (s *Server) nowString(scope ConfigScope) string {
	df := s.Config.GetString(scope, "Date format", "%a %b %d %Y")
	tf := s.Config.GetString(scope, "Time format", "%H:%M")
	return FormatDate(df+" "+tf, time.Now())
}

// logbookTitle is the second line of the banner: the Title of the logbook (or
// of the whole server on the selection page).
func (s *Server) logbookTitle(group string) string {
	if group == "" {
		return s.Config.GetString(ConfigScope{Group: "global"}, "Title", "Logbooks")
	}
	return s.Config.GetString(ConfigScope{Group: group, TopGroup: group}, "Title", group)
}

func (s *Server) userLine(q *Request) string {
	if q.User != "" || q.FullName != "" {
		name := q.displayName()
		if q.User != "" && q.FullName != "" {
			name = fmt.Sprintf("%s (%s)", q.FullName, q.User)
		}
		return HTMLEscape(name)
	}
	return HTMLEscape(s.Config.GetString(q.Cfg, "Anonymous nickname", "Anonymous"))
}

// writeMenu renders the command bar. The buttons are submit buttons of one form
// whose name is "cmd" and whose value is the (possibly translated) command name,
// which is why the dispatch accepts the translated spellings too.
func (s *Server) writeMenu(q *Request) {
	allowed := s.Config.GetList(q.Cfg, "Allowed commands")
	if len(allowed) == 0 {
		allowed = DefaultAllowedCommands
	}
	fmt.Fprintf(q.W, "<form name=\"theForm\" method=\"post\" action=\"%s\">\n",
		HTMLEscape(q.R.URL.Path))
	if q.msgID > 0 {
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"message_id\" value=\"%d\">\n", q.msgID)
	}
	fmt.Fprint(q.W, "<div class=\"navbar\">")
	for _, c := range allowed {
		if !s.userAllowed(q, c) || !s.commandAllowed(q, c) {
			continue
		}
		fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\"> ",
			HTMLEscape(s.loc(c)))
	}
	// The search box belongs to the "Find" command and posts along with it.
	if s.commandAllowed(q, "Find") {
		fmt.Fprintf(q.W, "<input type=\"text\" name=\"subtext\" size=\"20\" value=\"%s\"> ",
			HTMLEscape(q.Param("subtext")))
	}
	if q.User == "" && s.Pwd != nil {
		fmt.Fprintf(q.W, "&nbsp;<input type=\"text\" name=\"unm\" size=\"8\" placeholder=\"%s\"> "+
			"<input type=\"password\" name=\"upwd\" size=\"8\" placeholder=\"%s\"> "+
			"<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\">",
			HTMLEscape(s.loc("User name")), HTMLEscape(s.loc("Password")), HTMLEscape(s.loc("Login")))
	} else {
		fmt.Fprintf(q.W, "&nbsp;<input class=\"navbar\" type=\"submit\" name=\"cmd\" value=\"%s\">",
			HTMLEscape(s.loc("Logout")))
	}
	fmt.Fprint(q.W, "</div>\n</form>\n")
}

func (s *Server) writeFooter(q *Request) {
	if v := s.Config.GetString(q.Cfg, "Footer", ""); v != "" {
		fmt.Fprintf(q.W, "<p class=\"footer\">%s</p>\n", v)
	}
	if v := s.Config.GetString(ConfigScope{Group: "global"}, "Comment", ""); v != "" {
		fmt.Fprintf(q.W, "<p class=\"footer\"><small>%s</small></p>\n", HTMLEscape(v))
	}
	fmt.Fprint(q.W, "</font>\n</body>\n</html>\n")
}

// errorf renders the error page. The original wraps the message in the same page
// chrome as everything else, so callers pass HTML in the message (it contains
// the <b> tags the C code emits).
func (s *Server) errorf(q *Request, code int, format string, args ...any) {
	if q == nil || q.W == nil {
		return
	}
	if code >= 400 && !wroteHeader(q.W) {
		q.W.Header().Set("Content-Type", "text/html; charset=utf-8")
		q.W.WriteHeader(code)
	}
	msg := fmt.Sprintf(format, args...)
	if q.User == "" && code == http.StatusForbidden && s.Pwd != nil && q.R != nil {
		// The original answers with the login page instead of a bare 403 when
		// the action needs an identity that is not there yet.
		s.showLoginPage(q, q.R.URL.RequestURI(), false)
		return
	}
	s.beginPage(q, "ELOG Error", "")
	fmt.Fprintf(q.W, "<h3>Error</h3>\n<p>%s</p>\n", msg)
	fmt.Fprintf(q.W, "<p><a href=\"%s\">%s</a></p>\n",
		HTMLEscape(s.BasePath+"/"+q.Cfg.Group+"/"), HTMLEscape(s.loc("DisplayList")))
	s.endPage(q)
}

// wroteHeader guards against a second WriteHeader (which would only log noise).
func wroteHeader(w http.ResponseWriter) bool {
	_, ok := w.(interface{ Written() bool })
	return ok
}

// redirect sends the 302 the original sends after a submit ("Location: <entry
// URL>"). The response has no body.
func (s *Server) redirect(q *Request, location string) {
	if location == "" {
		location = s.BasePath + "/" + q.Cfg.Group + "/"
	}
	q.W.Header().Set("Location", location)
	q.W.Header().Set("Cache-Control", "no-cache, must-revalidate")
	q.W.WriteHeader(http.StatusFound)
}

// showFormError re-displays an error above a link back into the form, which is
// what the original does so the user does not lose the text he typed (the
// browser keeps the POST data on Back, so the entry is not lost).
func (s *Server) showFormError(q *Request, msg string, id int) {
	s.beginPage(q, "Error", "")
	fmt.Fprintf(q.W, "<h3>%s</h3>\n<p>%s</p>\n", HTMLEscape(s.loc("Error")), msg)
	back := s.BasePath + "/" + q.Cfg.Group + "/"
	if id > 0 {
		back = s.BasePath + "/" + q.Cfg.Group + "/?cmd=" + URLEncode(s.loc("Edit")) +
			"&message_id=" + strconv.Itoa(id)
	}
	fmt.Fprintf(q.W, "<p><a href=\"%s\">%s</a></p>\n", HTMLEscape(back), HTMLEscape(s.loc("Back")))
	s.endPage(q)
}

// ---------------------------------------------------------------------------
// Selection page (no logbook in the URL)
// ---------------------------------------------------------------------------

// showSelectionPage lists the logbooks the visitor may read, with their
// descriptions - the "?cmd=" free page at the root of the server.
func (s *Server) showSelectionPage(q *Request) {
	scope := ConfigScope{Group: "global"}
	s.beginPage(q, s.Config.GetString(scope, "Title", "Logbooks"), "")
	fmt.Fprint(q.W, "<table class=\"list\" border=\"0\" cellpadding=\"4\" cellspacing=\"1\" width=\"100%\">\n")
	for _, name := range s.LogbookNames(q.User, false) {
		lb := s.LB(name)
		if lb == nil || !s.IsLogbookAllowed(name, q.User) {
			continue
		}
		ls := ConfigScope{Group: name, TopGroup: name}
		desc := s.Config.GetString(ls, "Description", "")
		title := s.logbookTitle(name)
		link := s.BasePath + "/" + name + "/"
		fmt.Fprint(q.W, "<tr>")
		if img := s.Config.GetString(ls, "Description image", ""); img != "" {
			fmt.Fprintf(q.W, "<td valign=\"top\"><a href=\"%s\"><img src=\"%s\" border=\"0\" alt=\"%s\"></a></td>",
				HTMLEscape(link), HTMLEscape(img), HTMLEscape(title))
		} else {
			fmt.Fprintf(q.W, "<td valign=\"top\"><a href=\"%s\">%s</a></td>",
				HTMLEscape(link), HTMLEscape(title))
		}
		fmt.Fprintf(q.W, "<td valign=\"top\">%s</td>", HTMLEscape(desc))
		fmt.Fprintf(q.W, "<td align=\"right\" valign=\"top\">%d</td></tr>\n", lb.Len())
	}
	fmt.Fprint(q.W, "</table>\n")
	s.endPage(q)
}

// ---------------------------------------------------------------------------
// List page
// ---------------------------------------------------------------------------

// showListPage renders the list of entries (cmd=DisplayList and the default
// view). The columns come from the attribute list, the first column links to the
// entry, and replies are marked the way the original marks them.
func (s *Server) showListPage(q *Request) {
	ids := q.searchIDs
	if ids == nil {
		all := q.LB.Messages()
		ids = make([]string, 0, len(all))
		for i := len(all) - 1; i >= 0; i-- {
			ids = append(ids, strconv.Itoa(all[i].ID()))
		}
	}
	s.renderList(q, ids, q.listTitle)
}

func (s *Server) renderList(q *Request, ids []string, heading string) {
	lb := q.LB
	per := s.Config.GetInt(q.Cfg, "Display", 50)
	if per <= 0 {
		per = 50
	}
	page := q.IntParam("page")
	if page < 1 {
		page = 1
	}
	start := (page - 1) * per
	if start > len(ids) {
		start = len(ids)
	}
	end := start + per
	if end > len(ids) {
		end = len(ids)
	}
	shown := ids[start:end]

	cols := s.Config.DisplayedAttrs(q.Cfg, s.Config.AttributeNames(q.Cfg))

	s.beginPage(q, s.logbookTitle(q.Cfg.Group), "")
	if heading != "" {
		fmt.Fprintf(q.W, "<p>%s</p>\n", HTMLEscape(heading))
	}
	fmt.Fprint(q.W, "<table class=\"list\" border=\"0\" cellpadding=\"2\" cellspacing=\"1\" width=\"100%\">\n"+
		"<tr class=\"header\">")
	for _, c := range cols {
		fmt.Fprintf(q.W, "<th align=\"left\">%s</th>", HTMLEscape(s.loc(c)))
	}
	if len(cols) == 0 {
		fmt.Fprint(q.W, "<th align=\"left\">"+HTMLEscape(s.loc("Title"))+"</th>")
	}
	fmt.Fprintf(q.W, "<th align=\"left\">%s</th></tr>\n", HTMLEscape(s.loc("Date")))

	df := s.Config.GetString(q.Cfg, "Date format", "%a %b %d %Y")
	tf := s.Config.GetString(q.Cfg, "Time format", "%H:%M")
	for _, sid := range shown {
		e, err := lb.Message(Atoi(sid))
		if err != nil {
			continue
		}
		link := s.BasePath + "/" + q.Cfg.Group + "/?cmd=" + URLEncode(s.loc("Display")) +
			"&message_id=" + strconv.Itoa(e.ID())
		d := e.DateValue()
		indent := ""
		if e.InReplyTo() > 0 {
			indent = "&nbsp;&nbsp;&nbsp;&#8627; "
		}
		fmt.Fprintf(q.W, "<tr class=\"row%d\">", page&1)
		if len(cols) == 0 {
			fmt.Fprintf(q.W, "<td><a href=\"%s\">%s%s</a></td>", HTMLEscape(link), indent,
				HTMLEscape(orText(e.Title(), "(no subject)")))
		}
		for _, c := range cols {
			v := e.Get2(c)
			switch {
			case EqualFold(c, "Title"), EqualFold(c, "Subject"):
				fmt.Fprintf(q.W, "<td><a href=\"%s\">%s%s</a></td>", HTMLEscape(link), indent,
					HTMLEscape(orText(v, "(no subject)")))
			case len(v) > 60:
				// Truncation for the list view. The C version copied into a
				// fixed buffer; ShortenUTF8 guarantees the cut cannot split a
				// UTF-8 character, which is the truncation bug the local
				// patches fixed in the RSS and list code.
				fmt.Fprintf(q.W, "<td>%s</td>", HTMLEscape(ShortenUTF8(v, 60)+"..."))
			default:
				fmt.Fprintf(q.W, "<td>%s</td>", HTMLEscape(v))
			}
		}
		fmt.Fprintf(q.W, "<td>%s</td></tr>\n", HTMLEscape(FormatDate(df+" "+tf, d)))
	}
	fmt.Fprint(q.W, "</table>\n")
	s.writePager(q, len(ids), page, per)
	s.endPage(q)
}

// writePager is the "First Previous 1 2 3 Next Last" line.
func (s *Server) writePager(q *Request, total, page, per int) {
	pages := (total + per - 1) / per
	if pages <= 1 {
		return
	}
	fmt.Fprint(q.W, "<div class=\"navbar\">")
	link := func(p int, label string) {
		u := fmt.Sprintf("%s?cmd=%s&page=%d", q.R.URL.Path, URLEncode(s.loc("DisplayList")), p)
		if q.HasParam("subtext") {
			u += "&subtext=" + URLEncode(q.Param("subtext"))
		}
		fmt.Fprintf(q.W, "<a href=\"%s\">%s</a>&nbsp;", HTMLEscape(u), HTMLEscape(s.loc(label)))
	}
	if page > 1 {
		link(1, "First")
		link(page-1, "Previous")
	}
	lo, hi := page-3, page+3
	if lo < 1 {
		lo = 1
	}
	if hi > pages {
		hi = pages
	}
	for p := lo; p <= hi; p++ {
		if p == page {
			fmt.Fprintf(q.W, "<b>%d</b>&nbsp;", p)
			continue
		}
		link(p, strconv.Itoa(p))
	}
	if page < pages {
		link(page+1, "Next")
		link(pages, "Last")
	}
	fmt.Fprint(q.W, "</div>\n")
}

// ---------------------------------------------------------------------------
// Text conversion
// ---------------------------------------------------------------------------

// TextToHTML converts a plain-text entry to HTML the way elogd does: empty lines
// separate paragraphs, single newlines become <br>.
func TextToHTML(t string) string {
	t = strings.ReplaceAll(t, "\r\n", "\n")
	paras := strings.Split(t, "\n\n")
	for i := range paras {
		paras[i] = strings.ReplaceAll(html.EscapeString(paras[i]), "\n", "<br>\n")
	}
	return "<p>" + strings.Join(paras, "</p>\n<p>") + "</p>"
}

// SanitizeHTML strips the constructs that would let a poster take over the page.
// elogd does not filter at all (it trusts its authors), so this is a hardening
// step that a deployment can turn on; by default nothing is filtered, because
// entries written by the original daemon may contain markup on purpose.
func SanitizeHTML(s string) string {
	out := s
	for _, tag := range []string{"<script", "<iframe", "<object", "<embed", "javascript:", "onclick=", "onload="} {
		out = replaceFold(out, tag, "&lt;"+tag[1:])
	}
	return out
}

func replaceFold(s, old, new string) string {
	if old == "" {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && EqualFold(s[i:i+len(old)], old) {
			b.WriteString(new)
			i += len(old)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// defaultCSS is used when the logbook does not ship an external style sheet. It
// carries the class names the shipped style sheets also use, so dropping the
// site's elogd.css next to the data directory is all it takes to get the
// production look back.
const defaultCSS = `
body { background: #ffffff; }
table.title { background: #e8eef4; }
span.apptitle { font-size: 140%; font-weight: bold; }
div.navbar { margin-top: 6px; margin-bottom: 6px; }
input.navbar { font-size: 90%; }
table.list th, tr.header th { background: #d0d8e0; text-align: left; }
td.entry_attrname { background: #e8eef4; font-weight: bold; vertical-align: top; }
td.entry_attr { background: #f4f6f8; vertical-align: top; }
td.entry_subject { background: #d0d8e0; font-weight: bold; font-size: 110%; }
div.entry_text { margin-top: 8px; }
p.footer, td.footer { font-size: 80%; color: #555; }
`
