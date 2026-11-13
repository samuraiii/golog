package elog

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// The handlers that are not list/display/edit pages
// ---------------------------------------------------------------------------
//
// These are the remaining "?cmd=..." commands of elogd. They are grouped here
// because none of them is big enough to deserve its own file and none of them
// shares state with the page renderer beyond the helpers of pages.go. The URL
// scheme, the permission checks and the command dispatch are in request.go.

// ---------------------------------------------------------------------------
// Status / summary / calendar
// ---------------------------------------------------------------------------

// showStatusPage is "?cmd=Status": what elogd prints for the daemon itself.
func (s *Server) showStatusPage(q *Request) {
	s.beginPage(q, s.loc("Status"), "")
	fmt.Fprintf(q.W, "<table border=\"0\" cellpadding=\"2\" cellspacing=\"1\">\n")
	row := func(k, v string) {
		fmt.Fprintf(q.W, "<tr><td class=\"entry_attrname\">%s</td><td class=\"entry_attr\">%s</td></tr>\n",
			HTMLEscape(k), HTMLEscape(v))
	}
	row("Version", Version+" (emulating elogd "+EmulatedVersion+")")
	row("Uptime", time.Since(s.StartTime).Round(time.Second).String())
	row("Config file", s.ConfigPath)
	if d := s.Config.ConfigDir(); d != "" {
		row("Config directory", d)
	}
	row("Data directory", s.DataDir)
	row("Resource directory", s.ResourceDir)
	row("Listening on", joinHostPort(s.Addr, s.Port))
	if s.BasePath != "" {
		row("BasePath", s.BasePath)
	}
	row("Sessions", strconv.Itoa(s.Sessions.Count()))
	row("User name", orText(q.displayName(), "(not logged in)"))
	for _, name := range s.LogbookNames(q.User, false) {
		lb := s.LB(name)
		if lb == nil {
			row(name, s.loc("cannot be opened"))
			continue
		}
		last := "-"
		if ms := lb.Messages(); len(ms) > 0 {
			last = FormatDate("%Y-%m-%d %H:%M", ms[len(ms)-1].DateValue())
		}
		row(name, fmt.Sprintf("%d entries, last %s, %s", lb.Len(), last, lb.Dir))
	}
	fmt.Fprint(q.W, "</table>\n")
	if v := q.Param("debug"); v == "1" {
		fmt.Fprintf(q.W, "<h4>%s</h4><pre>%s</pre>\n", HTMLEscape("request parameters"),
			HTMLEscape(q.dumpParams()))
	}
	s.endPage(q)
}

// showSummaryPage is "?cmd=Summary": entries per logbook and category.
func (s *Server) showSummaryPage(q *Request) {
	catAttr := s.Config.GetString(q.Cfg, "Category", "Category")
	s.beginPage(q, s.loc("Summary"), "")
	names := s.LogbookNames(q.User, true)
	if q.LB != nil {
		names = []string{q.Cfg.Group}
	}
	fmt.Fprintf(q.W, "<table border=\"0\" cellpadding=\"3\" cellspacing=\"1\">\n")
	fmt.Fprintf(q.W, "<tr class=\"header\"><th align=\"left\">%s</th><th align=\"left\">%s</th>"+
		"<th align=\"right\">%s</th></tr>\n",
		HTMLEscape(s.loc("Logbook")), HTMLEscape(s.loc("Category")),
		HTMLEscape(s.loc("Number of messages")))
	for _, name := range names {
		lb := s.LB(name)
		if lb == nil {
			continue
		}
		counts := map[string]int{}
		var order []string
		for _, e := range lb.Messages() {
			k := TrimSpaceASCII(e.Get2(catAttr))
			if k == "" {
				k = "(none)"
			}
			if _, ok := counts[k]; !ok {
				order = append(order, k)
			}
			counts[k]++
		}
		sort.Strings(order)
		total := 0
		for i, k := range order {
			total += counts[k]
			label := ""
			if i == 0 {
				label = name
			}
			fmt.Fprintf(q.W, "<tr><td>%s</td><td>%s</td><td align=\"right\">%d</td></tr>\n",
				HTMLEscape(label), HTMLEscape(k), counts[k])
		}
		if len(order) == 0 {
			total = lb.Len()
			fmt.Fprintf(q.W, "<tr><td>%s</td><td>(none)</td><td align=\"right\">%d</td></tr>\n",
				HTMLEscape(name), total)
		}
		fmt.Fprintf(q.W, "<tr class=\"header\"><td><b>%s</b></td><td></td>"+
			"<td align=\"right\"><b>%d</b></td></tr>\n", HTMLEscape(s.loc("Total")), total)
	}
	fmt.Fprint(q.W, "</table>\n")
	s.endPage(q)
}

// showCalendarPage is "?cmd=Calendar": one month with the entries per day.
func (s *Server) showCalendarPage(q *Request) {
	now := time.Now()
	year, month := now.Year(), int(now.Month())
	if v := q.Param("year"); v != "" {
		year = Atoi(v)
	}
	if v := q.Param("month"); v != "" {
		month = Atoi(v)
	}
	if month < 1 || month > 12 {
		month = int(now.Month())
	}
	first := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.Local)
	start := first.AddDate(0, 0, -int(first.Weekday()))
	if s.Config.GetBool(q.Cfg, "Monday first") {
		start = first.AddDate(0, 0, -((int(first.Weekday()) + 6) % 7))
	}
	byDay := map[int][]*Entry{}
	if q.LB != nil {
		for _, e := range q.LB.Messages() {
			d := e.DateValue()
			if d.Year() == year && int(d.Month()) == month {
				byDay[d.Day()] = append(byDay[d.Day()], e)
			}
		}
	}
	s.beginPage(q, s.loc("Calendar"), "")
	fmt.Fprintf(q.W, "<table class=\"list\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" width=\"100%%\">\n"+
		"<tr class=\"header\">")
	for _, d := range weekDayNames(s, q) {
		fmt.Fprintf(q.W, "<th align=\"left\">%s</th>", HTMLEscape(d))
	}
	fmt.Fprint(q.W, "</tr>\n<tr>")
	for i := 0; i < 42; i++ {
		d := start.AddDate(0, 0, i)
		if i%7 == 0 && i > 0 {
			fmt.Fprint(q.W, "</tr>\n<tr>")
		}
		cell := ""
		if d.Month() == first.Month() {
			cell = strconv.Itoa(d.Day())
			for _, e := range byDay[d.Day()] {
				link := fmt.Sprintf("%s/%s/%d", s.BasePath, q.Cfg.Group, e.ID())
				cell += fmt.Sprintf("<br><a href=\"%s\">#%d %s</a>", HTMLEscape(link), e.ID(),
					HTMLEscape(ShortenUTF8(orText(e.Title(), "(no subject)"), 40)))
			}
		}
		fmt.Fprintf(q.W, "<td valign=\"top\" width=\"14%%\">%s</td>", cell)
	}
	fmt.Fprint(q.W, "</tr>\n</table>\n")
	s.writeCalendarNav(q, year, month)
	s.endPage(q)
}

// writeCalendarNav is the "< Month Year >" line under the calendar.
func (s *Server) writeCalendarNav(q *Request, year, month int) {
	first := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.Local)
	prev, next := first.AddDate(0, -1, 0), first.AddDate(0, 1, 0)
	base := q.R.URL.Path
	cmd := URLEncode(s.loc("Calendar"))
	fmt.Fprintf(q.W, "<div class=\"navbar\">"+
		"<a href=\"%s?cmd=%s&year=%d&month=%d\">&lt;</a> <b>%s %d</b> "+
		"<a href=\"%s?cmd=%s&year=%d&month=%d\">&gt;</a></div>\n",
		HTMLEscape(base), cmd, prev.Year(), int(prev.Month()),
		HTMLEscape(monthName(int(first.Month()))), first.Year(),
		HTMLEscape(base), cmd, next.Year(), int(next.Month()))
}

func monthName(m int) string {
	if m >= 1 && m <= 12 {
		return monthNames[m-1]
	}
	return ""
}

// weekDayNames are the column headings of the calendar, localised and rotated
// when the logbook wants Monday first.
func weekDayNames(s *Server, q *Request) []string {
	week := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	if s.Config.GetBool(q.Cfg, "Monday first") {
		week = append(append([]string{}, week[1:]...), week[0])
	}
	out := make([]string, 0, 7)
	for _, d := range week {
		out = append(out, s.loc(d))
	}
	return out
}

// ---------------------------------------------------------------------------
// Configuration page
// ---------------------------------------------------------------------------

// showConfigPage dumps the effective configuration of the current scope. The
// original can also edit it ("Setup"); here the dump is always available to an
// administrator and a single key can be written back with "?cmd=Save config"
// when the global "Allow config edit" switch is on.
func (s *Server) showConfigPage(q *Request) {
	if !s.userIn(q.Cfg, "Admin", q.User) {
		s.errorf(q, http.StatusForbidden, "Only the logbook administrator may look at the configuration.")
		return
	}
	s.beginPage(q, s.loc("Setup"), "")
	fmt.Fprintf(q.W, "<p>%s <tt>%s</tt></p>\n", HTMLEscape(s.loc("Configuration file")),
		HTMLEscape(s.ConfigPath))
	section := q.Cfg.Group
	if section == "" {
		section = "global"
	}
	fmt.Fprintf(q.W, "<table border=\"0\" cellpadding=\"2\" cellspacing=\"1\">\n"+
		"<tr class=\"header\"><th align=\"left\">%s</th><th align=\"left\">%s</th></tr>\n",
		HTMLEscape(s.loc("Parameter")), HTMLEscape(s.loc("Value")))
	for _, p := range s.Config.Params(section) {
		fmt.Fprintf(q.W, "<tr><td class=\"entry_attrname\">%s</td><td class=\"entry_attr\"><tt>%s</tt></td></tr>\n",
			HTMLEscape(p.Key), HTMLEscape(p.Value))
	}
	fmt.Fprint(q.W, "</table>\n")
	if s.Config.GetBool(ConfigScope{Group: "global"}, "Allow config edit") {
		fmt.Fprintf(q.W, "<form method=\"post\" action=\"%s\">\n", HTMLEscape(q.R.URL.Path))
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"cmd\" value=\"%s\">\n", HTMLEscape(s.loc("Save config")))
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"section\" value=\"%s\">\n", HTMLEscape(section))
		fmt.Fprintf(q.W, "%s <input type=\"text\" name=\"param\" size=\"30\"> %s "+
			"<input type=\"text\" name=\"value\" size=\"40\"> <input class=\"navbar\" type=\"submit\" value=\"%s\">\n",
			HTMLEscape(s.loc("Parameter")), HTMLEscape(s.loc("Value")), HTMLEscape(s.loc("Save")))
		fmt.Fprint(q.W, "</form>\n")
	}
	s.endPage(q)
}

// saveConfig writes one parameter back to the configuration file. elogd does
// this with save_param(), which rewrites the whole file; here the key inside its
// section is replaced or appended, comments elsewhere are preserved.
func (s *Server) saveConfig(q *Request) {
	if !s.userIn(q.Cfg, "Admin", q.User) {
		s.errorf(q, http.StatusForbidden, "Only the logbook administrator may change the configuration.")
		return
	}
	section := orText(q.Param("section"), q.Cfg.Group)
	if section == "" {
		section = "global"
	}
	key := TrimSpaceASCII(q.Param("param"))
	if key == "" {
		s.errorf(q, http.StatusBadRequest, "No parameter given.")
		return
	}
	if err := s.Config.SetParam(section, key, q.Param("value")); err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot write the configuration file: %s",
			HTMLEscape(err.Error()))
		return
	}
	if _, err := s.Config.ReloadIfChanged(); err != nil {
		s.Logf("reloading configuration: %v", err)
	}
	s.Logf("configuration: [%s] %s changed by %s", section, key, q.displayName())
	s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/?cmd="+URLEncode(s.loc("Setup")))
}

// ---------------------------------------------------------------------------
// Users and subscriptions
// ---------------------------------------------------------------------------

// showUserPage is the "Edit user" page: a logged-in user may change his own
// name, e-mail and password; an administrator may do it for anybody.
func (s *Server) showUserPage(q *Request) {
	if s.Pwd == nil {
		s.errorf(q, http.StatusNotFound, "This server has no password file.")
		return
	}
	name := orText(q.Param("user"), q.User)
	if name != q.User && !s.userIn(q.Cfg, "Admin", q.User) {
		s.errorf(q, http.StatusForbidden, "You may only edit your own account.")
		return
	}
	u := s.Pwd.User(name)
	if u == nil {
		s.errorf(q, http.StatusNotFound, "No such user %s", HTMLEscape(name))
		return
	}
	s.beginPage(q, s.loc("Edit user"), "")
	fmt.Fprintf(q.W, "<form method=\"post\" action=\"%s\">\n", HTMLEscape(q.R.URL.Path))
	fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"cmd\" value=\"%s\">\n", HTMLEscape(s.loc("Save user")))
	fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"user\" value=\"%s\">\n", HTMLEscape(name))
	fmt.Fprintf(q.W, "<table border=\"0\" cellpadding=\"2\">\n")
	userTextRow(q, s.loc("User name"), name)
	userInputRow(q, "fullname", s.loc("Full name"), u.FullName)
	userInputRow(q, "email", s.loc("E-mail"), u.Email)
	fmt.Fprintf(q.W, "<tr><td class=\"entry_attrname\">%s</td><td class=\"entry_attr\">"+
		"<input type=\"password\" name=\"password\" size=\"20\" autocomplete=\"off\"></td></tr>\n",
		HTMLEscape(s.loc("New password")))
	fmt.Fprint(q.W, "</table>\n")
	fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" value=\"%s\">\n", HTMLEscape(s.loc("Save")))
	fmt.Fprint(q.W, "</form>\n")
	s.endPage(q)
}

func userTextRow(q *Request, label, value string) {
	fmt.Fprintf(q.W, "<tr><td class=\"entry_attrname\">%s</td><td class=\"entry_attr\">%s</td></tr>\n",
		HTMLEscape(label), HTMLEscape(value))
}

func userInputRow(q *Request, field, label, value string) {
	fmt.Fprintf(q.W, "<tr><td class=\"entry_attrname\">%s</td><td class=\"entry_attr\">"+
		"<input type=\"text\" name=\"%s\" size=\"30\" value=\"%s\"></td></tr>\n",
		HTMLEscape(label), HTMLEscape(field), HTMLEscape(value))
}

// saveUser stores the changes made on the user page.
func (s *Server) saveUser(q *Request) {
	if s.Pwd == nil {
		s.errorf(q, http.StatusNotFound, "This server has no password file.")
		return
	}
	name := orText(q.Param("user"), q.User)
	if name != q.User && !s.userIn(q.Cfg, "Admin", q.User) {
		s.errorf(q, http.StatusForbidden, "You may only edit your own account.")
		return
	}
	u := s.Pwd.User(name)
	if u == nil {
		s.errorf(q, http.StatusNotFound, "No such user %s", HTMLEscape(name))
		return
	}
	if v, ok := q.body["fullname"]; ok {
		u.FullName = v[0]
	}
	if v, ok := q.body["email"]; ok {
		u.Email = v[0]
	}
	if err := s.Pwd.Save(); err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot write the password file: %s",
			HTMLEscape(err.Error()))
		return
	}
	if pw := q.Param("password"); pw != "" {
		if err := s.Pwd.SetPassword(name, pw); err != nil {
			s.errorf(q, http.StatusInternalServerError, "Cannot change the password: %s",
				HTMLEscape(err.Error()))
			return
		}
		s.Logf("password changed for %s by %s", name, q.displayName())
	}
	s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/")
}

// showSubscriptionPage lists who gets a notification for this logbook and lets
// the logged-in user switch himself on or off. The data is the <email_notify>
// list of the password file, which is what elogd uses.
func (s *Server) showSubscriptionPage(q *Request) {
	if s.Pwd == nil {
		s.errorf(q, http.StatusNotFound, "This server has no password file.")
		return
	}
	lbName := q.Cfg.Group
	s.beginPage(q, s.loc("Subscription"), "")
	fmt.Fprintf(q.W, "<table border=\"0\" cellpadding=\"2\" cellspacing=\"1\">\n"+
		"<tr class=\"header\"><th align=\"left\">%s</th><th align=\"left\">%s</th>"+
		"<th align=\"left\">%s</th></tr>\n",
		HTMLEscape(s.loc("User name")), HTMLEscape(s.loc("E-mail")), HTMLEscape(s.loc("Subscribed")))
	for _, u := range s.Pwd.Users {
		if u.IsInactive() {
			continue
		}
		on := "-"
		if s.Pwd.NotifyFor(u.Name, lbName) {
			on = "X"
		}
		fmt.Fprintf(q.W, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			HTMLEscape(u.Name), HTMLEscape(u.Email), HTMLEscape(on))
	}
	fmt.Fprint(q.W, "</table>\n")
	if q.User != "" {
		checked := ""
		if s.Pwd.NotifyFor(q.User, lbName) {
			checked = " checked"
		}
		fmt.Fprintf(q.W, "<form method=\"post\" action=\"%s\">\n", HTMLEscape(q.R.URL.Path))
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"cmd\" value=\"%s\">\n",
			HTMLEscape(s.loc("Save subscription")))
		fmt.Fprintf(q.W, "<label><input type=\"checkbox\" name=\"notify\" value=\"1\"%s> %s</label> ",
			checked, HTMLEscape(fmt.Sprintf("%s %s", s.loc("Send me a notification about new entries in"), lbName)))
		fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" value=\"%s\">\n", HTMLEscape(s.loc("Save")))
		fmt.Fprint(q.W, "</form>\n")
	}
	s.endPage(q)
}

// saveSubscription stores the "notify me" tick of the logged-in user.
func (s *Server) saveSubscription(q *Request) {
	if s.Pwd == nil || q.User == "" {
		s.errorf(q, http.StatusForbidden, "You must be logged in.")
		return
	}
	lbName := q.Cfg.Group
	if s.Pwd.User(q.User) == nil {
		s.errorf(q, http.StatusNotFound, "No such user")
		return
	}
	var list []string
	on := q.Param("notify") == "1"
	had := false
	for _, n := range s.Pwd.User(q.User).EmailNotify {
		if EqualFold(n, lbName) {
			had = true
			if !on {
				continue
			}
		}
		list = append(list, n)
	}
	if on && !had {
		list = append(list, lbName)
	}
	if err := s.Pwd.SetEmailNotify(q.User, list); err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot write the password file: %s",
			HTMLEscape(err.Error()))
		return
	}
	s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/?cmd="+URLEncode(s.loc("Subscription")))
}

// signup is the "?cmd=Signup" self-registration page, gated by the global
// "Enable signup" switch (the C code writes the new account into the password
// file, which is exactly what happens here too).
func (s *Server) signup(q *Request) {
	g := ConfigScope{Group: "global"}
	if !s.Config.GetFlagDefault(g, "Enable signup", false) || s.Pwd == nil {
		s.errorf(q, http.StatusForbidden, "Signup is not enabled.")
		return
	}
	if q.R.Method != http.MethodPost {
		s.beginPage(q, s.loc("Signup"), "")
		fmt.Fprintf(q.W, "<form method=\"post\" action=\"%s\">\n", HTMLEscape(q.R.URL.Path))
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"cmd\" value=\"%s\">\n", HTMLEscape(s.loc("Signup")))
		fmt.Fprintf(q.W, "<table border=\"0\" cellpadding=\"2\">\n")
		userInputRow(q, "unm", s.loc("User name"), "")
		userInputRow(q, "fullname", s.loc("Full name"), "")
		userInputRow(q, "email", s.loc("E-mail"), "")
		fmt.Fprintf(q.W, "<tr><td class=\"entry_attrname\">%s</td><td class=\"entry_attr\">"+
			"<input type=\"password\" name=\"upwd\" size=\"20\" autocomplete=\"off\"></td></tr>\n",
			HTMLEscape(s.loc("Password")))
		fmt.Fprint(q.W, "</table>\n")
		fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" value=\"%s\">\n", HTMLEscape(s.loc("Signup")))
		fmt.Fprint(q.W, "</form>\n")
		s.endPage(q)
		return
	}
	name := TrimSpaceASCII(orText(q.Param("user"), q.Param("unm")))
	pass := orText(q.Param("password"), q.Param("upwd"))
	if name == "" || pass == "" {
		s.showLoginPage(q, q.Param("redir"), true)
		return
	}
	if err := s.Pwd.AddUser(name, pass, q.Param("fullname"), q.Param("email")); err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot create the user: %s", HTMLEscape(err.Error()))
		return
	}
	s.Logf("new user %s signed up from %s", name, q.ClientIP())
	s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/")
}

// showExpirePage is "?cmd=Expire": the accounts that have not been used for
// "Expire" days, which the original lists so the administrator can delete them.
func (s *Server) showExpirePage(q *Request) {
	if !s.userIn(q.Cfg, "Admin", q.User) {
		s.errorf(q, http.StatusForbidden, "Only the logbook administrator may look at the user list.")
		return
	}
	if s.Pwd == nil {
		s.errorf(q, http.StatusNotFound, "This server has no password file.")
		return
	}
	days := s.Config.GetInt(ConfigScope{Group: "global"}, "Expire", 0)
	limit := time.Now().AddDate(0, 0, -days)
	s.beginPage(q, s.loc("Expire"), "")
	fmt.Fprintf(q.W, "<p>%s <b>%d</b> %s</p>\n", HTMLEscape(s.loc("Users inactive for more than")),
		days, HTMLEscape(s.loc("days")))
	fmt.Fprintf(q.W, "<table border=\"0\" cellpadding=\"2\" cellspacing=\"1\">\n"+
		"<tr class=\"header\"><th align=\"left\">%s</th><th align=\"left\">%s</th>"+
		"<th align=\"left\">%s</th></tr>\n",
		HTMLEscape(s.loc("User name")), HTMLEscape(s.loc("Last activity")), HTMLEscape(s.loc("Delete")))
	n := 0
	for _, u := range s.Pwd.Users {
		last, ok := ParseCTime(u.LastActivity)
		if !ok || !last.Before(limit) {
			continue
		}
		n++
		fmt.Fprintf(q.W, "<tr><td>%s</td><td>%s</td><td><form method=\"post\" action=\"%s\" "+
			"style=\"display:inline\"><input type=\"hidden\" name=\"cmd\" value=\"%s\">"+
			"<input type=\"hidden\" name=\"user\" value=\"%s\">"+
			"<input class=\"navbar\" type=\"submit\" value=\"%s\"></form></td></tr>\n",
			HTMLEscape(u.Name), HTMLEscape(FormatDate("%Y-%m-%d %H:%M", last)),
			HTMLEscape(q.R.URL.Path), HTMLEscape(s.loc("Expire users")),
			HTMLEscape(u.Name), HTMLEscape(s.loc("Delete")))
	}
	fmt.Fprint(q.W, "</table>\n")
	if n == 0 {
		fmt.Fprintf(q.W, "<p>%s</p>\n", HTMLEscape(s.loc("No user is inactive.")))
	}
	s.endPage(q)
}

// expireUsers marks the selected accounts inactive (never deletes them: the
// entries they wrote reference their login name).
func (s *Server) expireUsers(q *Request) {
	if !s.userIn(q.Cfg, "Admin", q.User) || s.Pwd == nil {
		s.errorf(q, http.StatusForbidden, "Only the logbook administrator may expire users.")
		return
	}
	names := q.ParamAll("user")
	if name := q.Param("user"); name != "" && len(names) == 0 {
		names = []string{name}
	}
	for _, name := range names {
		if err := s.Pwd.SetInactive(name, true); err != nil {
			s.logf("expiring user %s: %v", name, err)
			continue
		}
		s.Logf("user %s expired by %s", name, q.displayName())
	}
	if err := s.Pwd.Save(); err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot write the password file: %s",
			HTMLEscape(err.Error()))
		return
	}
	s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/?cmd="+URLEncode(s.loc("Expire")))
}

// ---------------------------------------------------------------------------
// Reverting an edited entry
// ---------------------------------------------------------------------------

// showRevertPage lists the archived copies of an entry so one can be restored.
// elogd keeps the previous version of an edited message next to it
// (display_revert_page()); the copies are "<message file>.<n>".
func (s *Server) showRevertPage(q *Request) {
	id := q.msgID
	if id == 0 {
		id = q.IntParam("message_id")
	}
	e, err := q.LB.Message(id)
	if err != nil {
		s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", id)
		return
	}
	s.beginPage(q, s.loc("Revert"), "")
	list := s.entryHistory(q.LB, e)
	if len(list) == 0 {
		fmt.Fprintf(q.W, "<p>%s</p>\n", HTMLEscape(s.loc("No previous version is stored for this entry.")))
	} else {
		fmt.Fprintf(q.W, "<form method=\"post\" action=\"%s\">\n", HTMLEscape(q.R.URL.Path))
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"cmd\" value=\"%s\">\n", HTMLEscape(s.loc("Revert")))
		fmt.Fprintf(q.W, "<input type=\"hidden\" name=\"message_id\" value=\"%d\">\n", id)
		fmt.Fprintf(q.W, "<select name=\"version\">\n")
		for i, h := range list {
			fmt.Fprintf(q.W, "<option value=\"%d\">%s</option>\n", i, HTMLEscape(h))
		}
		fmt.Fprint(q.W, "</select>\n")
		fmt.Fprintf(q.W, "<input class=\"navbar\" type=\"submit\" value=\"%s\">\n", HTMLEscape(s.loc("Revert")))
		fmt.Fprint(q.W, "</form>\n")
	}
	s.endPage(q)
}

// entryHistory lists the archived copies next to the message file. The lock
// file ("<name>.1") is deliberately skipped: it is not a version.
func (s *Server) entryHistory(lb *Logbook, e *Entry) []string {
	if e.File == "" {
		return nil
	}
	dir := lb.DataDirFor(e.Subdir)
	matches, _ := filepath.Glob(filepath.Join(dir, filepath.Base(e.File)+".*"))
	sort.Strings(matches)
	var out []string
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || st.IsDir() || filepath.Ext(m) == ".1" {
			continue
		}
		out = append(out, filepath.Base(m)+"  "+FormatDate("%Y-%m-%d %H:%M", st.ModTime()))
	}
	return out
}

// revertTo restores an archived copy of an entry.
func (s *Server) revertTo(q *Request) {
	id := q.msgID
	if id == 0 {
		id = q.IntParam("message_id")
	}
	e, err := q.LB.Message(id)
	if err != nil {
		s.errorf(q, http.StatusNotFound, "Entry #%d does not exist", id)
		return
	}
	list := s.entryHistory(q.LB, e)
	n := q.IntParam("version")
	if n < 0 || n >= len(list) {
		s.errorf(q, http.StatusBadRequest, "No such version.")
		return
	}
	src := filepath.Join(q.LB.DataDirFor(e.Subdir), strings.Fields(list[n])[0])
	if !strings.HasPrefix(src, q.LB.DataDirFor(e.Subdir)+string(os.PathSeparator)) {
		s.errorf(q, http.StatusBadRequest, "Bad version name.")
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot read %s", HTMLEscape(src))
		return
	}
	restored, err := ParseEntryBytes(data)
	if err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot parse the archived entry: %s",
			HTMLEscape(err.Error()))
		return
	}
	restored.SetID(id)
	restored.Subdir = e.Subdir
	restored.File = e.File
	if err := q.LB.Update(restored); err != nil {
		s.errorf(q, http.StatusInternalServerError, "Cannot store the entry: %s", HTMLEscape(err.Error()))
		return
	}
	s.Logf("entry #%d of %s reverted to %s by %s", id, q.Cfg.Group, filepath.Base(src), q.displayName())
	s.redirect(q, s.BasePath+"/"+q.Cfg.Group+"/"+strconv.Itoa(id))
}

// ---------------------------------------------------------------------------
// The machine interface: post an entry with POST
// ---------------------------------------------------------------------------

// servePost is "?cmd=POST" (and a plain POST carrying a "Text" parameter): the
// interface elogd offers so a shell script or an experiment controls system can
// post with curl. The form fields are the attribute names, exactly like the web
// form, so submit() does the work - including permissions, attachments and mail.
func (s *Server) servePost(q *Request) {
	s.submit(q)
}

// ServePost is the exported form (tests).
func (s *Server) ServePost(q *Request) { s.servePost(q) }

// ServeTextPost is the "curl -d" variant: a body that is not a form is taken as
// the text of a new entry, which is what elogd's "post by mail/script" setups
// do.
func (s *Server) ServeTextPost(w http.ResponseWriter, r *http.Request, logbook, text string) error {
	srv := r
	lb := s.LB(logbook)
	if lb == nil {
		return fmt.Errorf("unknown logbook %q", logbook)
	}
	body, err := io.ReadAll(io.LimitReader(srv.Body, 8<<20))
	if err != nil {
		return err
	}
	if text == "" {
		text = string(body)
	}
	e := &Entry{}
	e.SetID(lb.NextID())
	e.SetHeader("Date", FormatRFC2822(time.Now()))
	e.SetHeader("Author", "anonymous")
	e.SetHeader("Subject", ShortenUTF8(firstLineOf(text), 60))
	e.Text = text
	if err := lb.Append(e); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%d\n", e.ID())
	return nil
}

// firstLineOf is the first non-empty line of a text, used as the subject of an
// entry that arrives without one.
func firstLineOf(s string) string {
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if TrimSpaceASCII(l) != "" {
			return TrimSpaceASCII(l)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

// help is "?cmd=Help". The original has no online help at all - the button is in
// the default menu of some configurations and the command falls through to the
// "command not allowed" error page, which is not a useful answer. This is the
// minimal page that explains the URL scheme the rest of this package implements,
// because that scheme is what an operator or a script author needs. It is
// reachable without any permission, and it lists only the commands the current
// logbook actually allows.
func (s *Server) help(q *Request) {
	s.beginPage(q, s.loc("Help"), "")
	fmt.Fprintf(q.W, "<h3>%s</h3>\n", HTMLEscape(s.loc("Help")))
	fmt.Fprint(q.W, "<table border=\"0\" cellpadding=\"2\" cellspacing=\"1\">\n")
	row := func(url, what string) {
		fmt.Fprintf(q.W, "<tr><td><tt>%s</tt></td><td>%s</td></tr>\n",
			HTMLEscape(url), HTMLEscape(what))
	}
	row(s.BasePath+"/", "list of logbooks")
	row(s.BasePath+"/<logbook>/", "list the entries of a logbook")
	row(s.BasePath+"/<logbook>/<id>", "one entry")
	row(s.BasePath+"/<logbook>/<id>/<n>", "attachment number n (1-based) of that entry")
	row("?cmd=DisplayList", "the list page")
	row("?cmd=New", "post a new entry")
	row("?cmd=Edit&message_id=<id>", "edit an entry")
	row("?cmd=Reply&message_id=<id>", "reply to an entry")
	row("?cmd=Find&subtext=<words>", "search; words are ANDed, &attr=<name> searches one attribute")
	row("?cmd=Display as Thread", "the entries as a thread tree")
	row("?cmd=RSS", "RSS 2.0 feed of the most recent entries")
	row("?cmd=RSSfull", "RSS feed with the whole text of each entry")
	row("?cmd=XML", "machine-readable XML of the listed entries")
	row("?cmd=JSON", "machine-readable JSON; &since=<id> returns only newer ids")
	row("?cmd=CSV", "semicolon-separated export")
	row("?cmd=Raw", "the raw message files, as stored on disk")
	row("?cmd=POST", "post an entry with an HTML form or with curl")
	fmt.Fprint(q.W, "</table>\n")

	allowed := s.Config.GetList(q.Cfg, "Allowed commands")
	if len(allowed) == 0 {
		allowed = DefaultAllowedCommands
	}
	fmt.Fprintf(q.W, "<p>%s: ", HTMLEscape(s.loc("Commands available in this logbook")))
	first := true
	for _, c := range allowed {
		if !s.commandAllowed(q, c) {
			continue
		}
		if !first {
			fmt.Fprint(q.W, ", ")
		}
		first = false
		fmt.Fprint(q.W, HTMLEscape(s.loc(c)))
	}
	fmt.Fprint(q.W, "</p>\n")
	s.endPage(q)
}

// Help is the exported form of help (tests).
func (s *Server) Help(q *Request) { s.help(q) }
