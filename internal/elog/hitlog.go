package elog

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// View statistics ("hit file")
// ---------------------------------------------------------------------------
//
// elogd appends one line every time a message is displayed, so the daemon can
// answer "how many views has this entry" and "what happened in the last 24
// hours". The three configuration keys, spelled exactly as the C code spells
// them, are all in the [global] section (getcfg(NULL, ...) is the global
// section in elogd):
//
//	Logging            xml | file | stdout | anything else (=off)
//	Record hit file    1/0 (the C default is off: record_hit_file = 0)
//	Logbook hit file   file name, default "mlog.hit"; a relative name is
//	                   resolved against the logbook's data directory
//
// The record itself is written by record_message():
//
//	logging != LOG_XML:  id|logbook|YYYY-MM-DD HH:MM:SS|user|ip|user agent\n
//	logging == LOG_XML:  <message id=".." logbook=".." time=".." user=".."
//	                          ip=".." useragent=".."/>
//
// (a plain fprintf, with no escaping - the Go version escapes the XML form,
// because a user agent containing "<" would otherwise corrupt the file; the
// plain form is passed through unchanged so a file written by elogd stays
// byte-identical).
//
// The old "mlog.hit" of the farm deployment was produced by the C program and
// is read here as-is; the reader accepts both the '|'-separated and the
// space-separated "<epoch> <logbook> <id> <ip>" spelling that older elogd
// versions used, plus the XML form, so the statistics survive the switch and a
// roll back.
//
// The original rewrites the file down to the last HITMAX (1000) lines once it
// grows past that. That behaviour is kept (it is what keeps the file small on
// a 15-year-old logbook) but the limit is configurable through "Hit file
// max lines"; set it to 0 to keep everything. The in-memory copy is loaded
// once at first use, so browsing never stats the file.

// hitLog is one logbook's view history.
type hitLog struct {
	mu     sync.Mutex
	path   string
	xmlFmt bool
	hits   []hit
	loaded bool
	max    int
}

type hit struct {
	when      time.Time
	id        int
	user      string
	ip        string
	userAgent string
}

var (
	hitMu   sync.Mutex
	hitLogs = map[string]*hitLog{}
)

// hitLoggingMode maps the "Logging" key onto what the C code stores in
// log_logging: off (anything), file (LOG_TEXT) or xml (LOG_XML). "stdout" in
// the original also goes to the log file, only with the messages mirrored to
// the console; the Go version logs to stderr in that case.
func hitLoggingMode(cfg *Config) (record bool, asXML bool) {
	v := strings.ToLower(TrimSpaceASCII(cfg.GetString(ConfigScope{Group: "global"}, "Logging", "none")))
	asXML = v == "xml"
	record = asXML || v == "file" || v == "stdout"
	if !record {
		return
	}
	// "Record hit file" is a plain atoi() in the original, default 0.
	if n, _ := cfg.GetInt(ConfigScope{Group: "global"}, "Record hit file", 0); n == 0 {
		return false, asXML
	}
	return true, asXML
}

// hitLogFor returns (and loads once) the hit log of a logbook.
func (s *Server) hitLogFor(lb *Logbook) *hitLog {
	if lb == nil {
		return nil
	}
	return s.hitLogByName(lb.Name)
}

// hitLogByName is hitLogFor for code that only has the logbook name (the view
// counters of the list page, the notification mail).
func (s *Server) hitLogByName(logbook string) *hitLog {
	if logbook == "" {
		return nil
	}
	name := s.Config.GetString(ConfigScope{Group: "global"}, "Logbook hit file", "mlog.hit")
	dir := ""
	if lb := s.LB(logbook); lb != nil {
		dir = lb.Dir
	}
	path := name
	if !filepath.IsAbs(path) {
		if dir == "" {
			dir = s.abs(logbook)
		}
		path = filepath.Join(dir, name)
	}
	hitMu.Lock()
	defer hitMu.Unlock()
	h, ok := hitLogs[path]
	if !ok {
		h = &hitLog{
			path: path,
			max:  s.Config.GetInt(ConfigScope{Group: "global"}, "Hit file max lines", 1000),
		}
		_, h.xmlFmt = hitLoggingMode(s.Config)
		hitLogs[path] = h
	}
	return h
}

// count is how often one message was displayed.
func (h *hitLog) count(id int) int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	n := 0
	for _, x := range h.hits {
		if x.id == id {
			n++
		}
	}
	return n
}

// total is the number of recorded views.
func (h *hitLog) total() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	return len(h.hits)
}

// RecordHit appends one view of message id to the history of logbook lb.
func (s *Server) RecordHit(lb *Logbook, id int, ip string) {
	s.RecordHitAs(lb, id, ip, s.UserNameForHit(), "")
}

// UserNameForHit is a hook so the request path can pass the logged-in user;
// without a request context there is none.
func (s *Server) UserNameForHit() string { return "" }

// RecordHitAs records a view with the full information of the original
// (user name and user agent end up in the record).
func (s *Server) RecordHitAs(lb *Logbook, id int, ip, user, userAgent string) {
	if lb == nil || id <= 0 {
		return
	}
	record, _ := hitLoggingMode(s.Config)
	if !record {
		return
	}
	h := s.hitLogFor(lb)
	if h == nil {
		return
	}
	now := time.Now()
	h.mu.Lock()
	h.loadLocked()
	h.hits = append(h.hits, hit{when: now, id: id, user: user, ip: ip, userAgent: userAgent})
	trimmed := false
	if h.max > 0 && len(h.hits) > h.max {
		h.hits = append([]hit(nil), h.hits[len(h.hits)-h.max:]...)
		trimmed = true
	}
	h.mu.Unlock()
	s.appendHit(h, now, lb.Name, id, user, ip, userAgent, trimmed)
}

// appendHit writes one record (or rewrites the whole file when the original's
// 1000-line trim kicked in). Errors are ignored on purpose: a read-only data
// directory must not break browsing, which is also what the C code does - it
// just does not report the failed fopen().
func (s *Server) appendHit(h *hitLog, when time.Time, logbook string, id int, user, ip, ua string, trimmed bool) {
	line := hitLine(h.xmlFmt, when, logbook, id, user, ip, ua)
	if trimmed {
		h.mu.Lock()
		var b strings.Builder
		if h.xmlFmt {
			b.WriteString("<hits>\n")
		}
		for _, x := range h.hits {
			b.WriteString(hitLine(h.xmlFmt, x.when, logbook, x.id, x.user, x.ip, x.userAgent))
		}
		if h.xmlFmt {
			b.WriteString("</hits>\n")
		}
		h.mu.Unlock()
		// #nosec G306 - the hit file is not secret; elogd creates it 0644.
		if err := os.WriteFile(h.path, []byte(b.String()), 0o644); err != nil {
			s.logf("hit file %s: %v", h.path, err)
		}
		return
	}
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		s.logf("hit file %s: %v", h.path, err)
		return
	}
	defer f.Close()
	fmt.Fprint(f, line)
}

func hitLine(asXML bool, when time.Time, logbook string, id int, user, ip, ua string) string {
	stamp := when.Format("2006-01-02 15:04:05")
	if asXML {
		return fmt.Sprintf("<message id=\"%d\" logbook=\"%s\" time=\"%s\" user=\"%s\" ip=\"%s\" useragent=%q/>\n",
			id, logbook, stamp, user, ip, ua)
	}
	return fmt.Sprintf("%d|%s|%s|%s|%s|%s\n", id, logbook, stamp, user, ip, ua)
}

// loadLocked reads the file into memory once.
func (h *hitLog) loadLocked() {
	if h.loaded {
		return
	}
	h.loaded = true
	data, err := os.ReadFile(h.path)
	if err != nil {
		return
	}
	text := string(data)
	if strings.HasPrefix(strings.TrimSpace(text), "<hits>") {
		text = strings.Replace(strings.TrimSpace(text), "<hits>", "", 1)
		text = strings.Replace(text, "</hits>", "", 1)
	}
	for _, line := range strings.Split(text, "\n") {
		line = TrimSpaceASCII(line)
		if line == "" {
			continue
		}
		if line[0] == '<' {
			if hh, ok := parseXMLHit(line); ok {
				h.hits = append(h.hits, hh)
			}
			h.xmlFmt = true
			continue
		}
		if hh, ok := parsePlainHit(line); ok {
			h.hits = append(h.hits, hh)
		}
	}
}

// parsePlainHit accepts "id|logbook|date time|user|ip|agent" and the older
// space-separated "<epoch> <logbook> <id> <ip>" spelling.
func parsePlainHit(line string) (hit, bool) {
	if strings.Contains(line, "|") {
		f := strings.Split(line, "|")
		if len(f) < 3 {
			return hit{}, false
		}
		id := Atoi(f[0])
		if id == 0 {
			return hit{}, false
		}
		t, _ := time.ParseInLocation("2006-01-02 15:04:05", f[2], time.Local)
		hh := hit{when: t, id: id}
		if len(f) > 3 {
			hh.user = f[3]
		}
		if len(f) > 4 {
			hh.ip = f[4]
		}
		if len(f) > 5 {
			hh.userAgent = f[5]
		}
		if hh.when.IsZero() {
			hh.when = time.Now()
		}
		return hh, true
	}
	f := strings.Fields(line)
	if len(f) < 3 {
		return hit{}, false
	}
	sec := Atoi(f[0])
	if sec <= 0 {
		return hit{}, false
	}
	return hit{when: time.Unix(int64(sec), 0), id: Atoi(f[2]), ip: orEmpty(f, 3)}, true
}

func orEmpty(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}

type xmlHitRec struct {
	ID        int    `xml:"id,attr"`
	Logbook   string `xml:"logbook,attr"`
	Time      string `xml:"time,attr"`
	User      string `xml:"user,attr"`
	IP        string `xml:"ip,attr"`
	UserAgent string `xml:"useragent,attr"`
}

func parseXMLHit(line string) (hit, bool) {
	var r xmlHitRec
	if err := xml.Unmarshal([]byte(strings.TrimSuffix(strings.TrimSpace(line), "/>")+"</message>"), &r); err != nil {
		if err := xml.Unmarshal([]byte(line), &r); err != nil {
			return hit{}, false
		}
	}
	t, _ := time.ParseInLocation("2006-01-02 15:04:05", r.Time, time.Local)
	if t.IsZero() {
		t = time.Now()
	}
	return hit{when: t, id: r.ID, user: r.User, ip: r.IP, userAgent: r.UserAgent}, r.ID != 0
}

// ViewsOf is the number of recorded views of one message. server.go's ViewsOf /
// Views are the spellings the page code uses; this is the logbook-object form.
func (s *Server) ViewsOfEntry(lb *Logbook, id int) int {
	return s.ViewsOf(lbNameOf(lb), id)
}

func lbNameOf(lb *Logbook) string {
	if lb == nil {
		return ""
	}
	return lb.Name
}

// LastView is the time of the most recent recorded view of a logbook (zero when
// nothing was recorded). It backs the "last visit" information of the list page,
// which formats it with the logbook's "Date format".
func (s *Server) LastView(scope ConfigScope) time.Time {
	h := s.hitLogByName(scope.Group)
	if h == nil {
		return time.Time{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	var last time.Time
	for _, x := range h.hits {
		if x.when.After(last) {
			last = x.when
		}
	}
	return last
}

// LastActivity is LastView formatted for the pages.
func (s *Server) LastActivity(scope ConfigScope) string {
	t := s.LastView(scope)
	if t.IsZero() {
		return ""
	}
	return FormatDate(s.Config.GetString(scope, "Date format", "%b %d %Y %H:%M:%S"), t)
}

// EntriesInWindow is the "N distinct entries displayed since ..." answer.
func (s *Server) EntriesInWindow(lb *Logbook, since time.Time) int {
	h := s.hitLogFor(lb)
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.loadLocked()
	seen := map[int]bool{}
	for _, x := range h.hits {
		if !since.IsZero() && x.when.Before(since) {
			continue
		}
		seen[x.id] = true
	}
	return len(seen)
}

// ---------------------------------------------------------------------------
// The "hits" pages
// ---------------------------------------------------------------------------
//
// The hits entry points answer "what was looked at recently". Two knobs:
//
//	n      how many entries the page may list
//	since  a period such as "24 h", "7 d", "2 w", or a plain number of hours
//
// The page is a normal list page restricted to the matching IDs, so the pager,
// the display mode and the attribute columns behave identically to the plain
// list.

// HitsSince turns "24 h" / "7 days" / "3 d" / "2w" / "12" into a time bound.
func HitsSince(v string) (time.Time, bool) {
	v = TrimSpaceASCII(v)
	if v == "" {
		return time.Time{}, false
	}
	num, unit := "", ""
	for i, r := range v {
		if (r < '0' || r > '9') && r != '.' {
			num, unit = v[:i], TrimSpaceASCII(v[i:])
			break
		}
	}
	if num == "" {
		num, unit = v, "h"
	}
	n := Atoi(num)
	if n <= 0 {
		if f, ok := parseFloat(num); ok {
			return time.Now().Add(-time.Duration(f * float64(time.Hour))), true
		}
		return time.Time{}, false
	}
	switch u := strings.ToLower(unit); {
	case strings.HasPrefix(u, "m"):
		return time.Now().Add(-time.Duration(n) * time.Minute), true
	case strings.HasPrefix(u, "d"):
		return time.Now().AddDate(0, 0, -n), true
	case strings.HasPrefix(u, "w"):
		return time.Now().AddDate(0, 0, -7*n), true
	case strings.HasPrefix(u, "y"):
		return time.Now().AddDate(-n, 0, 0), true
	default:
		return time.Now().Add(-time.Duration(n) * time.Hour), true
	}
}

// hitsPage lists the entries that were displayed in the requested window.
func (s *Server) hitsPage(q *Request) {
	scope := q.Cfg
	n := s.Config.GetInt(scope, "Display", 0)
	since, hasSince := HitsSince(s.Config.GetString(scope, "Show hits for", ""))
	if v := q.Param("since"); v != "" {
		if t, ok := HitsSince(v); ok {
			since, hasSince = t, true
		}
	}
	if v := q.Param("n"); v != "" {
		n = Atoi(v)
	}
	h := s.hitLogFor(q.LB)
	if h == nil {
		s.errorPage(q, "hits are not available for this logbook")
		return
	}
	h.mu.Lock()
	h.loadLocked()
	hits := append([]hit(nil), h.hits...)
	h.mu.Unlock()

	seen := map[int]bool{}
	var picked []string
	for i := len(hits) - 1; i >= 0; i-- {
		if hasSince && hits[i].when.Before(since) {
			continue
		}
		if seen[hits[i].id] {
			continue
		}
		seen[hits[i].id] = true
		picked = append(picked, strconv.Itoa(hits[i].id))
		if n > 0 && len(picked) >= n {
			break
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(picked)))
	q.searchIDs = picked
	q.listTitle = s.loc("Recent entries")
	s.showListPage(q)
}

// ResetHits truncates the statistics of one logbook; reachable only through
// the configuration-driven maintenance actions, never from a page.
func (s *Server) ResetHits(lb *Logbook) error {
	h := s.hitLogFor(lb)
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hits = nil
	h.loaded = true
	return os.Truncate(h.path, 0)
}

// sortHitsDesc orders hit records newest first. It is an insertion sort because
// the slice is at most a few thousand entries and is already nearly ordered (the
// hit file is appended to), so the extra import of "sort" is not worth it.
func sortHitsDesc(h []hit) {
	for i := 1; i < len(h); i++ {
		for j := i; j > 0 && h[j].when.After(h[j-1].when); j-- {
			h[j], h[j-1] = h[j-1], h[j]
		}
	}
}

// logbookNamesVisible is the set of logbook names a visitor may see, which the
// "recent views" page needs but the generic LogbookNames() does not offer (that
// one takes no arguments and lists every logbook).
func (s *Server) logbookNamesVisible(user string, admin bool) []string {
	out := make([]string, 0, len(s.Order))
	for _, n := range s.Order {
		if s.IsLogbookAllowed(n, user) || admin {
			out = append(out, n)
		}
	}
	return out
}

// sortStringsDesc orders message numbers written as strings from the largest
// down, which is what the hits page hands to the list page as its ID filter.
func sortStringsDesc(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j-1] < v[j]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
