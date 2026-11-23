// ELOG rewritten in Go - the optional fail-to-ban layer in front of logins.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// what this is, and what it is not
// ---------------------------------------------------------------------------
//
// throttle.go slows a brute-force caller down. This file stops him: after
// "Fail ban max" failed logins from one key (an address, a user name, or both)
// inside "Fail ban window", that key is refused for "Fail ban time" - and, this
// is the part that matters for security, the refusal happens *before* any back
// end is asked. A banned client causes no password comparison, no LDAP bind, no
// helper process and no Negotiate round trip, because AuthenticateLogin() asks
// this file first (see authiface.go).
//
// It is deliberately not a port of fail2ban: fail2ban watches a log file from
// the outside and installs firewall rules, which needs root, a firewall and a
// platform-specific tool. golog has no such privilege and runs on Windows as
// well as on Linux. Instead the two work together:
//
//   - golog emits one stable, machine-readable line per failed login and per
//     ban (failBanLog), so an external fail2ban can react on the daemon log.
//     See docs/fail2ban/ for a filter and a jail that match these lines.
//   - golog blocks on its own, in-process, which works everywhere the daemon
//     runs, and keeps working while fail2ban is starting up.
//
// The layer is OFF unless "Fail ban = 1" is set, so an upgrade cannot lock
// anybody out by surprise.
//
// The state is in memory and mirrored to a JSON file in the data directory so a
// restart does not hand the attacker a clean slate. It is a single process
// state: with several gologd instances behind a load balancer each bans only
// itself, and banning the whole network of the attacker is what the fail2ban
// filter is for.

// ---------------------------------------------------------------------------
// configuration (all of them global, all optional)
// ---------------------------------------------------------------------------
//
//	Fail ban = 1                   # off by default
//	Fail ban by = ip               # ip | user | both
//	Fail ban max = 5               # failures inside the window that trigger a ban
//	Fail ban window = 10m          # counting window
//	Fail ban time = 15m            # how long a ban lasts
//	Fail ban step = 2              # each further ban is multiplied by this (1 = never)
//	Fail ban max time = 1d         # cap of the multiplied ban
//	Fail ban reset = 2h            # this long without a failure clears the counters
//	Fail ban whitelist = 127.0.0.1, 10.0.0.0/8   # never counted, never banned
//	Fail ban persist = 1           # keep bans across a restart
//	Fail ban file =                # state file (default <data dir>/golog.failban.json)
//
// Durations take the s/m/h/d suffix that Config.GetDuration already accepts
// ("10m", "12h", "7d"); a plain number is seconds, like every other elogd
// duration key.

const (
	failBanFileMode = 0600
	failBanDirMode  = 0700
	// failBanKeep is how many past failures are remembered per key at most,
	// whichever way the window is configured: the memory of one key must not
	// grow without bound when the window is long.
	failBanKeep = 512
	// failBanMaxKeys bounds the table. An attacker who sprays user names must
	// not be able to grow memory without limit; the row whose ban ran out (or
	// which has been idle longest) is dropped when the table is full.
	failBanMaxKeys = 20000
	// failBanDefaultReset is the quiet period after which the counters of a
	// key forget each other.
	failBanDefaultReset = 2 * time.Hour
	// failBanStateFileName is the file the bans are mirrored to.
	failBanStateFileName = "golog.failban.json"
)

// FailBanKeyKind tells the two kinds of key apart. They share one table, so the
// kind is part of the key string and is reported to the operator.
type FailBanKeyKind string

// The kinds of key a ban can be recorded against.
const (
	FailBanIP   FailBanKeyKind = "ip"
	FailBanUser FailBanKeyKind = "user"
)

// FailBanEntry is one ban or one counted history, as FailBanList reports it.
type FailBanEntry struct {
	Kind     FailBanKeyKind `json:"kind"`
	Key      string         `json:"key"`
	BannedAt time.Time      `json:"banned_at,omitempty"`
	Until    time.Time      `json:"until,omitempty"`
	Fails    int            `json:"fails"`
	Strikes  int            `json:"strikes"`
	Last     time.Time      `json:"last,omitempty"`
}

// active reports whether the entry is a ban that is still in force at now.
func (e FailBanEntry) active(now time.Time) bool {
	return !e.Until.IsZero() && now.Before(e.Until)
}

// String is the one-line form used by the list command.
func (e FailBanEntry) String() string {
	if !e.Until.IsZero() {
		return sprintf("%s=%s banned until %s (%d failure%s)", e.Kind, e.Key,
			e.Until.Format("2006-01-02 15:04:05"), e.Fails, plural(e.Fails))
	}
	return sprintf("%s=%s %d failure%s, last %s", e.Kind, e.Key, e.Fails,
		plural(e.Fails), e.Last.Format("2006-01-02 15:04:05"))
}

// plural is the "s" of "1 failure" / "2 failures".
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// entriesWord is "entry" / "entries", spelled here because two callers need it.
func entriesWord(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}

// failBanSettings is the parsed configuration of the layer, read on every use
// so that a configuration change takes effect without a restart. A zero value
// means "off", which is what a configuration without the keys gives.
type failBanSettings struct {
	on        bool
	by        string // "ip", "user", "both"
	max       int
	window    time.Duration
	banTime   time.Duration
	maxBan    time.Duration
	step      float64
	reset     time.Duration
	whitelist []string
	persist   bool
	file      string // "" = derive from the data directory
}

// failbanDefaultSettings is what the configuration keys default to. The layer
// is off; the numbers are fail2ban's defaults (5 failures in 10 minutes)
// rounded to the values an operator of a logbook server picks.
var failbanDefaultSettings = failBanSettings{
	on:      false,
	by:      "ip",
	max:     5,
	window:  10 * time.Minute,
	banTime: 15 * time.Minute,
	maxBan:  24 * time.Hour,
	step:    1,
	reset:   failBanDefaultReset,
	persist: true,
}

// readFailBanSettings reads the "Fail ban*" keys. The scope is the global one:
// a ban is a property of the process, not of one logbook, and a per-logbook
// ban list would let an attacker keep trying through another logbook.
func readFailBanSettings(c *Config) failBanSettings {
	s := failbanDefaultSettings
	if c == nil {
		return s
	}
	cfg := ConfigScope{Group: "global"}
	s.on = c.GetFlagDefault(cfg, "Fail ban", failbanDefaultSettings.on)
	s.by = strings.ToLower(TrimSpaceASCII(c.GetStringDefault(cfg, "Fail ban by", s.by)))
	switch s.by {
	case "ip", "user", "both":
	default:
		Logf("golog auth: unknown Fail ban by %q, using ip", s.by)
		s.by = "ip"
	}
	if n := c.GetInt(cfg, "Fail ban max", s.max); n > 0 {
		s.max = n
	}
	s.window = c.GetDuration(cfg, "Fail ban window", s.window)
	s.banTime = c.GetDuration(cfg, "Fail ban time", s.banTime)
	s.maxBan = c.GetDuration(cfg, "Fail ban max time", s.maxBan)
	if s.banTime <= 0 {
		s.banTime = failbanDefaultSettings.banTime
	}
	if s.window <= 0 {
		s.window = failbanDefaultSettings.window
	}
	if s.maxBan < s.banTime {
		s.maxBan = s.banTime
	}
	s.step = 1
	if v, ok := c.Get(cfg, "Fail ban step"); ok && TrimSpaceASCII(v) != "" {
		if f, err := strconv.ParseFloat(TrimSpaceASCII(v), 64); err == nil && f >= 1 {
			s.step = f
		}
	}
	s.reset = c.GetDuration(cfg, "Fail ban reset", s.reset)
	s.whitelist = c.GetList(cfg, "Fail ban whitelist")
	s.persist = c.GetFlagDefault(cfg, "Fail ban persist", failbanDefaultSettings.persist)
	s.file = TrimSpaceASCII(c.GetStringDefault(cfg, "Fail ban file", ""))
	return s
}

// ---------------------------------------------------------------------------
// the table
// ---------------------------------------------------------------------------

// failBanKey is one row of the table: the failures of the current window plus
// the ban they produced, if any.
type failBanKey struct {
	Kind FailBanKeyKind `json:"kind"`
	Key  string         `json:"key"`

	// Fails are the timestamps of the failures still inside the window, oldest
	// first. Timestamps rather than a counter because the window slides.
	Fails []time.Time `json:"fails,omitempty"`
	// Strikes counts the bans that followed each other without a successful
	// login in between; it drives the "Fail ban step" multiplication.
	Strikes int `json:"strikes,omitempty"`
	// Banned and Until are the ban in force, zero when none is.
	Banned time.Time `json:"banned,omitempty"`
	Until  time.Time `json:"until,omitempty"`
	// Last is the last event of any kind, used to expire the history and to
	// order the eviction of a full table.
	Last time.Time `json:"last,omitempty"`
}

// entry flattens the row for the list API.
func (k *failBanKey) entry() FailBanEntry {
	return FailBanEntry{
		Kind: k.Kind, Key: k.Key, BannedAt: k.Banned, Until: k.Until,
		Fails: len(k.Fails), Strikes: k.Strikes, Last: k.Last,
	}
}

// failBanTable is the state of the layer. One mutex, no background goroutine:
// the pruning that keeps the table small runs inline on write, which is cheap
// (a few hundred rows) and avoids a timer to stop in tests and on shutdown.
type failBanTable struct {
	mu sync.Mutex

	// clock is time.Now; a test replaces it to move time forward.
	clock func() time.Time
	// out is where the fail2ban-parseable lines go; nil means the daemon log.
	out io.Writer
	// loaded guards the one-off read of the state file.
	loaded bool
	// path is the state file in force, resolved on first use.
	path string
	// rows are the keys, indexed by "<kind>:<key>".
	rows map[string]*failBanKey
	// settings are the settings the table was last consulted with, kept only
	// so that a change of the configuration is visible in the log.
	settings failBanSettings
	// dirty says the file is behind the table.
	dirty bool
	// saved is the last time the file was written, to rate the writes.
	saved time.Time
}

// globalFailBan is the process-wide table. golog runs as a single daemon with
// one configuration, like the C program it replaces; the login handlers reach
// the table through the Server anyway (failBanFor), so a test that wants a
// private table can build one.
var globalFailBan = &failBanTable{clock: time.Now, rows: map[string]*failBanKey{}}

// FailBanTable is the exported handle on the layer, so that an administrative
// command or a test can hold one.
type FailBanTable = failBanTable

// SetFailBanClock points the layer at another clock (tests). Passing nil puts
// time.Now back. It touches the process-wide table only.
func SetFailBanClock(f func() time.Time) {
	globalFailBan.mu.Lock()
	defer globalFailBan.mu.Unlock()
	if f == nil {
		f = time.Now
	}
	globalFailBan.clock = f
}

// SetFailBanOutput sends the fail2ban-parseable lines to w instead of the
// daemon log (tests). Passing nil puts the daemon log back.
func SetFailBanOutput(w io.Writer) {
	globalFailBan.mu.Lock()
	defer globalFailBan.mu.Unlock()
	globalFailBan.out = w
}

// ResetFailBanState forgets the loaded state and reads the file again (tests and
// the administrative "reload" path).
func ResetFailBanState() {
	globalFailBan.mu.Lock()
	globalFailBan.loaded = false
	globalFailBan.rows = map[string]*failBanKey{}
	globalFailBan.path = ""
	globalFailBan.mu.Unlock()
}

// now is the table's clock; the caller holds the mutex.
func (t *failBanTable) now() time.Time {
	if t.clock == nil {
		return time.Now()
	}
	return t.clock()
}

// log writes one fail2ban-parseable line. With no redirect it goes through the
// package logger, so it carries the daemon's own timestamp prefix and lands
// wherever the daemon log goes (file with -l, stderr, the event log on Windows).
func (t *failBanTable) log(format string, args ...any) {
	if t.out != nil {
		fmt.Fprintf(t.out, format+"\n", args...)
		return
	}
	Logf(format, args...)
}

// rowID builds the index of a key. The kind is part of it so that a user named
// "10.0.0.7" and that address cannot share a row.
func failBanRowID(kind FailBanKeyKind, key string) string {
	return string(kind) + ":" + key
}

// loadLocked reads the persisted bans once per process (or after
// ResetFailBanState). A broken file is logged and ignored: a corrupt ban list
// must not keep the daemon from starting, and it must not silently disable the
// layer either, hence the log line.
func (t *failBanTable) loadLocked(set failBanSettings) {
	if t.loaded {
		return
	}
	t.loaded = true
	if t.rows == nil {
		t.rows = map[string]*failBanKey{}
	}
	if !set.persist {
		return
	}
	path := t.pathLocked(set)
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			t.log("golog auth: fail ban state %s not read: %v", path, err)
		}
		return
	}
	var st struct {
		Version int           `json:"version"`
		SavedAt time.Time     `json:"saved_at"`
		Rows    []*failBanKey `json:"rows"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.log("golog auth: fail ban state %s not understood, starting empty: %v", path, err)
		return
	}
	now := t.now()
	for _, r := range st.Rows {
		if r == nil || r.Key == "" {
			continue
		}
		if r.Kind != FailBanIP && r.Kind != FailBanUser {
			continue
		}
		if !r.Until.IsZero() && !now.Before(r.Until) {
			continue // expired while we were down
		}
		if len(r.Fails) > failBanKeep {
			r.Fails = append([]time.Time(nil), r.Fails[len(r.Fails)-failBanKeep:]...)
		}
		t.rows[failBanRowID(r.Kind, r.Key)] = r
	}
}

// pathLocked is the state file to use, "" when the layer must not persist.
func (t *failBanTable) pathLocked(set failBanSettings) string {
	if !set.persist {
		return ""
	}
	if set.file != "" {
		return set.file
	}
	if t.path != "" {
		return t.path
	}
	dir := ""
	if s := currentServer(); s != nil {
		dir = s.DataDir
		if dir == "" {
			dir = filepath.Dir(s.ConfigPath)
		}
	}
	if dir == "" || dir == "." {
		return ""
	}
	t.path = filepath.Join(dir, failBanStateFileName)
	return t.path
}

// saveLocked writes the bans back. It is called after a ban is created or
// lifted and at most once a second otherwise, so a flood of failures does not
// turn into a flood of file writes. The write is atomic (temporary file plus
// rename) because the file is read again at startup and a half-written file
// would look like a corrupt one.
func (t *failBanTable) saveLocked(set failBanSettings) {
	t.dirty = false
	path := t.pathLocked(set)
	if path == "" {
		return
	}
	now := t.now()
	if !t.saved.IsZero() && now.Sub(t.saved) < time.Second && len(t.rows) > 0 {
		// Rate-limited: remember that the file is behind and write on the next
		// event that is not inside the same second.
		t.dirty = true
		return
	}
	t.saved = now

	bans := make([]*failBanKey, 0, len(t.rows))
	for _, r := range t.rows {
		if r.Until.IsZero() {
			continue // only bans matter across a restart
		}
		if !now.Before(r.Until) {
			continue
		}
		cp := *r
		cp.Fails = append([]time.Time(nil), r.Fails...)
		bans = append(bans, &cp)
	}
	sort.Slice(bans, func(i, j int) bool {
		if bans[i].Until.Equal(bans[j].Until) {
			return bans[i].Key < bans[j].Key
		}
		return bans[i].Until.Before(bans[j].Until)
	})
	data, err := json.MarshalIndent(struct {
		Version int           `json:"version"`
		SavedAt time.Time     `json:"saved_at"`
		Rows    []*failBanKey `json:"rows"`
	}{Version: 1, SavedAt: now, Rows: bans}, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, failBanDirMode); err != nil {
		t.log("golog auth: fail ban state %s not written: %v", path, err)
		return
	}
	tmp, err := os.CreateTemp(dir, ".golog.failban.*")
	if err != nil {
		t.log("golog auth: fail ban state %s not written: %v", path, err)
		return
	}
	name := tmp.Name()
	written := false
	defer func() {
		tmp.Close()
		if !written {
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(failBanFileMode); err != nil {
		t.log("golog auth: fail ban state %s could not be protected: %v", path, err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		t.log("golog auth: fail ban state %s not written: %v", path, err)
		return
	}
	if err := tmp.Sync(); err != nil {
		t.log("golog auth: fail ban state %s not written: %v", path, err)
		return
	}
	if err := tmp.Close(); err != nil {
		t.log("golog auth: fail ban state %s not written: %v", path, err)
		return
	}
	if err := os.Rename(name, path); err != nil {
		t.log("golog auth: fail ban state %s not written: %v", path, err)
		return
	}
	written = true
}

// pruneLocked drops what no longer counts: expired bans, failures outside the
// window, rows with nothing left. It runs before every read and write so the
// table cannot grow with history nobody needs.
func (t *failBanTable) pruneLocked(set failBanSettings, now time.Time) {
	for id, r := range t.rows {
		if !r.Until.IsZero() && !now.Before(r.Until) {
			r.Until = time.Time{}
			r.Banned = time.Time{}
		}
		keep := r.Fails[:0]
		for _, ts := range r.Fails {
			if now.Sub(ts) <= set.window {
				keep = append(keep, ts)
			}
		}
		r.Fails = keep
		if len(r.Fails) > failBanKeep {
			r.Fails = append([]time.Time(nil), r.Fails[len(r.Fails)-failBanKeep:]...)
		}
		if !r.Until.IsZero() {
			continue
		}
		if len(r.Fails) == 0 && r.Strikes == 0 {
			delete(t.rows, id)
			continue
		}
		if set.reset > 0 && !r.Last.IsZero() && now.Sub(r.Last) > set.reset {
			// Quiet for the reset period: the strikes of a finished ban are
			// forgotten, the counted failures of a live window are not.
			r.Strikes = 0
			if len(r.Fails) == 0 {
				delete(t.rows, id)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// keys and the whitelist
// ---------------------------------------------------------------------------

// failBanUserKey is the key a user name maps onto. It is compared
// case-insensitively like every other name in golog, and an empty name is not a
// key at all - a ban on "" would lock everybody who has not typed a name yet
// out of the login page, which is exactly the denial of service this layer is
// supposed to prevent.
func failBanUserKey(user string) string {
	user = TrimSpaceASCII(user)
	if user == "" {
		return ""
	}
	return strings.ToLower(user)
}

// failBanIPKey is the key an address maps onto: the canonical text form, so
// that "10.0.0.7", " 10.0.0.7 " and "::ffff:10.0.0.7" share a row. An
// unparseable address is not a key.
func failBanIPKey(ip string) string {
	ip = TrimSpaceASCII(ip)
	if ip == "" {
		return ""
	}
	if i := strings.LastIndex(ip, "%"); i > 0 { // IPv6 zone
		ip = ip[:i]
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		if host, _, err := net.SplitHostPort(ip); err == nil {
			parsed = net.ParseIP(host)
			ip = host
		}
	}
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// failBanKeyPair is one (kind, key) a login attempt belongs to.
type failBanKeyPair struct {
	kind FailBanKeyKind
	key  string
}

// failBanKeys returns the keys a failure at (user, ip) belongs to under the
// configured policy.
func failBanKeys(set failBanSettings, user, ip string) []failBanKeyPair {
	var out []failBanKeyPair
	add := func(kind FailBanKeyKind, key string) {
		if key == "" {
			return
		}
		out = append(out, failBanKeyPair{kind: kind, key: key})
	}
	switch set.by {
	case "user":
		add(FailBanUser, failBanUserKey(user))
	case "both":
		add(FailBanUser, failBanUserKey(user))
		add(FailBanIP, failBanIPKey(ip))
	default:
		add(FailBanIP, failBanIPKey(ip))
	}
	return out
}

// failBanWhitelisted reports whether ip is on the never-ban list. An address
// that cannot be parsed is not whitelisted: a typo in the configuration must
// not open a hole.
func failBanWhitelisted(set failBanSettings, ip string) bool {
	if len(set.whitelist) == 0 {
		return false
	}
	parsed := net.ParseIP(failBanIPKey(ip))
	if parsed == nil {
		return false
	}
	for _, item := range set.whitelist {
		for _, netOrIP := range strings.Split(item, ",") {
			netOrIP = TrimSpaceASCII(netOrIP)
			if netOrIP == "" {
				continue
			}
			if strings.Contains(netOrIP, "/") {
				_, block, err := net.ParseCIDR(netOrIP)
				if err != nil {
					continue
				}
				if block.Contains(parsed) {
					return true
				}
				continue
			}
			if other := net.ParseIP(netOrIP); other != nil && other.Equal(parsed) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// the three operations
// ---------------------------------------------------------------------------

// failBanFor returns the table a server uses. Today there is one table per
// process; the indirection is here so that a future multi-tenant server can
// have one per configuration without touching the callers.
func (s *Server) failBanFor() *failBanTable { return globalFailBan }

// failBanSettings reads the layer's configuration for this server.
func (s *Server) failBanSettings() failBanSettings {
	var c *Config
	if s != nil {
		c = s.Config
	}
	if c == nil {
		c = currentServerConfig()
	}
	return readFailBanSettings(c)
}

// check is the worker behind FailBanCheck: is this caller banned?
//
// It returns the seconds to put into Retry-After (0 when not banned) and the
// reason for the log line. A positive answer is the only thing a caller needs to
// know: ask no back end, answer 429.
func (t *failBanTable) check(set failBanSettings, user, ip string) (int, string) {
	if !set.on {
		return 0, ""
	}
	if failBanWhitelisted(set, ip) {
		return 0, ""
	}
	keys := failBanKeys(set, user, ip)
	if len(keys) == 0 {
		return 0, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.settings = set
	t.loadLocked(set)
	now := t.now()
	t.pruneLocked(set, now)
	secs, why := 0, ""
	for _, k := range keys {
		r := t.rows[failBanRowID(k.kind, k.key)]
		if r == nil || r.Until.IsZero() || !now.Before(r.Until) {
			continue
		}
		left := r.Until.Sub(now)
		n := int((left + time.Second - 1) / time.Second)
		if n < 1 {
			n = 1
		}
		if secs == 0 || n < secs {
			secs = n
			why = sprintf("too many failed logins for %s %s", k.kind, k.key)
		}
	}
	return secs, why
}

// failure is the worker behind FailBanFailure: record one failed login.
func (t *failBanTable) failure(set failBanSettings, user, ip string) (int, string) {
	if !set.on {
		return 0, ""
	}
	if failBanWhitelisted(set, ip) {
		return 0, ""
	}
	keys := failBanKeys(set, user, ip)
	if len(keys) == 0 {
		return 0, ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.settings = set
	t.loadLocked(set)
	now := t.now()
	t.pruneLocked(set, now)

	secs, why := 0, ""
	bannedNow := false
	for _, k := range keys {
		id := failBanRowID(k.kind, k.key)
		r := t.rows[id]
		if r == nil {
			if len(t.rows) >= failBanMaxKeys {
				if !t.evictLocked(now) {
					continue
				}
			}
			r = &failBanKey{Kind: k.kind, Key: k.key}
			t.rows[id] = r
		}
		r.Last = now
		if !r.Until.IsZero() && now.Before(r.Until) {
			// Already banned; do not extend the ban on every attempt, that
			// would let a persistent attacker ban himself forever.
			left := int((r.Until.Sub(now) + time.Second - 1) / time.Second)
			if left < 1 {
				left = 1
			}
			if secs == 0 || left < secs {
				secs = left
			}
			continue
		}
		// Forget failures that are older than the window before counting.
		keep := r.Fails[:0]
		for _, ts := range r.Fails {
			if now.Sub(ts) <= set.window {
				keep = append(keep, ts)
			}
		}
		r.Fails = append(keep, now)
		if len(r.Fails) > failBanKeep {
			r.Fails = r.Fails[len(r.Fails)-failBanKeep:]
		}
		if len(r.Fails) < set.max {
			continue
		}
		d := failBanDuration(set, r.Strikes+1)
		r.Strikes++
		r.Banned = now
		r.Until = now.Add(d)
		r.Fails = nil
		bannedNow = true
		// The line fail2ban's filter.d/golog.conf matches. A user ban cannot
		// be acted on by a firewall, so the address is reported next to it
		// when it is known.
		if k.kind == FailBanIP {
			t.log("golog auth: banned ip=%s for %s", failBanToken(k.key), d)
		} else {
			t.log("golog auth: banned user=%s ip=%s for %s", failBanToken(k.key),
				failBanToken(failBanIPKey(ip)), d)
		}
		why = sprintf("too many failed logins: %s %s is blocked", k.kind, k.key)
		secs = int((d + time.Second - 1) / time.Second)
	}
	if bannedNow {
		t.saveLocked(set)
	}
	return secs, why
}

// evictLocked makes room for one more key by dropping the row whose ban ran out
// (or whose last event is the oldest). It reports whether it made room.
func (t *failBanTable) evictLocked(now time.Time) bool {
	var oldestID string
	var oldest time.Time
	for id, r := range t.rows {
		if r.Until.IsZero() || !now.Before(r.Until) {
			delete(t.rows, id)
			return true
		}
		if oldestID == "" || r.Last.Before(oldest) {
			oldestID, oldest = id, r.Last
		}
	}
	if oldestID == "" {
		return false
	}
	delete(t.rows, oldestID)
	return true
}

// failBanDuration is the ban of the n-th strike: "Fail ban time" multiplied by
// "Fail ban step" to the power of n-1, capped at "Fail ban max time". With the
// default step of 1 every ban has the same length, which is the behaviour
// fail2ban shows; a step of 2 gives 15m, 30m, 1h, ... up to the cap.
func failBanDuration(set failBanSettings, strike int) time.Duration {
	d := set.banTime
	if strike > 1 && set.step > 1 {
		f := float64(set.banTime)
		for i := 1; i < strike; i++ {
			f *= set.step
			if time.Duration(f) >= set.maxBan {
				return set.maxBan
			}
		}
		d = time.Duration(f)
	}
	if d > set.maxBan {
		d = set.maxBan
	}
	if d < time.Second {
		d = time.Second
	}
	return d
}

// success is the worker behind FailBanSuccess: the caller proved who he is, so
// his counters are cleared. Without this a user who mistyped his password four
// times every morning would be banned at some point even though every login but
// the last one succeeded.
func (t *failBanTable) success(set failBanSettings, user, ip string) {
	if !set.on {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked(set)
	now := t.now()
	changed := false
	for _, k := range failBanKeys(set, user, ip) {
		r := t.rows[failBanRowID(k.kind, k.key)]
		if r == nil {
			continue
		}
		if len(r.Fails) > 0 || r.Strikes != 0 {
			changed = true
		}
		r.Fails = nil
		r.Strikes = 0
		r.Last = now
		// A successful login does not lift a ban that is already running: a
		// stolen password still belongs to its owner, but somebody who is
		// banned must wait. (Lifting it would let an attacker who guesses one
		// password of a sprayed account clear the address for the rest.)
		if r.Until.IsZero() {
			delete(t.rows, failBanRowID(k.kind, k.key))
		}
	}
	if changed {
		t.saveLocked(set)
	}
}

// failBanToken makes a value safe for a key=value log line: no blanks, no
// control characters, no newline, so that one line stays one line and a regex
// cannot be confused by a crafted user name. Empty yields "-", like fail2ban's
// example filters do.
func failBanToken(s string) string {
	s = TrimSpaceASCII(s)
	if s == "" {
		return "-"
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f':
			sb.WriteByte('_')
		case r < 0x20 || r == 0x7f:
			sb.WriteByte('?')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// the exported API
// ---------------------------------------------------------------------------

// FailBanEnabled reports whether the layer is switched on for the current
// configuration.
func (s *Server) FailBanEnabled() bool { return s.failBanSettings().on }

// FailBanCheck reports whether this caller is banned before any back end is
// asked. A positive answer means: answer the request now (429 with
// Retry-After), do not compare a password, do not contact a directory.
//
// user is the name from the login form ("" when there is none yet), ip the
// client address as returned by (*Server).LoginSourceIP - the address of a
// trusted proxy is already unwrapped there.
func (s *Server) FailBanCheck(user, ip string) (banned bool, retryAfter time.Duration) {
	secs, why := s.failBanFor().check(s.failBanSettings(), user, ip)
	if secs <= 0 {
		return false, 0
	}
	Infof("golog auth: refused login from %s: %s", failBanToken(failBanIPKey(ip)), why)
	return true, time.Duration(secs) * time.Second
}

// FailBanFailure records one failed login and reports whether it triggered a ban
// (with its length). Call it from the place that knows the password did not
// match: the ban must be a consequence of a real authentication failure, not of
// a broken back end.
func (s *Server) FailBanFailure(user, ip string) (banned bool, retryAfter time.Duration) {
	secs, _ := s.failBanFor().failure(s.failBanSettings(), user, ip)
	if secs <= 0 {
		return false, 0
	}
	return true, time.Duration(secs) * time.Second
}

// FailBanSuccess forgets the failures of a caller who authenticated.
func (s *Server) FailBanSuccess(user, ip string) {
	s.failBanFor().success(s.failBanSettings(), user, ip)
}

// FailBanLogFailedLogin emits the fail2ban-parseable line for one failed login.
// The login handlers already log their failures; this helper is here so that
// every failure is written in exactly one spelling.
//
// The line is
//
//	<daemon timestamp> golog auth: login failed user=<u> ip=<ip>
//
// where <u> is the name as typed (sanitized with failBanToken, so never blank,
// never a control character, never a newline) and <ip> the canonical address or
// "-". The name is NOT lower-cased: an operator reading the log, and the
// fail2ban whois action, need what the client actually sent.
// See docs/fail2ban/ for the filter that matches it.
func (s *Server) FailBanLogFailedLogin(user, ip string) {
	t := s.failBanFor()
	t.mu.Lock()
	out := t.out
	t.mu.Unlock()
	line := sprintf("golog auth: login failed user=%s ip=%s",
		failBanToken(user), failBanToken(failBanIPKey(ip)))
	if out != nil {
		fmt.Fprintln(out, line)
		return
	}
	logS(s, "%s", line)
}

// FailBanList is the administrative view: every key with a ban in force or with
// failures counted in the current window, bans first, then by name. Keys with
// no history are not listed, so the output is short in normal operation.
func (s *Server) FailBanList() []FailBanEntry {
	set := s.failBanSettings()
	t := s.failBanFor()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked(set)
	now := t.now()
	t.pruneLocked(set, now)
	out := make([]FailBanEntry, 0, len(t.rows))
	for _, r := range t.rows {
		out = append(out, r.entry())
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].active(now), out[j].active(now)
		if ai != aj {
			return ai
		}
		if ai && !out[i].Until.Equal(out[j].Until) {
			return out[i].Until.Before(out[j].Until)
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// FailBanClear removes the rows belonging to one key: an address clears the ip
// rows, a name clears the user rows, and anything else (a host name, a name that
// is also an address) clears both kinds when its key matches. It reports how
// many rows were removed. Clearing is an administrative action: whoever can
// reach it can lift a ban, so it is not exposed on any page by default.
func (s *Server) FailBanClear(key string) int {
	set := s.failBanSettings()
	t := s.failBanFor()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked(set)
	want := TrimSpaceASCII(key)
	if want == "" {
		return 0
	}
	n := 0
	ips := failBanIPKey(want)
	usr := failBanUserKey(want)
	for id, r := range t.rows {
		match := false
		switch r.Kind {
		case FailBanIP:
			match = ips != "" && r.Key == ips
		case FailBanUser:
			match = usr != "" && r.Key == usr
		}
		if !match {
			continue
		}
		delete(t.rows, id)
		n++
	}
	if n > 0 {
		t.log("golog auth: unbanned %s (%d %s lifted)", failBanToken(want), n, entriesWord(n))
		t.saveLocked(set)
	}
	return n
}

// FailBanClearAll drops every ban and every counted failure. It is the panic
// button after a misconfiguration locked the operators out; the log records it
// because a ban list that can be emptied silently is not much of a protection.
func (s *Server) FailBanClearAll() int {
	set := s.failBanSettings()
	t := s.failBanFor()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked(set)
	n := len(t.rows)
	t.rows = map[string]*failBanKey{}
	if n > 0 {
		t.log("golog auth: fail ban list cleared (%d %s dropped)", n, entriesWord(n))
		t.saveLocked(set)
	}
	return n
}

// FailBanStats is the one-line summary for a status page. Nothing secret: the
// configured numbers and how many keys are banned right now.
func (s *Server) FailBanStats() string {
	set := s.failBanSettings()
	if !set.on {
		return "fail ban: off"
	}
	bans := 0
	for _, e := range s.FailBanList() {
		if e.active(s.failBanFor().now()) {
			bans++
		}
	}
	return sprintf("fail ban: on, %d banned, ban after %d failure%s in %s, ban time %s, by %s",
		bans, set.max, plural(set.max), set.window, set.banTime, set.by)
}

// FailBanWriteState writes the table to its file now (the administrative path;
// the normal path writes when a ban changes). It reports the file it wrote, or
// "" when the layer does not persist.
func (s *Server) FailBanWriteState() string {
	set := s.failBanSettings()
	t := s.failBanFor()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked(set)
	path := t.pathLocked(set)
	t.dirty = false
	t.saved = time.Time{}
	t.saveLocked(set)
	return path
}
