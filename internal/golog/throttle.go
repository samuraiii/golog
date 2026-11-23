package golog

// Login throttling for golog, and the split between it and the fail ban.
//
// Two layers, deliberately separate:
//
//   - The LOGIN THROTTLE (this file) is on by default. It makes the login form
//     slow and then useless for one source that keeps failing, without ever
//     delaying a correct login and without needing a second program. It lives in
//     memory: a restart clears it, which is right for something whose job is to
//     stop a script.
//
//   - The FAIL BAN (failban.go) is off by default. It is the same counting, but
//     persisted across restarts, optionally escalating, applied to the whole web
//     server rather than to the login form only, and it writes one stable log
//     line per rejected login so that fail2ban can do the actual banning in
//     iptables / the Windows firewall, which is where a real ban belongs. golog
//     does not touch the firewall itself: that needs privileges the daemon should
//     not have, and it would need OS-specific code for every platform the daemon
//     runs on.
//
// The configuration keys are the same set with two prefixes ("Login throttle"
// and "Fail ban"), documented in docs/hardening.md.
//
// Both layers key on the source address of the request, taken with
// (*Server).LoginSourceIP: the request's peer address, or the leftmost
// X-Forwarded-For entry ONLY when the peer is one of the addresses in "Trusted
// proxy" - because a ban that an attacker can point at somebody else's address
// is a denial of service tool, not a defence.

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// LoginThrottleDecision is the answer of the throttle for one login attempt.
type LoginThrottleDecision struct {
	// Blocked says this attempt must be refused without asking any back end.
	Blocked bool
	// RetryIn is how long the caller should tell the user to wait.
	RetryIn time.Duration
	// Reason is a short text for the log ("too many failed logins").
	Reason string
	// Delay is how long the caller should wait before answering, so that the
	// refusal does not answer faster than a real directory round trip.
	Delay time.Duration
}

// loginThrottleState is one counter entry.
type loginThrottleState struct {
	// fails counts the failures inside the current window.
	fails int
	// first is the start of the window that counts.
	first time.Time
	// lastFail is the time of the last failure.
	lastFail time.Time
	// blockedUntil is when the entry stops blocking.
	blockedUntil time.Time
	// generation is bumped on every block so that a block can be extended at most
	// once per blocked period (Step), not once per attempt.
	generation int
}

// LoginThrottleCfg is the configuration of one guard layer. The fail ban has its
// own settings structure in failban.go; this one drives the throttle.
type LoginThrottleCfg struct {
	// Enabled is "Login throttle"; the throttle defaults to on.
	Enabled bool
	// Max is the number of failures that triggers the block ("... max").
	Max int
	// Window is the length of the counting period in seconds ("... window").
	Window int
	// Block is how long a blocked source stays blocked in seconds ("... time").
	Block int
	// Step is the factor a block is multiplied by when the source keeps trying
	// while blocked ("... step", 1 = never escalate).
	Step float64
	// Cap is the longest a block can grow to in seconds ("... cap").
	Cap int
	// FixedDelay is the pause in front of a refused attempt in milliseconds
	// ("... delay"), so that a refusal does not look like a fast wrong answer.
	FixedDelay int
	// WindowMode is "fixed" or "sliding" ("... window mode"); both mean "restart
	// the count once the window has passed quietly" here, the spelling is kept
	// because the fail ban documents the same word.
	WindowMode string
	// By is "ip", "user" or "both" ("... by"): what a counter is keyed on.
	// "user" alone is a weak key (an attacker with a proxy pool can lock a
	// colleague out), so the default is the address.
	By string
	// Purge is how long an idle entry is kept, in seconds.
	Purge int
	// Whitelist holds addresses/CIDRs that are never counted ("... allow").
	Whitelist []string
}

// defaultLoginThrottleCfg is what an operator gets without configuring anything:
// five failures in ten minutes block the source for a minute, with no escalation
// and no artificial delay.
func defaultLoginThrottleCfg() LoginThrottleCfg {
	return LoginThrottleCfg{
		Enabled:    true,
		Max:        5,
		Window:     600,
		Block:      60,
		Step:       1,
		Cap:        3600,
		FixedDelay: 0,
		WindowMode: "sliding",
		By:         "ip",
		Purge:      3600,
	}
}

// readLoginThrottleCfg reads "<prefix> ..." keys on top of the given defaults.
func readLoginThrottleCfg(s *Server, prefix string, def LoginThrottleCfg) LoginThrottleCfg {
	c := def
	if s == nil || s.Config == nil {
		return c
	}
	g := ConfigScope{Group: "global"}
	cfg := s.Config
	// The enable switch: a present key decides, an absent key keeps the default.
	if v, ok := cfg.Get(g, prefix); ok {
		c.Enabled = Bool(v)
	}
	c.Max = positiveInt(cfg, g, prefix+" max", def.Max)
	c.Window = positiveInt(cfg, g, prefix+" window", def.Window)
	c.Block = positiveInt(cfg, g, prefix+" time", def.Block)
	if v, ok := cfg.Get(g, prefix+" step"); ok {
		c.Step = orFloat(v, def.Step)
		if c.Step < 1 {
			c.Step = 1
		}
	}
	c.Cap = positiveInt(cfg, g, prefix+" cap", def.Cap)
	c.FixedDelay = nonNegInt(cfg, g, prefix+" delay", def.FixedDelay)
	if v := TrimSpaceASCII(cfg.GetString(g, prefix+" window mode", def.WindowMode)); v != "" {
		c.WindowMode = strings.ToLower(v)
	}
	if v := TrimSpaceASCII(cfg.GetString(g, prefix+" by", def.By)); v != "" {
		c.By = strings.ToLower(v)
	}
	if c.By != "ip" && c.By != "user" && c.By != "both" {
		Logf("golog auth: unknown %s by %q, using ip", prefix, c.By)
		c.By = "ip"
	}
	c.Purge = positiveInt(cfg, g, prefix+" purge", def.Purge)
	for _, e := range cfg.GetList(g, prefix+" allow") {
		if e = TrimSpaceASCII(e); e != "" {
			c.Whitelist = append(c.Whitelist, e)
		}
	}
	return c
}

// positiveInt reads a key that must be at least 1.
func positiveInt(cfg *Config, g ConfigScope, key string, def int) int {
	v, ok := cfg.Get(g, key)
	if !ok || TrimSpaceASCII(v) == "" {
		return def
	}
	n := Atoi(v)
	if n < 1 {
		return def
	}
	return n
}

// nonNegInt reads a key that may legitimately be 0.
func nonNegInt(cfg *Config, g ConfigScope, key string, def int) int {
	v, ok := cfg.Get(g, key)
	if !ok || TrimSpaceASCII(v) == "" {
		return def
	}
	n := Atoi(v)
	if n < 0 {
		return def
	}
	return n
}

// LoginThrottle is the counter table of one layer.
type LoginThrottle struct {
	mu    sync.Mutex
	cfg   LoginThrottleCfg
	table map[string]*loginThrottleState
	now   func() time.Time
	name  string
}

// NewLoginThrottle builds a layer with the given name (for the log lines) and
// configuration.
func NewLoginThrottle(name string, cfg LoginThrottleCfg) *LoginThrottle {
	return &LoginThrottle{
		cfg:   cfg,
		table: make(map[string]*loginThrottleState),
		now:   time.Now,
		name:  name,
	}
}

// SetClock replaces the clock of the layer (tests).
func (t *LoginThrottle) SetClock(f func() time.Time) {
	if t == nil || f == nil {
		return
	}
	t.mu.Lock()
	t.now = f
	t.mu.Unlock()
}

// Configure replaces the configuration in place; a reload of the configuration
// file calls this instead of dropping the counters, because dropping them on a
// reload would be the one window an attacker can plan for.
func (t *LoginThrottle) Configure(cfg LoginThrottleCfg) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.cfg = cfg
	t.mu.Unlock()
}

// Config is a copy of the live configuration.
func (t *LoginThrottle) Config() LoginThrottleCfg {
	if t == nil {
		return defaultLoginThrottleCfg()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

// Enabled says whether the layer does anything at all.
func (t *LoginThrottle) Enabled() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg.Enabled
}

// keyOf is the counter key of an attempt: the address, the (lower-cased,
// trimmed) user name, or both, depending on "Login throttle by".
func (t *LoginThrottle) keyOf(cfg LoginThrottleCfg, user, ip string) string {
	u := strings.ToLower(TrimSpaceASCII(user))
	if u == "" {
		u = "-"
	}
	a := hostOnly(ip)
	if a == "" {
		a = "unknown"
	}
	switch cfg.By {
	case "user":
		return "u:" + u
	case "both":
		return "b:" + u + "|" + a
	default:
		return "i:" + a
	}
}

// whitelisted says whether an address is exempt from counting. The entries are
// addresses, CIDRs or interface names, exactly like "Trusted proxy", and an
// unparsable entry exempts nothing.
func (t *LoginThrottle) whitelisted(cfg LoginThrottleCfg, ip string) bool {
	if len(cfg.Whitelist) == 0 || ip == "" {
		return false
	}
	nets, _ := ParseTrustedProxies(cfg.Whitelist)
	return ipInNets(ip, nets...) != ""
}

// Check asks whether this attempt may go to a back end. It never counts: a
// blocked attempt is reported, and hammering while blocked only extends the
// block once per period (see the escalation comment below).
func (t *LoginThrottle) Check(user, ip string) LoginThrottleDecision {
	if t == nil {
		return LoginThrottleDecision{}
	}
	t.mu.Lock()
	cfg := t.cfg
	if !cfg.Enabled || t.table == nil {
		t.mu.Unlock()
		return LoginThrottleDecision{}
	}
	if t.whitelisted(cfg, ip) {
		t.mu.Unlock()
		return LoginThrottleDecision{}
	}
	key := t.keyOf(cfg, user, ip)
	st := t.table[key]
	now := t.now()
	if st == nil {
		t.mu.Unlock()
		return LoginThrottleDecision{}
	}
	if st.blockedUntil.After(now) {
		d := LoginThrottleDecision{
			Blocked: true,
			RetryIn: st.blockedUntil.Sub(now),
			Reason:  "too many failed logins",
			Delay:   time.Duration(cfg.FixedDelay) * time.Millisecond,
		}
		// Keep the block alive while the hammering goes on, but escalate at most
		// once per blocked period: an hour block must not become a year because a
		// script fired a thousand attempts during it.
		if cfg.Step > 1 && st.blockedUntil.Sub(now) < time.Duration(cfg.Block)*time.Second {
			if cfg.Cap <= 0 || st.blockedUntil.Before(now.Add(time.Duration(cfg.Cap)*time.Second)) {
				st.blockedUntil = now.Add(t.blockTime(cfg, st.generation))
				st.generation++
			}
		}
		t.mu.Unlock()
		return d
	}
	// An expired window with no recent failure: forget it so the table cannot
	// grow without bound.
	if cfg.Purge > 0 && !st.lastFail.IsZero() && now.Sub(st.lastFail) > time.Duration(cfg.Purge)*time.Second {
		delete(t.table, key)
	}
	t.mu.Unlock()
	return LoginThrottleDecision{}
}

// blockTime is the length of a block for the given escalation generation.
func (t *LoginThrottle) blockTime(cfg LoginThrottleCfg, gen int) time.Duration {
	secs := float64(cfg.Block)
	for i := 0; i < gen && i < 16; i++ {
		secs *= cfg.Step
	}
	if cfg.Cap > 0 && secs > float64(cfg.Cap) {
		secs = float64(cfg.Cap)
	}
	if secs < 1 {
		secs = 1
	}
	return time.Duration(secs * float64(time.Second))
}

// Failure records a failed login and returns what should happen now: a block may
// start with this very failure, which is what makes the counter useless for a
// spray-at-many-users attack.
func (t *LoginThrottle) Failure(user, ip string) LoginThrottleDecision {
	if t == nil {
		return LoginThrottleDecision{}
	}
	t.mu.Lock()
	cfg := t.cfg
	if !cfg.Enabled || t.whitelisted(cfg, ip) {
		t.mu.Unlock()
		return LoginThrottleDecision{}
	}
	key := t.keyOf(cfg, user, ip)
	if t.table == nil {
		t.table = make(map[string]*loginThrottleState)
	}
	st := t.table[key]
	now := t.now()
	if st == nil {
		st = &loginThrottleState{first: now}
		t.table[key] = st
	}
	if cfg.Window > 0 && now.Sub(st.first) > time.Duration(cfg.Window)*time.Second {
		// The window has passed quietly: start again, so that a slow attack
		// never accumulates a block it does not deserve.
		st.fails = 0
		st.first = now
	}
	st.fails++
	st.lastFail = now
	d := LoginThrottleDecision{}
	if cfg.Max > 0 && st.fails >= cfg.Max && !st.blockedUntil.After(now) {
		st.blockedUntil = now.Add(t.blockTime(cfg, st.generation))
		st.generation++
		d.Blocked = true
		d.RetryIn = st.blockedUntil.Sub(now)
		d.Reason = "too many failed logins"
		d.Delay = time.Duration(cfg.FixedDelay) * time.Millisecond
		t.printf("%s: blocked %s after %d failures for %s", t.layerName(),
			failBanToken(key), st.fails, st.blockedUntil.Sub(now))
	}
	t.mu.Unlock()
	return d
}

// Success clears the counter of an identity: a person who proved he knows the
// password must not stay throttled.
func (t *LoginThrottle) Success(user, ip string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	cfg := t.cfg
	if t.table != nil {
		delete(t.table, t.keyOf(cfg, user, ip))
	}
	t.mu.Unlock()
}

// layerName is the label used in the log lines; it is read with the lock held.
func (t *LoginThrottle) layerName() string {
	if t.name == "" {
		return "login throttle"
	}
	return t.name
}

// throttleOut redirects the layer's own log lines when a test sets it. It is
// package-internal on purpose: production always goes to the daemon log.
var throttleOut io.Writer

// SetLoginThrottleOutput sends the throttle's log lines to w (nil restores the
// daemon log). Tests use it to assert what an operator would see.
func SetLoginThrottleOutput(w io.Writer) { throttleOut = w }

// printf writes one log line. It is called with the mutex held, so it must not
// take it again.
func (t *LoginThrottle) printf(format string, args ...any) {
	line := sprintf("golog auth: "+format, args...)
	if w := throttleOut; w != nil {
		fmt.Fprintln(w, line)
		return
	}
	Logf("%s", line)
}

// LoginThrottleEntry is one row of the live table, for the status page.
type LoginThrottleEntry struct {
	Key        string
	Fails      int
	Blocked    bool
	BlockedFor time.Duration
	LastFail   time.Time
}

// String is the one-line form of an entry.
func (e LoginThrottleEntry) String() string {
	if e.Blocked {
		return fmt.Sprintf("%s: %d failures, blocked for %s", e.Key, e.Fails, e.BlockedFor)
	}
	return fmt.Sprintf("%s: %d failures", e.Key, e.Fails)
}

// Entries lists the table (sorted) for an administrator.
func (t *LoginThrottle) Entries() []LoginThrottleEntry {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := make([]LoginThrottleEntry, 0, len(t.table))
	for k, st := range t.table {
		e := LoginThrottleEntry{
			Key:      k,
			Fails:    st.fails,
			Blocked:  st.blockedUntil.After(now),
			LastFail: st.lastFail,
		}
		if e.Blocked {
			e.BlockedFor = st.blockedUntil.Sub(now)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Blocked != out[j].Blocked {
			return out[i].Blocked
		}
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].LastFail.After(out[j].LastFail)
	})
	return out
}

// Clear empties the table (or the counters of one identity when a key is given).
// The key may be the counter key as Entries lists it, a bare address or a bare
// user name, which is what an operator types.
func (t *LoginThrottle) Clear(key string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.table == nil {
		return 0
	}
	if key == "" {
		n := len(t.table)
		t.table = make(map[string]*loginThrottleState)
		return n
	}
	want := TrimSpaceASCII(key)
	if want == "" {
		return 0
	}
	matched := 0
	for _, c := range []string{"i:" + want, "u:" + strings.ToLower(want), want, strings.ToLower(want)} {
		if _, ok := t.table[c]; ok {
			delete(t.table, c)
			matched++
		}
	}
	if matched > 0 {
		return matched
	}
	// Substring match, so that clearing an address also clears the per-user
	// counters of that address ("both" mode) and vice versa.
	lower := strings.ToLower(want)
	for k := range t.table {
		if strings.Contains(k, want) || strings.Contains(strings.ToLower(k), lower) {
			delete(t.table, k)
			matched++
		}
	}
	return matched
}

// Stats is the one-line description of the layer for the status page.
func (t *LoginThrottle) Stats() string {
	if t == nil {
		return "login throttle: off"
	}
	t.mu.Lock()
	cfg := t.cfg
	n := 0
	for _, st := range t.table {
		if st.blockedUntil.After(t.now()) {
			n++
		}
	}
	t.mu.Unlock()
	if !cfg.Enabled {
		return "login throttle: off"
	}
	return fmt.Sprintf("login throttle: on, %d blocked, %d failure%s in %ds block for %ds (by %s)",
		n, cfg.Max, pluralY(cfg.Max), cfg.Window, cfg.Block, cfg.By)
}

// pluralY is "y" for one and "ies" for anything else.
func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// loginThrottleMessage is the browser-visible text of a blocked attempt. It says
// what to do, and nothing about the counter, so that a probe learns nothing
// beyond what the timing tells him anyway.
func loginThrottleMessage(d LoginThrottleDecision) string {
	if !d.Blocked {
		return ""
	}
	secs := int(d.RetryIn.Seconds() + 0.5)
	if secs < 1 {
		secs = 1
	}
	if secs >= 120 {
		return sprintf("Too many failed logins from this address. Try again in %d minutes.", secs/60)
	}
	return sprintf("Too many failed logins from this address. Try again in %d seconds.", secs)
}

// ---------------------------------------------------------------------------
// the process-wide layer
// ---------------------------------------------------------------------------

var (
	loginGuardsMu      sync.Mutex
	loginThrottleLayer *LoginThrottle
	loginThrottleCfg   *Config // the configuration the layer was built from
)

// LoginThrottleLayer is the process-wide login throttle ("Login throttle" keys).
// Without a server it uses the defaults, which is what an unconfigured daemon
// gets: the throttle is on.
func LoginThrottleLayer(s *Server) *LoginThrottle {
	loginGuardsMu.Lock()
	defer loginGuardsMu.Unlock()
	var cfg *Config
	if s != nil {
		cfg = s.Config
	}
	if cfg == nil {
		cfg = currentServerConfig()
	}
	if loginThrottleLayer != nil && loginThrottleCfg == cfg {
		return loginThrottleLayer
	}
	built := NewLoginThrottle("login throttle",
		readLoginThrottleCfg(s, "Login throttle", defaultLoginThrottleCfg()))
	if loginThrottleLayer != nil {
		// Configuration reload: keep the counters, change the rules.
		built.table = loginThrottleLayer.table
	}
	loginThrottleLayer = built
	loginThrottleCfg = cfg
	return loginThrottleLayer
}

// ReloadLoginGuards re-reads the throttle configuration after a configuration
// reload, keeping the counters, and logs the new state.
func ReloadLoginGuards(s *Server) {
	t := LoginThrottleLayer(s)
	logS(s, "golog auth: %s", t.Stats())
}

// CloseLoginGuards drops the process-wide layer (shutdown path, tests).
func CloseLoginGuards() {
	loginGuardsMu.Lock()
	loginThrottleLayer = nil
	loginThrottleCfg = nil
	loginGuardsMu.Unlock()
}

// SetLoginThrottleClock replaces the clock of the process-wide layer (tests).
func SetLoginThrottleClock(f func() time.Time) {
	loginGuardsMu.Lock()
	t := loginThrottleLayer
	loginGuardsMu.Unlock()
	if t == nil {
		t = LoginThrottleLayer(nil)
	}
	t.SetClock(f)
}

// ---------------------------------------------------------------------------
// the entry points the login path uses
// ---------------------------------------------------------------------------

// LoginThrottleEnabled reports whether the throttle is on for this server.
func LoginThrottleEnabled(s *Server) bool { return LoginThrottleLayer(s).Enabled() }

// LoginThrottleCheck is the guard call in front of a login: it says whether this
// attempt may reach a back end at all. It must be called BEFORE any password
// comparison, directory bind or helper process, because a refused attempt should
// cost nothing.
func LoginThrottleCheck(s *Server, user, ip string) LoginThrottleDecision {
	return LoginThrottleLayer(s).Check(user, ip)
}

// LoginThrottleFailure records that a back end rejected this attempt.
func LoginThrottleFailure(s *Server, user, ip string) LoginThrottleDecision {
	return LoginThrottleLayer(s).Failure(user, ip)
}

// LoginThrottleSuccess clears the counters of an identity that logged in.
func LoginThrottleSuccess(s *Server, user, ip string) {
	LoginThrottleLayer(s).Success(user, ip)
}

// LoginThrottleList is the live table.
func LoginThrottleList(s *Server) []LoginThrottleEntry { return LoginThrottleLayer(s).Entries() }

// LoginThrottleClear lifts counters: all of them with an empty key, otherwise the
// ones matching the given address, user name or counter key. It returns how many
// were removed.
func LoginThrottleClear(s *Server, key string) int { return LoginThrottleLayer(s).Clear(key) }

// LoginThrottleStats is the one-line status of the layer.
func LoginThrottleStats(s *Server) string { return LoginThrottleLayer(s).Stats() }
