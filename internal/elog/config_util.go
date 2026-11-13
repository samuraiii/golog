package elog

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration: the helpers getcfg() callers actually use
// ---------------------------------------------------------------------------
//
// config.go holds the parser and the getcfg() lookup chain; this file holds the
// typed accessors and the logbook-specific derived values (attribute lists,
// option lists, ...). Every accessor mirrors one idiom from elogd.cxx, and the
// comment names it, because the whole point of the port is that a value read
// here behaves like the value the C code read from the same file.

// GetStringDefault is GetParameter(): the value, or def when the key is absent
// *or empty* - the C helper treats an empty value as "not set", which is why it
// exists next to GetString (which follows getcfg() and does accept empty).
func (c *Config) GetStringDefault(scope ConfigScope, param, def string) string {
	v, ok := c.Get(scope, param)
	if !ok || TrimSpaceASCII(v) == "" {
		return def
	}
	return v
}

// GetFlag is the "atoi(getcfg(...)) != 0" switch of the original, but also
// accepts yes/no/true/false/on/off because many shipped configuration files use
// them (elogd's TRUE() macro does).
func (c *Config) GetFlag(scope ConfigScope, param string) bool {
	return c.GetFlagDefault(scope, param, false)
}

// GetFlagDefault is GetFlag with an explicit default.
func (c *Config) GetFlagDefault(scope ConfigScope, param string, def bool) bool {
	v, ok := c.Get(scope, param)
	if !ok || TrimSpaceASCII(v) == "" {
		return def
	}
	return Bool(v)
}

// GetBoolDefault is atoi-style truth with a default, matching
// "if (getcfg(...) == 1)"; an absent key gives def.
func (c *Config) GetBoolDefault(scope ConfigScope, param string, def bool) bool {
	v, ok := c.Get(scope, param)
	if !ok {
		return def
	}
	return Atoi(v) != 0
}

// Hours is the "Login expiration"-style float-in-hours value (atof()).
func (c *Config) Hours(scope ConfigScope, param string, def float64) float64 {
	v, ok := c.Get(scope, param)
	if !ok || TrimSpaceASCII(v) == "" {
		return def
	}
	f, ok := parseFloat(v)
	if !ok {
		return def
	}
	return f
}

// GetDuration reads a value that elogd stores in seconds ("Lock timeout",
// "Expires", ...). A unit suffix is accepted because a few keys are documented
// with one ("10 m").
func (c *Config) GetDuration(scope ConfigScope, param string, def time.Duration) time.Duration {
	v, ok := c.Get(scope, param)
	if !ok || TrimSpaceASCII(v) == "" {
		return def
	}
	v = TrimSpaceASCII(v)
	mult := time.Second
	if i := strings.IndexAny(v, "smhd"); i > 0 {
		switch v[i] {
		case 's':
			mult = time.Second
		case 'm':
			mult = time.Minute
		case 'h':
			mult = time.Hour
		case 'd':
			mult = 24 * time.Hour
		}
		v = TrimSpaceASCII(v[:i])
	}
	n := Atoi(v)
	if n == 0 {
		return def
	}
	return time.Duration(n) * mult
}

// GetList splits a comma separated list parameter the way the original walks
// them with strbreak(): blanks around items are dropped, empty items ignored.
func (c *Config) GetList(scope ConfigScope, param string) []string {
	v, ok := c.Get(scope, param)
	if !ok {
		return nil
	}
	return SplitList(v, ",", false)
}

// IntList is GetList for the numeric lists ("Display", "Page length", the
// "Expires" seconds list).
func (c *Config) IntList(scope ConfigScope, param string) []int {
	var out []int
	for _, s := range c.GetList(scope, param) {
		out = append(out, Atoi(s))
	}
	return out
}

// GetAll returns every value stored under the same key. elogd's display code
// iterates the section array directly for the repeatable keys
// ("Attribute = ..." repeated, "Options xxx" repeated in older files), so a
// single-key lookup is not enough there.
func (c *Config) GetAll(scope ConfigScope, param string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.getAllLocked(scope, param)
}

func (c *Config) getAllLocked(scope ConfigScope, param string) []string {
	var out []string
	s := c.sectionLocked(scope.Group)
	up := strings.ToUpper(param)
	if s != nil {
		for _, p := range s.Params {
			if MatchParam(p.UPKey, up, scope.Condition, false) {
				out = append(out, p.Value)
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	if scope.Group == "" || IsLogbookName(scope.Group) {
		sub := scope
		sub.Group = "global"
		if !sameScope(sub, scope) {
			out = c.getAllLocked(sub, param)
		}
	}
	return out
}

func sameScope(a, b ConfigScope) bool {
	return EqualFold(a.Group, b.Group) && a.Condition == b.Condition
}

// Params lists the parameters of one section in file order (the configuration
// page and the "Attribute" scan both need the order).
func (c *Config) Params(section string) []Param {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.sectionLocked(section)
	if s == nil {
		return nil
	}
	out := make([]Param, len(s.Params))
	copy(out, s.Params)
	return out
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

// AttributeNames is the "Attribute" key: the ordered list of user attributes of
// a logbook. The value is a comma separated list; a logbook without the key has
// no extra attributes (elogd then shows only Date/Author/Text).
func (c *Config) AttributeNames(scope ConfigScope) []string {
	var out []string
	for _, v := range c.GetAll(scope, "Attribute") {
		for _, a := range SplitList(v, ",", false) {
			if a == "" || hasName(out, a) {
				continue
			}
			out = append(out, a)
		}
	}
	return out
}

func hasName(list []string, name string) bool {
	for _, x := range list {
		if EqualFold(x, name) {
			return true
		}
	}
	return false
}

// OptionsFor is the "Options <Attribute>" key: the fixed value list of one
// attribute (a drop-down instead of a text box). Several spellings appear in the
// wild, all of which the C code accepted because the comparison is
// case-insensitive and the key is built by concatenation.
func (c *Config) OptionsFor(scope ConfigScope, attr string) []string {
	keys := []string{"Options " + attr, "Options" + attr, "options " + attr}
	for _, k := range keys {
		if v, ok := c.FirstOf(scope, k); ok && TrimSpaceASCII(v) != "" {
			return SplitList(v, ",", false)
		}
	}
	// "Attribute = Category:one,two,three" is the other documented form.
	for _, a := range c.GetAll(scope, "Attribute") {
		for _, item := range SplitList(a, ",", false) {
			name, opts, found := strings.Cut(item, ":")
			if found && EqualFold(TrimSpaceASCII(name), attr) {
				return SplitList(opts, ",", false)
			}
		}
	}
	return nil
}

// MandatoryAttrs is "Mandatory attribute" (a comma separated list of attribute
// names that must not be empty on submit).
func (c *Config) MandatoryAttrs(scope ConfigScope) []string {
	var out []string
	for _, v := range c.GetAll(scope, "Mandatory attribute") {
		for _, a := range SplitList(v, ",", false) {
			if a != "" && !hasName(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// DisplayedAttrs is "Display in List": the columns of the list page, in the
// order given there. With no second argument the logbook's own attribute list is
// used as the universe; a leading "-" removes a column.
func (c *Config) DisplayedAttrs(scope ConfigScope, all ...string) []string {
	universe := append([]string{}, all...)
	if len(universe) == 0 {
		universe = c.AttributeNames(scope)
	}
	list := c.GetList(scope, "Display in List")
	if len(list) == 0 {
		return universe
	}
	out := make([]string, 0, len(list))
	for _, want := range list {
		if strings.HasPrefix(want, "-") {
			continue
		}
		if want == "" {
			continue
		}
		// Take the configured spelling when the logbook knows it, so the
		// header label is the attribute's canonical name.
		name := want
		for _, u := range universe {
			if EqualFold(u, want) {
				name = u
				break
			}
		}
		if hasName(out, name) {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return universe
	}
	return out
}

// ---------------------------------------------------------------------------
// Editing and reloading
// ---------------------------------------------------------------------------

// ConfigDir is the directory of the configuration file, the base for relative
// "Dir" and "Password file" values when no -d directory was given (elogd
// resolves them against the current working directory, which for a daemon
// started from its own directory is the same thing).
func (c *Config) ConfigDir() string {
	if c.fileName == "" {
		return "."
	}
	abs, err := filepath.Abs(c.fileName)
	if err != nil {
		return filepath.Dir(c.fileName)
	}
	return filepath.Dir(abs)
}

// SetParam changes (or adds) one key inside a section and writes the file back.
// elogd's save_param() rewrites the whole file from its in-memory arrays; here
// the file is rewritten in the same canonical layout the parser produces, which
// loses comments - the same trade-off the original makes.
func (c *Config) SetParam(sectionName, key, value string) error {
	c.Set(sectionName, key, value)
	return c.Save()
}

// Save writes the configuration back.
func (c *Config) Save() error {
	c.mu.RLock()
	name := c.fileName
	c.mu.RUnlock()
	if name == "" {
		return os.ErrInvalid
	}
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, []byte(c.Dump("")), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// Dump renders the configuration (all sections, or just one) in the canonical
// form the parser reads back.
func (c *Config) Dump(section string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var b strings.Builder
	for _, s := range c.Sections {
		if section != "" && !EqualFold(s.Name, section) {
			continue
		}
		b.WriteString("[" + s.Name + "]\n")
		for _, p := range s.Params {
			b.WriteString(p.Key + " = " + p.Value + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ReloadIfChanged re-reads the file when its mtime moved, which elogd checks at
// the top of every request so a configuration edit takes effect immediately.
func (c *Config) ReloadIfChanged() (bool, error) {
	c.mu.RLock()
	name, cur := c.fileName, c.mtime
	c.mu.RUnlock()
	if name == "" {
		return false, nil
	}
	st, err := os.Stat(name)
	if err != nil {
		return false, err
	}
	if cur != 0 && st.ModTime().UnixNano() == cur {
		return false, nil
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parse(string(data))
	c.mtime = st.ModTime().UnixNano()
	return true, nil
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

// FormatBoolInt writes a switch the way elogd writes them (0/1).
func FormatBoolInt(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// QuoteIfNeeded wraps a value in quotes when it contains a separator, matching
// the way configuration files are written back out.
func QuoteIfNeeded(v string) string {
	if strings.ContainsAny(v, "\n") {
		return strconv.Quote(v)
	}
	return v
}
