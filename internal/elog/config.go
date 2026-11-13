package elog

import (
	"os"
	"strings"
	"sync"
)

// Config is a parsed elogd.cfg.
//
// The C implementation keeps an ordered array of sections, each with an
// ordered array of key/value pairs, and looks values up with
// stricmp()-based matching plus a handful of fallback rules (see getcfg()).
// The same model is reproduced here - including the ordering, because
// "Options xxx" style keys and the configuration editor page rely on the file
// order, and because elogd returns the *first* match, not the last, so
// duplicated keys keep the first value.
type Config struct {
	mu       sync.RWMutex
	Sections []*Section
	fileName string
	mtime    int64
}

// Section is one [name] block.
type Section struct {
	Name   string
	Params []Param // in file order
}

// Param is one "key = value" line. Key keeps the original spelling (used by
// the configuration editor), UPKey the upper-cased form used for matching.
type Param struct {
	Key   string
	UPKey string
	Value string
}

// LoadConfig parses name. A missing file is not an error for elogd (it warns
// and continues), so the caller decides what to do.
func LoadConfig(name string) (*Config, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	c := &Config{fileName: name}
	c.parse(string(data))
	return c, nil
}

// ParseConfig is exposed for tests and for the "-t" style dry run.
func ParseConfig(data string) *Config {
	c := &Config{}
	c.parse(data)
	return c
}

// FileName is the path this config was loaded from.
func (c *Config) FileName() string { return c.fileName }

func (c *Config) parse(data string) {
	sections := []*Section{}
	// elogd walks the file character by character: a line starting with '#' or
	// ';' is skipped, '[' opens a section, everything until the next '[' or
	// EOF are its parameters. Text before the first '[' is ignored.
	lines := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	var cur *Section
	for _, line := range lines {
		trimmed := TrimSpaceASCII(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			name := trimmed[1:]
			if i := strings.IndexByte(name, ']'); i >= 0 {
				name = name[:i]
			}
			cur = &Section{Name: TrimSpaceASCII(name)}
			sections = append(sections, cur)
			continue
		}
		if cur == nil {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := TrimSpaceASCII(strings.TrimRight(line[:eq], " \t="))
		value := TrimSpaceASCII(line[eq+1:])
		if key == "" {
			continue
		}
		cur.Params = append(cur.Params, Param{
			Key:   key,
			UPKey: strings.ToUpper(key),
			Value: value,
		})
	}
	c.Sections = sections
}

// Section returns the named section (case insensitive), or nil.
func (c *Config) Section(name string) *Section {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sectionLocked(name)
}

func (c *Config) sectionLocked(name string) *Section {
	for _, s := range c.Sections {
		if EqualFold(s.Name, name) {
			return s
		}
	}
	return nil
}

// SectionNames lists section names in file order (elogd's enumgrp()).
func (c *Config) SectionNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.Sections))
	for _, s := range c.Sections {
		out = append(out, s.Name)
	}
	return out
}

// Set replaces (or appends) a parameter in a section, keeping the file order
// of the existing parameters. Used by the in-browser configuration editor.
func (c *Config) Set(sectionName, key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.sectionLocked(sectionName)
	if s == nil {
		s = &Section{Name: sectionName}
		c.Sections = append(c.Sections, s)
	}
	up := strings.ToUpper(key)
	for i := range s.Params {
		if s.Params[i].UPKey == up {
			s.Params[i].Value = value
			return
		}
	}
	s.Params = append(s.Params, Param{Key: key, UPKey: up, Value: value})
}

// ---------------------------------------------------------------------------
// getcfg()
// ---------------------------------------------------------------------------

// Condition is the "{...}" conditional-value mechanism of elogd: a config line
// may be written as
//
//	{Setup}= Display = 2
//
// meaning "use this value only while the condition string equals Setup".
// _condition is a process-wide (per request) setting in the original, which is
// kept here as an explicit argument so this implementation is safe for
// concurrent requests instead of relying on global state.
type ConfigScope struct {
	// Group is the logbook name (or "global").
	Group string
	// Condition is the active condition, "" normally.
	Condition string
	// TopGroup is the top group of the logbook, from the hierarchy.
	TopGroup string
}

// Get is getcfg(group, param): the full elogd lookup chain.
//
//  1. if group is "global" and a top group is set: [global <TopGroup>]
//  2. conditional ({...}=) entries of <group>
//  3. <group> itself
//  4. recursively [global <TopGroup>] then [global]
//
// The bool result is false when the parameter is absent; note that an empty
// value *is* a hit, exactly like in elogd (getcfg returns 1 with str[0]==0),
// which callers rely on for "Turn this feature off by setting it empty".
func (c *Config) Get(scope ConfigScope, param string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.getLocked(scope, param)
}

func (c *Config) getLocked(scope ConfigScope, param string) (string, bool) {
	group := scope.Group
	if EqualFold(group, "global") && scope.TopGroup != "" {
		sub := scope
		sub.Group = "global " + scope.TopGroup
		if v, ok := c.getLocked(sub, param); ok {
			return v, true
		}
	}
	if scope.Condition != "" {
		if v, ok := c.getSimpleLocked(group, param, scope.Condition, true); ok {
			return v, true
		}
	}
	if v, ok := c.getSimpleLocked(group, param, scope.Condition, false); ok {
		return v, true
	}
	if group == "" || IsLogbookName(group) {
		sub := scope
		sub.Group = "global"
		return c.getLocked(sub, param)
	}
	return "", false
}

// getSimpleLocked looks the parameter up in one section. conditional==true
// only accepts "{cond}=key" lines whose cond matches; conditional==false
// accepts plain keys only, matching C's strchr(uparam,'{') logic.
func (c *Config) getSimpleLocked(group, param, condition string, conditional bool) (string, bool) {
	s := c.sectionLocked(group)
	if s == nil {
		return "", false
	}
	up := strings.ToUpper(param)
	for _, p := range s.Params {
		if MatchParam(p.UPKey, up, condition, conditional) {
			return p.Value, true
		}
	}
	return "", false
}

// MatchParam implements match_param(): compare an (optionally conditional)
// config key with the upper-cased parameter we are looking for.
//
//	"{A,B}KEY"   matches KEY when the current condition contains A or B
//	"{A&B}KEY"   matches KEY when the condition contains both A and B
//	"KEY"        matches KEY literally (ASCII case insensitive)
func MatchParam(configKey, upParam, condition string, conditionalOnly bool) bool {
	if conditionalOnly && !strings.HasPrefix(configKey, "{") {
		return false
	}
	if condition == "" || !strings.HasPrefix(configKey, "{") {
		// elogd uses stricmp(), i.e. plain ASCII case-insensitive equality.
		return EqualFold(configKey, upParam)
	}
	rest := configKey
	if i := strings.IndexByte(rest, '}'); i >= 0 {
		rest = TrimSpaceASCII(rest[i+1:])
	}
	condPart := configKey
	if i := strings.IndexByte(condPart, '}'); i >= 0 {
		condPart = condPart[:i]
	}
	condPart = strings.Replace(condPart, "{", " ", 1)
	wanted := SplitList(condPart, ",", false)
	have := SplitList(condition, ",", false)
	for _, h := range have {
		for _, w := range wanted {
			if EqualFold(h, w) {
				return EqualFold(rest, upParam)
			}
		}
	}
	// AND-ed conditions
	for _, w := range wanted {
		if !strings.Contains(w, "&") {
			continue
		}
		all := SplitList(w, "&", false)
		matched := true
		for _, a := range all {
			found := false
			for _, h := range have {
				if EqualFold(h, a) {
					found = true
					break
				}
			}
			if !found {
				matched = false
				break
			}
		}
		if matched {
			return EqualFold(rest, upParam)
		}
	}
	return false
}

// GetString is a convenience wrapper with a default.
func (c *Config) GetString(scope ConfigScope, param, def string) string {
	if v, ok := c.Get(scope, param); ok {
		return v
	}
	return def
}

// GetInt is a convenience wrapper; a non-numeric value yields def, like
// atoi() on garbage would yield 0 (callers pass 0 as def in that case).
func (c *Config) GetInt(scope ConfigScope, param string, def int) int {
	v, ok := c.Get(scope, param)
	if !ok {
		return def
	}
	return Atoi(v)
}

// GetBool is elogd's "getcfg(...); atoi(str)" idiom (which is TRUE for both
// "1" and "yes" only when the code uses TRUE(); most switches use atoi, so
// this mirrors atoi unless the caller asks for the yes/no form).
func (c *Config) GetBool(scope ConfigScope, param string) bool {
	v, ok := c.Get(scope, param)
	if !ok {
		return false
	}
	return Atoi(v) != 0
}

// IsLogbookName is is_logbook(): "global", "global <topgroup>" and the like
// are not logbooks; everything else is.
func IsLogbookName(name string) bool {
	if EqualFold(name, "global") {
		return false
	}
	return !EqualFold(name, "global ") && !HasPrefixFold(name, "global ")
}

// FirstOf returns the value of the first parameter that exists.
func (c *Config) FirstOf(scope ConfigScope, params ...string) (string, bool) {
	for _, p := range params {
		if v, ok := c.Get(scope, p); ok {
			return v, true
		}
	}
	return "", false
}
