package golog

// Helpers the authentication batch needs.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.
//
// This file holds only what the authentication code needs and the rest of golog
// does not have yet: a duration spelling that accepts plain seconds (the way the
// C daemon writes its intervals), a bounded single-value cache for the session
// cookie name, and the notes on why no authentication path may print a credential.
//
// Nothing here duplicates a helper that already exists elsewhere in the package.
// The logging front end the authentication files use is logS/logSBool in
// authext.go; the string helpers TrimSpaceASCII, EqualFold, HasPrefixFold,
// HasSuffixFold, SplitList, Atoi and Bool are in text.go, sprintf is in util.go,
// Itoa is in support.go, orBool/orInt/orFloat are in nums.go and orString is in
// auth.go - they are used as they are and are NOT redeclared here.

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// durations
// ---------------------------------------------------------------------------

// secondFallback is the last attempt at reading an interval: a bare number.
//
// Config.GetDuration only takes time.ParseDuration, so the way the C daemon writes
// its intervals - "Login timeout = 60", "Check expired = 12", "Expires = 48" - is
// rejected there with a warning, and the value silently falls back to its default.
// A site that sets a one-minute login lockout and gets the four-minute default is
// not a rare case, it is what happens when you port a configuration file. This
// helper is used for every interval key the authentication batch reads, so that a
// plain number means seconds and everything else is passed to time.ParseDuration
// unchanged.
//
// It deliberately does not go through Config.GetDuration, because that method logs
// a warning for a value it cannot parse; the bare-number spelling is legal here
// and must not fill the log on every daemon start.
func cfgDuration(c *Config, sc ConfigScope, key string, def time.Duration) time.Duration {
	if c == nil {
		return def
	}
	if v, ok := c.Get(sc, key); ok {
		return durationOf(TrimSpaceASCII(v), def)
	}
	return def
}

// durationOf parses one interval: a bare number is seconds, anything else goes to
// time.ParseDuration, and a value that neither understands (including a
// non-positive one) becomes def.
func durationOf(s string, def time.Duration) time.Duration {
	s = TrimSpaceASCII(s)
	if s == "" {
		return def
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		if n <= 0 {
			return def
		}
		return time.Duration(n * float64(time.Second))
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return def
		}
		return d
	}
	return def
}

// orDuration returns d when it is positive and otherwise the default: the spelling
// used where the value has already been read.
func orDuration(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// orSeconds turns a count of seconds into a duration, def when the count is not
// positive.
func orSeconds(sec, def int) time.Duration {
	if sec > 0 {
		return time.Duration(sec) * time.Second
	}
	return time.Duration(def) * time.Second
}

// ---------------------------------------------------------------------------
// a small cache
// ---------------------------------------------------------------------------

// oneValue caches one derived string for one *Config. It exists for the things
// that are read once per request but must not re-parse their configuration every
// time: the session cookie name is a string plus a sanitising pass, and it is
// looked up on every request that carries a cookie.
//
// The value is kept per *Config pointer, so a configuration reload - which builds
// a new *Config - cannot serve a stale value; an old entry costs one string.
type oneValue struct {
	mu     sync.Mutex
	cfg    *Config
	value  string
	loaded bool
}

// get returns the cached value, building it with make when needed. A nil config is
// passed straight to make, which is then called on every request; that is the
// fallback path only.
func (o *oneValue) get(c *Config, build func(*Config) string) string {
	if build == nil {
		return ""
	}
	if c == nil {
		return build(nil)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.loaded && o.cfg == c {
		return o.value
	}
	o.value = build(c)
	o.cfg = c
	o.loaded = true
	return o.value
}

// ---------------------------------------------------------------------------
// logging discipline
// ---------------------------------------------------------------------------
//
// The authentication back ends keep their configuration in one struct, and that
// struct holds the service account's password (ldapOptions.bindPassword) and the
// helper's environment (externalOptions). A %v or %s of such a struct would print
// the secret, so:
//
//   - no option struct of this batch is ever passed to a format verb as a whole;
//     the *AuthDescription methods print the individual non-secret fields instead,
//     and
//   - nothing in this batch logs a password: the login name and the client address
//     go to the log, the secret does not. safeLine below is the guard for values
//     that came from a form field.

// safeLine makes a value safe for one log line: no control characters, no line
// breaks, and at most 64 bytes, so that a value typed into a form cannot add a
// line to the daemon log - which is the file fail2ban reads.
func safeLine(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 64; i++ {
		c := s[i]
		switch {
		case c == '\n' || c == '\r' || c == '\t':
			b.WriteByte(' ')
		case c < 0x20 || c == 0x7f:
			b.WriteString("?")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
