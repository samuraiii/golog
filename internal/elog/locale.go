package elog

import (
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Localised user interface ("Locale"/"Language" configuration keys, *.lng files)
// ---------------------------------------------------------------------------
//
// elogd ships language files with lines "English string = Translation" and
// looks a string up with the tr() macro. Only the user-visible strings go
// through it; command names are translated too, which is why the server accepts
// both the English and the translated form of every command (see
// Server.sameCommand).
//
// LoadLocale itself does not cache: the caller owns the lifetime of a catalogue.
// The server caches its own in Server.locCache (compat.go, guarded by
// Server.locMu) and per-logbook overrides in the sync.Map of compat.go, so this
// file needs no global state - and a reload of the resource directory is picked
// up instead of being pinned by a package-level cache.

// LoadLocale reads <resourceDir>/<name>.lng and returns its catalogue. An
// unknown or missing language, an unreadable file or a name that could not
// select a file all yield the identity catalogue, i.e. every string comes back
// in English - which is what an installation without language files does.
//
// The C program resolves its language by searching the resource directory for
// "<Name>.lng" case insensitively (so "japanese" finds "Japanese.lng"); the
// lookup below reproduces that, then falls back to the exact name.
func LoadLocale(resourceDir, name string) *Locale {
	c := &localeData{m: map[string]string{}}
	if name == "" || resourceDir == "" {
		return &Locale{m: c.m}
	}
	path := filepath.Join(resourceDir, name+".lng")
	if !fileExists(path) {
		if hit := findLocaleFile(resourceDir, name); hit != "" {
			path = hit
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return &Locale{m: c.m}
	}
	c.parse(string(data))
	return &Locale{m: c.m}
}

// localeData is the parsed .lng file.
type localeData struct {
	m map[string]string
}

// parse reads the "English = Translation" lines. Comments start with '#' or ';',
// a line without '=' is ignored, and the first definition of a string wins, like
// the linear search of locext.cxx does.
func (c *localeData) parse(data string) {
	for _, line := range strings.Split(data, "\n") {
		line = TrimSpaceASCII(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = TrimSpaceASCII(k)
		v = TrimSpaceASCII(v)
		if k == "" {
			continue
		}
		if _, seen := c.m[k]; !seen {
			c.m[k] = v
		}
	}
}

// findLocaleFile returns the path of the file of the wanted language, searching
// the resource directory for "<wanted>.lng" with the file-name comparison elogd
// uses (case insensitive on every platform, because that is what the original
// does with its strcasecmp on the directory entries). "" when there is none.
func findLocaleFile(resourceDir, wanted string) string {
	des, err := os.ReadDir(resourceDir)
	if err != nil {
		return ""
	}
	want := strings.ToLower(wanted + ".lng")
	// First an exact (case insensitive) hit, then, like the original, the first
	// file whose name merely contains the wanted language ("Japanese.lng" for a
	// "Japanese UTF-8" locale).
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		if strings.ToLower(de.Name()) == want {
			return filepath.Join(resourceDir, de.Name())
		}
	}
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		n := strings.ToLower(de.Name())
		if strings.HasSuffix(n, ".lng") && strings.Contains(n, strings.ToLower(wanted)) {
			return filepath.Join(resourceDir, de.Name())
		}
	}
	return ""
}

// Locale is a message catalogue: the English string to its translation. The
// zero/nil value is the identity catalogue.
type Locale struct {
	m map[string]string
}

// Get translates one string, returning the English text when there is no entry
// (which is what loc() of the original does with an unloaded language file).
func (l *Locale) Get(en string) string {
	if l == nil || l.m == nil {
		return en
	}
	if v, ok := l.m[en]; ok && v != "" {
		return v
	}
	return en
}

// Count is the number of translated strings, used by the status page.
func (l *Locale) Count() int {
	if l == nil {
		return 0
	}
	return len(l.m)
}
