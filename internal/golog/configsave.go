package golog

import (
	"os"
	"strings"
)

// renderPreserving writes the configuration back into the text it was read
// from, changing only what changed: comments, blank lines, the order of the
// sections, the spelling of the keys and every untouched line stay as they are.
// (A rewrite from the parsed model would delete every comment, including a
// "# Authentication = Header" that documents why a setting is off.)
//
// A line whose key is no longer in the model is dropped, a changed value is
// rewritten in place, a new key goes after the last line of its section and a
// new section at the end. It reports false when the model has a value this line
// based editor cannot express (a newline in a value); the caller then falls back
// to the canonical dump.
func (c *Config) renderPreserving(orig string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	type slot struct {
		p    Param
		used bool
	}
	model := map[string][]*slot{}
	var order []string
	for _, s := range c.Sections {
		name := strings.ToUpper(s.Name)
		if _, ok := model[name]; !ok {
			order = append(order, s.Name)
			model[name] = nil
		}
		for _, p := range s.Params {
			if strings.ContainsAny(p.Value, "\r\n") || strings.ContainsAny(p.Key, "\r\n=") {
				return "", false
			}
			model[name] = append(model[name], &slot{p: p})
		}
	}
	// the sections of the file, to tell which ones already exist
	inFile := map[string]bool{}

	lines := strings.Split(strings.ReplaceAll(orig, "\r\n", "\n"), "\n")
	var out []string
	cur := ""         // upper-cased name of the current section ("" before the first)
	lastParam := 0    // index in out of the last parameter line of the current section
	flush := func() { // new keys of the section that is ending
		if "" == cur {
			return
		}
		var add []string
		for _, sl := range model[cur] {
			if !sl.used {
				sl.used = true
				add = append(add, sl.p.Key+" = "+sl.p.Value)
			}
		}
		if 0 == len(add) {
			return
		}
		at := lastParam + 1
		out = append(out[:at], append(add, out[at:]...)...)
	}
	for _, line := range lines {
		trimmed := TrimSpaceASCII(line)
		switch {
		case strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || "" == trimmed:
			out = append(out, line)
		case strings.HasPrefix(trimmed, "["):
			flush()
			name := trimmed[1:]
			if i := strings.IndexByte(name, ']'); i >= 0 {
				name = name[:i]
			}
			cur = strings.ToUpper(TrimSpaceASCII(name))
			inFile[cur] = true
			if _, ok := model[cur]; !ok {
				// the section is gone from the model: drop its header and keys
				cur = "\x00gone"
				continue
			}
			out = append(out, line)
			lastParam = len(out) - 1
		default:
			if "" == cur {
				out = append(out, line) // text before the first section is ignored by the parser
				continue
			}
			if "\x00gone" == cur {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq < 0 {
				out = append(out, line)
				continue
			}
			key := TrimSpaceASCII(strings.TrimRight(line[:eq], " \t="))
			var hit *slot
			for _, sl := range model[cur] {
				if !sl.used && sl.p.UPKey == strings.ToUpper(key) {
					hit = sl
					break
				}
			}
			if nil == hit {
				continue // the key was deleted
			}
			hit.used = true
			if TrimSpaceASCII(line[eq+1:]) == hit.p.Value {
				out = append(out, line)
			} else {
				out = append(out, key+" = "+hit.p.Value)
			}
			lastParam = len(out) - 1
		}
	}
	flush()
	for _, name := range order {
		up := strings.ToUpper(name)
		if inFile[up] {
			continue
		}
		for len(out) > 0 && "" == TrimSpaceASCII(out[len(out)-1]) {
			out = out[:len(out)-1]
		}
		out = append(out, "", "["+name+"]")
		for _, sl := range model[up] {
			out = append(out, sl.p.Key+" = "+sl.p.Value)
		}
	}
	text := strings.Join(out, "\n")
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text, true
}

// saveText is what Save writes: the old file edited in place, or the canonical
// dump when there is no old file or it cannot be edited that way.
func (c *Config) saveText(name string) string {
	if orig, err := os.ReadFile(name); err == nil {
		if text, ok := c.renderPreserving(string(orig)); ok {
			return text
		}
	}
	return c.Dump("")
}
