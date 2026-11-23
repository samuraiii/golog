package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// optionLine matches "Key = value" and "# Key = value" (a commented option).
var optionLine = regexp.MustCompile(`^(?:#|;)? ?([A-Za-z][A-Za-z0-9 -]*[A-Za-z0-9]) = `)

// group is a run of lines of the sample [global] section with no blank line in
// it: a few lines of help and the option lines they describe.
type group struct {
	lines []string
	keys  []string // upper-cased option keys in lines, in order
}

// sampleGlobalGroups cuts the [global] section of the sample into groups.
func sampleGlobalGroups() []group {
	text, err := renderSampleConfig()
	if err != nil {
		return nil
	}
	i := strings.Index(text, "[global]\n")
	if i < 0 {
		return nil
	}
	text = text[i+len("[global]\n"):]
	if j := strings.Index(text, "\n[Demo]"); j >= 0 {
		text = text[:j]
	}
	var out []group
	var cur group
	flush := func() {
		if len(cur.keys) > 0 {
			out = append(out, cur)
		}
		cur = group{}
	}
	for _, line := range strings.Split(text, "\n") {
		if "" == strings.TrimSpace(line) {
			flush()
			continue
		}
		cur.lines = append(cur.lines, line)
		if m := optionLine.FindStringSubmatch(line); m != nil {
			cur.keys = append(cur.keys, strings.ToUpper(m[1]))
		}
	}
	flush()
	return out
}

// commented turns an active "Key = value" line of the sample into a comment: an
// update must never switch anything on, in particular not a default the file did
// not have (the sample sets "Logbook dir", the server's own default differs).
func commented(line string) string {
	if optionLine.MatchString(line) && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, ";") {
		return "# " + line
	}
	return line
}

// globalKeys returns the upper-cased option keys the existing file mentions in
// its [global] section, active or commented out.
func globalKeys(text string) map[string]bool {
	keys := map[string]bool{}
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			in = strings.EqualFold(strings.Trim(t, "[] \t"), "global")
			continue
		}
		if !in {
			continue
		}
		if m := optionLine.FindStringSubmatch(t); m != nil {
			keys[strings.ToUpper(m[1])] = true
		}
	}
	return keys
}

// updateConfigText adds to an existing configuration the options of the sample
// it does not mention yet, as commented-out help blocks at the end of [global].
// Nothing that is in the file is changed, so the behaviour of the server does not
// change: the new options only become visible (and available) to the operator.
// It returns the new text and the keys that were added.
func updateConfigText(existing string, now time.Time) (string, []string) {
	have := globalKeys(existing)
	var block []string
	var added []string
	for _, g := range sampleGlobalGroups() {
		var missing []int
		for i, k := range g.keys {
			if !have[k] {
				missing = append(missing, i)
			}
		}
		if 0 == len(missing) {
			continue
		}
		if len(missing) == len(g.keys) {
			// the whole group is new: keep its help text too
			block = append(block, "")
			for _, line := range g.lines {
				block = append(block, commented(line))
			}
			added = append(added, g.keys...)
			continue
		}
		// part of the group exists: add only the option lines that are missing
		block = append(block, "")
		for _, line := range g.lines {
			if m := optionLine.FindStringSubmatch(line); m != nil && !have[strings.ToUpper(m[1])] {
				block = append(block, commented(line))
				added = append(added, strings.ToUpper(m[1]))
			}
		}
	}
	if 0 == len(added) {
		return existing, nil
	}
	head := []string{"", "# --- options added by \"gologd config-update\" on " + now.Format("2006-01-02") +
		" (all commented out; remove the \"# \" to use one) ---"}
	insert := strings.Join(append(head, block...), "\n") + "\n"

	nl := "\n"
	if strings.Contains(existing, "\r\n") {
		nl = "\r\n"
		insert = strings.ReplaceAll(insert, "\n", "\r\n")
	}
	// the insertion point: before the first section after [global], else the end
	lines := strings.SplitAfter(existing, "\n")
	in := false
	at := len(existing)
	pos := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			if in {
				at = pos
				break
			}
			in = strings.EqualFold(strings.Trim(t, "[] \t"), "global")
		}
		pos += len(l)
	}
	if !in {
		// no [global] section at all: create one at the end
		insert = nl + "[global]" + insert
	}
	prefix := existing[:at]
	if at == len(existing) && !strings.HasSuffix(prefix, "\n") && "" != prefix {
		prefix += nl
	}
	return prefix + insert + nl + existing[at:], added
}

// backupName is "<file>.bak-<date>-<time>" next to the configuration.
func backupName(path string, now time.Time) string {
	return path + ".bak-" + now.Format("20060102-150405")
}

// configUpdateCommand is "gologd config-update [-c file] [-n]": add the options
// the program knows and the file does not mention. The existing file is copied to
// "<file>.bak-<date>-<time>" first and then replaced atomically; with -n only the
// list of new options is printed and nothing is written.
func configUpdateCommand(argv []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("config-update", flag.ContinueOnError)
	path := fs.String("c", "golog.cfg", "configuration file to update")
	dry := fs.Bool("n", false, "only list the options that would be added")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	orig, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gologd:", err)
		return 1
	}
	now := time.Now()
	text, added := updateConfigText(string(orig), now)
	if 0 == len(added) {
		fmt.Fprintln(stdout, "the configuration already mentions every option; nothing to add")
		return 0
	}
	fmt.Fprintf(stdout, "%d options to add: %s\n", len(added), strings.Join(added, ", "))
	if *dry {
		return 0
	}
	st, err := os.Stat(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gologd:", err)
		return 1
	}
	bak := backupName(*path, now)
	if err := os.WriteFile(bak, orig, st.Mode().Perm()); err != nil {
		fmt.Fprintln(os.Stderr, "gologd: cannot write the backup, nothing changed:", err)
		return 1
	}
	tmp, err := os.CreateTemp(filepath.Dir(*path), "."+filepath.Base(*path)+".*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gologd:", err)
		return 1
	}
	name := tmp.Name()
	_, werr := tmp.WriteString(text)
	cerr := tmp.Chmod(st.Mode().Perm())
	if e := tmp.Close(); werr == nil {
		werr = e
	}
	if werr != nil || cerr != nil {
		os.Remove(name)
		fmt.Fprintln(os.Stderr, "gologd: cannot write the new file, nothing changed:", werr, cerr)
		return 1
	}
	if err := os.Rename(name, *path); err != nil {
		os.Remove(name)
		fmt.Fprintln(os.Stderr, "gologd:", err)
		return 1
	}
	fmt.Fprintf(stdout, "updated %s (previous version kept as %s)\n", *path, bak)
	return 0
}
