// gologd convert - rewrite a legacy logbook as UTF-8, once, explicitly.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samuraiii/golog/internal/golog"
)

// ---------------------------------------------------------------------------
// What this file is for
// ---------------------------------------------------------------------------
//
// golog stores UTF-8 and only UTF-8: every message it writes is UTF-8, and every
// page, feed, mail and CSV it serves is UTF-8. A logbook written by the classic
// elogd holds its text in a national code page (windows-1250 or ISO-8859-2 for
// Czech, KOI8-R for Russian, ...). golog READS such a logbook as it is, decoding
// each message on the fly with the "Legacy codepage" option, and it never rewrites
// it: a legacy logbook that is only browsed stays byte for byte as elogd left it,
// modification time with it.
//
// Turning a store into UTF-8 is this separate, deliberate operation. It is not
// reachable from a request handler and the daemon never calls it, because it is the
// one thing in the encoding feature that changes files in place. The safety rules
// (docs/encoding.md):
//
//   - DRY RUN BY DEFAULT. Nothing is written until -dry-run=false is given, so
//     "gologd convert -all" is a report you can run on a production tree.
//   - A file that is already valid UTF-8 - and every pure ASCII file, which is
//     valid UTF-8 - is REFUSED with "already UTF-8": it is already in the target
//     encoding and rewriting it would change nothing but its mtime. That is what
//     makes the command idempotent: the second run converts nothing.
//   - A file with bytes that cannot be mapped to the code page is REFUSED unless
//     -force says that replacing them with U+FFFD is acceptable. The count is in the
//     report either way, per file.
//   - The write is atomic: a temporary file in the same data directory, fsynced,
//     verified, then renamed over the original, so a crash or a full disk leaves
//     either the old file or the new one, never half of either.
//   - -backup keeps what was there, next to the original or in a directory.
//   - The file mode is always kept; the modification time with -keep-mtime.
//   - The command refuses to run while a daemon holds the PID file of the data
//     directory (that daemon has an index of byte offsets into those files and would
//     rewrite a file from stale offsets); -force overrides, and says so.
//   - Files of several gigabytes, which a linux/386 or windows/386 build could not
//     hold twice in memory, are converted streaming, block by block.
//
// What it does NOT touch, ever: attachments and any other binary, and the
// configuration file itself. Attachment names on disk are never re-encoded either,
// so a converted logbook keeps its files where they are.
//
// Both spellings of the invocation work, because the daemon's own switches are parsed
// by hand in main.go: "gologd convert -all" and "gologd -convert -all". ConvertCommand
// recognises both, ConvertMain runs the operation; the one line that calls them from
// run() is in MERGE-NOTES.md.

// ConvertUsage is the help text of the subcommand (-convert -h, and on a bad
// command line).
const ConvertUsage = `usage: gologd convert [flags]     convert legacy logbooks to UTF-8 (dry run by default)
       gologd -convert [flags]    the same, for a command line that takes a leading dash

  -all                 every logbook of the configuration
  -logbook <name>      one logbook, by the name of its section in the configuration file
  -dir <dir>[,<dir>...] one data directory, whether or not it is in the configuration
  -config <file>       configuration file (default: $ELOGCFG, then ` + `./elogd.cfg)
  -codepage <name>     code page the legacy files are written in, e.g. windows-1250,
  -charset <name>      ISO-8859-2, KOI8-R: an IANA name or a usual alias, and the
                       C01/C02 numbers (cp1250 and 1250 both mean windows-1250).
                       "auto" detects it from the bytes (review the report!),
                       "list" prints the names golog knows and exits.
                       Without this flag each logbook's "Legacy codepage" option is
                       used, and what is left is detected.
  -dry-run             report what would change and change nothing (the default; -n
                       means the same, -dry-run=false does the conversion)
  -force               convert even with undecodable bytes (they become U+FFFD) and
                       even while a daemon appears to run
  -backup              keep the previous file next to the converted one
  -backup-dir <dir>    keep the previous files in <dir>, under their own names
  -markers             write a "golog-encoding: <codepage>" line into each converted
                       entry, so that the source code page stays known in the file
  -keep-mtime          keep the modification time of each converted file
  -userdb <file>       also convert a user or password file that is not UTF-8
  -pidfile <file>      refuse to run while this PID file names a live process
  -quiet               only the summary and the errors
  -v                   also list the files that need nothing
`

// convertFlags is the parsed form of the flags above.
type convertFlags struct {
	all       bool
	logbook   string
	dirs      string
	config    string
	codepage  string
	dryRun    bool
	force     bool
	backup    bool
	backupDir string
	markers   bool
	keepMTime bool
	userdb    string
	pidfile   string
	quiet     bool
	verbose   bool
}

// ConvertCommand reports whether this run of gologd is a conversion rather than a
// daemon, and returns the arguments for it (with "-convert" or "convert" removed).
//
// It is called from run() before the daemon's own switches are parsed, so that
//
//	gologd convert -all
//	gologd -convert -logbook Czech -codepage windows-1250 -dry-run=false -backup
//
// work while every other invocation - "gologd -D -p 8080" above all - keeps behaving
// exactly as before. A "-convert=false" is accepted and means "serve", which lets a
// start-up script carry the flag switched off.
func ConvertCommand(argv []string) (rest []string, wanted bool) {
	if len(argv) > 0 && (argv[0] == "convert" || argv[0] == "convert-logfiles") {
		return argv[1:], true
	}
	for i, a := range argv {
		switch a {
		case "-convert", "--convert", "-convert=true", "--convert=true":
			out := make([]string, 0, len(argv)-1)
			out = append(out, argv[:i]...)
			return append(out, argv[i+1:]...), true
		case "-convert=false", "--convert=false":
			return nil, false
		}
	}
	return nil, false
}

// ConvertMain is the body of the subcommand; it returns the process exit status: 0
// when everything asked for is UTF-8 now (including a dry run that found files to
// convert - a dry run changes nothing, and failing on it would make "check, then
// convert" awkward in a script), 2 on a command line error, 1 when a file could not
// be converted.
func ConvertMain(argv []string) int {
	f := &convertFlags{}
	fs := flag.NewFlagSet("convert", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, "\n"+ConvertUsage) }

	fs.BoolVar(&f.all, "all", false, "every logbook of the configuration")
	fs.BoolVar(&f.all, "a", false, "shorthand for -all")
	fs.StringVar(&f.logbook, "logbook", "", "one logbook, by its section name")
	fs.StringVar(&f.logbook, "l", "", "shorthand for -logbook")
	fs.StringVar(&f.dirs, "dir", "", "one data directory, or several separated by commas")
	fs.StringVar(&f.config, "config", "", "configuration file")
	fs.StringVar(&f.config, "c", "", "shorthand for -config")
	fs.StringVar(&f.codepage, "codepage", "", "legacy code page, or \"auto\", or \"list\"")
	fs.StringVar(&f.codepage, "charset", "", "deprecated alias of -codepage, the elogd spelling")
	fs.StringVar(&f.codepage, "cp", "", "shorthand for -codepage")
	fs.BoolVar(&f.dryRun, "dry-run", true, "report what would change, change nothing")
	fs.BoolVar(&f.force, "force", false, "convert despite undecodable bytes or a running daemon")
	fs.BoolVar(&f.backup, "backup", false, "keep the previous file next to the converted one")
	fs.StringVar(&f.backupDir, "backup-dir", "", "keep the previous files in this directory")
	fs.BoolVar(&f.markers, "markers", false, "write a golog-encoding line into the entries")
	fs.BoolVar(&f.keepMTime, "keep-mtime", false, "keep the modification time of each file")
	fs.StringVar(&f.userdb, "userdb", "", "also convert this user or password file")
	fs.StringVar(&f.pidfile, "pidfile", "", "refuse to run while this PID file is held")
	fs.BoolVar(&f.quiet, "quiet", false, "only the summary and the errors")
	fs.BoolVar(&f.verbose, "v", false, "also list the files that need nothing")
	// -n is the spelling every other conversion tool uses; like -dry-run it is the
	// default, so it only has to be spelled out to keep a wrapper honest.
	keepDry := fs.Bool("n", true, "shorthand for -dry-run")

	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if !*keepDry {
		f.dryRun = false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "gologd convert: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return 2
	}

	if strings.EqualFold(strings.TrimSpace(f.codepage), "list") {
		printConvertCodepages()
		return 0
	}

	// The PID file first: a running daemon is the one failure that no file's report
	// would show (the conversion itself is atomic, but the daemon's index of byte
	// offsets into those files goes stale under it).
	if f.pidfile != "" {
		pid, held, err := golog.PIDFileHeld(f.pidfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gologd convert: %s: %v\n", f.pidfile, err)
			return 2
		}
		if held {
			if !f.force {
				fmt.Fprintf(os.Stderr, "gologd convert: refusing: %s is held by the running process %d.\n"+
					"           Stop that daemon first, or use -force when you know it does not serve\n"+
					"           the data directories given here.\n", f.pidfile, pid)
				return 1
			}
			fmt.Fprintf(os.Stderr, "gologd convert: %s is held by process %d; continuing because of -force\n",
				f.pidfile, pid)
		}
	}

	cfg, cfgErr := convertLoadConfig(f.config)
	targets, status, ok := convertTargets(f, cfg, cfgErr)
	if !ok {
		if status == 0 {
			fmt.Fprint(os.Stderr, "\n"+ConvertUsage)
			status = 2
		}
		return status
	}

	if f.dryRun {
		fmt.Println("gologd convert: dry run, nothing is written. Add -dry-run=false to convert.")
	} else {
		fmt.Println("gologd convert: writing. Each original is replaced by an atomically renamed temporary file.")
	}
	if f.userdb != "" {
		if err := convertCheckReadable(f.userdb); err != nil {
			fmt.Fprintf(os.Stderr, "gologd convert: %v\n", err)
			return 1
		}
	}

	var wrote, skipped, failed, messages, replaced int
	report := func(kind, label string, rep golog.ConvertReport) {
		switch {
		case rep.Err != nil && !errors.Is(rep.Err, golog.ErrAlreadyUTF8):
			failed++
			fmt.Printf("FAIL   %s: %v\n", label, rep.Err)
		case rep.Skipped:
			skipped++
			if f.verbose || (!f.quiet && !strings.Contains(rep.Reason, "already valid UTF-8")) {
				fmt.Printf("skip   %s: %s\n", label, rep.Reason)
			}
		default:
			wrote++
			messages += rep.Entries
			replaced += rep.Replaced
			fmt.Printf("wrote  %s: %s\n", label, rep.Reason)
			for _, b := range rep.Backups {
				fmt.Printf("       backup: %s\n", b)
			}
		}
	}

	for _, t := range targets {
		opts := convertOptionsFor(f, cfg, t.cfgName)
		for _, path := range t.files {
			label := t.name + "/" + convertRel(t.dir, path)
			report("log", label, golog.ConvertFileAuto(path, opts))
		}
		for _, path := range t.text {
			if f.quiet && !f.verbose {
				continue
			}
			report("text", t.name+"/"+convertRel(t.dir, path), golog.ConvertFileAuto(path, opts))
		}
	}
	if f.userdb != "" {
		opts := convertOptionsFor(f, cfg, "")
		report("user", f.userdb, golog.ConvertFileAuto(f.userdb, opts))
	}

	what := "converted"
	if f.dryRun {
		what = "would convert"
	}
	fmt.Printf("\ngologd convert: %d file(s) %s, %d skipped, %d failed; %d message(s), %d undecodable byte(s)\n",
		wrote, what, skipped, failed, messages, replaced)
	if f.dryRun && wrote > 0 {
		fmt.Println("gologd convert: rerun with -dry-run=false" + convertBackupHint(f) + " to write these files.")
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

// convertTarget is one data directory selected for conversion, with the files of it
// that take part.
type convertTarget struct {
	name    string // what the report calls it ("logbook czech")
	dir     string // the data directory
	cfgName string // its configuration section ("" for a bare -dir)
	files   []string
	text    []string
}

// convertTargets resolves -all / -logbook / -dir, in that order of precedence. An
// unknown logbook name is an error that lists the names that do exist, which beats
// converting the wrong logbook.
func convertTargets(f *convertFlags, cfg *golog.Config, cfgErr error) ([]convertTarget, int, bool) {
	var out []convertTarget
	switch {
	case f.dirs != "":
		for _, d := range convertSplitList(f.dirs) {
			if !convertIsDir(d) {
				fmt.Fprintf(os.Stderr, "gologd convert: %s: not a directory\n", d)
				return nil, 2, false
			}
			t := convertTarget{
				name: "dir " + filepath.Base(filepath.Clean(d)),
				dir:  d,
			}
			if t.cfgName != "" {
				t.name = "logbook " + t.cfgName
			}
			t.files, t.text = convertFilesOf(d)
			out = append(out, t)
		}
	case f.logbook != "":
		if cfgErr != nil {
			fmt.Fprintf(os.Stderr, "gologd convert: %v\n", cfgErr)
			return nil, 2, false
		}
		dir, ok := convertSectionDir(cfg, f.logbook)
		if !ok {
			fmt.Fprintf(os.Stderr, "gologd convert: logbook %q not found in %s (this file has: %s)\n",
				f.logbook, cfg.FileName(), strings.Join(convertListLogbooks(cfg), ", "))
			return nil, 2, false
		}
		t := convertTarget{name: "logbook " + f.logbook, dir: dir, cfgName: f.logbook}
		t.files, t.text = convertFilesOf(dir)
		out = append(out, t)
	case f.all:
		if cfgErr != nil {
			fmt.Fprintf(os.Stderr, "gologd convert: %v\n", cfgErr)
			return nil, 2, false
		}
		for _, name := range convertListLogbooks(cfg) {
			dir, ok := convertSectionDir(cfg, name)
			if !ok {
				fmt.Fprintf(os.Stderr, "gologd convert: logbook %q has no \"Dir\", skipped\n", name)
				continue
			}
			if !convertIsDir(dir) {
				fmt.Fprintf(os.Stderr, "gologd convert: logbook %q: %s does not exist, skipped\n", name, dir)
				continue
			}
			t := convertTarget{name: "logbook " + name, dir: dir, cfgName: name}
			t.files, t.text = convertFilesOf(dir)
			out = append(out, t)
		}
		if len(out) == 0 {
			fmt.Fprintf(os.Stderr, "gologd convert: %s has no logbook with a \"Dir\"\n", cfg.FileName())
			return nil, 1, false
		}
	default:
		return nil, 0, false
	}
	return out, 0, true
}

// convertFilesOf lists what of a data directory takes part in the conversion: the
// message files, and the handful of text files elogd keeps next to them (header.html
// and friends). Nothing else - attachments are the user's bytes and are never
// re-encoded.
func convertFilesOf(dir string) (files, text []string) {
	if l, err := golog.LogbookLogFiles(dir); err == nil {
		files = l
	} else {
		fmt.Fprintf(os.Stderr, "gologd convert: %s: %v\n", dir, err)
	}
	text = golog.LogbookConfigFiles(dir)
	return files, text
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// convertOptionsFor builds the options for one target: the code page (from the
// command line, else from that logbook's "Legacy codepage", else detection) and the
// safety switches.
func convertOptionsFor(f *convertFlags, cfg *golog.Config, section string) golog.ConvertOptions {
	opts := golog.ConvertOptions{
		DryRun:     f.dryRun,
		BackupDir:  f.backupDir,
		KeepMTime:  f.keepMTime,
		Force:      f.force,
		AddMarkers: f.markers,
	}
	if f.backup && f.backupDir == "" {
		opts.BackupDir = "."
	}

	name := strings.TrimSpace(f.codepage)
	if name == "" {
		// Nothing asked for on the command line: honour the configuration, logbook
		// by logbook, so that an operator who set "Legacy codepage = windows-1250"
		// does not have to repeat it as a flag. What is left without a configured
		// value is detected, which the report says out loud.
		if cfg != nil && section != "" {
			if cp := golog.LogbookCodepageName(cfg, golog.ConfigScope{Group: section}); cp != "" {
				if codes, err := golog.LookupCodecs(cp); err == nil && codes != nil && codes.IsLegacy() {
					opts.Codepage = codes
					return opts
				}
				fmt.Fprintf(os.Stderr, "gologd convert: logbook %s: ignoring the configured codepage %q\n",
					section, cp)
			}
		}
		opts.Auto = true
		if g := golog.GlobalLegacyCodepage(); g != nil && g.IsLegacy() {
			opts.Codepage = g
		}
		return opts
	}
	if strings.EqualFold(name, "auto") {
		opts.Auto = true
		fmt.Println("gologd convert: detecting the code page from the bytes; review the report before trusting it")
		return opts
	}
	codes, err := golog.LookupCodecs(name)
	if err != nil || codes == nil || !codes.IsLegacy() {
		// The caller printed nothing yet; be loud, because silently detecting a
		// different code page than the one the operator typed is the worst
		// possible outcome of a conversion.
		fmt.Fprintf(os.Stderr, "gologd convert: unknown code page %q (see -codepage list, or use -codepage auto)\n", name)
		opts.Codepage = nil
		opts.Auto = false
		return opts
	}
	opts.Codepage = codes
	return opts
}

// printConvertCodepages prints the names -codepage accepts: the table golog links in
// (golang.org/x/text/encoding/charmap) spelled the IANA way, which is also the way
// elogd's own "Charset" values are usually spelled.
func printConvertCodepages() {
	fmt.Println("gologd convert: the code page names golog knows. An IANA name or a common alias")
	fmt.Println("              works too, and so do the C01/C02 numbers: cp1250 and 1250 both")
	fmt.Println("              mean windows-1250, latin2 means ISO-8859-2.")
	for _, n := range golog.CodepageNames() {
		fmt.Printf("  %-14s %s\n", n, golog.CodecsDescriptionOf(n))
	}
	fmt.Println("  auto          detect the code page from the bytes of each file")
	fmt.Println("  list          this list")
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------
//
// They carry a convert prefix on purpose: main.go, daemon.go and smtp.go, which own
// the daemon side of the command line and are shared with the other jobs of this
// batch, already declare global, orAny, defaultConfigDir, trimSpace, writePID and
// friends. Redeclaring one of those names here would stop the build, and editing
// those files to share a helper would collide with the other jobs, so this file keeps
// to itself.

// convertSplitList splits a comma separated list, dropping blanks and empties.
func convertSplitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func convertIsDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// convertRel is the file name relative to the data directory, for a report line that
// has to fit on a terminal.
func convertRel(dir, path string) string {
	if r, err := filepath.Rel(dir, path); err == nil {
		return filepath.ToSlash(r)
	}
	return filepath.Base(path)
}

// convertLoadConfig reads the configuration the same way the daemon does, so that
// "gologd convert -all" converts the logbooks "gologd -D" serves.
func convertLoadConfig(path string) (*golog.Config, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		p = os.Getenv("ELOGCFG")
	}
	if p == "" {
		p = filepath.Join(defaultConfigDir(), golog.ConfigFileName)
	}
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("cannot open configuration file %s (%v)", p, err)
	}
	return golog.LoadConfig(p)
}

// convertListLogbooks is every logbook section of the configuration, in the order the
// file lists them.
func convertListLogbooks(c *golog.Config) []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, name := range c.SectionNames() {
		if golog.IsLogbookName(name) {
			out = append(out, name)
		}
	}
	return out
}

// convertSectionDir is the data directory of one logbook section, absolute the way
// the server resolves it: an absolute path is taken as it stands, a relative one
// lives under the directory of the configuration file. The key is "Dir", which is
// what (*Server).logbookDir reads; "Directory" is the spelling some old files use,
// so it is tried too.
func convertSectionDir(c *golog.Config, name string) (string, bool) {
	if c == nil {
		return "", false
	}
	scope := golog.ConfigScope{Group: name}
	for _, key := range []string{"Dir", "Directory"} {
		if v, ok := c.Get(scope, key); ok && strings.TrimSpace(v) != "" {
			return golog.Abs(strings.TrimSpace(v)), true
		}
	}
	return "", false
}

// convertCheckReadable fails early on a -userdb that does not exist: a typo in that
// option must not look like a successful conversion.
func convertCheckReadable(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// convertBackupHint nudges towards the option that makes a conversion reversible. The
// tool never writes a file it was not asked to write, so a bare conversion has no
// undo, and that deserves one line of advice.
func convertBackupHint(f *convertFlags) string {
	if f.backup || f.backupDir != "" {
		return ""
	}
	return " (and consider -backup)"
}
