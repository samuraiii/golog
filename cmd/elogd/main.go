// Command elogd is a drop-in replacement for the ELOG daemon (elogd), written
// from scratch in Go. It reads the same elogd.cfg, serves the same URLs and
// reads and writes the same on-disk logbook files as the C program it replaces.
//
// Usage mirrors the C program:
//
//	elogd [-C <url>] [-c <file>] [-D] [-d <dir>] [-f <file>] [-h] [-k]
//	      [-l <logbook>] [-M] [-m] [-n <interface>] [-p <port>] [-S]
//	      [-s <dir>] [-t <pwd>] [-T] [-v <n>] [-x] [-g] [-V]
//
// The switches that only exist to talk to a remote elogd (cloning -C and the
// logbook synchronisation -m/-M) are not implemented; see RESULT.md.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samuraiii/golog/internal/elog"
)

const usageText = `usage: elogd [-C <url>] [-c <file>] [-D] [-d <dir>] [-f <file>] [-h] [-k]
               [-l <logbook>] [-M] [-m] [-n <interface>] [-p <port>] [-S]
               [-s <dir>] [-t <pwd>] [-T] [-v <n>] [-x] [-g] [-V]

       -C <url> clone remote elogd configuration (not implemented)
       -c <file> specify configuration file
       -M synchronize with removing deleted entries (not implemented)
       -m synchronize logbook(s) with remote server (not implemented)
       -D become a daemon
       -d <dir> specify logbook root directory
       -f <file> PID file
       -h this help
       -k do not use keep-alive (accepted for compatibility; net/http
          manages connection reuse itself)
       -l <logbook> specify logbook for the -m and -C commands
       -n <interface> hostname/IP interface to listen on
       -p <port> TCP/IP port
       -S silent
       -s <dir> specify resource directory (themes, icons, ...)
       -t <pwd> create/overwrite SMTP password in config file
       -T print the current date/time as yymmdd_hhmmss and exit
       -v <n> verbose output (1:URL, 2:INFO, 3:DEBUG)
       -x enable execution of shell commands
       -g generate thumbnails with ImageMagick's convert(1)
       -V print the version and exit
`

// global is the [global] configuration scope, used for every value main() reads.
var global = elog.ConfigScope{Group: "global"}

// notImplemented is the error used for the switches whose feature did not make
// it into this port, so that the message is identical wherever the switch
// appears.
var notImplemented = errors.New("not implemented in the Go rewrite (see RESULT.md)")

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "elogd:", err)
		os.Exit(1)
	}
}

// opts is the parsed command line.
type opts struct {
	configFile string
	resource   string
	logbookDir string
	pidFile    string
	iface      string
	logbook    string
	smtpPwd    string
	port       int
	verbose    int
	verboseSet bool
	daemon     bool
	execCmds   bool
	thumbs     bool
	silent     bool
	keepAlive  bool // -k: only reported, net/http decides by itself
}

// parseArgs walks the command line the way main() of the C program does: a
// switch may be followed by its value ("-p 8080") or carry it attached
// ("-p8080"), because an existing init script may use either spelling.
func parseArgs(argv []string) (*opts, error) {
	o := &opts{keepAlive: true}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
			return nil, fmt.Errorf("unexpected argument %q", a)
		}
		// value returns the attached value (a[2:]) or the next argv element.
		value := func() (string, error) {
			if len(a) > 2 {
				return a[2:], nil
			}
			if i+1 >= len(argv) {
				return "", fmt.Errorf("switch %s needs an argument", a)
			}
			i++
			return argv[i], nil
		}
		switch a[1] {
		case 'h':
			fmt.Print(usageText)
			os.Exit(0)
		case 'V':
			fmt.Println("elogd", elog.EmulatedVersion, "(Go rewrite", elog.Version+")")
			os.Exit(0)
		case 'T':
			// The C program prints the time in the same format the attachment
			// names use, which is what the cron scripts that drive it parse.
			fmt.Println("Actual date/time: " + time.Now().Format("060102_150405"))
			os.Exit(0)
		case 'D':
			o.daemon = true
		case 'S':
			o.silent = true
		case 'x':
			o.execCmds = true
		case 'g':
			o.thumbs = true
		case 'k':
			o.keepAlive = false
		case 'v':
			// Like the C code: "-v" alone means VERBOSE_INFO, and "-v 3" is
			// only taken when it parses as a positive number.
			n, err := value()
			if err != nil {
				n = ""
			}
			if v := elog.Atoi(n); v > 0 {
				o.verbose, o.verboseSet = v, true
			} else {
				o.verbose, o.verboseSet = elog.VerboseInfo, true
			}
		case 'm', 'M', 'C':
			// -m/-M take no value; -C carries the URL attached or as the next
			// element. Nothing is synchronised in this port, so the switch is
			// refused instead of silently doing nothing - the C program exits
			// after the sync either way.
			return nil, fmt.Errorf("switch -%c: %w", a[1], notImplemented)
		case 'p', 'c', 's', 'd', 't', 'l', 'n', 'f':
			v, err := value()
			if err != nil {
				return nil, err
			}
			switch a[1] {
			case 'p':
				o.port = elog.Atoi(v)
			case 'c':
				o.configFile = v
			case 's':
				o.resource = v
			case 'd':
				o.logbookDir = v
			case 't':
				o.smtpPwd = v
			case 'l':
				o.logbook = v
			case 'n':
				o.iface = v
			case 'f':
				o.pidFile = v
			}
		default:
			fmt.Fprintf(os.Stderr, "elogd: unknown switch -%c\n\n", a[1])
			fmt.Print(usageText)
			os.Exit(1)
		}
	}
	return o, nil
}

// run is main's body, so that the error handling (one message, exit status 1)
// lives in one place.
func run(argv []string) error {
	o, err := parseArgs(argv)
	if err != nil {
		return err
	}
	switch {
	case o.silent:
		elog.SetVerbose(elog.VerboseSilent)
	case o.verboseSet:
		elog.SetVerbose(o.verbose)
	}

	// The environment first, the command line on top of it, so that an init
	// script can point several instances at their own directories.
	if o.configFile == "" {
		o.configFile = os.Getenv("ELOGCFG")
	}
	if o.configFile == "" {
		o.configFile = filepath.Join(defaultConfigDir(), elog.ConfigFileName)
	}
	if o.logbookDir == "" {
		o.logbookDir = os.Getenv("ELOGDIR")
	}
	if v := os.Getenv("ELOGUSER"); v != "" {
		// setuid is not performed by the Go rewrite (see RESULT.md); the
		// variable is accepted so a start-up script does not fail.
		elog.Logf("ELOGUSER=%s ignored: drop privileges with the service manager instead", v)
	}

	// The original refuses to start without a configuration file, and says so
	// with the file name, which is the message operators search for.
	if _, err := os.Stat(o.configFile); err != nil {
		return fmt.Errorf("cannot open configuration file %s (%v)", o.configFile, err)
	}
	cfg, err := elog.LoadConfig(o.configFile)
	if err != nil {
		return fmt.Errorf("cannot parse %q: %w", o.configFile, err)
	}

	// -t <pwd>: write the SMTP password into the configuration file and exit,
	// before any logbook is opened or any port is bound.
	if o.smtpPwd != "" {
		return storeSMTPPassword(cfg, o.configFile, o.smtpPwd)
	}

	// Directories, in the order of the original's main(): the resource
	// directory must exist (the themes and the .lng files live there), the
	// logbook directory is created when it is missing.
	res := o.resource
	if res == "" {
		res = cfg.GetString(global, "Resource dir", "")
	}
	if res == "" {
		res = filepath.Dir(o.configFile)
	}
	res = strings.TrimRight(res, `/\`)
	if res == "" {
		res = "."
	}
	if st, err := os.Stat(res); err != nil || !st.IsDir() {
		return fmt.Errorf("resource directory \"%s\" does not exist", res)
	}

	lbDir := o.logbookDir
	if lbDir == "" {
		lbDir = cfg.GetString(global, "Logbook dir", "")
	}
	if lbDir == "" {
		// Same shape as the C code: <directory of the config file>/logbooks,
		// which for a bare "./elogd.cfg" is plain "logbooks".
		if d := filepath.Dir(o.configFile); d != "" && d != "." {
			lbDir = filepath.Join(d, "logbooks")
		} else {
			lbDir = "logbooks"
		}
	}
	if st, err := os.Stat(lbDir); err != nil || !st.IsDir() {
		if err := os.MkdirAll(lbDir, 0o775); err != nil {
			return fmt.Errorf("cannot create logbook directory %q: %w", lbDir, err)
		}
		elog.Logf("logbook directory \"%s\" successfully created", lbDir)
	}

	// Port: 80 (443 with SSL), overridden by "Port" from [global], then by -p.
	s := elog.New(cfg, o.configFile)
	s.ResourceDir = res
	s.DataDir = lbDir
	if cfg.GetFlag(global, "SSL") {
		s.Port = 443
	}
	if n := cfg.GetInt(global, "Port", 0); n > 0 {
		s.Port = n
	}
	if o.port != 0 {
		s.Port = o.port
	}
	if o.iface != "" {
		s.Addr = o.iface
	}
	if cert := cfg.GetString(global, "SSL cert", ""); cert != "" {
		s.SSLCert = s.Abs(cert)
		s.SSLKey = s.Abs(cfg.GetString(global, "SSL key", ""))
	}
	s.Thumbnail = o.thumbs || cfg.GetFlag(global, "Use thumbs")
	s.Exec = o.execCmds
	s.RealIP = cfg.GetFlag(global, "Use X-Forwarded-For")

	// The daemon detaches before it binds, so that a failure to bind is
	// reported by the exit status of the parent rather than only in a log file
	// that a start-up script then truncates.
	if o.daemon {
		if err := daemonize(); err != nil {
			return fmt.Errorf("cannot become daemon: %w", err)
		}
	}

	if o.pidFile != "" {
		if err := writePID(o.pidFile); err != nil {
			return err
		}
		defer os.Remove(o.pidFile)
	}

	// Rebuild the indexes of every logbook at start-up, the way the original
	// does in el_index_logbooks() before the first accept().
	if err := s.OpenAll(); err != nil {
		elog.Logf("warning: %v", err)
	}
	// Publish the instance for the transcribed helpers that reach the daemon
	// the way the C code reached its globals (see state.go for why).
	elog.SetCurrentServer(s)

	if elog.Verbose() >= elog.VerboseURL {
		elog.Logf("listening on %s:%d (config %s, logbooks %d, data %s, execute %v, thumbs %v)",
			orAny(s.Addr, "*"), s.Port, o.configFile, len(s.Order), s.DataDir, s.Exec, s.Thumbnail)
	}
	if !s.Exec {
		elog.Logf("external commands are disabled (start with -x to honour the \"Execute ...\" keys)")
	}
	if !o.keepAlive {
		elog.Logf("-k ignored: net/http manages connection reuse itself")
	}
	return s.ListenAndServe()
}

// defaultConfigDir is the compiled-in CONFIG_PATH of the C build; it is empty
// for a normal build, where the configuration is simply ./elogd.cfg. ELOGPATH is
// this port's spelling of the same idea, for a package that wants to ship its
// configuration outside the working directory.
func defaultConfigDir() string {
	return os.Getenv("ELOGPATH")
}

func orAny(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
