package elog

import (
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// External commands
// ---------------------------------------------------------------------------
//
// elogd can run external programs in four places:
//
//	"Execute new" / "Execute edit" / "Execute delete"   around a store
//	"$shell(command)" / "$(shell command)"              inside page text and config values
//	"Incoming mail filter"                              a pipe receiving a notification
//	"Sendmail"                                          a pipe receiving a notification
//
// This is the site of the shell-injection bug the local patches fix: the C code
// built a single command line and passed it to system(), so an attachment named
//
//	; rm -rf /
//
// - or an entry value substituted into the line - became shell syntax. The patch
// quotes the file name; the fix used here is stronger: nothing in this program
// ever goes through a shell. A configured command is split into argv words
// (SplitCommand) and started with exec.Command by runProgram in procs.go, so a
// name containing shell metacharacters is one inert argument.
//
// Execution is opt-in with the -x switch (Server.AllowExecute, declared in
// server.go together with runCommand, which is the single path from a configured
// command line to a process). Without it the hooks and $shell() are skipped and
// logged, so a logbook file or a configuration value that grew a $shell() cannot
// execute code on a server whose operator never enabled it.
//
// This file holds the two things that sit above that path: the &-substitutions
// elogd applies to the "Execute" strings, and the $shell() expansion. Both end in
// runCommand, i.e. in argv words, never in a shell string.

// maxShellDepth bounds the nesting of $shell(...) inside $shell(...) so that a
// pathological configuration value cannot recurse forever.
const maxShellDepth = 4

// runEntryHook runs the "Execute new" / "Execute edit" / "Execute delete" command
// around a store. Substitutions happen first, the -x gate lives inside
// runCommand, so a caller cannot bypass the gate by calling this.
func (s *Server) runEntryHook(command, dir string, e *Entry, logbook, url string) error {
	command = TrimSpaceASCII(s.substituteEntry(command, e, logbook, url))
	return s.runCommand(command, dir)
}

// RunEntryHook is the exported form of runEntryHook.
func (s *Server) RunEntryHook(command, dir string, e *Entry, logbook, url string) error {
	return s.runEntryHook(command, dir, e, logbook, url)
}

// substituteEntry performs the &-substitutions elogd applies to the "Execute"
// strings and to the display text:
//
//	&num / &id   the message number      &logbook  the logbook name
//	&dir         the logbook directory   &charset  the character set
//	&url         the entry URL           &title    the entry title
//	&attrX       the value of attribute X
//
// The substituted text is data: it is later split into argv words, so a value
// containing $(...), a backquote or a semicolon stays one argument.
func (s *Server) substituteEntry(text string, e *Entry, logbook, url string) string {
	if e == nil {
		text = strings.ReplaceAll(text, "&logbook", logbook)
		return text
	}
	lb := logbook
	if lb == "" {
		lb = e.Logbook
	}
	text = strings.ReplaceAll(text, "&logbook", lb)
	if url != "" {
		text = strings.ReplaceAll(text, "&url", url)
	} else if u := e.Get2("_URL"); u != "" {
		text = strings.ReplaceAll(text, "&url", u)
	}
	if dir := e.Get2("_DIR"); dir != "" {
		text = strings.ReplaceAll(text, "&dir", dir)
	}
	if cs := e.Encoding(); cs != "" {
		text = strings.ReplaceAll(text, "&charset", cs)
	}
	text = strings.ReplaceAll(text, "&num", strconv.Itoa(e.ID()))
	for _, a := range e.AttrNames() {
		text = strings.ReplaceAll(text, "&attr"+a, e.Get2(a))
	}
	text = strings.ReplaceAll(text, "&id", strconv.Itoa(e.ID()))
	text = strings.ReplaceAll(text, "&title", e.Title())
	return text
}

// SubstituteEntry is the exported form of substituteEntry, used by the pages for
// the display text where elogd applies the same &-substitutions.
func (s *Server) SubstituteEntry(text string, e *Entry, logbook, url string) string {
	return s.substituteEntry(text, e, logbook, url)
}

// shellSubst expands  $shell(command args)  and  $(shell command args)  inside
// page text or a configuration value: this is how a logbook puts live output into
// its header or footer. Each command runs through runCommand (argv words, no
// shell) and its exit status is ignored, as in the original. Without the -x switch
// the substitution yields "".
//
// It is a free function taking the server so that Server.ShellSubst (server.go)
// and Server.ShellSubstFor (state.go, which adds the logbook's directory as the
// working directory) share one parser.
func shellSubst(s *Server, text string) string {
	return shellSubstInDir(s, text, "")
}

// shellSubstInDir is shellSubst with an explicit working directory.
func shellSubstInDir(s *Server, text, dir string) string {
	if s == nil || !strings.Contains(text, "shell(") && !strings.Contains(text, "$(shell") {
		return text
	}
	return s.shellSubstDepth(text, dir, 0)
}

// shellSubstDepth is the worker of shellSubstInDir. The text is assembled
// left to right and the program output is appended to the result without being
// rescanned, so output that itself contains "$shell(...)" is never executed - the
// C original restarts its scan from the beginning of the buffer and would run it.
func (s *Server) shellSubstDepth(text, dir string, depth int) string {
	var b strings.Builder
	for {
		i := indexShellCall(text)
		if i < 0 {
			b.WriteString(text)
			return b.String()
		}
		b.WriteString(text[:i])
		// i points at '$'; the call is $( ... ) or $shell( ... ). Find the matching
		// closing parenthesis by counting nesting, so a command whose argument
		// contains a parenthesis is not cut short (the original scans for the first
		// ')' and truncates such a command).
		open := strings.IndexByte(text[i:], '(')
		if open < 0 {
			b.WriteString(text[i:])
			return b.String()
		}
		open += i
		depthParen, end := 0, -1
		for j := open; j < len(text); j++ {
			switch text[j] {
			case '(':
				depthParen++
			case ')':
				depthParen--
				if depthParen == 0 {
					end = j
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			b.WriteString(text[i:])
			return b.String()
		}
		inner := TrimSpaceASCII(strings.TrimPrefix(TrimSpaceASCII(text[open+1:end]), "shell"))
		out := ""
		switch {
		case depth >= maxShellDepth:
			s.logf("$shell(...) nesting limit reached, not running %q", inner)
		case !s.AllowExecute():
			s.logf("execution disabled (-x), not running $shell(...)")
		default:
			var err error
			out, err = s.captureProgram(inner, dir, depth+1)
			if err != nil {
				s.logf("$shell(%s): %v", inner, err)
			}
		}
		b.WriteString(out)
		text = text[end+1:]
	}
}

// indexShellCall finds the start of the next $shell( or $(shell call, or -1.
func indexShellCall(text string) int {
	for i := 0; i < len(text); i++ {
		if text[i] != '$' {
			continue
		}
		if strings.HasPrefix(text[i:], "$shell(") || strings.HasPrefix(text[i:], "$shell (") {
			return i
		}
		if strings.HasPrefix(text[i:], "$(") &&
			(strings.HasPrefix(text[i+2:], "shell ") || strings.HasPrefix(text[i+2:], "shell(")) {
			return i
		}
	}
	return -1
}

// captureProgram splits a command line, applies the nested $shell() expansions
// that may still be in its arguments (bounded by maxShellDepth), and returns the
// program's standard output with the trailing newlines removed. The -x gate is
// applied here too, because the pages reach a program only through this function.
func (s *Server) captureProgram(command, dir string, depth int) (string, error) {
	command = s.shellSubstDepth(command, dir, depth)
	command = TrimSpaceASCII(command)
	if command == "" {
		return "", nil
	}
	argv := SplitCommand(command)
	if len(argv) == 0 {
		return "", nil
	}
	if !s.AllowExecute() {
		s.logf("execution disabled (-x), not running %q", argv[0])
		return "", nil
	}
	s.logf("$shell: %v", argv)
	data, err := runProgram(argv, dir, nil)
	return strings.TrimRight(string(data), "\n"), err
}

// runCommandCapture is runCommand with the program's standard output returned
// instead of only logged. The trailing newline is removed, which is what the page
// text wants.
func (s *Server) runCommandCapture(command, dir string, out *string) error {
	o, err := s.captureProgram(command, dir, 0)
	if out != nil {
		*out = o
	}
	return err
}

// SplitCommand splits a command line into argv words, honouring single and double
// quotes and backslash escapes. It exists so that a configured command can still
// be written naturally in the configuration file while the program is started
// directly: the result goes to exec.Command, never to /bin/sh, so shell
// metacharacters in a substituted value have no effect.
//
// Note what this is NOT: it is not a shell. Nothing is globbed, nothing is
// redirected, $(...) is not executed, and the words are handed to exec.Command as
// they stand. The quoting the local patch added to the C code (which wrapped the
// attachment name in single quotes before system()) is therefore unnecessary
// here - the name is one argv word either way.
func SplitCommand(s string) []string {
	var out []string
	var cur strings.Builder
	started := false
	i := 0
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
			i++
		case '\'':
			started = true
			i++
			for i < len(s) && s[i] != '\'' {
				cur.WriteByte(s[i])
				i++
			}
			i++
		case '"':
			started = true
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
				i++
			}
			i++
		case '\\':
			started = true
			if i+1 < len(s) {
				cur.WriteByte(s[i+1])
				i += 2
			} else {
				i++
			}
		default:
			started = true
			cur.WriteByte(s[i])
			i++
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}
