package elog

import (
	"bytes"
	"io"
	"os/exec"
)

// ---------------------------------------------------------------------------
// Subprocesses: the single entry point
// ---------------------------------------------------------------------------
//
// Every external program this daemon starts goes through runProgram, so that the
// shell-injection story is one line instead of a review of every call site: the
// command is given as an argv slice to exec.Command and /bin/sh is never
// involved. The C code built one string and handed it to system(), which is how
// a file name like
//
//	"; rm -rf /"
//
// became a command; the local patches quoted the name (a workaround) and this
// port removes the class of bug by construction. The same holds for the mail
// filter, the sendmail pipe and the "Execute new/edit/delete" hooks, where a
// substituted entry value (&title, &attrX) is data, never syntax.
//
// Whether a subprocess may run at all is decided by exactly one place,
// (*Server).runCommand in server.go (and, for the page text that embeds output,
// (*Server).captureProgram in shell.go), which check the -x switch. The helpers
// here do not re-check it, so that a caller that already decided is not silently
// blocked twice - and so that a caller which must run something regardless of a
// configuration value (none exists today) is not blocked at all.

// execCommand is exec.Command under a name that grep finds, so that "where does
// this program start a process?" has one answer.
func execCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// runProgram starts argv, feeds stdin to it if non-nil, and returns its standard
// output. A non-zero exit status is returned as an error along with the stderr the
// program produced, which is what the callers log.
//
// Output is collected into a Go slice that grows as needed; there is no fixed
// buffer here, which is the class of bug (a char buf[N] filled with strcpy by way
// of sprintf) that the applied patches removed from the C code. Nothing is
// truncated at MAX_STRING or MAX_PATH either: a path longer than the C program's
// buffer is simply a longer string here.
func runProgram(argv []string, dir string, stdin io.Reader) ([]byte, error) {
	if len(argv) == 0 {
		return nil, nil
	}
	cmd := execCommand(argv[0], argv[1:]...)
	if dir != "" {
		cmd.Dir = dir
	}
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		if msg := TrimSpaceASCII(errb.String()); msg != "" {
			return out, &cmdError{cmd: argv[0], err: err, output: msg}
		}
		return out, err
	}
	return out, nil
}

// runProgram is the method form used by the subsystem that reaches a program
// through the server (thumbnails via convert/identify, the mail filter, the
// sendmail pipe). It is a one-line delegation: the point of the method is that a
// reader can trace a subprocess start back to this file from either call style,
// not that it does anything else.
func (s *Server) runProgram(argv []string, dir string, stdin io.Reader) ([]byte, error) {
	if s != nil && len(argv) > 0 {
		Debugf("exec %v (dir %q)", argv, dir)
	}
	return runProgram(argv, dir, stdin)
}

// cmdError keeps the stderr of a failed subprocess with the error, which is what
// the daemon log and the configuration page show.
type cmdError struct {
	cmd    string
	err    error
	output string
}

func (e *cmdError) Error() string {
	s := e.cmd + ": " + e.err.Error()
	if e.output != "" {
		s += ": " + firstLine(e.output)
	}
	return s
}

func (e *cmdError) Unwrap() error { return e.err }
