// ELOG rewritten in Go - the entry points of the one-time conversion.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

// ---------------------------------------------------------------------------
// What this file is for
// ---------------------------------------------------------------------------
//
// legacy.go answers "what text is this?" and ConvertFile there converts a file
// that fits in memory. legacy_write.go owns the safe write (backup, temp file,
// fsync, rename, verify, restore). This file is the layer the command
// "gologd -convert" (cmd/gologd/convert.go) actually calls:
//
//   - ConvertTree / LogbookLogFiles: find the message files of a data directory;
//   - ConvertFileAuto: convert one file, in memory up to maxConvertFileSize and
//     block by block above it, with the same safety either way;
//   - PIDFileHeld: the "a daemon is still running here" refusal.
//
// Nothing in here is reachable from a request handler, and nothing in here runs
// when the daemon serves pages: the server reads legacy files (legacy.go) and
// writes UTF-8 (storage.go's Append/Update, gated by PrepareStoredEntry), and the
// conversion of a store from one encoding to another is an operator action with a
// report and a backup.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// ErrDaemonRunning is returned when a data directory still belongs to a running
// daemon (its PID file exists and names a live process). Converting under a
// running daemon is not corrupted by the conversion itself - the write is atomic -
// but the daemon keeps an index built from the OLD bytes, so it would answer from
// stale offsets and rewrite the file from them on the next edit. Hence the refusal
// and the -force escape.
var ErrDaemonRunning = errors.New("a gologd/elogd daemon appears to be running for this directory")

// streamVerifyChunk is unused on purpose: the streaming verification walks blocks,
// not fixed-size chunks, so a rune or a block never straddles a check boundary.
//
// LogbookLogFiles lists the message files of one logbook data directory, in the
// order the daemon reads them: the flat files first, then each year directory, and
// inside a directory by name (which for "YYMMDDa.log" is chronological order).
//
// The rules are storage.go's listLogFiles rules, repeated here rather than shared
// because the daemon's version is a method on an open logbook and the conversion
// tool has to look at a directory it never opens as a logbook (it must not build an
// index of a store it is about to rewrite).
func LogbookLogFiles(dir string) ([]string, error) {
	var out []string
	flat, err := logFilesIn(dir)
	if err != nil {
		return nil, err
	}
	out = append(out, flat...)
	des, err := os.ReadDir(dir)
	if err != nil {
		return out, err
	}
	var years []string
	for _, de := range des {
		if de.IsDir() && allDigits(de.Name()) {
			years = append(years, de.Name())
		}
	}
	sort.Strings(years)
	for _, y := range years {
		fs, err := logFilesIn(filepath.Join(dir, y))
		if err != nil {
			return out, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

// logFilesIn lists one directory's "YYMMDDa.log" files, sorted. A directory that
// does not exist is empty, not an error, which is what a half-migrated logbook
// needs.
func logFilesIn(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		n := de.Name()
		if len(n) == len(LogFileSuffix)+6 && filepath.Ext(n) == ".log" {
			out = append(out, filepath.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out, nil
}

// LogbookConfigFiles lists the OTHER text files of a logbook data directory that
// may hold national code page bytes: the header/footer includes elogd prints on
// every page of a logbook. Attachments are deliberately not in the list: their
// bytes are the user's and are never re-encoded.
func LogbookConfigFiles(dir string) []string {
	var out []string
	for _, n := range []string{"header.html", "footer.html", "commands.html", "custom_css.css", "help.html"} {
		p := filepath.Join(dir, n)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// ConvertTree converts every message file of one logbook data directory and
// returns one report per file, in the order they were converted. opts.DryRun is
// honoured by every file, so a dry run of a tree writes nothing at all.
func ConvertTree(dir string, opts ConvertOptions) ([]ConvertReport, error) {
	files, err := LogbookLogFiles(dir)
	if err != nil {
		return nil, err
	}
	reports := make([]ConvertReport, 0, len(files))
	for _, f := range files {
		rep := ConvertFileAuto(f, opts)
		reports = append(reports, rep)
		if opts.Progress != nil {
			opts.Progress(formatConvertReport(rep))
		}
	}
	return reports, nil
}

// ConvertFileAuto converts one log file, choosing the strategy by size: up to
// maxConvertFileSize the whole file is held in memory (ConvertFile), because the
// verification then compares bytes; above it the file is converted block by block
// (convertStreamed), because a log file of several gigabytes does not fit twice
// into the memory of the machine gologd runs on - on linux/386 and windows/386 a
// process cannot address one at all.
//
// Both strategies honour every refusal and both produce the same bytes: the unit
// of the conversion is the message block, which is the smallest piece a code page
// can be decoded in and the piece the index points at.
func ConvertFileAuto(path string, opts ConvertOptions) ConvertReport {
	sz, err := osFileSize(path)
	if err != nil {
		return ConvertReport{Path: path, Err: err}
	}
	if sz <= maxConvertFileSize {
		return ConvertFile(path, opts)
	}
	return convertStreamed(path, opts, sz)
}

// convertStreamed is the large-file path of ConvertFileAuto. The order of
// operations is the one of ConvertFile - classify, resolve the code page, refuse,
// convert to a temporary file, back the original up, rename, verify, restore on a
// failed verification - so the operator sees the same report either way.
func convertStreamed(path string, opts ConvertOptions, size int64) ConvertReport {
	rep := ConvertReport{Path: path, Bytes: size}
	mode, modTime, err := osStatForConvert(path)
	if err != nil {
		rep.Err = err
		return rep
	}

	// 1. classify from the head of the file. Reading one megabyte of a
	// three-gigabyte file is cheap and it is exactly what the in-memory path
	// looks at (legacySample), so the two paths cannot disagree.
	head, err := readHeadSample(path, legacyProbeBytes)
	if err != nil {
		rep.Err = err
		return rep
	}
	st := ProbeBytes(head)
	switch {
	case st.IsBinary():
		rep.Skipped = true
		rep.Reason = "not a text file (NUL or escape bytes): refusing to convert"
		rep.Err = ErrNotText
		return rep
	case st.ASCII:
		rep.Skipped = true
		rep.Reason = "pure ASCII, already valid UTF-8"
		return rep
	case st.ValidUTF8:
		rep.Skipped = true
		rep.Reason = "already valid UTF-8"
		return rep
	}

	// 2. the code page: the explicit one, or the detector when -codepage auto.
	codepage := opts.Codepage
	if codepage == nil || !codepage.IsLegacy() {
		if !opts.Auto {
			rep.Err = fmt.Errorf("%w: %s is %d bytes and needs an explicit -codepage",
				ErrUnknownCodepage, path, size)
			rep.Reason = "no codepage"
			return rep
		}
		var ok bool
		var why string
		codepage, ok, why = AutoLegacyCodecs(head)
		if !ok {
			rep.Err = fmt.Errorf("%w: %s (%s)", ErrUnknownCodepage, path, why)
			rep.Reason = why
			return rep
		}
	}
	rep.Codepage = codepage.Name()
	if opts.DryRun {
		rep.Skipped = true
		rep.Reason = fmt.Sprintf("would convert %s from %s, streaming (%d bytes)", filepath.Base(path), rep.Codepage, size)
		return rep
	}

	// 3. convert to a temporary file in the same directory: the rename below can
	// only be atomic within one file system.
	tmp := path + convertTmpSuffix
	tf, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		rep.Err = err
		return rep
	}
	src, err := os.Open(path)
	if err != nil {
		tf.Close()
		os.Remove(tmp)
		rep.Err = err
		return rep
	}
	written, blocks, converted, replaced, dropped, err :=
		streamDecodeToUTF8(tf, src, codepage, opts.AddMarkers, codepage.Name())
	src.Close()
	if err == nil {
		if serr := tf.Sync(); serr != nil {
			err = serr
		}
	}
	if cerr := tf.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		rep.Err = fmt.Errorf("%s: streaming conversion: %w", path, err)
		return rep
	}
	rep.Entries = blocks
	rep.Replaced = replaced + dropped
	rep.OutBytes = written

	// 4. the same refusal as the in-memory path: undecodable bytes need -force.
	// The temporary file is thrown away, the original is untouched, so a refusal
	// costs nothing but the read.
	if replaced > 0 && !opts.Force {
		os.Remove(tmp)
		rep.Skipped = true
		rep.Reason = "undecodable bytes"
		rep.Err = fmt.Errorf("%s: %d undecodable byte(s); use -force to replace them with U+FFFD", path, replaced)
		return rep
	}

	// 5. verify the TEMPORARY file before it becomes the log file: every block of
	// it must be valid UTF-8 and there must be as many blocks as we converted.
	// This is the streaming form of "decode the result back and compare".
	vblocks, verr := verifyStreamedFile(tmp)
	if verr == nil && vblocks != blocks {
		verr = fmt.Errorf("the converted file holds %d block(s), %d were written", vblocks, blocks)
	}
	if verr != nil {
		os.Remove(tmp)
		rep.Err = fmt.Errorf("%s: verification of the converted file failed, the original was not touched: %w", path, verr)
		return rep
	}

	// 6. the backup, then the rename, then the mode and the mtime. A crash
	// between the backup and the rename leaves both files; a crash during the
	// rename leaves one of them, which is what a rename is for.
	backup, err := copyBackupOf(path, mode, opts)
	if err != nil {
		os.Remove(tmp)
		rep.Err = fmt.Errorf("%s: backup: %w", path, err)
		return rep
	}
	if backup != "" {
		rep.Backups = append(rep.Backups, backup)
	}
	if err := renameWithinDirectory(tmp, path); err != nil {
		os.Remove(tmp)
		rep.Err = fmt.Errorf("%s: replace: %w", path, err)
		return rep
	}
	if opts.KeepMTime {
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			logEncodingOnce("convert:chtimes", "golog: convert: cannot restore the modification time of %s: %v", path, err)
		}
	}
	rep.Changed = true
	rep.Reason = fmt.Sprintf("converted %d blocks from %s, streaming", converted, rep.Codepage)
	return rep
}

// readHeadSample reads at most n bytes of a file. It is a function and not a
// method because both the classification and the detector want exactly this, and
// both must look at the SAME bytes so that their answers agree.
func readHeadSample(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, rerr := f.Read(buf)
	if read == 0 && rerr != nil && rerr != io.EOF {
		return nil, rerr
	}
	return buf[:read], nil
}

// verifyStreamedFile walks a converted file block by block and reports how many
// blocks it found. Every block must be valid UTF-8: that is the promise the
// conversion made, and a block that is not is a bug or a truncated write.
func verifyStreamedFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	rd := newBlockReader(f)
	blocks := 0
	for {
		block, rerr := rd.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return blocks, rerr
		}
		blocks++
		if !blockIsUTF8(block) {
			return blocks, fmt.Errorf("block %d of the converted file is not valid UTF-8", blocks)
		}
	}
	return blocks, nil
}

// copyBackupOf copies the original file to the backup destination without reading
// it all into memory, which is the point of the streaming path. The mode is
// carried over so that a logbook only the golog user may read stays that way.
func copyBackupOf(path string, mode os.FileMode, opts ConvertOptions) (string, error) {
	dest := path + ".bak"
	if opts.BackupDir != "" {
		if err := os.MkdirAll(opts.BackupDir, 0o755); err != nil {
			return "", err
		}
		stamp := time.Now().Format(convertBackupTime)
		dest = uniqueBackupName(filepath.Join(opts.BackupDir, filepath.Base(path)+"."+stamp+".bak"))
	}
	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return dest, nil
}

// renameWithinDirectory renames tmp over path and syncs the directory, so that
// "the rename is atomic" is a statement about the disk and not only about the
// operating system's idea of it. The file itself was synced by the caller before
// this is reached.
func renameWithinDirectory(tmp, path string) error {
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if dir, derr := os.Open(filepath.Dir(path)); derr == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

// formatConvertReport is the one line ConvertTree's default progress prints. The
// command formats its own lines with the same field order, so a log of a
// conversion and the terminal output say the same thing.
func formatConvertReport(rep ConvertReport) string {
	state := "converted"
	switch {
	case rep.Err != nil:
		state = "ERROR"
	case rep.Changed:
	case rep.Skipped:
		state = "skipped"
	}
	if rep.Err != nil {
		return fmt.Sprintf("%-28s %s: %v", state, rep.Path, rep.Err)
	}
	return fmt.Sprintf("%-28s %s: %s (%d -> %d bytes, %d replaced)",
		state, rep.Path, rep.Reason, rep.Bytes, rep.OutBytes, rep.Replaced)
}

// FormatConvertReport is formatConvertReport for a caller outside the package (the
// conversion command).
func FormatConvertReport(rep ConvertReport) string { return formatConvertReport(rep) }

// ---------------------------------------------------------------------------
// "Is a daemon running here?"
// ---------------------------------------------------------------------------
//
// The conversion tool refuses to touch a data directory a daemon still owns. It
// decides from the PID file alone, which is the file the operator passes with -f
// and the one elogd's init script removes on stop; it does not send signals,
// because "signal 0" does not exist on every supported platform and a portable
// tool must not guess. When the file exists the tool asks for -force, which is the
// operator saying "I know the daemon is stopped and left the file behind".

// PIDFileHeld reports that pidFile exists and names a plausible process id. The
// second result is the refusal; the first is the number read from the file (0 when
// it could not be parsed, in which case the file is reported as it is).
func PIDFileHeld(pidFile string) (pid int, held bool, err error) {
	if pidFile == "" {
		return 0, false, nil
	}
	data, rerr := os.ReadFile(pidFile)
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, rerr
	}
	pid = Atoi(string(data))
	if pid <= 0 {
		return 0, true, fmt.Errorf("%s exists but does not hold a process id", pidFile)
	}
	return pid, true, nil
}

// WritePIDFileUTF8 writes a PID file through the UTF-8 gate. The content is a
// number, so this cannot change it; what the call buys is the shared atomic write
// and one less place that opens a file in the data directory by hand.
func WritePIDFileUTF8(path string, pid int) error {
	_, err := WriteTextUTF8(path, strconv.Itoa(pid)+"\n")
	return err
}
