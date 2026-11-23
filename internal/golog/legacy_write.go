// ELOG rewritten in Go - the write side of the one-time conversion.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog

// ---------------------------------------------------------------------------
// Writing a converted file safely
// ---------------------------------------------------------------------------
//
// This is the only place in golog that rewrites a logbook file's bytes from a
// different encoding, so all of the safety lives here and nowhere else:
//
//   - the new bytes go to a temporary file in the SAME directory (a rename can
//     only be atomic within one file system), are flushed to the storage device
//     and only then renamed over the original;
//   - the original is copied to a backup before the rename, and restored if the
//     verification afterwards fails;
//   - the mode of the original is carried over to the temporary file and to the
//     backup, so a logbook only the golog user may read stays that way;
//   - nothing here creates a file outside the directory it was given.
//
// The server never calls any of this: it is reached from "gologd -convert"
// (cmd/gologd/convert.go) and from tests only. If you are adding a call to
// anything in this file to a request handler, stop: the daemon's one job about
// encodings is to READ legacy files and WRITE UTF-8, and it does both elsewhere.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// convertTmpSuffix is the extension of the temporary file. It is visible in a
// directory listing on purpose ("golog-convert" says who made it), and the name
// does not end in the log-file suffix, so a crashed conversion leaves a file the
// daemon will not read as a logbook.
const convertTmpSuffix = ".golog-convert.tmp"

// convertBackupTime is the time stamp format of a backup file name in
// ConvertOptions.BackupDir.
const convertBackupTime = "20060102-150405"

// writeConvertedFile performs steps 4-7 of ConvertFile (see legacy.go): backup,
// atomic write, verify, restore-on-failure.
func writeConvertedFile(path string, old, out []byte, opts ConvertOptions, rep *ConvertReport) error {
	mode, modTime, err := osStatForConvert(path)
	if err != nil {
		return err
	}

	// 4. the backup, before anything is touched.
	backup, err := makeBackup(path, old, mode, opts)
	if err != nil {
		return fmt.Errorf("%s: backup: %w", path, err)
	}
	if backup != "" {
		rep.Backups = append(rep.Backups, backup)
	}

	// 5. temp file + fsync + rename.
	tmp := path + convertTmpSuffix
	if err := writeTempAndRename(tmp, path, out, mode); err != nil {
		// The temporary file may exist; make sure a crashed run does not leave
		// litter that confuses the next one.
		os.Remove(tmp)
		return fmt.Errorf("%s: %w", path, err)
	}

	// 6. verify by reading the result back and checking it against what we
	// intended to write. The text is what must survive and the byte form is what
	// we deliberately changed, so the comparison is against our own output and not
	// against the original file.
	if err := verifyConverted(path, out); err != nil {
		if rerr := restoreBackup(path, backup, mode); rerr != nil {
			return fmt.Errorf("%s: verify: %v; RESTORE FAILED, the original is in %s: %v",
				path, err, backup, rerr)
		}
		return fmt.Errorf("%s: verification failed, original restored from %s: %w", path, backup, err)
	}

	// 7. mtime, when the operator asked to keep the old one.
	if opts.KeepMTime {
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			logEncodingOnce("convert:chtimes", "golog: convert: cannot restore the modification time of %s: %v", path, err)
		}
	}
	return nil
}

// writeTempAndRename writes data to tmp with mode and renames it over path. The
// fsync of the file and of the directory is what makes "rename is atomic" a
// statement about the disk and not only about the operating system's idea of it:
// without the file sync, a power failure can leave the renamed name pointing at
// blocks that never arrived.
func writeTempAndRename(tmp, path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Syncing the directory is best effort: not every platform lets a directory
	// be opened for reading, and a missing directory sync costs durability,
	// never the correctness of the file's content.
	if dir, derr := os.Open(filepath.Dir(path)); derr == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

// verifyConverted reads path back and checks that it is valid UTF-8 with exactly
// the bytes we wrote.
func verifyConverted(path string, want []byte) error {
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("read back %d bytes, wrote %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			return fmt.Errorf("read back different bytes at offset %d", i)
		}
	}
	if st := ProbeBytes(got); !st.ValidUTF8 {
		return fmt.Errorf("the converted file is not valid UTF-8 (%d damaged byte(s))", st.Bad)
	}
	return nil
}

// makeBackup copies the original bytes to "<path>.bak" or into opts.BackupDir,
// keeping the mode, and returns the name. The copy is fsynced: a backup that only
// exists in the page cache is no backup at all.
func makeBackup(path string, old []byte, mode os.FileMode, opts ConvertOptions) (string, error) {
	dest := path + ".bak"
	if opts.BackupDir != "" {
		if err := os.MkdirAll(opts.BackupDir, 0o755); err != nil {
			return "", err
		}
		stamp := time.Now().Format(convertBackupTime)
		dest = uniqueBackupName(filepath.Join(opts.BackupDir, filepath.Base(path)+"."+stamp+".bak"))
	}
	if err := writeBackupFile(dest, old, mode); err != nil {
		return "", err
	}
	return dest, nil
}

// writeBackupFile writes one backup, refusing to follow a symlink or to overwrite
// anything that is not a regular file (an attacker-placed "<file>.log.bak" symlink
// must not become a write primitive). An existing backup of the SAME content is
// kept as it is, which is what makes a re-run harmless.
func writeBackupFile(dest string, data []byte, mode os.FileMode) error {
	if st, err := os.Lstat(dest); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file", dest)
		}
		if existing, rerr := os.ReadFile(dest); rerr == nil && len(existing) == len(data) {
			same := true
			for i := range existing {
				if existing[i] != data[i] {
					same = false
					break
				}
			}
			if same {
				return nil
			}
		}
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// uniqueBackupName adds ".1", ".2", ... until the name is free, so that two
// conversions on the same day do not overwrite each other's safety copy.
func uniqueBackupName(name string) string {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return name
	}
	for i := 1; i < 10000; i++ {
		cand := fmt.Sprintf("%s.%d", name, i)
		if _, err := os.Stat(cand); os.IsNotExist(err) {
			return cand
		}
	}
	return name
}

// restoreBackup puts the original bytes back after a failed verification.
func restoreBackup(path, backup string, mode os.FileMode) error {
	if backup == "" {
		return fmt.Errorf("no backup to restore from")
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	tmp := path + convertTmpSuffix
	if err := writeTempAndRename(tmp, path, data, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Small file helpers of this file
// ---------------------------------------------------------------------------
//
// They are named for what the conversion needs them for, not for the system call,
// and deliberately not "stat", "readFile" or "size": a name that short is already
// taken somewhere in a package of this size, and a collision would be a compile
// error in whichever batch touched the file that owns it.

// osStatForConvert returns the mode and the modification time of a file.
func osStatForConvert(path string) (os.FileMode, time.Time, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, time.Time{}, err
	}
	if st.IsDir() {
		return 0, time.Time{}, fmt.Errorf("%s is a directory", path)
	}
	return st.Mode().Perm(), st.ModTime(), nil
}

// osFileSize is the size of a file.
func osFileSize(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// osReadFile reads a whole file. The size limit is checked by the caller
// (legacy.go's readFileForConvert), because only there it is known which limit and
// which error a caller expects.
func osReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// ---------------------------------------------------------------------------
// Streaming conversion of very large files
// ---------------------------------------------------------------------------
//
// A logbook file of a few megabytes is converted in memory (see ConvertFile); a
// multi-gigabyte one does not fit into the memory of the machine gologd runs on
// twice (the in-memory path needs the old and the new version at the same time for
// its verification), so the conversion reads it message block by message block.
// The message block is the smallest unit the code page can be decoded in (see the
// header of legacy.go) and it is also what "--add-markers" has to find its way
// into.
//
// The blocks are assembled by hand from the raw bytes instead of being read as
// text lines: a code page outside the Latin family (IBM Code Page 1026, for
// instance) maps a byte of 0x0A to a printable character, so "split on \n" is a
// statement about the encoding, not about the file. The marker and the separator
// line are 7-bit by construction, so they can be found in undecoded bytes.

// convertStreamChunk is how much of the file is read at a time.
const convertStreamChunk = 512 * 1024

// StreamDecodeToUTF8 converts a logbook file from src into a UTF-8 logbook file on
// dst, block by block, holding at most two chunks plus one block in memory.
//
// codes is the code page to decode with; nil or the UTF-8 code page means the
// bytes are already UTF-8 and are only copied (and counted). A block whose own
// bytes are valid UTF-8 is copied and not decoded, which is the per-block rule
// again and what makes the conversion idempotent: running it twice converts
// nothing the second time.
//
// addMarkers puts "golog-encoding = <name>" into the text of every block it
// converted, where name is the code page name.
//
// It reports how many bytes it wrote and how many blocks it converted, replaced
// and dropped; see ConvertReport for the meaning of the counts.
func StreamDecodeToUTF8(dst io.Writer, src io.Reader, codes *Codecs) (written int64, err error) {
	n, _, _, _, _, err := streamDecodeToUTF8(dst, src, codes, false, "")
	return n, err
}

// streamDecodeToUTF8 is the worker behind StreamDecodeToUTF8 and behind
// encoding_util.go's DecodeReaderToUTF8, which needs the block counts for its
// report.
func streamDecodeToUTF8(dst io.Writer, src io.Reader, codes *Codecs, addMarkers bool, markerName string) (written int64, blocks, converted, replaced, dropped int, err error) {
	rd := newBlockReader(src)
	marker := []byte(MsgMarker)
	legacy := codes != nil && codes.IsLegacy()
	for {
		block, rerr := rd.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return written, blocks, converted, replaced, dropped, rerr
		}
		blocks++
		out := block
		// Only a message block is converted. The banner and any stray text before
		// the first marker stay byte-identical, so a converted file differs from
		// the original exactly where a message was decoded.
		if legacy && len(block) >= len(SeparatorLine) && indexInBytes(block, marker) >= 0 &&
			!blockIsUTF8(block) {
			text, n := DecodeToUTF8(block, codes)
			out = []byte(text)
			converted++
			replaced += n
			dropped += CountReplacementRunes(text) - n // defensive: normally 0
			if addMarkers && markerName != "" {
				out = []byte(markBlockText(string(out), markerName))
			}
		}
		m, werr := dst.Write(out)
		written += int64(m)
		if werr != nil {
			return written, blocks, converted, replaced, dropped, werr
		}
	}
	return written, blocks, converted, replaced, dropped, nil
}

// blockReader hands out the raw bytes of a logbook file, one message block (or one
// banner chunk) at a time, without ever holding more than two chunks of the file.
type blockReader struct {
	rd  io.Reader
	buf []byte
	off int // bytes of buf already handed out
	eof bool
	// started says whether the head of the file (the banner, the bytes before the
	// first marker) has been handed out already.
	started bool
}

func newBlockReader(rd io.Reader) *blockReader {
	return &blockReader{rd: rd, buf: make([]byte, 0, 2*convertStreamChunk)}
}

// fill reads one more chunk into the buffer. It reports io.EOF once the reader is
// exhausted and nothing is buffered.
func (r *blockReader) fill() error {
	if r.eof && r.off >= len(r.buf) {
		return io.EOF
	}
	if r.eof {
		return nil
	}
	chunk := make([]byte, convertStreamChunk)
	n, err := r.rd.Read(chunk)
	if n > 0 {
		r.buf = append(r.buf, chunk[:n]...)
	}
	if err == io.EOF {
		r.eof = true
		return nil
	}
	return err
}

// Next returns the next block: everything up to the next marker (the banner on the
// first call), or the whole remaining file when there is no marker any more.
func (r *blockReader) Next() ([]byte, error) {
	marker := []byte(MsgMarker)
	if !r.started {
		// The head of the file: read until the first marker appears.
		for {
			if i := indexInBytes(r.buf[r.off:], marker); i >= 0 {
				r.started = true
				if r.off+i == 0 {
					// No banner at all: do not hand out an empty block, go
					// straight to the first message.
					return r.nextBlock(marker)
				}
				return r.take(r.off + i), nil
			}
			if err := r.fill(); err != nil {
				if err == io.EOF {
					r.started = true
					if r.off >= len(r.buf) {
						return nil, io.EOF
					}
					return r.take(len(r.buf)), nil
				}
				return nil, err
			}
		}
	}
	return r.nextBlock(marker)
}

// nextBlock hands out the bytes of one message block.
func (r *blockReader) nextBlock(marker []byte) ([]byte, error) {
	for {
		if i := indexInBytes(r.buf[r.off:], marker); i >= 0 {
			return r.take(r.off + i), nil
		}
		if err := r.fill(); err != nil {
			if err == io.EOF {
				if r.off >= len(r.buf) {
					return nil, io.EOF
				}
				return r.take(len(r.buf)), nil
			}
			return nil, err
		}
	}
}

// take hands out buf[off:abs] and keeps the rest for later. The buffer is only
// compacted, never duplicated, so the memory stays bounded by two chunks whatever
// the size of the file.
func (r *blockReader) take(abs int) []byte {
	out := make([]byte, abs-r.off)
	copy(out, r.buf[r.off:abs])
	r.off = abs
	r.compact()
	return out
}

func (r *blockReader) compact() {
	if r.off == 0 {
		return
	}
	n := copy(r.buf, r.buf[r.off:])
	for i := n; i < len(r.buf); i++ {
		r.buf[i] = 0
	}
	r.buf = r.buf[:n]
	r.off = 0
}

// indexInBytes is strings.Index for raw bytes. It is this file's own because the
// standard library one takes a string, and turning a multi-megabyte buffer into a
// string is exactly what the streaming path exists to avoid.
func indexInBytes(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
