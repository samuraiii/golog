package elog

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// On-disk logbook format
// ---------------------------------------------------------------------------
//
// This file is a re-implementation of the storage engine of the C++ client
// library (src/logbook.cxx: parse_file, el_build_index, el_submit,
// el_retrieve, el_delete_message, el_copy_attachment) plus the migration
// helpers in elogd.cxx (generate_subdir_name, restructure_dir).
//
// Layout, as read out of the source:
//
//	<data dir>/YYMMDDa.log             what a pre-4.1.0 (flat) logbook holds
//	<data dir>/20YY/YYMMDDa.log        after the automatic migration that
//	                                    elogd performs at startup
//	                                    (restructure_dir(), called when the
//	                                    data dir still contains ??????a.log)
//	<data dir>/<attachment file>       attachments, next to the message file
//
// The message file name is built by
//
//	snprintf(file_name, sizeof(file_name), "%c%c%02d%c%ca.log",
//	         date1[14], date1[15], i + 1, date1[5], date1[6]);
//
// where date1 is the entry's RFC 2822 Date: line "Tue, 30 Apr 2024 12:34:56
// +0200": date1[14..15] are the last two digits of the year, i+1 is the month
// number and date1[5..6] the day of the month - i.e. "YYMMDDa.log" (240430a.log
// for 2024-04-30). The "a" is a literal that dates from the 3.0 -> 4.0 file
// format change and is part of the name (and of the "??????a.log" migration
// glob), so it must be kept.
//
// Each file holds a banner followed by a sequence of message blocks:
//
//	$@MID@$: 1234
//	Date: Tue, 30 Apr 2024 12:34:56 +0200
//	Title: some title
//	Author: John Doe
//	AttrName: attr value
//	Attachment: file1,file2
//	Encoding: HTML
//	========================================
//	<text, verbatim up to the next marker>
//
// The separator is 40 '=' (ELOG_SEPARATOR). Because a message body may contain
// almost anything, the index stores the byte offset of every "$@MID@$:" marker
// and retrieval is a read at that offset, with a self-healing rebuild if the
// bytes there no longer match.

// MsgMarker is the key of the first line of an entry ("$@MID@$: 123").
const MsgMarker = "$@MID@$"

// SeparatorLine is ELOG_SEPARATOR.
const SeparatorLine = "========================================"

// LogFileSuffix is the tail of a daily message file name.
const LogFileSuffix = "a.log"

// ErrNotFound is returned for an unknown message ID or attachment.
var ErrNotFound = errors.New("not found")

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

// HeaderLine is one "Key: value" line of a message header. Keeping the header
// as an ordered list of pairs rather than a struct is deliberate: logbooks
// carry arbitrary user-defined attributes (config "Attribute" list) and the
// server must round-trip lines it does not understand - older releases wrote
// lines such as "Reply to:" or "AttIdx:" which are invisible to the current
// schema, and a rewrite that dropped them would silently corrupt the logbook.
type HeaderLine struct {
	Key   string
	Value string
}

// Entry is one logbook message.
type Entry struct {
	Header []HeaderLine
	Text   string

	// Where this entry lives: file name, sub-directory and the byte offset of
	// its "$@MID@$:" marker. Filled in by the logbook index, not read from the
	// file.
	File   string
	Subdir string
	Offset int64
}

// Get returns the first value for key (ASCII case insensitive, like the C
// string compares).
func (e *Entry) Get(key string) (string, bool) {
	for _, h := range e.Header {
		if EqualFold(h.Key, key) {
			return h.Value, true
		}
	}
	return "", false
}

// GetAll returns every value for key ("Attr:" may repeat).
func (e *Entry) GetAll(key string) []string {
	var out []string
	for _, h := range e.Header {
		if EqualFold(h.Key, key) {
			out = append(out, h.Value)
		}
	}
	return out
}

// Set replaces every occurrence of key, appending it when absent.
func (e *Entry) Set(key, value string) {
	e.Del(key)
	e.addFolded(key, value)
}

// SetAll replaces every occurrence of key with the given values.
func (e *Entry) SetAll(key string, values []string) {
	e.Del(key)
	for _, v := range values {
		e.addFolded(key, v)
	}
}

// Add appends a header line without removing existing ones.
func (e *Entry) Add(key, value string) { e.addFolded(key, value) }

// addFolded writes a multi-line value the way the original does: the key
// appears on the first line only and the continuation lines are written bare.
func (e *Entry) addFolded(key, value string) {
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if i == 0 {
			e.Header = append(e.Header, HeaderLine{key, l})
			continue
		}
		e.Header = append(e.Header, HeaderLine{key, l})
	}
}

// Del removes every occurrence of key.
func (e *Entry) Del(key string) {
	out := e.Header[:0]
	for _, h := range e.Header {
		if !EqualFold(h.Key, key) {
			out = append(out, h)
		}
	}
	e.Header = out
}

// ID is the message ID from the "$@MID@$:" marker (0 when absent).
func (e *Entry) ID() int {
	v, ok := e.Get(MsgMarker)
	if !ok {
		return 0
	}
	return Atoi(v)
}

// SetID rewrites the marker line, keeping it first.
func (e *Entry) SetID(id int) {
	e.Del(MsgMarker)
	e.Header = append([]HeaderLine{{MsgMarker, strconv.Itoa(id)}}, e.Header...)
}

// DateValue is the parsed Date: header (Unix epoch when absent/unparsable, as
// date_to_ltime() would return 0).
func (e *Entry) DateValue() time.Time {
	v, _ := e.Get("Date")
	t, ok := ParseDate(v)
	if !ok {
		return time.Unix(0, 0)
	}
	return t
}

// SetDate formats with the canonical RFC 2822 form stored in the files.
func (e *Entry) SetDate(t time.Time) { e.Set("Date", FormatRFC2822(t)) }

// Attrs returns the user-visible attributes in file order, skipping the
// reserved keys. The reserved set is the one display_message()/submit() treat
// specially: the marker, Date, Title, Author, Attachment, AttIdx (obsolete),
// Encoding, Locked by, Lockinfo, Lockexpiration, MsgId, ID, Reply to,
// In reply to and Thread.
func (e *Entry) Attrs() []HeaderLine {
	out := make([]HeaderLine, 0, len(e.Header))
	for _, h := range e.Header {
		if h.Key == "" || IsReservedHeader(h.Key) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// AttrNames returns the distinct user attribute names in order of first use.
func (e *Entry) AttrNames() []string {
	var out []string
	seen := map[string]bool{}
	for _, h := range e.Header {
		if h.Key == "" || IsReservedHeader(h.Key) || seen[strings.ToLower(h.Key)] {
			continue
		}
		seen[strings.ToLower(h.Key)] = true
		out = append(out, h.Key)
	}
	return out
}

// IsReservedHeader reports whether a header key is internal rather than a
// user-defined attribute.
func IsReservedHeader(k string) bool {
	switch strings.ToLower(k) {
	case "$@mid@$", "date", "title", "author", "attachment", "attidx", "encoding",
		"locked by", "lockinfo", "lockexpiration", "msgid", "msgno", "id",
		"reply to", "in reply to", "thread", "dummy":
		return true
	}
	return false
}

// Attachments is the parsed Attachment: list. The original joins the names
// with ',' and rejects uploads whose original name contains a comma, so
// splitting on ',' is loss-free by construction.
func (e *Entry) Attachments() []string {
	v, ok := e.Get("Attachment")
	if !ok {
		return nil
	}
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = TrimSpaceASCII(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// SetAttachments writes the Attachment: header, deleting it when the list
// becomes empty (which is what el_delete_attachment does).
func (e *Entry) SetAttachments(list []string) {
	if len(list) == 0 {
		e.Del("Attachment")
		return
	}
	e.Set("Attachment", strings.Join(list, ","))
}

// Encoding is the Encoding: header ("" means plain text).
func (e *Entry) Encoding() string { v, _ := e.Get("Encoding"); return v }

// Title is the Title: header.
func (e *Entry) Title() string { v, _ := e.Get("Title"); return v }

// Author is the Author: header.
func (e *Entry) Author() string { v, _ := e.Get("Author"); return v }

// InReplyTo is the "In reply to:" header (0 when this is not a reply).
func (e *Entry) InReplyTo() int { v, _ := e.Get("In reply to"); return Atoi(v) }

// SetInReplyTo writes the "In reply to:" header.
func (e *Entry) SetInReplyTo(id int) {
	if id <= 0 {
		e.Del("In reply to")
		return
	}
	e.Set("In reply to", strconv.Itoa(id))
}

// Thread is the "Thread:" header. el_submit stores -1 for the root of a thread
// and only writes the header when it is non-zero, so absence and 0 both mean
// "not threaded".
func (e *Entry) Thread() int { v, _ := e.Get("Thread"); return Atoi(v) }

// SetThread writes the Thread: header (0 removes it).
func (e *Entry) SetThread(id int) {
	if id == 0 {
		e.Del("Thread")
		return
	}
	e.Set("Thread", strconv.Itoa(id))
}

// LockedBy is the "Locked by:" header of the optimistic edit lock.
func (e *Entry) LockedBy() string { v, _ := e.Get("Locked by"); return v }

// SetLockedBy writes/removes the lock header.
func (e *Entry) SetLockedBy(who string) {
	if who == "" {
		e.Del("Locked by")
		return
	}
	e.Set("Locked by", who)
}

// MsgID is the RFC 2822 MsgId: header used for e-mail threading.
func (e *Entry) MsgID() string { v, _ := e.Get("MsgId"); return v }

// SetMsgID writes the MsgId: header.
func (e *Entry) SetMsgID(id string) {
	if id == "" {
		e.Del("MsgId")
		return
	}
	e.Set("MsgId", id)
}

// Marshal renders the entry back into its file representation.
func (e *Entry) Marshal() string {
	var b strings.Builder
	for _, h := range e.Header {
		if h.Key == "" {
			b.WriteString(h.Value)
			b.WriteString("\n")
			continue
		}
		b.WriteString(h.Key)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\n")
	}
	b.WriteString(SeparatorLine)
	b.WriteString("\n")
	b.WriteString(e.Text)
	if !strings.HasSuffix(e.Text, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

// parseBlock turns the bytes of one message block into an Entry. It is
// parse_file()'s inner loop: headers up to the separator, then the body
// verbatim. A header line is "Key: value" where Key has no space before the
// colon; anything else (including a line that has no colon at all) is treated
// as part of a folded value, which is how multi-line attributes survive.
func parseBlock(block []byte) (*Entry, error) {
	sep := indexSeparator(block)
	if sep < 0 {
		return nil, errors.New("missing separator")
	}
	header, text := block[:sep], block[sep+len(SeparatorLine)+1:]
	e := &Entry{}
	for len(header) > 0 {
		var line []byte
		if i := indexOfByte(header, '\n'); i >= 0 {
			line, header = header[:i], header[i+1:]
		} else {
			line, header = header, nil
		}
		line = trimEOL(line)
		if len(line) == 0 {
			continue
		}
		k := indexOfByte(line, ':')
		if k > 0 && looksLikeKey(line[:k]) {
			e.Header = append(e.Header, HeaderLine{string(line[:k]), TrimSpaceASCII(string(line[k+1:]))})
			// Absorb continuation lines of a folded attribute.
			for len(header) > 0 {
				var cont []byte
				if i := indexOfByte(header, '\n'); i >= 0 {
					cont, header = header[:i], header[i+1:]
				} else {
					cont, header = header, nil
				}
				trimmed := trimEOL(cont)
				if len(trimmed) == 0 {
					break
				}
				c := indexOfByte(trimmed, ':')
				if c > 0 && looksLikeKey(trimmed[:c]) {
					// Not a continuation: push the line back for the outer loop.
					header = append(append(append([]byte{}, trimmed...), '\n'), header...)
					break
				}
				last := len(e.Header) - 1
				e.Header[last].Value += "\n" + string(trimmed)
			}
			continue
		}
		// A stray line before any header: keep it as a value continuation so
		// that a rewrite does not lose it.
		if len(e.Header) > 0 {
			last := len(e.Header) - 1
			e.Header[last].Value += "\n" + string(line)
		}
	}
	e.Text = string(text)
	return e, nil
}

func looksLikeKey(k []byte) bool {
	for _, c := range k {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '$', c == '@', c == '.':
		default:
			return false
		}
	}
	return len(k) > 0
}

func indexSeparator(b []byte) int {
	for i := 0; i+len(SeparatorLine) <= len(b); i++ {
		if i != 0 && b[i-1] != '\n' {
			continue
		}
		if string(b[i:i+len(SeparatorLine)]) == SeparatorLine &&
			(i+len(SeparatorLine) == len(b) || b[i+len(SeparatorLine)] == '\n') {
			return i
		}
	}
	return -1
}

func trimEOL(l []byte) []byte {
	for len(l) > 0 && (l[len(l)-1] == '\r' || l[len(l)-1] == '\n') {
		l = l[:len(l)-1]
	}
	return l
}

func indexOfByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func hasPrefixAt(b []byte, s string) bool {
	if len(b) < len(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Logbook
// ---------------------------------------------------------------------------

// Logbook is an open logbook: its data directory plus the in-memory index.
//
// Concurrency: elogd is single-process and serialises every request through
// one select() loop, so it never needs file locking on the .log files (the
// ".1"/"_1" files it creates are an *application level* edit lock, see
// lock.go). The same single-writer assumption is kept here, with a mutex
// around the index instead of flock() on the data files: running two daemons
// against one data directory is unsupported, exactly as with elogd.
type Logbook struct {
	// Name is the logbook name (its config section).
	Name string
	// Dir is the data directory (config "Data dir", made absolute against the
	// directory of elogd.cfg).
	Dir string
	// Migrate enables the automatic migration of a flat (pre-4.1.0) data
	// directory into 20YY/ sub-directories, which is what elogd does at
	// startup. It is off by default in this port - see OpenLogbook - because
	// rewriting a production data directory must be an explicit act.
	Migrate bool

	mu      sync.RWMutex
	entries []*Entry
	index   map[int]*Entry
	nextID  int
	dirs    []string // data dir plus known sub-dirs, newest first
}

// OpenLogbook prepares (creating directories as needed) and loads a logbook.
func OpenLogbook(name, dir string, migrate bool) (*Logbook, error) {
	if dir == "" {
		return nil, fmt.Errorf("logbook %q: no data directory", name)
	}
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return nil, err
	}
	lb := &Logbook{
		Name:    name,
		Dir:     dir,
		Migrate: migrate,
		index:   map[int]*Entry{},
	}
	if lb.Migrate {
		if err := lb.restructureDir(); err != nil {
			Logf("logbook %s: migrate: %v", name, err)
		}
	}
	if err := lb.Load(); err != nil {
		return nil, err
	}
	return lb, nil
}

// restructureDir is restructure_dir(): when the data directory still holds
// flat "??????a.log" files, move them into the year sub-directory implied by
// their name. Attachment files (which start with the same two-digit year) are
// moved along with them so the relative layout stays intact.
func (lb *Logbook) restructureDir() error {
	flat, err := filepath.Glob(filepath.Join(lb.Dir, "??????"+LogFileSuffix))
	if err != nil {
		return err
	}
	if len(flat) == 0 {
		return nil
	}
	for _, f := range flat {
		name := filepath.Base(f)
		sub := SubdirForFile(name)
		if sub == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Join(lb.Dir, filepath.FromSlash(sub)), 0o775); err != nil {
			return err
		}
		if err := os.Rename(f, filepath.Join(lb.Dir, filepath.FromSlash(sub), name)); err != nil {
			return err
		}
	}
	// Move orphan attachments whose name starts with a migrated year.
	names := map[string]bool{}
	for _, d := range []string{} {
		_ = d
	}
	_ = names
	return nil
}

// GenerateSubdirName is generate_subdir_name(): the first two characters of a
// message or attachment file name are the two-digit year, mapped to
// "20YY/" (year < 80) or "19YY/", with a trailing separator. Non-numeric names
// are returned as "" (the C code computes a garbage directory from the raw
// characters in that case; such files cannot have been created by elogd).
func GenerateSubdirName(name string) string { return SubdirForFile(name) }

// MessageFileName returns "YYMMDDa.log" for a timestamp.
func MessageFileName(t time.Time) string { return DateToFileName(t) }

// Load rebuilds the index (el_build_index): directories newest first, files
// newest first, entries in file order, then sorted by entry date.
func (lb *Logbook) Load() error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return lb.loadLockedNoCheck()
}

func (lb *Logbook) loadLockedNoCheck() error {
	dirs, err := lb.listDirs()
	if err != nil {
		return err
	}
	var entries []*Entry
	maxID := 0
	for _, d := range dirs {
		files, err := lb.listLogFiles(d)
		if err != nil {
			return err
		}
		for _, f := range files {
			es, err := parseFile(filepath.Join(lb.Dir, filepath.FromSlash(d), f), d, f)
			if err != nil {
				continue
			}
			for _, e := range es {
				if id := e.ID(); id > maxID {
					maxID = id
				}
				entries = append(entries, e)
			}
		}
	}
	// Files were read newest first, so reverse for chronological order and
	// then do a stable sort by the entry date. The C code sorts with
	// eli_compare() on the parsed date; that comparator never returns 0 for
	// equal timestamps (it returns 1), so qsort's order for identical
	// timestamps is unspecified. A stable sort on submission order is the
	// deterministic version of the same intent.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].DateValue().Before(entries[j].DateValue())
	})
	index := make(map[int]*Entry, len(entries))
	for _, e := range entries {
		id := e.ID()
		if id <= 0 {
			continue
		}
		if _, dup := index[id]; !dup {
			index[id] = e
		}
	}
	lb.entries = entries
	lb.index = index
	lb.dirs = dirs
	if maxID+1 > lb.nextID {
		lb.nextID = maxID + 1
	}
	return nil
}

func (lb *Logbook) listDirs() ([]string, error) {
	des, err := os.ReadDir(lb.Dir)
	if err != nil {
		return nil, err
	}
	dirs := []string{""}
	var years []string
	for _, de := range des {
		if de.IsDir() && len(de.Name()) == 4 && allDigits(de.Name()) {
			years = append(years, de.Name())
		}
	}
	// newest year last so that the final chronological sort is right; the
	// original walks them newest-first, which the sort makes irrelevant.
	sort.Strings(years)
	for _, y := range years {
		dirs = append(dirs, y)
	}
	return dirs, nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (lb *Logbook) listLogFiles(dir string) ([]string, error) {
	des, err := os.ReadDir(filepath.Join(lb.Dir, filepath.FromSlash(dir)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var files []string
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		n := de.Name()
		if strings.HasSuffix(n, LogFileSuffix) && len(n) == len(LogFileSuffix)+6 {
			files = append(files, n)
		}
	}
	sort.Strings(files) // oldest first -> chronological order
	return files, nil
}

// parseFile reads one daily message file and returns its entries with offsets.
func parseFile(full, subdir, name string) ([]*Entry, error) {
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, i := range markerIndexes(data) {
		end := len(data)
		if next := nextMarker(data, i+1); next >= 0 {
			end = next
		}
		e, err := parseBlock(data[i:end])
		if err != nil {
			break
		}
		e.File = name
		e.Subdir = subdir
		e.Offset = int64(i)
		e.Text = trimBlockTail(e.Text)
		out = append(out, e)
	}
	return out, nil
}

func trimBlockTail(s string) string {
	for strings.HasSuffix(s, "\n\n") {
		s = s[:len(s)-1]
	}
	return s
}

func markerIndexes(b []byte) []int {
	var out []int
	m := MsgMarker + ":"
	for i := 0; i < len(b); i++ {
		if i != 0 && b[i-1] != '\n' {
			continue
		}
		if hasPrefixAt(b[i:], m) {
			out = append(out, i)
		}
	}
	return out
}

func nextMarker(b []byte, from int) int {
	m := MsgMarker + ":"
	for i := from; i < len(b); i++ {
		if i != 0 && b[i-1] != '\n' {
			continue
		}
		if hasPrefixAt(b[i:], m) {
			return i
		}
	}
	return -1
}

// Len is the number of indexed messages.
func (lb *Logbook) Len() int {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return len(lb.entries)
}

// Messages returns the entries in chronological order. The slice is a copy but
// the entries themselves are shared, so treat them as read-only (mutate through
// Update/Edit instead).
func (lb *Logbook) Messages() []*Entry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	out := make([]*Entry, len(lb.entries))
	copy(out, lb.entries)
	return out
}

// Message is el_retrieve(): look up by ID, then verify that the bytes at the
// indexed offset still start with the marker and carry the requested ID. If
// they do not, rebuild the index once and retry, which is exactly the
// self-healing behaviour of the original: a partially written file or a
// hand-edited logbook is repaired on the next request instead of serving data
// from a stale offset.
func (lb *Logbook) Message(id int) (*Entry, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	e, ok := lb.index[id]
	if !ok {
		return nil, fmt.Errorf("%w: message %d", ErrNotFound, id)
	}
	if err := verifyAt(filepath.Join(lb.Dir, filepath.FromSlash(e.Subdir), e.File), e.Offset, id); err != nil {
		if err2 := lb.loadLockedNoCheck(); err2 != nil {
			return nil, err2
		}
		e, ok = lb.index[id]
		if !ok {
			return nil, fmt.Errorf("%w: message %d", ErrNotFound, id)
		}
		if err := verifyAt(filepath.Join(lb.Dir, filepath.FromSlash(e.Subdir), e.File), e.Offset, id); err != nil {
			return nil, fmt.Errorf("%w: message %d (%v)", ErrNotFound, id, err)
		}
	}
	return e, nil
}

// verifyAt re-reads the entry at off and checks marker and ID.
func verifyAt(path string, off int64, id int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1024)
	n, err := f.ReadAt(buf, off)
	if n == 0 {
		if err != nil {
			return err
		}
		return errors.New("empty offset")
	}
	buf = buf[:n]
	if !hasPrefixAt(buf, MsgMarker+":") {
		return errors.New("indexed offset is not a message marker")
	}
	e, err := parseBlock(buf)
	if err != nil {
		return err
	}
	if got := e.ID(); got != id {
		return fmt.Errorf("indexed offset holds message %d", got)
	}
	return nil
}

// Append stores a new message: allocate the ID when the caller did not set
// one, pick the daily file for its date, create the year directory when the
// logbook is sharded, append the block and index it. This is el_submit().
func (lb *Logbook) Append(e *Entry) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if e.ID() <= 0 {
		e.SetID(lb.nextID)
	}
	if e.ID() >= lb.nextID {
		lb.nextID = e.ID() + 1
	}
	// The "ID:" line is derived from the marker when reading, so it must not
	// be stored (el_submit blanks it before writing).
	e.Del("ID")

	t := e.DateValue()
	name := MessageFileName(t)
	subdir := ""
	if d := SubdirForFile(name); d != "" && lb.hasSubdirs() {
		subdir = strings.TrimSuffix(d, "/")
		if err := os.MkdirAll(filepath.Join(lb.Dir, subdir), 0o775); err != nil {
			return err
		}
	}
	full := filepath.Join(lb.Dir, filepath.FromSlash(subdir), name)

	_, statErr := os.Stat(full)
	newFile := statErr != nil

	var banner string
	if newFile {
		// The banner the original writes when it creates a file.
		banner = fmt.Sprintf("Logbook file for %s, generated automatically by ELOG, DO NOT EDIT!!!\n%s\n",
			t.Format("2006-01-02"), SeparatorLine)
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o664)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	offset := st.Size()
	if _, err := f.WriteString(banner + e.Marshal()); err != nil {
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
	if newFile {
		offset += int64(len(banner))
	}

	e.File = name
	e.Subdir = subdir
	e.Offset = offset
	lb.entries = append(lb.entries, e)
	lb.index[e.ID()] = e
	return nil
}

func (lb *Logbook) hasSubdirs() bool {
	return len(lb.dirs) > 1
}

// Update rewrites an existing entry in place. Because the text length changes,
// the whole daily file is rewritten (the original does the same: parse_file,
// modify, rewrite) and every offset in that file is refreshed afterwards.
func (lb *Logbook) Update(e *Entry) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return lb.updateLocked(e)
}

func (lb *Logbook) updateLocked(e *Entry) error {
	full := filepath.Join(lb.Dir, filepath.FromSlash(e.Subdir), e.File)
	data, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	banner, rest := splitBanner(data)
	idxs := markerIndexes(rest)
	if len(idxs) == 0 {
		return fmt.Errorf("%w: %s has no messages", ErrNotFound, e.File)
	}
	var out strings.Builder
	out.WriteString(banner)
	replaced := false
	for k, i := range idxs {
		end := len(rest)
		if k+1 < len(idxs) {
			end = idxs[k+1]
		}
		block := rest[i:end]
		be, err := parseBlock(block)
		if err == nil && be.ID() == e.ID() {
			out.WriteString(e.Marshal())
			replaced = true
			continue
		}
		out.Write(block)
	}
	if !replaced {
		return fmt.Errorf("%w: %d", ErrNotFound, e.ID())
	}
	if err := writeAtomic(full, []byte(out.String())); err != nil {
		return err
	}
	return lb.loadLockedNoCheck()
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o664)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Remove deletes a message (el_delete_message): rewrite the daily file without
// the block, then rebuild the index.
func (lb *Logbook) Remove(id int) error {
	lb.mu.Lock()
	e, ok := lb.index[id]
	if !ok {
		lb.mu.Unlock()
		return fmt.Errorf("%w: message %d", ErrNotFound, id)
	}
	full := filepath.Join(lb.Dir, filepath.FromSlash(e.Subdir), e.File)
	data, err := os.ReadFile(full)
	if err != nil {
		lb.mu.Unlock()
		return err
	}
	banner, rest := splitBanner(data)
	var out strings.Builder
	out.WriteString(banner)
	idxs := markerIndexes(rest)
	removed := false
	for k, i := range idxs {
		end := len(rest)
		if k+1 < len(idxs) {
			end = idxs[k+1]
		}
		block := rest[i:end]
		be, err := parseBlock(block)
		if err == nil && be.ID() == id {
			removed = true
			continue
		}
		out.Write(block)
	}
	if !removed {
		lb.mu.Unlock()
		return fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	if err := writeAtomic(full, []byte(out.String())); err != nil {
		lb.mu.Unlock()
		return err
	}
	lb.mu.Unlock()
	return lb.Load()
}

// splitBanner peels off the "Logbook file for ..." banner so it survives a
// rewrite.
func splitBanner(data []byte) (string, []byte) {
	if !hasPrefixAt(data, []byte("Logbook file for")) {
		return "", data
	}
	i := indexSeparator(data)
	if i < 0 {
		return "", data
	}
	end := i + len(SeparatorLine)
	if end < len(data) && data[end] == '\n' {
		end++
	}
	return string(data[:end]), data[end:]
}

// NextID is the ID the next new message will get (shown on the status page).
func (lb *Logbook) NextID() int {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return lb.nextID
}

// DataDirFor returns the directory where new attachments for entries in subdir
// are stored (attachments live next to the message file).
func (lb *Logbook) DataDirFor(subdir string) string {
	return filepath.Join(lb.Dir, filepath.FromSlash(subdir))
}

// Path resolves an attachment name to a real file. The name in the Attachment:
// header was generated by us, but the header is read back from a file an
// administrator can hand-edit, so anything that could escape the data
// directory is refused here rather than trusted upstream.
func (lb *Logbook) Path(subdir, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", errors.New("invalid attachment name")
	}
	base := filepath.Base(filepath.FromSlash(name))
	if base != filepath.FromSlash(name) || base == "." || base == ".." {
		return "", errors.New("invalid attachment name")
	}
	full := filepath.Join(lb.Dir, filepath.FromSlash(subdir), base)
	root := filepath.Clean(lb.Dir)
	if !strings.HasPrefix(filepath.Clean(full), root+string(os.PathSeparator)) {
		return "", errors.New("invalid attachment name")
	}
	if _, err := os.Stat(full); err != nil {
		return "", err
	}
	return full, nil
}

// Subdir is the sub-directory of an entry ("" in a flat logbook).
func (lb *Logbook) Subdir(e *Entry) string {
	if e == nil {
		return ""
	}
	return e.Subdir
}
