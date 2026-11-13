// ELOG rewritten in Go - outgoing notification mail.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Notification mail
// ---------------------------------------------------------------------------
//
// elogd builds the notification message itself (compose_mail(),
// create_mime_header()) and hands it either to a command ("Incoming mail
// filter", "Mail command", "Sendmail") on its standard input or to an SMTP
// server ("SMTP server"). Both paths are implemented here, and the header
// construction is the part where the local patches to the C code fixed real
// bugs, so it is spelled out in full:
//
//   - exactly one MIME-Version: header and exactly one Content-Type: header are
//     written (the patched C code drops a duplicate pair that made some mail
//     readers show the raw body);
//   - a body that is pure ASCII is announced "7bit", a body with the high bit
//     set as "8bit" - with 7bit a UTF-8 author name or text was destroyed by any
//     MTA that enforces 7-bit SMTP;
//   - non-ASCII words in Subject/to/cc become RFC 2047 encoded words that are at
//     most 75 octets long and are split between whole UTF-8 characters, never in
//     the middle of one;
//   - the multipart part that carries the attachments is closed with a final
//     "--boundary--" line; when that line was missing, mail readers threw the
//     attachments away.

// mailHeader is one header line of a generated message. Order is preserved
// because a duplicated header is a bug and because some mail tools care.
type mailHeader struct {
	Key string
	Val string
}

// mailMessage is one outgoing message: ordered headers, a plain-text body and
// the files to attach.
type mailMessage struct {
	Headers []mailHeader
	Body    string
	Files   []string // attachment file names to attach
}

// Set replaces a header or appends it, so a header can never appear twice.
func (m *mailMessage) Set(key, val string) {
	for i := range m.Headers {
		if EqualFold(m.Headers[i].Key, key) {
			m.Headers[i].Val = val
			return
		}
	}
	m.Headers = append(m.Headers, mailHeader{key, val})
}

// Add appends a header even if one with that name exists (used for the
// informational X-ELOG-* headers, which elogd emits one per attribute).
func (m *mailMessage) Add(key, val string) {
	m.Headers = append(m.Headers, mailHeader{key, val})
}

// Get is the header value ("" when absent); the first match wins.
func (m *mailMessage) Get(key string) string {
	for _, h := range m.Headers {
		if EqualFold(h.Key, key) {
			return h.Val
		}
	}
	return ""
}

func (m *mailMessage) has(key string) bool {
	for _, h := range m.Headers {
		if EqualFold(h.Key, key) {
			return true
		}
	}
	return false
}

// render writes the RFC 822 message. Attachments that disappeared in the
// meantime are dropped silently, as in elogd (a missing thumbnail must not
// swallow the notification).
func (m *mailMessage) render() string {
	var b strings.Builder
	enc := "7bit"
	if !IsASCIIPrintable(m.Body) {
		enc = "8bit"
	}
	var files []string
	for _, f := range m.Files {
		if st, err := os.Stat(f); err == nil && !st.IsDir() && st.Size() < maxMailAttachment {
			files = append(files, f)
		}
	}
	boundary := ""
	if len(files) > 0 {
		boundary = "----=_Part_" + RandomToken(24)
	}
	for _, h := range m.Headers {
		if len(files) > 0 && EqualFold(h.Key, "Content-Type") {
			continue // replaced by the multipart header below
		}
		b.WriteString(h.Key + ": " + EncodeWord(h.Val) + "\r\n")
	}
	if len(files) == 0 {
		// One MIME-Version and one Content-Type, each added only when the caller
		// did not set one: the duplicate pair the patch removed came from here.
		if !m.has("MIME-Version") {
			b.WriteString("MIME-Version: 1.0\r\n")
		}
		if !m.has("Content-Type") {
			b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		}
		if !m.has("Content-Transfer-Encoding") {
			b.WriteString("Content-Transfer-Encoding: " + enc + "\r\n")
		}
	} else {
		b.WriteString("MIME-Version: 1.0\r\n")
		b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n")
	}
	b.WriteString("\r\n")

	if len(files) == 0 {
		b.WriteString(m.Body)
		if !strings.HasSuffix(m.Body, "\n") {
			b.WriteString("\n")
		}
		return b.String()
	}

	// multipart: the text part first, then one part per attachment, and the
	// closing boundary line - without that last line the attachments are lost.
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: " + enc + "\r\n\r\n")
	b.WriteString(m.Body)
	if !strings.HasSuffix(m.Body, "\n") {
		b.WriteString("\n")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		name := filepathBase(f)
		// Drop the "YYMMDD_HHMMSS_" the storage prepends so the reader sees the
		// name the author uploaded.
		if orig := OriginalAttachmentName(name); orig != "" {
			name = orig
		}
		b.WriteString("\r\n--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + ContentTypeFor(name) + "\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("Content-Disposition: attachment; filename=\"" +
			MakeFilenameHeaderSafe(name) + "\"\r\n\r\n")
		b.WriteString(EncodeBase64Wrapped(data, 76))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return b.String()
}

// maxMailAttachment caps one attachment in a notification mail. The size is a
// policy choice, not a memory-safety limit (Go reads the file into a slice that
// grows as needed); the original silently skipped attachments above its buffer
// and, in one version, overflowed a fixed buffer while base64-ing them. 25 MB is
// above every attachment actually posted to the farm logbooks and below the
// 35 MB limit of the destination MTA.
const maxMailAttachment = 25 << 20

// EncodeBase64Wrapped is base64 with CRLF line breaks every n characters, as a
// mail body part needs.
func EncodeBase64Wrapped(data []byte, n int) string {
	s := EncodeBase64Std(data)
	if n <= 0 {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		if i > 0 {
			b.WriteString("\r\n")
		}
		if i+n > len(s) {
			b.WriteString(s[i:])
		} else {
			b.WriteString(s[i : i+n])
		}
	}
	return b.String()
}

func filepathBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ---------------------------------------------------------------------------
// RFC 2047 encoded words
// ---------------------------------------------------------------------------

// encodeMax is the longest encoded word emitted: RFC 2047 requires a consumer
// to handle at least 75 characters, and longer words get folded or truncated by
// picky MTAs.
const encodeMax = 75

// EncodeWord encodes one header word/phrase. ASCII text is returned unchanged
// (so ordinary subjects stay readable and copy-pasteable); anything else becomes
// one or more RFC 2047 encoded words.
//
// The split between two encoded words is always at a UTF-8 character boundary:
// counting bytes instead is exactly the bug the local patch to the C code fixed
// - a subject with Czech text came out with a broken character in the middle
// when the 75-byte budget cut a three-byte sequence in half.
func EncodeWord(s string) string {
	s = TrimSpaceASCII(s)
	if s == "" {
		return s
	}
	if IsASCIIPrintable(s) && !strings.ContainsAny(s, "=?") {
		return s
	}
	// Base64 when the text is mostly non-ASCII (it expands by 4/3 but needs no
	// per-character escaping), quoted-printable otherwise.
	nonASCII := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			nonASCII++
		}
	}
	if nonASCII*4 > len(s) {
		return encodeWordB64(s)
	}
	return encodeWordQ(s)
}

func encodeWordB64(s string) string {
	const prefix, suffix = "=?UTF-8?B?", "?="
	// Whole UTF-8 characters that fit in the budget: base64 needs 4 output
	// characters per 3 input bytes.
	per := (encodeMax - len(prefix) - len(suffix)) / 4 * 3
	if per < 4 {
		per = 4 // must hold at least one 4-byte rune (an emoji), else no progress
	}
	var out []string
	runes := []rune(s)
	for i := 0; i < len(runes); {
		j, bytes := i, 0
		for j < len(runes) && bytes+utf8.RuneLen(runes[j]) <= per {
			bytes += utf8.RuneLen(runes[j])
			j++
		}
		if j == i {
			j = i + 1 // a single rune that does not fit: emit it anyway
		}
		out = append(out, prefix+EncodeBase64Std(string(runes[i:j]))+suffix)
		i = j
	}
	return strings.Join(out, " ")
}

func encodeWordQ(s string) string {
	const prefix, suffix = "=?UTF-8?Q?", "?="
	var per strings.Builder
	var out []string
	var cur strings.Builder
	cur.WriteString(prefix)
	flush := func() {
		if cur.Len() == len(prefix) {
			return
		}
		cur.WriteString(suffix)
		out = append(out, cur.String())
		cur.Reset()
		cur.WriteString(prefix)
	}
	for _, r := range s {
		per.Reset()
		rs := string(r)
		switch {
		case r == ' ':
			per.WriteByte('_')
		case r < 0x20 || r >= 0x7f:
			for i := 0; i < len(rs); i++ {
				fmt.Fprintf(&per, "=%02X", rs[i])
			}
		case strings.IndexByte("=_?\"", int(r)) >= 0:
			fmt.Fprintf(&per, "=%02X", byte(r))
		default:
			per.WriteString(rs)
		}
		// +len(suffix) so that the word is still inside the budget once closed.
		if cur.Len()+per.Len()+len(suffix) > encodeMax {
			flush()
		}
		cur.WriteString(per.String())
	}
	flush()
	return strings.Join(out, " ")
}

// EncodeHeaderPhrase encodes a "Name <mail@example.com>" phrase for a header:
// the display name is RFC 2047 encoded when needed, the address is left alone.
func EncodeHeaderPhrase(s string) string {
	s = TrimSpaceASCII(s)
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "<"); i > 0 && strings.HasSuffix(s, ">") {
		name := TrimSpaceASCII(s[:i])
		addr := s[i:]
		if name == "" {
			return addr
		}
		return EncodeWord(name) + " " + addr
	}
	return EncodeWord(s)
}

// ---------------------------------------------------------------------------
// Composing the notification
// ---------------------------------------------------------------------------

// notify sends the notification for one stored entry. old is nil for a new
// entry (the subject then gets no "(edit)" marker, as in compose_mail()).
func (s *Server) notify(q *Request, lb *Logbook, e *Entry, old *Entry, url string) error {
	if s.Config.GetFlagDefault(q.Cfg, "Disable email", false) {
		return nil
	}
	recip := s.recipients(q, e)
	if recip == "" {
		return nil
	}
	subject := notificationSubject(s.Config, q.Cfg, e, old == nil)

	var body strings.Builder
	if url != "" {
		body.WriteString(url + "\n")
	}
	body.WriteString("Details\n")
	body.WriteString("--------\n")
	for _, a := range s.displayedAttrs(q.Cfg) {
		if v := e.Get2(a); v != "" {
			fmt.Fprintf(&body, "%-12s : %s\n", a+":", v)
		}
	}
	fmt.Fprintf(&body, "%-12s : %s\n", "Date:", e.Get2("Date"))
	body.WriteString("\n")
	fmt.Fprintf(&body, "Logbook ID : %d\n", e.ID())
	body.WriteString("\n")
	body.WriteString(e.Text)
	if !strings.HasSuffix(e.Text, "\n") {
		body.WriteString("\n")
	}

	from := s.mailFrom(q, e)
	m := &mailMessage{}
	m.Set("From", EncodeHeaderPhrase(from))
	m.Set("To", encodePhraseList(recip))
	if cc := s.Config.GetStringDefault(q.Cfg, "Notification list cc", ""); cc != "" {
		m.Set("Cc", encodePhraseList(cc))
	}
	m.Set("Subject", EncodeWord(subject))
	m.Set("Date", FormatRFC2822(time.Now()))
	id := fmt.Sprintf("%d.%s@%s", e.ID(), RandomToken(12), mailDomain(from))
	m.Set("Message-ID", "<"+id+">")
	m.Set("X-Elog-Message-ID", id)
	m.Set("X-Elog-Logbook", q.Cfg.Group)
	m.Set("X-Elog-ID", fmt.Sprint(e.ID()))
	if !s.Config.GetFlag(q.Cfg, "No mail header") {
		// elogd copies every attribute into an X-ELOG-<attr>: header so that a
		// mail filter can file the message; the id/attachment/charset
		// bookkeeping headers are skipped.
		for _, h := range e.Header {
			if h.Key == "" || IsReservedHeader(h.Key) {
				continue
			}
			m.Add("X-ELOG-"+EncodeWord(h.Key), EncodeWord(h.Value))
		}
	}
	m.Set("User-Agent", "ELOG "+Version)
	m.Set("Reply-To", EncodeHeaderPhrase(s.Config.GetStringDefault(q.Cfg, "Reply-to", from)))
	m.Body = strings.ToValidUTF8(body.String(), "\uFFFD")
	if lb != nil {
		for _, a := range AttachmentRefs(e) {
			if p, err := lb.Path(e.Subdir, a.Name); err == nil {
				m.Files = append(m.Files, p)
			}
		}
	}
	return s.sendMail(q, m)
}

// notificationSubject is "[<prefix>] <Type> <title>" with "(edit) " inserted for
// an edit, the layout compose_mail() produces.
func notificationSubject(cfg *Config, scope ConfigScope, e *Entry, isNew bool) string {
	prefix := cfg.GetStringDefault(scope, "Mail subject prefix",
		cfg.GetStringDefault(scope, "Title", scope.Group))
	mark := ""
	if !isNew {
		mark = "(edit) "
	}
	s := fmt.Sprintf("[%s] %s%s", prefix, mark, strings.TrimSpace(e.Get2("Type")+" "+e.Title()))
	return strings.ReplaceAll(s, "  ", " ")
}

// mailFrom is the "From" of a notification: the logbook's "From" key, else the
// poster's e-mail, else a localhost fallback (elogd uses the SMTP login when
// "SMTP authentication" is on, which this port keeps as a configuration value).
func (s *Server) mailFrom(q *Request, e *Entry) string {
	if v := s.Config.GetStringDefault(q.Cfg, "From", ""); v != "" {
		return v
	}
	if v := s.Config.GetString(ConfigScope{Group: "global"}, "From", ""); v != "" {
		return v
	}
	if v := e.Get2("Email"); v != "" {
		return v
	}
	if v := e.Get2("E-mail"); v != "" {
		return v
	}
	if v := e.Author(); strings.Contains(v, "@") {
		return v
	}
	return "elogd@localhost"
}

// mailDomain is the part after '@' of the sender, used for the Message-ID
// domain (elogd uses its own host name; the sender domain is available without a
// name lookup and is unique enough for a Message-ID).
func mailDomain(from string) string {
	if i := strings.LastIndex(from, "@"); i >= 0 {
		if j := strings.IndexAny(from[i+1:], "> \t\r\n"); j >= 0 {
			return from[i+1 : i+1+j]
		}
		return from[i+1:]
	}
	return "elog"
}

func encodePhraseList(list string) string {
	var out []string
	for _, p := range SplitList(list, ",", false) {
		out = append(out, EncodeHeaderPhrase(p))
	}
	return strings.Join(out, ", ")
}

// recipients is the To: list: every user whose notification subscription matches
// the entry, plus the logbook's "Notification list".
//
// The password-file subscription is matched against the category and, when a
// sub-category exists, also against "category/subcategory", because elogd's
// "Email notify" entries are written in both shapes depending on how the user
// ticked the subscription page (see matchNotify in compat.go).
func (s *Server) recipients(q *Request, e *Entry) string {
	cat := e.Get2("Category")
	var list []string
	list = append(list, s.NotifyAddresses(q.Cfg.Group, cat, e.Author())...)
	if sub := e.Get2("Subcategory"); sub != "" {
		list = append(list, s.NotifyAddresses(q.Cfg.Group, cat+"/"+sub, e.Author())...)
	}
	list = append(list, SplitList(s.Config.GetString(q.Cfg, "Notification list", ""), ",", false)...)
	return strings.Join(dedupeStrings(list), ", ")
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		k := strings.ToLower(s)
		if s == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

// sendMail delivers a message. The three configurations of the original are
// honoured, in its order of preference: a mail filter/command pipeline,
// "Sendmail", and finally a direct SMTP submission to "SMTP server".
func (s *Server) sendMail(q *Request, m *mailMessage) error {
	raw := m.render()
	scope := ConfigScope{Group: "global"}
	if q != nil {
		scope = q.Cfg
	}
	if pipe := s.Config.GetString(scope, "Incoming mail filter", ""); pipe != "" {
		return s.runFilter(scope, s.filterCommand(q, pipe, m), raw)
	}
	if pipe := s.Config.GetString(scope, "Mail command", ""); pipe != "" {
		return s.runFilter(scope, s.filterCommand(q, pipe, m), raw)
	}
	if sm := s.Config.GetString(scope, "Sendmail", ""); sm != "" {
		return s.runFilter(scope, sm, raw)
	}
	srv := s.Config.GetStringDefault(scope, "SMTP server",
		s.Config.GetString(ConfigScope{Group: "global"}, "SMTP server", "localhost"))
	return smtpSend(srv, fromAddress(m), recipientsOf(m), []byte(raw))
}

// runFilter pipes the message into a command's standard input. The command is
// split into argv words (quotes honoured) and started WITHOUT a shell, through
// the single subprocess entry point in procs.go: this is one of the two places
// where elogd handed a string built from configuration values and file names to
// system() (the shell-injection bug the local patches fixed by quoting); in Go,
// not going through a shell at all removes the class of bug instead of patching
// one instance of it. Running anything at all still requires the -x switch.
func (s *Server) runFilter(scope ConfigScope, command, message string) error {
	command = s.ShellSubstFor(scope, command)
	argv := SplitCommand(command)
	if len(argv) == 0 {
		return fmt.Errorf("empty mail command")
	}
	if !s.AllowExecute() {
		s.logf("mail delivery to %s skipped: execution disabled (-x)", argv[0])
		return fmt.Errorf("execution disabled (-x), cannot run %s", argv[0])
	}
	out, err := runProgram(argv, "", strings.NewReader(message))
	if err != nil {
		return fmt.Errorf("%s: %v: %s", argv[0], err, firstErrorLine(string(out)))
	}
	return nil
}

// filterCommand expands the &title &logbook substitutions of the mail filter
// command line. The result is split into argv words afterwards, so a subject
// containing $(...) or `x` is one literal argument rather than code.
func (s *Server) filterCommand(q *Request, command string, m *mailMessage) string {
	title := m.Get("Subject")
	if q != nil {
		command = strings.ReplaceAll(command, "&logbook", q.Cfg.Group)
	}
	command = strings.ReplaceAll(command, "&title", title)
	return command
}

func fromAddress(m *mailMessage) string {
	if v := m.Get("From"); v != "" {
		return emailAddress(v)
	}
	return "elogd@localhost"
}

func recipientsOf(m *mailMessage) []string {
	var out []string
	for _, h := range m.Headers {
		if EqualFold(h.Key, "To") || EqualFold(h.Key, "Cc") {
			for _, p := range SplitList(h.Val, ",", false) {
				if a := emailAddress(p); a != "" {
					out = append(out, a)
				}
			}
		}
	}
	return dedupeStrings(out)
}

// emailAddress pulls the address out of "Name <a@b.c>" (or returns the string).
func emailAddress(s string) string {
	s = TrimSpaceASCII(s)
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.LastIndex(s, ">"); j > i {
			return TrimSpaceASCII(s[i+1 : j])
		}
	}
	return s
}

// smtpSend delivers over SMTP. ELOG's own client does not authenticate (the
// local MSA on this farm relays from localhost), but a "user:pass@host" value is
// honoured and STARTTLS is used when the server offers it and the port is not
// 465 (implicit TLS is not implemented: an operator who needs it should point
// "Sendmail" at msmtp or at an ssh tunnel).
func smtpSend(server, from string, to []string, msg []byte) error {
	if len(to) == 0 {
		return nil
	}
	host, port, user, pass := parseSMTPServer(server)
	c, err := smtp.Dial(JoinHostPort(host, port))
	if err != nil {
		return err
	}
	defer c.Quit()
	if ok, _ := c.Extension("STARTTLS"); ok && port != "465" {
		// Best effort: a local MTA usually offers no TLS at all and the message
		// stays local, so a failed STARTTLS must not lose the notification.
		_ = c.StartTLS(nil)
	}
	if user != "" && pass != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(plainAuth{user, pass}); err != nil {
				return err
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
}

// parseSMTPServer accepts "host", "host:port", "user:pass@host" and
// "user:pass@host:port", the forms the "SMTP server" configuration key uses.
func parseSMTPServer(v string) (host, port, user, pass string) {
	v = TrimSpaceASCII(v)
	rest := v
	if at := strings.LastIndex(rest, "@"); at > 0 {
		user = rest[:at]
		rest = rest[at+1:]
		if c := strings.Index(user, ":"); c > 0 {
			user, pass = user[:c], user[c+1:]
		}
	}
	host, port, _ = splitHostPort(rest, "25")
	return
}

type plainAuth struct{ user, pass string }

func (a plainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a plainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return []byte("\x00" + a.user + "\x00" + a.pass), nil
	}
	return nil, nil
}
