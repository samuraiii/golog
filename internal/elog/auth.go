package elog

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// sha256-crypt, the scheme used by elogd's bundled crypt.cxx
// ---------------------------------------------------------------------------
//
// elogd stores passwords in the Ulrich Drepper SHA-256 crypt scheme
// ("$5$<salt>$<hash>") but *strips the leading "$5$"*:
//
//	do_crypt() { strlcpy(d, sha256_crypt(s, "$5$") + 4, size); }
//
// so the value inside the password file is only "<salt>$<hash>". Verifying a
// password therefore means re-running the scheme with the embedded salt and
// comparing the tail. It is implemented here from scratch (pure Go) so the
// binary does not depend on libcrypt and behaves identically on every
// platform.

const b64Shadow = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// sha256FinalB64 is the scrambled byte order of the final base64 block.
var sha256FinalB64 = [33]int{
	0, 10, 20, 21, 1, 11, 12, 22, 2, 3, 13, 23, 24, 4, 14,
	15, 25, 5, 6, 16, 26, 27, 7, 17, 18, 28, 8, 9, 19, 29,
	30, 31, -1, // -1 == the implicit zero byte of the 3-character tail
}

// SHA256CryptString returns "$5$[rounds=N$]salt$hash" for key.
func SHA256CryptString(key, salt string) string {
	const (
		roundsDefault uint = 5000
		roundsMin     uint = 1000
		roundsMax     uint = 999999999
	)

	s := strings.TrimPrefix(salt, "$5$")
	rounds := roundsDefault
	roundsCustom := false
	if rest, ok := strings.CutPrefix(s, "rounds="); ok {
		if idx := strings.IndexByte(rest, '$'); idx >= 0 {
			if n, err := strconv.ParseUint(rest[:idx], 10, 32); err == nil {
				rounds = uint(n)
				if rounds < roundsMin {
					rounds = roundsMin
				}
				if rounds > roundsMax {
					rounds = roundsMax
				}
				roundsCustom = true
				s = rest[idx+1:]
			}
		}
	}
	if i := strings.IndexByte(s, '$'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 16 {
		s = s[:16]
	}

	keyB := []byte(key)
	saltB := []byte(s)
	n := len(keyB)
	slen := len(saltB)

	sum := func(parts ...[]byte) []byte {
		h := sha256.New()
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil)
	}
	repeatDigest := func(b []byte, times int) []byte {
		h := sha256.New()
		for i := 0; i < times; i++ {
			h.Write(b)
		}
		return h.Sum(nil)
	}

	// B = digest(key || salt || key)
	B := sum(keyB, saltB, keyB)

	// A
	hA := sha256.New()
	hA.Write(keyB)
	hA.Write(saltB)
	for cnt := n; cnt > 32; cnt -= 32 {
		hA.Write(B)
	}
	hA.Write(B[:n%32])
	for cnt := n; cnt > 0; cnt >>= 1 {
		if cnt&1 != 0 {
			hA.Write(B)
		} else {
			hA.Write(keyB)
		}
	}
	hA.Write(B)
	a := hA.Sum(nil)

	// byte sequence P
	seqP := make([]byte, 0, n+32)
	if n > 0 {
		pb := repeatDigest(keyB, n)
		for cnt := n; cnt > 32; cnt -= 32 {
			seqP = append(seqP, pb...)
		}
		seqP = append(seqP, pb[:n%32]...)
	}

	// byte sequence S
	seqS := make([]byte, 0, slen+32)
	if slen > 0 {
		sb := repeatDigest(saltB, 16+int(a[0]))
		for cnt := slen; cnt > 32; cnt -= 32 {
			seqS = append(seqS, sb...)
		}
		seqS = append(seqS, sb[:slen%32]...)
	}

	for cnt := uint(0); cnt < rounds; cnt++ {
		h := sha256.New()
		if cnt&1 != 0 {
			h.Write(seqP)
		} else {
			h.Write(a)
		}
		if cnt%3 != 0 {
			h.Write(seqS)
		}
		if cnt%7 != 0 {
			h.Write(seqP)
		}
		if cnt&1 != 0 {
			h.Write(a)
		} else {
			h.Write(seqP)
		}
		a = h.Sum(nil)
	}

	var out strings.Builder
	out.WriteString("$5$")
	if roundsCustom {
		fmt.Fprintf(&out, "rounds=%d$", rounds)
	}
	out.WriteString(s)
	out.WriteByte('$')

	for i := 0; i < 10; i++ {
		out.WriteString(b64Group(a, sha256FinalB64[3*i], sha256FinalB64[3*i+1], sha256FinalB64[3*i+2], 4))
	}
	out.WriteString(b64Group(a, sha256FinalB64[30], sha256FinalB64[31], -1, 3))
	return out.String()
}

func b64Group(r []byte, i0, i1, i2, n int) string {
	pick := func(i int) uint {
		if i < 0 {
			return 0
		}
		return uint(r[i])
	}
	w := pick(i0)<<16 | pick(i1)<<8 | pick(i2)
	chars := make([]byte, 0, n)
	// b64_from_24bit(): the low 6 bits are emitted first; with n==3 the
	// top-most character is skipped.
	shifts := []int{18, 12, 6, 0}[4-n:]
	for _, sh := range shifts {
		chars = append(chars, b64Shadow[(w>>uint(sh))&0x3f])
	}
	return string(chars)
}

// DoCrypt is elogd's do_crypt(): "$5$" stripped off the front.
func DoCrypt(password string) string {
	full := SHA256CryptString(password, "$5$"+makeSalt())
	return strings.TrimPrefix(full, "$5$")
}

func makeSalt() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Never fail a request over entropy: degrade to a clock-derived salt.
		t := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(t >> (8 * (i % 8)))
		}
	}
	for i := range b {
		b[i] = b64Shadow[2+int(b[i])%62] // alphanumerics only, like the C rand() loop
	}
	return string(b)
}

// VerifyStoredPassword checks password against the value stored in the
// password file. Both the elogd form ("<salt>$<hash>") and the full crypt form
// ("$5$...") are accepted, plus the pre-SHA256 plaintext form (which is what
// convert_password_encoding() migrates away from).
func VerifyStoredPassword(password, stored string) bool {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return password == ""
	}
	switch {
	case strings.HasPrefix(stored, "$5$"):
		c := SHA256CryptString(password, stored)
		return subtle.ConstantTimeCompare([]byte(c), []byte(stored)) == 1
	case strings.Contains(stored, "$"):
		c := SHA256CryptString(password, "$5$"+stored)
		return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(c, "$5$")), []byte(stored)) == 1
	default:
		return subtle.ConstantTimeCompare([]byte(password), []byte(stored)) == 1
	}
}

// ---------------------------------------------------------------------------
// Password file
// ---------------------------------------------------------------------------

// PwdFile is the XML password file. The schema uses child elements (not XML
// attributes) because that is what elogd's own reader looks for:
//
//	<root>
//	  <list>
//	    <user>
//	      <name>jdoe</name>
//	      <password encoding="SHA256">salt$hash</password>
//	      <full_name>John Doe</full_name>
//	      <last_logout>0</last_logout>
//	      <last_activity>Tue Apr 30 12:00:00 2024</last_activity>
//	      <email>jdoe@example.org</email>
//	      <email_notify>logbookA</email_notify>   (repeatable, or "all")
//	      <inactive>0</inactive>
//	    </user>
//	  </list>
//	</root>
type PwdFile struct {
	mu    sync.Mutex
	path  string
	Users []*PwdUser `xml:"list>user"`
}

// PwdUser is one <user> record.
type PwdUser struct {
	Name         string   `xml:"name"`
	Password     string   `xml:"password"`
	Encoding     string   `xml:"password>encoding,attr,omitempty"`
	FullName     string   `xml:"full_name"`
	LastLogout   string   `xml:"last_logout"`
	LastActivity string   `xml:"last_activity"`
	Email        string   `xml:"email"`
	EmailNotify  []string `xml:"email_notify"`
	Inactive     string   `xml:"inactive"`
}

// IsInactive reports the <inactive> flag.
func (u *PwdUser) IsInactive() bool { return u.Inactive == "1" || EqualFold(u.Inactive, "true") }

// LoadPwdFile reads the password file. A missing file is not an error -
// load_password_file() creates it (mode 0600) - and a non-XML file is treated
// as the legacy colon-separated format and converted, exactly as
// convert_password_encoding() does.
func LoadPwdFile(path string) (*PwdFile, error) {
	pf := &PwdFile{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return pf, pf.Save()
	}
	if !strings.Contains(string(data), "<?xml") {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.SplitN(line, ":", 5)
			for len(f) < 5 {
				f = append(f, "")
			}
			pf.Users = append(pf.Users, &PwdUser{
				Name: f[0], Password: f[1], Encoding: "SHA256", FullName: f[2],
				LastLogout: "0", LastActivity: "0", Email: f[3],
				EmailNotify: splitNotify(f[4]), Inactive: "0",
			})
		}
		return pf, pf.Save()
	}
	if err := xml.Unmarshal(data, pf); err != nil {
		return nil, fmt.Errorf("password file %s: %w", path, err)
	}
	return pf, nil
}

func splitNotify(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = TrimSpaceASCII(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Path is the file this was loaded from.
func (pf *PwdFile) Path() string { return pf.path }

// Save writes the file back in elogd's XML layout, atomically.
func (pf *PwdFile) Save() error {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.path == "" {
		return errors.New("no password file path")
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<root>\n")
	b.WriteString("\t<list>\n")
	for _, u := range pf.Users {
		b.WriteString("\t\t<user>\n")
		writeXMLVal(&b, "\t\t\t", "name", u.Name)
		b.WriteString("\t\t\t<password encoding=\"" + xmlEscape(orString(u.Encoding, "SHA256")) + "\">" +
			xmlEscape(u.Password) + "</password>\n")
		writeXMLVal(&b, "\t\t\t", "full_name", u.FullName)
		writeXMLVal(&b, "\t\t\t", "last_logout", orString(u.LastLogout, "0"))
		writeXMLVal(&b, "\t\t\t", "last_activity", orString(u.LastActivity, "0"))
		writeXMLVal(&b, "\t\t\t", "email", u.Email)
		if len(u.EmailNotify) == 0 {
			writeXMLVal(&b, "\t\t\t", "email_notify", "")
		}
		for _, n := range u.EmailNotify {
			writeXMLVal(&b, "\t\t\t", "email_notify", n)
		}
		writeXMLVal(&b, "\t\t\t", "inactive", orString(u.Inactive, "0"))
		b.WriteString("\t\t</user>\n")
	}
	b.WriteString("\t</list>\n")
	b.WriteString("</root>\n")

	tmp := pf.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, pf.path)
}

func writeXMLVal(b *strings.Builder, indent, name, value string) {
	b.WriteString(indent + "<" + name + ">" + xmlEscape(value) + "</" + name + ">\n")
}

func orString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// User returns a user by login name (case sensitive, like the XML path lookup).
func (pf *PwdFile) User(name string) *PwdUser {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	for _, u := range pf.Users {
		if u.Name == name {
			return u
		}
	}
	return nil
}

// UserByEmail returns the first user with the given e-mail address.
func (pf *PwdFile) UserByEmail(email string) *PwdUser {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	for _, u := range pf.Users {
		if u.Email != "" && EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// AddUser appends a user record with the defaults elogd writes.
func (pf *PwdFile) AddUser(name, password, fullName, email string) error {
	pf.mu.Lock()
	for _, u := range pf.Users {
		if u.Name == name {
			pf.mu.Unlock()
			return errors.New("user already exists")
		}
	}
	pf.Users = append(pf.Users, &PwdUser{
		Name: name, Password: DoCrypt(password), Encoding: "SHA256",
		FullName: fullName, LastLogout: "0", LastActivity: "0",
		Email: email, Inactive: "0",
	})
	pf.mu.Unlock()
	return pf.Save()
}

// SetPassword changes the password of a user.
func (pf *PwdFile) SetPassword(name, password string) error {
	pf.mu.Lock()
	var u *PwdUser
	for _, x := range pf.Users {
		if x.Name == name {
			u = x
			break
		}
	}
	if u != nil {
		u.Password = DoCrypt(password)
		u.Encoding = "SHA256"
	}
	pf.mu.Unlock()
	if u == nil {
		return errors.New("user does not exist")
	}
	return pf.Save()
}

// SetInactive flags a user inactive/active (the admin "expire" switch).
func (pf *PwdFile) SetInactive(name string, inactive bool) error {
	pf.mu.Lock()
	var u *PwdUser
	for _, x := range pf.Users {
		if x.Name == name {
			u = x
			break
		}
	}
	if u != nil {
		u.Inactive = "0"
		if inactive {
			u.Inactive = "1"
		}
	}
	pf.mu.Unlock()
	if u == nil {
		return errors.New("user does not exist")
	}
	return pf.Save()
}

// SetEmailNotify replaces the subscription list of a user.
func (pf *PwdFile) SetEmailNotify(name string, logbooks []string) error {
	pf.mu.Lock()
	var u *PwdUser
	for _, x := range pf.Users {
		if x.Name == name {
			u = x
			break
		}
	}
	if u != nil {
		u.EmailNotify = logbooks
	}
	pf.mu.Unlock()
	if u == nil {
		return errors.New("user does not exist")
	}
	return pf.Save()
}

// TouchActivity updates last_activity/last_logout with the same throttling
// elogd applies (only when more than 60 s have passed; last_logout follows
// last_activity when the gap exceeded an hour). The throttle matters: without
// it every click rewrites the shared password file.
func (pf *PwdFile) TouchActivity(name string) error {
	pf.mu.Lock()
	var u *PwdUser
	for _, x := range pf.Users {
		if x.Name == name {
			u = x
			break
		}
	}
	if u == nil {
		pf.mu.Unlock()
		return nil
	}
	last, ok := ParseCTime(u.LastActivity)
	if !ok {
		last = time.Time{}
	}
	now := time.Now()
	if now.After(last.Add(60 * time.Second)) {
		if now.After(last.Add(time.Hour)) {
			u.LastLogout = u.LastActivity
		}
		u.LastActivity = FormatCTime(now)
		pf.mu.Unlock()
		return pf.Save()
	}
	pf.mu.Unlock()
	return nil
}

// UserNames lists all logins (the admin user page).
func (pf *PwdFile) UserNames() []string {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	out := make([]string, 0, len(pf.Users))
	for _, u := range pf.Users {
		out = append(out, u.Name)
	}
	return out
}

// NotifyFor reports whether this user subscribed to logbook lb ("all" or a
// per-logbook <email_notify> entry).
func (pf *PwdFile) NotifyFor(name, lb string) bool {
	u := pf.User(name)
	if u == nil {
		return false
	}
	for _, n := range u.EmailNotify {
		if EqualFold(n, "all") || EqualFold(n, lb) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// Session is one entry of elogd's sid[] table. The original keys a session on
// (session id, remote IP), which is why a session does not survive a NAT
// change. That is kept: it is a security property, not an accident.
type Session struct {
	ID     string
	User   string
	HostIP string
	Time   time.Time
	Expiry time.Duration
}

// SessionStore is the sid[] array plus a mutex.
type SessionStore struct {
	mu       sync.Mutex
	sessions []*Session
	expiry   time.Duration
}

// NewSessionStore builds a store. expiryHours is the "Login expiration"
// config value; the C code forces a 24 h minimum ("one day minimum for
// dangling edit pages") and defaults to 24 h.
func NewSessionStore(expiryHours float64) *SessionStore {
	if expiryHours < 24 {
		expiryHours = 24
	}
	return &SessionStore{expiry: time.Duration(expiryHours * float64(time.Hour))}
}

// New registers a session and returns its id. The id is 16 upper-case hex
// characters, the same shape sprintf("%04X") x4 produced, because it travels
// in a cookie that other tooling may have come to expect.
func (ss *SessionStore) New(user, hostIP string) string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.gcLocked()
	id := newSessionID()
	ss.sessions = append(ss.sessions, &Session{
		ID: id, User: user, HostIP: hostIP, Time: time.Now(), Expiry: ss.expiry,
	})
	return id
}

func newSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(t >> (8 * (i % 8)))
		}
	}
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 16)
	for i, v := range b {
		out[2*i] = hexDigits[v>>4]
		out[2*i+1] = hexDigits[v&0xf]
	}
	return string(out)
}

// Check resolves a session id for a client IP and refreshes its timestamp.
func (ss *SessionStore) Check(id, hostIP string) (string, bool) {
	if id == "" {
		return "", false
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for _, s := range ss.sessions {
		if s.ID == id && s.HostIP == hostIP {
			if time.Since(s.Time) > s.Expiry {
				continue
			}
			s.Time = time.Now()
			return s.User, true
		}
	}
	return "", false
}

// Remove logs a session out.
func (ss *SessionStore) Remove(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for i, s := range ss.sessions {
		if s.ID == id {
			ss.sessions = append(ss.sessions[:i], ss.sessions[i+1:]...)
			return
		}
	}
}

// Count is for the status page.
func (ss *SessionStore) Count() int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return len(ss.sessions)
}

func (ss *SessionStore) gcLocked() {
	keep := ss.sessions[:0]
	for _, s := range ss.sessions {
		if time.Since(s.Time) <= s.Expiry {
			keep = append(keep, s)
		}
	}
	ss.sessions = keep
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------
//
// elogd carries its own base64 (standard alphabet). Outgoing MIME and the
// Authorization header use standard encoding, so the stdlib is a drop-in
// replacement; LegacyB64Decode exists for the pre-SHA256 password file, whose
// passwords were stored as base64(DES-crypt(...)) and which base64_decode()
// mapped '=' onto index 0.

// LegacyB64Decode decodes the old password-file encoding.
func LegacyB64Decode(s string) string {
	const map64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	cind := func(c byte) int {
		if c == '=' {
			return 0
		}
		return strings.IndexByte(map64, c)
	}
	var out []byte
	for i := 0; i+4 <= len(s); i += 4 {
		var t uint32
		for k := 0; k < 4; k++ {
			idx := cind(s[i+k])
			if idx < 0 {
				idx = 0
			}
			t |= uint32(idx) << uint(6*(3-k))
		}
		out = append(out, byte(t>>16), byte(t>>8), byte(t))
	}
	out = []byte(strings.TrimRight(string(out), "\x00"))
	if n := strings.IndexByte(s, '='); n >= 0 {
		keep := n / 4 * 3
		switch n % 4 {
		case 2:
			keep++
		case 3:
			keep += 2
		}
		if keep < len(out) {
			out = out[:keep]
		}
	}
	return string(out)
}

// EncodeBase64Std names the stdlib call so intent is visible at call sites.
func EncodeBase64Std(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// DecodeBase64Std decodes standard base64, tolerating missing padding and
// embedded whitespace (MIME headers fold lines in the middle of long values).
func DecodeBase64Std(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s + strings.Repeat("=", (4-len(s)%4)%4))
}

// ---------------------------------------------------------------------------
// Password file placement
// ---------------------------------------------------------------------------

// ResolvePasswordFile is get_password_file(): the "Password file" value made
// absolute against the resource dir when it is relative.
func ResolvePasswordFile(cfg *Config, scope ConfigScope, resourceDir string) (string, bool) {
	v, ok := cfg.Get(scope, "Password file")
	if !ok || TrimSpaceASCII(v) == "" {
		return "", false
	}
	v = TrimSpaceASCII(v)
	if filepath.IsAbs(v) || (len(v) > 1 && v[1] == ':') {
		return v, true
	}
	return filepath.Join(resourceDir, filepath.FromSlash(v)), true
}
