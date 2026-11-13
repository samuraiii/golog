package elog

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// The daemon
// ---------------------------------------------------------------------------
//
// Server is the process-wide state: the configuration, the set of open logbooks,
// the session table and the HTTP listener. Everything is rooted at the
// configuration file, exactly like elogd, which "discovers" a logbook on the
// first request for /<name> when the configuration has such a section
// (init_logbooks() plus the GetParameterDirectory() path in
// display_logbook_page()). Here a logbook section is opened at start-up and a
// directory that appears later is opened on demand.
//
// The HTTP request pipeline itself lives in request.go (Server.serve), because
// that is where the URL/parameter decoding and the command dispatch are.
//
// What a *Server does NOT hold: the view statistics (hitlog.go owns them), the
// configuration accessors (support.go), the page renderer (pages.go).

// Server is the elogd process state.
type Server struct {
	Config     *Config
	ConfigPath string
	Logbooks   map[string]*Logbook
	Order      []string // logbook names in configuration order
	Pwd        *PwdFile
	Sessions   *SessionStore

	Port        int
	Addr        string
	BasePath    string // "" at the root, "/elog" with -p elog
	ResourceDir string // -s <dir>: themes, .lng files, favicon
	DataDir     string // -d <dir>: prefix for relative logbook directories
	SSLCert     string
	SSLKey      string
	RealIP      bool // -f: trust X-Forwarded-For
	Thumbnail   bool // generate thumbnails with convert(1)
	ConvertCmd  string
	IdentifyCmd string
	MaxUpload   int64 // MiB, from "Max total size" / -v
	// Exec gates every external command (-x): the "Execute new/edit/delete"
	// hooks, $shell(...) in configuration values. The original has no such
	// switch of its own because it runs everything through system(); a Go
	// binary has no shell to hide behind, but an operator can still opt in
	// explicitly, which is the safer default.
	Exec          bool
	SessionCookie string
	DaemonUser    string
	// Version is what the pages and the status line print. It carries the
	// version of the emulated elogd (EmulatedVersion), not of this binary
	// (Version), so that a client or a monitoring script which parses it keeps
	// working.
	Version string
	// Locale is the language of the user interface: the "Locale" configuration
	// key, whose .lng file is read from the resource directory. "English" is the
	// default and the fallback for every untranslated string.
	Locale    string
	StartTime time.Time

	// Log is where the daemon log goes (stderr, or the file -l opened). Code
	// without a *Server reaches it through support.go's logWriter().
	Log io.Writer

	// locMu guards locCache, the parsed .lng file. The C program reads the
	// language file once at start-up; here it is loaded on first use because
	// the resource directory is only known after the command line was parsed,
	// and the cache is guarded because this port serves requests on several
	// goroutines while elogd has one select() loop.
	locMu    sync.Mutex
	locCache *Locale

	// inflight is the request currently being served by Server.serve. elogd
	// knows "the current request" implicitly (one request at a time); helpers
	// that were transcribed without a Request parameter read it here, which is
	// why the field exists and why it is guarded by mu.
	inflight *Request

	mu             sync.Mutex
	logbooksOpenMu sync.Mutex
	logger         *log.Logger
	listener       net.Listener
	lastReload     time.Time
}

// New builds a server from a parsed configuration. The values the C program
// takes from the command line (Port, ResourceDir, DataDir, ...) are filled in by
// cmd/elogd afterwards; the ones it takes from [global] are read here.
func New(cfg *Config, cfgPath string) *Server {
	s := &Server{
		Config:        cfg,
		ConfigPath:    cfgPath,
		Logbooks:      make(map[string]*Logbook),
		Port:          80,
		Version:       EmulatedVersion,
		StartTime:     time.Now(),
		SessionCookie: CookieName,
		ConvertCmd:    "convert",
		IdentifyCmd:   "identify",
		MaxUpload:     30,
		logger:        log.New(os.Stderr, "elogd: ", log.LstdFlags),
	}
	g := ConfigScope{Group: "global"}

	s.Addr = s.Config.GetString(g, "Interface", "")
	if v, ok := s.Config.Get(g, "Port"); ok && Atoi(v) > 0 {
		s.Port = Atoi(v)
	}
	if s.Config.GetBool(g, "SSL") && s.Port == 80 {
		// The original switches the default port when SSL is on.
		s.Port = 443
	}
	if v := s.Config.GetString(g, "BasePath", ""); v != "" && v != "/" {
		s.BasePath = "/" + strings.Trim(v, "/")
	}
	if v := s.Config.GetString(g, "Session cookie", ""); v != "" {
		s.SessionCookie = v
	}
	// The language of the user interface: elogd's -l switch and the "Locale" /
	// "Language" keys. English is the shipped default and the fallback.
	s.Locale = "English"
	if v := TrimSpaceASCII(s.Config.GetString(g, "Locale", "")); v != "" {
		s.Locale = v
	}
	if v := TrimSpaceASCII(s.Config.GetString(g, "Language", "")); v != "" {
		s.Locale = v
	}
	if v, ok := ResolvePasswordFile(s.Config, g, s.ResourceDir); ok {
		pf, err := LoadPwdFile(v)
		if err != nil {
			s.logf("password file %s: %v", v, err)
			pf = &PwdFile{}
		}
		s.Pwd = pf
	} else {
		s.Pwd = &PwdFile{}
	}

	// "Login expiration" is in hours in the configuration file and the C code
	// forces a minimum of one day ("one day minimum for dangling edit pages");
	// NewSessionStore applies that clamp.
	s.Sessions = NewSessionStore(s.Config.Hours(g, "Login expiration", 24))

	if n := s.Config.GetInt(g, "Max total size", 0); n > 0 {
		s.MaxUpload = int64(n)
	}
	if n := s.Config.GetInt(g, "Max content length", 0); n > 0 {
		s.MaxUpload = int64(n)
	}
	s.Thumbnail = s.Config.GetFlag(g, "Use thumbs")
	if v := s.Config.GetString(g, "Convert command", ""); v != "" {
		s.ConvertCmd = v
	}
	if v := s.Config.GetString(g, "Identify command", ""); v != "" {
		s.IdentifyCmd = v
	}
	return s
}

// Logf writes to the daemon log (stderr, or whatever the -l redirect opened).
func (s *Server) Logf(format string, args ...any) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.logger == nil {
		w := io.Writer(os.Stderr)
		if s.Log != nil {
			w = s.Log
		}
		s.logger = log.New(w, "elogd: ", log.LstdFlags)
	}
	l := s.logger
	s.mu.Unlock()
	l.Printf(format, args...)
}

func (s *Server) logf(format string, args ...any) { s.Logf(format, args...) }

// SetOutput redirects the daemon log (used by -l).
func (s *Server) SetOutput(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Log = w
	s.logger = log.New(w, "elogd: ", log.LstdFlags)
}

// ---------------------------------------------------------------------------
// Logbooks
// ---------------------------------------------------------------------------

// OpenLogbook opens (or returns the cached) logbook with the given section name.
// dir is the logbook directory from the configuration; when it is empty the name
// itself is tried under the server's -d directory, as elogd's relative-dir
// handling does.
//
// migrate decides whether a flat pre-4.1.0 data directory is restructured into
// 20YY/ sub-directories (restructure_dir()). cmd/elogd passes the value of the
// "Restructure dir" configuration key, defaulting to false, because rewriting a
// production data directory must be an explicit act.
func (s *Server) OpenLogbook(name, dir string, migrate bool) (*Logbook, error) {
	s.logbooksOpenMu.Lock()
	defer s.logbooksOpenMu.Unlock()
	if lb, ok := s.Logbooks[name]; ok {
		return lb, nil
	}
	var cands []string
	if dir != "" {
		cands = append(cands, s.abs(dir))
	}
	cands = append(cands, filepath.Join(s.DataDir, name))
	if s.DataDir != "" {
		cands = append(cands, name)
	}
	var last error
	for i, c := range cands {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err != nil {
			// Only the first candidate may be created on the fly; a fallback that
			// does not exist yet must not silently turn a typo in "Dir" into an
			// empty logbook in the data directory.
			if i > 0 || !s.mayCreate(c) {
				last = err
				continue
			}
		}
		lb, err := OpenLogbook(name, c, migrate)
		if err != nil {
			last = err
			continue
		}
		s.Logbooks[name] = lb
		if !containsString(s.Order, name) {
			s.Order = append(s.Order, name)
		}
		return lb, nil
	}
	return nil, fmt.Errorf("logbook %q: %w", name, last)
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// mayCreate reports whether a not-yet-existing directory may be created as a
// logbook data directory (true for anything under the -d directory).
func (s *Server) mayCreate(dir string) bool {
	if s.DataDir == "" {
		return false
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	return strings.HasPrefix(abs, filepath.Clean(s.DataDir)+string(os.PathSeparator))
}

// LB returns an already open logbook, opening it on demand when the
// configuration has a section of that name - exactly elogd's lazy
// init_logbooks()/display_logbook_page() behaviour.
func (s *Server) LB(name string) *Logbook {
	s.logbooksOpenMu.Lock()
	lb := s.Logbooks[name]
	s.logbooksOpenMu.Unlock()
	if lb != nil {
		return lb
	}
	if name == "" || !IsLogbookName(name) {
		return nil
	}
	if s.Config.Section(name) == nil {
		return nil
	}
	lb, err := s.OpenLogbook(name, s.logbookDir(name), s.restructure())
	if err != nil {
		s.logf("cannot open logbook %s: %v", name, err)
		return nil
	}
	return lb
}

// logbookDir is the "Dir" of a logbook section (elogd's GetParameterDirectory).
func (s *Server) logbookDir(name string) string {
	if v, ok := s.Config.Get(ConfigScope{Group: name}, "Dir"); ok && TrimSpaceASCII(v) != "" {
		return TrimSpaceASCII(v)
	}
	return ""
}

// restructure is the global "Restructure dir" switch (default off in this port;
// the C program always runs restructure_dir() at start-up).
func (s *Server) restructure() bool {
	return s.Config.GetBool(ConfigScope{Group: "global"}, "Restructure dir")
}

// OpenAll opens every logbook section of the configuration.
func (s *Server) OpenAll() error {
	var first error
	for _, name := range s.Config.SectionNames() {
		if !IsLogbookName(name) {
			continue
		}
		if _, err := s.OpenLogbook(name, s.logbookDir(name), s.restructure()); err != nil {
			if first == nil {
				first = err
			}
			s.logf("cannot open logbook %s: %v", name, err)
		}
	}
	return first
}

// Close releases every logbook. The index is kept in memory only, so this just
// drops the references; it exists so that cmd/elogd has something to defer.
func (s *Server) Close() {
	s.logbooksOpenMu.Lock()
	defer s.logbooksOpenMu.Unlock()
	s.Logbooks = map[string]*Logbook{}
	s.Order = nil
}

// ReloadIfChanged re-reads the configuration file when its mtime moved, which is
// what elogd does at the top of every request. Logbooks are *not* dropped on
// reload: the original keeps the already-open ones and only picks up new
// sections, and dropping them would lose nothing but cost a full re-index of
// every logbook on every save of the configuration.
func (s *Server) ReloadIfChanged() error { return s.reloadIfChanged() }

func (s *Server) reloadIfChanged() error {
	if s.Config == nil {
		return nil
	}
	changed, err := s.Config.ReloadIfChanged()
	if err != nil || !changed {
		return err
	}
	s.mu.Lock()
	s.lastReload = time.Now()
	s.mu.Unlock()
	g := ConfigScope{Group: "global"}
	if n := s.Config.GetInt(g, "Max total size", 0); n > 0 {
		s.MaxUpload = int64(n)
	}
	s.Thumbnail = s.Config.GetFlag(g, "Use thumbs")
	if v := s.Config.GetString(g, "Session cookie", ""); v != "" {
		s.SessionCookie = v
	}
	if v := TrimSpaceASCII(s.Config.GetString(g, "Locale", "")); v != "" {
		s.locMu.Lock()
		s.Locale = v
		s.locCache = nil
		s.locMu.Unlock()
	}
	s.logf("configuration reloaded")
	return nil
}

// LogbookNames returns the open logbooks in configuration order; with
// visible==true the ones the user may not read drop out.
func (s *Server) LogbookNames(user string, visible bool) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if seen[name] || !IsLogbookName(name) {
			return
		}
		seen[name] = true
		if visible && !s.IsLogbookAllowed(name, user) {
			return
		}
		out = append(out, name)
	}
	for _, name := range s.Order {
		add(name)
	}
	for _, name := range s.Config.SectionNames() {
		add(name)
	}
	return out
}

// abs resolves a configuration path against the -d directory when relative.
func (s *Server) abs(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if s.DataDir != "" {
		return filepath.Join(s.DataDir, p)
	}
	if s.Config != nil {
		return filepath.Join(s.Config.ConfigDir(), p)
	}
	return p
}

// CookiePath is the Path= attribute of the session cookie: the prefix the daemon
// is mounted under, so a site that serves several instances side by side does
// not mix their sessions.
func (s *Server) CookiePath() string {
	if s.BasePath == "" {
		return "/"
	}
	return s.BasePath
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

// Handler returns the root http.Handler of the daemon.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serve)
	return mux
}

// ListenAndServe runs the daemon until the listener fails.
func (s *Server) ListenAndServe() error {
	addr := net.JoinHostPort(s.Addr, fmt.Sprint(s.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve runs the daemon on an existing listener (used by tests too).
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.listener = ln
	l := s.logger
	s.mu.Unlock()
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(l.Writer(), "", 0),
	}
	if s.SSLCert != "" && s.SSLKey != "" {
		return srv.ServeTLS(ln, s.SSLCert, s.SSLKey)
	}
	return srv.Serve(ln)
}

// ListenAddr is the address the listener ended up on (tests).
func (s *Server) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Shutdown stops the listener (used by tests).
func (s *Server) Shutdown() {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

// httpsRedirect is the "Require https" switch of the original: the redirect is
// done by the server rather than by the browser because "some do not honour it".
// Local addresses are exempt so that an operator can still fix a
// misconfiguration from the machine itself.
func (s *Server) httpsRedirect(r *http.Request) bool {
	if !s.Config.GetBool(ConfigScope{Group: "global"}, "Require https") {
		return false
	}
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		return false
	}
	ip := clientIP(r, s.RealIP)
	return !(ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127."))
}

// clientIP is the remote address, taking X-Forwarded-For into account only when
// the operator said the daemon sits behind a proxy (-f). Trusting that header by
// default would let any client forge its address and hijack the session of
// somebody else, since sessions are keyed on the address.
func clientIP(r *http.Request, realIP bool) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if realIP {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			if list := SplitList(xf, ",", false); len(list) > 0 {
				return list[0]
			}
		}
	}
	return host
}

// ---------------------------------------------------------------------------
// Resources (themes, images, language files)
// ---------------------------------------------------------------------------

// findResource looks a file up in the resource directory and then under the
// logbooks' own directories, like the original's resource handling which serves
// anything below <logdir>/<name> for URL /<logbook>/<name>.
func (s *Server) findResource(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	clean := filepath.Clean("/" + strings.TrimPrefix(name, "/"))
	var tries []string
	if s.ResourceDir != "" {
		tries = append(tries, filepath.Join(s.ResourceDir, clean))
	}
	for _, lbName := range s.Order {
		lb := s.LB(lbName)
		if lb == nil {
			continue
		}
		tries = append(tries, filepath.Join(lb.Dir, clean))
	}
	for _, p := range tries {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
	}
	return "", false
}

// ServeResource writes a static resource (CSS, logo, favicon, ...). Missing
// files are a plain 404, because elogd's pages reference a few optional files.
func (s *Server) ServeResource(w http.ResponseWriter, r *http.Request, name string) {
	p, ok := s.findResource(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	if !headerSet(w, "Content-Type") {
		w.Header().Set("Content-Type", ContentTypeFor(p))
	}
	http.ServeContent(w, r, filepath.Base(p), st.ModTime(), f)
}

// ReadResource returns the contents of a resource file (used for the .lng files
// and for an external style sheet that has to be inlined).
func (s *Server) ReadResource(name string) ([]byte, error) {
	if p, ok := s.findResource(name); ok {
		return os.ReadFile(p)
	}
	if s.ResourceDir != "" {
		if b, err := fs.ReadFile(os.DirFS(s.ResourceDir), strings.TrimPrefix(name, "/")); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("resource not found: " + name)
}

// ---------------------------------------------------------------------------
// External commands
// ---------------------------------------------------------------------------

// ShellSubst expands $(shell ...) / $shell(...) in one configuration value (see
// shell.go for the syntax and for the -x gate). This is the method every caller
// uses; the parsing itself lives in shell.go.
func (s *Server) ShellSubst(value string) string {
	if s == nil || !strings.Contains(value, "shell(") {
		return value
	}
	return shellSubst(s, value)
}

// RunCommand runs one configured external command ("Execute on new entry" and
// friends) after the -x gate. It is exported for cmd/elogd; the request paths use
// runEntryHook (procs.go).
func (s *Server) RunCommand(command, dir string) error {
	return s.runCommand(command, dir)
}

// AllowExecute is the -x switch: may this daemon run an external program at all?
func (s *Server) AllowExecute() bool {
	if s == nil {
		return false
	}
	return s.Exec
}

// runCommand runs one configured command line through the single process entry
// point of procs.go. The command line is split into argv words there and handed
// to exec.Command: no shell is involved, ever. That is the deliberate answer to
// the shell-injection bug the local patches fix in the C code (where a file name
// was pasted into a string given to system()); quoting a name is a workaround,
// never building a shell string is the fix.
//
// Execution is opt-in (Exec, the -x flag): a logbook file or a configuration
// value that grew a hook cannot execute code on a server whose operator never
// allowed it.
func (s *Server) runCommand(command, dir string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	argv := SplitCommand(command)
	if len(argv) == 0 {
		return nil
	}
	if !s.AllowExecute() {
		s.logf("execution disabled (-x), not running %q", argv[0])
		return nil
	}
	out, err := runProgram(argv, dir, nil)
	if len(out) > 0 {
		s.logf("hook %s: %s", argv[0], TrimSpaceASCII(string(out)))
	}
	return err
}
