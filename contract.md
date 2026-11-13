# Package-wide API contract (internal/elog)

This is the single source of truth for cross-file names in the Go port. Every
file must agree with it. All names are in package `elog`.

## Types

```go
type Server struct{ ... }            // server.go
type Request struct{ ... }           // request.go
type Config struct{ ... }            // config.go
type ConfigScope struct{ Group, Condition, TopGroup string }
type Logbook struct{ ... }           // storage.go
type Entry struct{ ... }             // storage.go
type HeaderLine struct{ Key, Value string }
type PwdFile struct{ ... }           // auth.go
type PwdUser struct{ ... }           // auth.go
type SessionStore struct{ ... }      // auth.go
type AttachmentRef struct{ Name, Display string; Index int }
type Locale struct{ ... }            // locale.go
```

## Config methods (exact arities)

```go
Get(scope ConfigScope, param string) (string, bool)
GetString(scope ConfigScope, param, def string) string
GetInt(scope ConfigScope, param string, def int) int
GetBool(scope ConfigScope, param string) bool           // atoi semantics
GetFlag(scope ConfigScope, param string) bool           // yes/no semantics
GetFlagDefault(scope ConfigScope, param string, def bool) bool
GetBoolDefault(scope ConfigScope, param string, def bool) bool
GetStringDefault(scope ConfigScope, param, def string) string
GetList(scope ConfigScope, param string) []string
GetAll(scope ConfigScope, param string) []string
GetDuration(scope ConfigScope, param string, def time.Duration) time.Duration
Hours(scope ConfigScope, param string, def float64) float64
IntList(scope ConfigScope, param string) []int
FirstOf(scope ConfigScope, params ...string) (string, bool)
Section(name string) *Section
SectionNames() []string
Set(sectionName, key, value string)
SetParam(section, key, value string) error
Save() error
ReloadIfChanged() (bool, error)
ConfigDir() string
FileName() string
Dump(section string) string
AttributeNames(scope ConfigScope) []string
OptionsFor(scope ConfigScope, attr string) []string
MandatoryAttrs(scope ConfigScope) []string
DisplayedAttrs(scope ConfigScope, all ...string) []string   // VARIADIC: 1 or 2 args
ConfigDir() string
```

`DisplayedAttrs` is variadic on purpose: some call sites pass the full
attribute list, others want it computed from the scope.

## Entry methods

`Get`, `GetAll`, `Get2`, `Set`, `SetAll`, `SetHeader`, `Add`, `Del`, `ID`,
`SetID`, `IDnum`, `IDstr`, `Date`, `SetDate`, `Attrs`, `AttrNames`, `AttrValue`,
`Attachments() []string`, `SetAttachments`, `Encoding`, `Title`, `Author`,
`InReplyTo`, `SetInReplyTo`, `Thread`, `SetThread`, `LockedBy`, `SetLockedBy`,
`LockedByName`, `MsgID`, `SetMsgID`, `Marshal`.
Fields: `Header []HeaderLine`, `Text`, `File`, `Subdir`, `Offset int64`.

## Logbook methods

`Name`, `Dir` fields; `Message(id) (*Entry, error)`, `Messages() []*Entry`,
`Len() int`, `Append(*Entry) error`, `Update(*Entry) error`, `Remove(id) error`,
`NextID() int`, `Load() error`, `DataDirFor(subdir) string`,
`Path(subdir, name) (string, error)`, `Subdir(*Entry) string`,
`AttachmentRefs(*Entry) []AttachmentRef`, `Attachments(*Entry) []AttachmentRef`,
`AttachmentByIndex(*Entry, int) (AttachmentRef, error)`,
`SaveAttachment(subdir, origName string, r io.Reader, now time.Time) (string, error)`,
`DeleteAttachment(subdir, name string)`,
`AttachmentDirFor(subdir string, now time.Time) string`.

## Server: what pages.go / request.go / submit.go may call

```go
Config *Config; ConfigPath string; Logbooks map[string]*Logbook; Order []string
Pwd *PwdFile; Sessions *SessionStore
BasePath, ResourceDir, DataDir, SessionCookie, ConvertCmd, IdentifyCmd string
Port int; MaxUpload int64; Exec, RealIP, UseThumbs, Thumbnail bool

serve(w, r)                         // the one HTTP pipeline (request.go)
dispatch(q *Request)                // single argument (request.go)
NewRequest(w, r, rel string) *Request
beginPage(q *Request, title, bodyClass string)
endPage(q *Request)
errorf(q *Request, code int, format string, args ...any)
redirect(q *Request, url string)
showLoginPage(q *Request, redir string, failed bool)
showSelectionPage(q *Request)
showListPage(q *Request)
showDisplayPage(q *Request, id int)
showEditPage(q *Request, id int, mode string)
showPreviewPage(q *Request)
showThreadPage(q *Request)
confirmDeletePage(q *Request)
deleteMessage(q *Request)
searchPage(q *Request)
hitsPage(q *Request)
showStatusPage(q *Request)
showSummaryPage(q *Request)
showCalendarPage(q *Request)
showConfigPage(q *Request)
showRaw(q *Request, mode string)
showRSS(q *Request, full bool)
ShowRSS(q *Request, full bool)
help(q *Request)
serveAttachment(q *Request)
serveStatic(q *Request, name string) bool
robotsTxt(w http.ResponseWriter)
login(q *Request); logout(q *Request); checkPassword(user, pass string) bool
loc(name string) string; locT(name string) string
requestBaseURL(r *http.Request) string
EntryURL(base, logbook string, id int) string
entryURL(r *http.Request, logbook string, id int) string
AttachmentURL(lbName string, e *Entry, ref AttachmentRef) string
attachmentURL(lbName string, e *Entry, ref AttachmentRef) string
AttachmentDisplayHTML(lbName string, e *Entry, editable bool) string
Thumbnail(dataDir, name string, w, h int) (string, bool)
RecordHit(lb *Logbook, id int, ip string)
RecordHitAs(lb *Logbook, id int, ip, user, userAgent string)
Views(lb *Logbook, id int) int
ShowViews(scope ConfigScope) bool
LastActivity(scope ConfigScope) string
EditLockBy(lb *Logbook, id int) string
SetEditLock(lb *Logbook, e *Entry, user string)
CanEdit(scope ConfigScope, user string) bool
IsLogbookAllowed(logbook, user string) bool
ShellSubst(text string) string
SubstituteEntry(text string, e *Entry, logbook, charset string) string
runCommand(command, dir string) error
notify(q *Request, lb *Logbook, e *Entry, old *Entry, url string) error
Logf(format string, args ...any)
nowString() string
```

## Request fields/methods

```go
W http.ResponseWriter; R *http.Request; S *Server; LB *Logbook
Cfg ConfigScope; User, FullName, Email string
params, body url.Values
path string; msgID int; attachIx int
searchIDs []string          // set by searchPage/hitsPage, honoured by showListPage
listTitle string            // optional title override for the list page
Param(name) string; ParamAll(name) []string; HasParam(name) bool
IntParam(name) string -> int
ClientIP() string
displayName() string
requestURL() string         // absolute URL of the current request
hasCmdParam() bool          // "cmd" present in query or body
attrs() map[string]string   // form values keyed by attribute name
dumpParams() string
```

## Free functions

```go
RunEntryHook(s *Server, command, dir string, id int, charset, url, file, logbook string) error
SplitCommand(s string) []string
AttachmentRefs(e *Entry) []AttachmentRef
MakeFilenameHeaderSafe(s string) string   // + lowercase alias
isASCIIString(s string) bool; ToASCIIFallback(s string) string
MakeFilenamePortable(name string, size int) string
EncodeWord(s string) string; EncodeHeaderPhrase(s string) string
JoinHostPort(host, port string) string
FormatDate(format string, t time.Time) string
FormatRFC2822(t time.Time) string; FormatCTime(t time.Time) string
ParseDate(s string) (time.Time, bool); ParseCTime(s string) (time.Time, bool)
MustParseDate(s string) time.Time
cfgBool(c *Config, sc ConfigScope, param string, def bool) bool
```

## Rules

* `Server.BasePath` is `""` at the root, otherwise `/elog` (no trailing slash).
  Every URL is built as `s.BasePath + "/" + ...`.
* No function is built as a shell string; `exec.Command(argv[0], argv[1:]...)`.
* Config lookups use `Config.Get*` with the arities above (no variadic except
  `DisplayedAttrs` and `FirstOf`).
* Truncation of user text always goes through `ShortenUTF8` (never byte-slice).
