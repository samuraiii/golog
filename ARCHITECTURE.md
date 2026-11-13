# Architecture of the Go rewrite of `elogd`

This document describes the design of the Go implementation of the ELOG
electronic logbook server. It is deliberately a *design* document: the mapping
from the C++ original (`inputs/elog/src/elogd.cxx`, ~31 000 lines, plus
`auth.cxx`, `crypt.cxx`, `strlcpy.cxx`, `locext.cxx`, `elog.cxx`) onto the Go
package layout, and the places where the port is intentionally *not* a literal
transcription. The behaviour that must stay identical is listed in
[Compatibility surface](#compatibility-surface); the deviations are listed in
[Deliberate deviations](#deliberate-deviations) and in `RESULT.md`.

---

## 1. Constraints the design starts from

1. **Drop-in replacement.** The same `elogd.cfg` (INI-style, `[logbook]`
   sections), the same command line, the same URLs, the same form fields, the
   same on-disk logbook files (`mlog*.log` + attachment files, optionally under
   `20YY/` sub-directories). An existing browser bookmark, an existing mail
   notification link, an existing mirror script and an existing data directory
   must all keep working.
2. **Behaviour-compatible with the *patched* tree.** The five local patches
   applied in `inputs/elog` are part of the target behaviour, not optional
   polish (MIME headers, 7bit/8bit, encoded-words, multipart closure,
   shell quoting, Windows-safe attachment names, UTF-8-safe RSS truncation).
   The Go code has to keep those properties *by construction* rather than by
   re-implementing the same fixes on the same fixed buffers.
3. **Idiomatic Go, not C in disguise.** No `char[N]` equivalents, no global
   arrays, no manual memory handling, no `system()`. The C code's single-threaded
   `select()` loop becomes `net/http` plus a mutex where the original relied on
   "there is only ever one request".
4. **The production target is known**: four logbooks, ~1600 entries, file-based
   auth (`<user>.xml` password files), mail notification through a local SMTP
   server, image thumbnails through ImageMagick `convert`/`identify`
   (`-g`), reverse-proxied HTTPS at `farm.particle.cz`.

## 2. Process and package layout

```
go.mod                       module github.com/samuraiii/golog (Go 1.21, no external deps)
cmd/elogd/main.go            command line, directory/port discovery, start-up
cmd/elogd/daemon.go          -D (re-exec + setsid), -f PID file
internal/elog/               the whole daemon, one package
  server.go    Server: config, logbook set, sessions, listener, resources
  request.go   URL/parameter decoding, authentication, permission gates,
               command dispatch, machine-readable output, attachment serving
  handlers.go  the "administrative" screens (config, users, subscriptions,
               status, summary, calendar, hits, revert, expire, POST API, help)
  pages.go     page chrome: header/menu/footer/style, list page, selection page
  entry.go     one entry, thread tree, edit form, preview, delete confirmation,
               login form
  render.go    renderers that fit none of the above (error pages, thread-of-one)
  submit.go    the store path: form -> Entry -> disk, attachments, hooks, mail
  storage.go   on-disk logbook: index, parse, append/update/remove, sub-dirs
  attachments.go attachment naming, storage, serving, thumbnails (convert/identify)
  auth.go      password file (<user>.xml), password hashing, sessions
  editlock.go  "<id>.lock" edit locks
  config.go    elogd.cfg parser + the getcfg() two-level lookup
  config_util.go  typed accessors, attribute lists, Save()/Dump(), reload
  mailer.go    the MIME writer, RFC 2047 encoded-words, SMTP and sendmail
  filters.go   (in mailer.go) the incoming-mail filter chain
  rss.go       RSS 2.0 / Atom feeds
  hitlog.go    mlog.hit: record formats, statistics queries
  hitlog_glue.go  the "Logging"/"Record hit file" glue + the view accessors
  locale.go    the .lng translation files
  shell.go     the &-substitutions and $shell(...) expansion, argv splitting
  procs.go     the ONE place a subprocess is started
  dates.go     the date formats elogd reads/writes, attachment time stamps
  text.go util.go support.go extra.go accessors.go compat.go  helpers
  logging.go verbose.go  the daemon's own diagnostics
```

Why one package: the C code is one program with ~700 functions that all reach
for the same globals (`log_cfg_t logbook[]`, `actual_lang`, `display_config`,
...). Splitting that into Go packages would force either import cycles or a
forest of parameters that carry no information. `internal/elog` therefore keeps
one namespace, and the *files* carry the structure. `internal/` is deliberate:
this is a binary, not a library, so nothing here is a public API promise.

The two packages that are *not* merged are the ones the original also keeps
separate: the HTTP layer (`request.go`) and the storage layer (`storage.go`)
talk through `Logbook`/`Entry` methods only.

## 3. The big objects

### `Server` (server.go)

The equivalent of the C process state: `Config`, the open `Logbooks` map plus
`Order` (configuration order, which decides the order of the selection page),
`Pwd` (password file), `Sessions`, the listener settings (`Addr`, `Port`,
`BasePath`, `SSLCert/SSLKey`), the directories (`ResourceDir` for themes/`.lng`,
`DataDir` as the prefix of relative `Data dir` values), and the feature switches
(`Exec`, `Thumbnail`, `RealIP`, `MaxUpload`, `SessionCookie`, `Locale`).

Two fields exist *only* to model C behaviour that assumed one request at a time:

* `inflight *Request` – `elogd` knows "the current request" implicitly. A few
  transcribed helpers take no request; they read it here instead of being given a
  parameter they would ignore in tests.
* `shellDir string` – `$shell(...)` runs in the logbook's directory; the
  directory is published around the call instead of threading it through the
  whole page renderer.

Both are guarded by `mu`. Everything else is either immutable after start-up or
guarded inside its own type (`Logbook.mu`, `Config.mu`, `SessionStore.mu`,
`hitMu`).

### `Logbook` / `Entry` (storage.go)

`Entry` is `{Header []HeaderLine, Text string}` plus the location of the entry in
the store (`File`, `Subdir`, `Offset`). That is exactly the on-disk format:

```
$@MID@$:<id>
<Attribute>: <value>
...
text:
<body, terminated by the next $@MID@$: or end of file>
```

The reader is a single pass per file that records byte offsets, so reading a
1600-entry logbook is one `stat` per file plus one read of the changed files.
`Append` writes at the end of the right `mlog<something>.log`, `Update` rewrites
one entry in place through a temporary file plus `os.Rename` (atomic, unlike the
C code's truncate-and-write), `Remove` rewrites the file minus that entry while
preserving any banner text before the first marker.

Sub-directories: if the data directory contains `20YY/`-style directories, the
logbook is treated as "restructured" (`20YYMMDD_HHMMSS.log` file names inside
`20YY/`), otherwise it is the flat layout. `Migrate` (the automatic migration
`elogd` performs at start-up) is **off by default** here: rewriting a production
data directory must be an explicit act, see `RESULT.md`.

### `Request` (request.go)

One request, with `W`, `R`, the owning `Server`, the resolved logbook (`LB`) and
config scope (`Cfg`), the resolved identity (`User`, `FullName`, `Email`), the
split URL (`lbName`, `rel`, `msgID`, `attachIx`) and the two parameter sets
(`params` = query string, `body` = POST form, body wins - like `elogd`, which
parses the body into the same flat list).

The pipeline is the original's order, so the error pages match:

1. `decodePath` - `/<logbook>/<id>[/<attachment index>]`, `?cmd=`/`?lb=`
2. `robots.txt` / `favicon.ico` / static resource short-circuits
3. `parseParams` (multipart handled by `net/http`, not by a hand-rolled reader)
4. `authenticate` - session cookie, then HTTP Basic, then `unm`/`upwd`, then the
   logbook `wpwd`, then (config-gated) an SSL client certificate
5. no logbook -> selection page (+ logout/login/status/help)
6. attachment URL -> attachment/thumbnail serving
7. `is_user_allowed()` equivalent (per-user `Allow * edit/delete/admin` lists)
8. `is_command_allowed()` equivalent (`Allowed commands`)
9. `dispatch`, which matches the command case-insensitively **and** against the
   translated button caption (`s.loc(name)`), because the pages post the
   translated caption.

### Configuration (config.go / config_util.go)

`Config` is the parsed file: ordered sections, each with ordered key/value pairs,
plus the file's mtime for the periodic re-read (`elogd` re-reads the config on a
timer from its select loop; here `serve()` calls `reloadIfChanged()`).

The lookup is `getcfg()`'s: logbook section value, else `[global]` value, else
the caller's default, with `Top group` adding the third level. Matching of a key
is `elogd`-compatible: ASCII case-insensitive, and a stored key may carry a
`:param` suffix (used for per-type attribute definitions), which the matcher
handles the same way the C code does.

Typed accessors (`GetString`, `GetInt`, `GetFlag`, `Hours`, `GetList`,
`MandatoryAttrs`, `DisplayedAttrs`, `OptionsFor`, `AttributeNames`) live in
`config_util.go`, together with `Save()`/`SetParam()` (the `-t SMTP password`
path and the `Setup` page) and `Dump()` (`?cmd=Display config`).

## 4. Subsystems

### Mail (mailer.go)

The MIME writer is hand-written (not `net/mail`/`mime/multipart`) because the
byte-exact output is part of the compatibility surface: the patched C code
emits `MIME-Version: 1.0`, `Content-Type` exactly once per part,
`Content-Transfer-Encoding: 8bit` for a UTF-8 body and `7bit` for an ASCII body,
base64 for binary attachments, and it must close every multipart boundary.
`mailMessage.render()` therefore builds the header block and the body from one
place, so "two Content-Type headers" cannot come back, and the attachment parts
are written in a loop that either writes a part completely or not at all - an
unreadable attachment is skipped and reported, never emitted as an unclosed part.

Encoded-words (RFC 2047) are produced by `EncodeWord`, which base64-encodes
*whole runes* and splits only between runes: a `=?UTF-8?B?...?=` word never
contains half a multi-byte character. The same rune-safe rule is applied by
`ShortenUTF8` to the RSS description and to the mail subject, which is the fix of
the "RSS text truncated mid-character" patch.

Delivery: `SMTP server`/`SMTP Port`/`SMTP User`/`SMTP Password` via
`net/smtp` (with AUTH LOGIN/PLAIN when credentials are present), or `Sendmail`
as a pipe through `procs.go`. `No mail`, `Mail sending` and the per-user
`email_notify` subscription list decide the recipient set; `Filters` post-process
or suppress the message (see below).

### External commands (shell.go, procs.go)

Four call sites in the original: `Execute new/edit/delete`, `$shell(...)` in
page text and configuration values, the incoming-mail filter and `Sendmail`.
All of them end in `runProgram(argv, dir, stdin)` -> `exec.Command`.

Two rules are enforced structurally:

* **never a shell.** A configured command line is split into argv words by
  `SplitCommand` (quotes and backslash escapes honoured, no globbing, no
  redirection, no `$(...)`). Attachment names and `&attrX` substitutions are
  argv words, so the shell-injection class of bug cannot exist here. The C patch
  that quotes the file name becomes unnecessary.
* **opt-in.** Without `-x`, every hook and every `$shell(...)` is skipped and
  logged instead of run. The original has no such gate (its `-x` only enables
  the *feature set*, but `system()` was reachable from a stored logbook file); a
  Go binary has no shell to hide behind, yet an explicit opt-in is still the
  safer default for a server whose logbook files are writable by several people.

`$shell(...)` nesting is bounded (`maxShellDepth`) and, unlike the C scanner,
program output is *not* rescanned for further `$shell(...)` calls.

### Auth (auth.go)

The `<user>.xml` password file is parsed and written back (`Save`), with the
element set `elogd` uses (`<user>`, `<name>`, `<password>`, `<email>`,
`<full_name>`, `<functions>`, `<real_name>`, `<forum_id>`, `<email_notify>`,
`<expiration>`, `<last_activity>`, `<properties>`, `<auth_type>`, `<inactive>`).
Passwords are stored in the same obfuscated form as the C code's
`encrypt_password()` (SHA-256 with the salted base-64 alphabet of
`crypt.cxx`, `1:` prefix), and `VerifyStoredPassword` accepts both that form and
a plain-text entry, which is what `check_password()` does.

Note the deliberate deviation: name comparison for "may I edit this entry"
(`SamePerson`) compares normalised names *completely* instead of over a
`MAX_STRING`-truncated buffer, so `"John Doe"` no longer matches `"John Doe2"`.
Sessions are the `sessionid` cookie, keyed on the client address (address
checking is `elogd`'s; behind a proxy `-f`/`X-Forwarded-For` is opt-in because
trusting that header by default would make sessions hijackable).

### Edit locks (editlock.go)

`<id>.lock` files in the logbook directory, containing the locker and the time,
`Edit lock timeout` deciding staleness - the same scheme on disk as the original,
so an `elogd` and a Go `elogd` never fight over the same entry during a gradual
rollout.

### Hit logging / statistics (hitlog.go, hitlog_glue.go)

`mlog.hit` is read in all three historical record formats (the pipe-separated
`id|logbook|time|user|ip|user agent` form, the `<message .../>` XML form, and the
old space-separated `<epoch> <logbook> <id> <ip>` form), so an existing file
stays useful. `Logging` (`xml|file|stdout`) and `Record hit file` control whether
anything is written; `Display views` puts the view count into the list page.

### Pages (pages.go, entry.go, handlers.go, render.go)

The HTML is regenerated rather than copied from the C strings, but the parts a
client depends on are kept: the form fields (`cmd`, `message_id`, `edit_id`,
`reply_to`, `in_reply_to`, `subject`, `text`, `attr<N>`/attribute names,
`unm`, `upwd`, `wpwd`, `subtext`, `attr`, `since`, `n`, `page`, `display`,
`encoding`, `user_email`, `attdelete`, `attachment<N>`), the classes and ids the
themes style (`.list`, `.title`, `.entry`, `.text`, `.odd`/`.even`, `#menu`, ...),
the submit-button-per-command menu, and the theme/`Stylesheet`/`Title picture`
configuration keys. `defaultCSS` is used when no theme file is found, so the
server is usable from a bare install.

## 5. Concurrency model

`net/http` serves requests on goroutines. Data that the C code guarded by
"one request at a time" is guarded explicitly:

* `Config.mu` (reload swaps the map), `Server.mu` (listener, logger, inflight),
* `Logbook.mu` - a read-mostly `RWMutex`; the index is rebuilt from the changed
  files (mtime compare) rather than from scratch,
* `hitMu` for the hit files, `SessionStore.mu`, `localeCache`.

Writes to the logbook files use a per-logbook critical section plus atomic
rename; the original has no locking at all (`elogd` is single-threaded), so this
is strictly better but changes one visible property: two simultaneous submits to
the same logbook are serialised instead of interleaving into one file.

## 6. Compatibility surface (what must not change)

* **CLI**: `-c -d -s -p -n -l -t -f -v -D -k -S -x -g -h -V`, `ELOGDIR`/`ELOGCFG`
  (`ELOGUSER` accepted-but-ignored), directory discovery order (command line,
  `[global]` key, config-file directory + `logbooks`), "resource directory
  missing is fatal", "logbook directory is created if missing", default port
  80/443-with-SSL.
* **URLs**: `/<lb>/`, `/<lb>/<id>`, `/<lb>/<id>/<n>`, `?cmd=...`, `?lb=`,
  `?thumb=1`, `/robots.txt`, `/favicon.ico`, `/-f-/<file>` form fields.
* **Commands**: `Display`, `DisplayList`, `New`, `Edit`, `Submit`, `Preview`,
  `Reply`, `Delete`, `Confirm Delete`, `Revert`, `Find`, `Login`, `Logout`,
  `Signup`, `Setup`, `Status`, `Summary`, `Calendar`, `Hits`, `Expire`, `Help`,
  `RSS`, `RSSfull`, `XML`, `JSON`, `CSV`, `Raw`, `POST` - plus their translated
  spellings.
* **Machine-readable output**: the XML element shape, the JSON object-per-id
  shape, the `;`-separated CSV, the raw `mlog` dump - because mirror scripts parse
  them.
* **Disk**: `mlog*.log` entry format, `$@MID@$:` marker, attribute folding,
  `YYMMDD_HHMMSS_` attachment prefixes, `20YY/` layout, `<id>.lock`, `mlog.hit`,
  `_deleted.log`, `<user>.xml`.

## 7. Deliberate deviations

| # | Deviation | Why |
|---|-----------|-----|
| 1 | No shell anywhere; `-x` gates all subprocesses | removes the injection class the patch only mitigated |
| 2 | Go strings/slices instead of `char[N]` | removes the overflow class; where a size *is* chosen it is commented (see `RESULT.md`) |
| 3 | `net/http` instead of the hand-rolled `select()`/keep-alive loop | HTTP/1.1 pipelining, chunking and `Content-Length` correctness come for free; `-k` becomes a no-op |
| 4 | `regexp` instead of the vendored `regex.c` | the vendored engine is ~5000 lines of pre-POSIX code |
| 5 | `Migrate` off by default | never rewrite a production data directory implicitly |
| 6 | `SamePerson` compares whole names | the C comparison used a fixed buffer and matched prefixes |
| 7 | `303 See Other` after a successful POST | replaces the original's meta-refresh auto-POST page |
| 8 | Added: `Help` page, `robots.txt`, XML escaping of hit records, `Max total size` enforcement through `ParseMultipartForm` | the original has none of these; each is additive |
| 9 | No LDAP / Kerberos / PAM / SAML / Windows-NT service / remote clone & sync (`-C`, `-m`, `-M`) | out of scope for the FZU/CESNET deployment (file auth, local SMTP); see `RESULT.md` |

## 8. Testing strategy

There is no Go toolchain in this environment, so the tests that are written
(`internal/elog/mailer_test.go`, and the exported `ShowRaw`/`ServeStatic`/
`CurrentServer` hooks that exist for tests) could not be executed. Verification
here is: reading the sources, per-file declaration inventories, and cross-file
"declared exactly once / used and declared" scans. `RESULT.md` records what was
checked that way and what a real `go build && go vet && go test ./...` run must
still confirm.
