# Character sets and encodings in golog

**Status: this documentation describes code that has never been compiled.** The
encoding batch (`internal/golog/encoding.go`, `encoding_util.go`, `legacy.go`,
`legacy_write.go`, `cmd/gologd/convert.go`, the tests) was written against the
declarations in the tree by static reading only; no `go build`, `go vet` or
`go test` was ever run on it. See `MERGE-NOTES.md` for the list of integration
edits a human has to make and for the doubts about compilation.

---

## 1. The decision

**golog stores UTF-8 and nothing else.** Every byte of text golog writes —
logbook message files, the XML password/user files, notification mail bodies,
every HTTP response — is UTF-8. There is no configuration option that makes the
server write another encoding, and there will not be one.

Logs written by the classic C `elogd` are a different matter. They hold whatever
bytes the poster's browser sent, which on a Czech site in 2005 meant
ISO-8859-2 or windows-1250, on a Russian one windows-1251 or KOI8-R, and
elsewhere usually ISO-8859-1. Those logbooks must stay readable, so golog
**decodes them on the fly** and never rewrites them as part of serving a
request. Turning a legacy logbook into UTF-8 on disk is a separate, explicit,
one-time operation: `gologd -convert`.

The C original has no charset configuration at all — `elogd.cxx` never calls
`getcfg()` for a charset or codepage, it stores the bytes it receives and
declares its pages in the charset of the locale it was built in. That is why
real log directories are a mixture today, and it is why the option below is a
golog concept rather than a port of an existing one.

### Repair, do not reject

Text arriving from a browser, an RPC client or a mail notification is
**repaired**, not refused:

| input | what golog stores |
|---|---|
| valid UTF-8 | unchanged |
| a byte sequence that is not valid UTF-8 | one `U+FFFD` (the maximal-subpart rule) |
| a NUL byte | dropped |
| a CR, or a CRLF pair | a LF |

Every substitution is counted and logged once per field name. The count is
returned by `PrepareUTF8` so that a caller which wants to be strict (the
conversion tool, an API POST handler) can reject on it.

The reason for repairing rather than showing an error page: a poster whose
browser emitted one stray `0x92` would otherwise lose everything he typed, and
`elogd` has always been "store something". The reason NUL is dropped rather
than replaced: a NUL in a message file truncates the entry when the C client
library reads it, so keeping one corrupts the file, not just the text.

Attachment **content** is never touched — those bytes are the user's. Attachment
**names** are, because they appear in HTML and in XML.

---

## 2. Configuration

```ini
[global]
    ; The code page that logbooks which are not UTF-8 are READ with.
    ; Default: empty, which means "read every logbook as UTF-8".
    Legacy codepage = windows-1250

[global / Test]
    ; Per logbook; overrides the global value.
    Legacy codepage = ISO-8859-2

[global / Run]
    ; An explicit statement that this logbook is not legacy.
    Legacy codepage = UTF-8
```

| key | status | notes |
|---|---|---|
| `Legacy codepage` | current | the name to use |
| `Charset` | deprecated alias | accepted so a site that already set one keeps its behaviour |
| `Codepage` | deprecated alias | |
| `Code page` | deprecated alias | |

The aliases are read in the order above; the first non-empty one wins. They are
looked up through the normal scope chain (`logbook` → `global <top group>` →
`global`), so a per-logbook value overrides a global one without any extra
configuration.

### Accepted values

Any IANA charset name or alias, case-insensitive, spaces and underscores
ignored: `UTF-8`, `utf8`, `US-ASCII`, `ISO-8859-2`, `iso 8859 2`,
`ISO_8859-2:1987`, `latin2`, `l2`, `windows-1250`, `cp1250`, `ms-ee`, `cee`,
`KOI8-R`, `koi8r`, `IBM852`, `mazovia`, `macintosh`, `macroman`, `cp437`, …

`gologd -list-codepages` prints the list golog resolves by itself (about 33
code pages, which are also the ones the tests cover); anything else is resolved
through the IANA registry that ships in `vendor/golang.org/x/text`. A name that
is registered but not implemented by that library is reported as unknown — golog
will not read a file with a guessed codepage.

### What an invalid value does

A value golog cannot resolve is **not** fatal:

* the daemon logs `golog: logbook Test: unknown codepage: "winz-1250" …` once and
  reads that logbook as UTF-8, which is exactly what it did before this option
  existed. A typo must not take the daemon down, and mojibake in one logbook is
  visible and recoverable.
* `gologd -convert` **does** exit with an error, because there an operator is
  watching and a wrong code page silently produces wrong text.

---

## 3. Reading a legacy logbook

The decision is made **per message block**, not per file, and the rule is:

1. a `golog-encoding` marker at the top of the block's text section decides
   alone (see §5);
2. otherwise a block that is itself valid UTF-8 is read as UTF-8;
3. otherwise the block is decoded with the code page configured for the logbook;
4. and if none is configured, with the last-resort `Legacy-ASCII` page (a
   Latin-1 mapping), once, with a log line naming the option to set.

Per block rather than per file because golog writes UTF-8: the moment somebody
edits one entry of a windows-1250 logbook, that entry is UTF-8 inside a file
that is not. A whole-file decision would render exactly that one entry as
mojibake. Blocks are independent in this format — the index points at each one
separately — so the per-block rule costs nothing.

Two special cases are handled before the rule:

* **A file whose bytes are pure ASCII** is valid UTF-8 and needs no code page.
  This is the common case and is why most logbooks convert to nothing.
* **A file with a UTF-16 byte order mark** is decoded as that UTF-16. `elogd`
  could never write such a file, but an operator who round-tripped a logbook
  through a Windows editor would otherwise get garbage.
* **A file containing NUL bytes or an escape stream** is treated as binary: golog
  hands out its bytes un-decoded rather than inventing plausible-looking text
  out of damage.

The residual risk of rule 2 is documented rather than hidden: a legacy block can
be valid UTF-8 by accident (a windows-1250 `Ä` followed by a byte in
`0x80..0xBF` is a legal two-byte UTF-8 sequence). The answer for a logbook where
that matters is the one-time conversion, which removes the ambiguity for good.

### Byte offsets

The logbook index stores **byte offsets into the file** — the position of each
`$@MID@$:` line — and retrieval is a `ReadAt` at that offset. Decoding
windows-1250 to UTF-8 changes byte counts (one Czech letter is one byte on disk
and two in memory), so the two coordinate systems must never be mixed. The
invariant this batch maintains:

* an offset is computed on the **raw file bytes** and stored unchanged;
* there is no "offset in the decoded text" anywhere in golog, and no function
  converts one space into the other;
* `verifyAt()` re-reads the window at an offset and parses it **without
  decoding** — the marker and the ID it compares are ASCII, so a legacy window
  verifies correctly;
* every byte-oriented search (marker positions, the separator line, the encoding
  marker) runs on undecoded file bytes; the marker word `golog-encoding` is
  7-bit by construction, which is what makes that legal.

The practical consequence is the order of operations in `parseFile()`: read the
bytes, decode the block to UTF-8, and only **then** parse the decoded text into
an `Entry`, setting `e.Offset` from the position in the *file*. `parseBlock()` is
never handed raw legacy bytes: it splits header lines at the first `:`, which
for KOI8-R or a double-byte code page could land inside a multi-byte character
and produce a header value that is not UTF-8.

### Search, attachments, summaries

Search runs on the decoded (UTF-8) strings, so a Czech word typed into the UTF-8
search form finds a windows-1250 entry. Attachment **file names on disk** are
never re-encoded (they are created by golog and are ASCII), but **display
names**, which come from the `Attachment:` header of a legacy entry, are UTF-8 by
the time they reach a page, and any name handed to `http.ServeContent` is
RFC 5987-encoded (`filename*=UTF-8''…`) because a bare `Content-Disposition`
cannot carry non-ASCII.

---

## 4. The web interface is UTF-8 only

| surface | what golog sends |
|---|---|
| every HTML page | `Content-Type: text/html; charset=utf-8`, `<meta http-equiv="Content-Type" content="text/html; charset=utf-8">` and `<meta charset="utf-8">` |
| every form | `accept-charset="utf-8"` on the `<form>` tag |
| RSS / any XML | `Content-Type: …; charset=utf-8` and `<?xml version="1.0" encoding="UTF-8"?>` |
| JSON | `application/json; charset=utf-8` |
| CSV | `text/csv; charset=utf-8` |
| raw / text post | `text/plain; charset=utf-8` |
| RPC | `application/octet-stream` stays binary; the body is UTF-8 text inside the framing |
| attachment download | the attachment's own type; binary types get **no** charset and their bytes are never re-encoded |
| mail | `MIME-Version: 1.0`, `Content-Type: text/plain; charset=utf-8`, `Content-Transfer-Encoding: quoted-printable` (or `7bit` when the body is ASCII), non-ASCII `Subject:`/`From:` display names RFC 2047-encoded |

A text response whose body contains invalid UTF-8 cannot happen: every string
that reaches a page came from the decoder (which always yields UTF-8) or from
`PrepareUTF8`.

There is deliberately **no** charset conversion in the other direction: no
request body is ever interpreted as anything but UTF-8. A browser that posts
ISO-8859-2 bytes despite `accept-charset="utf-8"` gets `U+FFFD` where the
accented letters were, and the daemon log says so. That is a deliberate,
visible failure instead of a silent guess.

---

## 5. The `golog-encoding` marker

```
$@MID@$: 4711
Date: Tue, 30 Apr 2024 12:34:56 +0200
Title: Údržava detektoru
Author: Jan Novák
========================================
golog-encoding = windows-1250

Kontrola …
```

* It is a line in the **text** section, directly after the separator line, in
  the configuration idiom `key = value`. The header section is parsed by every
  client of the format (`elogd`, `elns`, hand-written readers) where an unknown
  header line is not guaranteed to be ignored; the text section is free-form by
  contract.
* It is **read** wherever it is the first text line — an operator may add one by
  hand, in either `=` or `:` spelling, and the conversion tool may have written
  one — and it is **written** only by the conversion tool, only with
  `-add-markers`.
* It is stripped from every rendered page, feed, mail body and attribute list,
  so it never reaches a reader.
* It names the code page the entry was *originally* written in. It survives the
  entry being concatenated into another file, which is the only case a
  per-file decision cannot see.

golog does not use the `Encoding:` header for this: that header means
`HTML`/`Plain`/`HyperText` and is part of the wire protocol.

---

## 6. `gologd convert`

One-time, safe, idempotent conversion of legacy log files to UTF-8.

```
gologd convert [flags] [--] [LOGBOOK ...]

  --apply             actually write; without it this is a dry run
  --dry-run           explicit dry run (the default)
  --config FILE       configuration file (default: the compiled-in elogd.cfg)
  -D DIR              configuration directory, same meaning as for the daemon
  --logbook NAME      convert only this logbook (repeatable)
  --file PATH         convert exactly this file (repeatable, bypasses logbook lookup)
  --codepage NAME     the code page to read with; required unless --codepage auto
                      or the logbook has a "Legacy codepage"
  --backup-dir DIR    put backups here instead of <file>.bak next to the file
  --force             ignore a running daemon; replace undecodable bytes
  --keep-mtime        restore the modification time of the original
  --add-markers       write "golog-encoding = <codepage>" into each converted entry
  --stream IN OUT     decode one file to a new name in constant memory
  --list-codepages    print the code page names golog knows and exit
```

`gologd` keeps its existing single-dash flag convention, so the subcommand is
also accepted as `-convert` / `--convert`; `-D`, `-p`, `-f`, `-P` and the rest
still work exactly as before for the daemon.

### What it does to one file

1. read it (refuse above 2 GiB — see `--stream`), classify it, and **refuse**
   anything that is already valid UTF-8, anything pure ASCII, anything binary,
   and anything with no legacy code page to read it with;
2. decode **every block separately**, with the banner as its own piece, so a
   per-entry marker and a per-entry damage count are possible and a block that
   is already UTF-8 (an entry golog wrote into a legacy file) is copied rather
   than decoded twice;
3. refuse the whole file when any entry has undecodable bytes, unless `--force`
   (then they become `U+FFFD` and are counted in the report);
4. copy the original to `<file>.bak` (or into `--backup-dir`, with a time stamp),
   preserving the mode; an existing `.bak` is never overwritten, a numbered name
   is used instead, so "the original" survives any number of runs;
5. write the new bytes to `<file>.golog-convert.tmp` in the **same directory**,
   `fsync` the file, `rename` it over the original, then `fsync` the directory;
6. read the result back and compare it with the bytes it produced; on any
   mismatch, **restore the original from the backup** and report;
7. restore the mode, and the mtime with `--keep-mtime`.

### Properties

* **Dry-run by default.** A conversion tool that converts when a flag was
  forgotten is a tool that loses logbooks.
* **Idempotent.** Step 1 refuses what step 6 produced, so a second run converts
  nothing. `convert --apply` twice is the test of this.
* **Never rewrites a file it does not understand** — binary, empty, or without
  entries is refused, and the daemon never reaches this code at all.
* **Crash safe.** A crash between 4 and 6 leaves either the old file or the new
  one (rename is atomic within a file system), plus a `.tmp` that the next run
  notices: `refuseTempLeftBehind()` skips a file whose stale temporary is newer
  than the log file, which is the signature of a crashed run.
* **Refuses to run against a live daemon** unless `--force`, using the PID file
  of the server that owns the data directory. This is a courtesy check, not a
  lock: a daemon that died without removing its PID file must not make a
  logbook unconvertible, which is what `--force` is for.
* **Huge files** go through `--stream`, which decodes through a transformer into
  a *new* file in constant memory and does not verify (it cannot hold both
  versions), which is why it only ever writes to a name you give it.

### Report

One line per file (`would convert`/`converted`/`skipped`/`failed` plus the code
page, the entry count and the byte counts) and a summary:

```
23 file(s): 4 converted, 19 already UTF-8 or skipped, 0 failed; 1287 entries,
0 undecodable byte(s) in 0 entry(ies); 8123456 -> 8411209 bytes
```

The exit status is 0 when everything converted or skipped, 1 when any file
failed. A dry run never exits non-zero for "would change" — that is not an error.

---

## 7. Which files hold text

| file | encoding | notes |
|---|---|---|
| `<data dir>/YYMMDDa.log` | UTF-8 written; any legacy code page read | the subject of this document |
| attachments | untouched bytes | never decoded |
| `elogd.cfg` | UTF-8 recommended | golog reads it as bytes; non-ASCII in a config value is passed through unchanged, so it should be UTF-8 |
| the XML password / user file | UTF-8, declared `<?xml version="1.0" encoding="UTF-8"?>` | the comment is sanitised too, see MERGE-NOTES |
| `.acnd` access-control files | UTF-8 | names may be non-ASCII |
| PID file, lock files | ASCII | nothing to convert |
| mail bodies | UTF-8, quoted-printable | see §4 |

User names, display names and "comment" fields are the places in the
auth/ACL files where a human can type non-ASCII; they go through
`SanitizeForWrite` before the file is written.

---

## 8. What an operator should do

1. Set `Legacy codepage` for each logbook that is not UTF-8 and check that the
   pages look right. Nothing on disk has changed.
2. Run `gologd convert` (dry run) and read the report: the code pages, the entry
   counts, and above all any *undecodable byte* count.
3. Stop the daemon, or accept the warning and use `--force`.
4. Run `gologd convert --apply`. The report names every backup.
5. Restart and check the pages, the search, the RSS feed and an attachment
   download. `file(1)` should now say "UTF-8 Unicode text" for every log file.
6. Keep the backups until you are sure, then delete them; golog will not.

Rollback is a copy of the `.bak` back over the file, because the conversion
changes the byte length of an entry, **restart the daemon afterwards**: the
in-memory index holds offsets into the file you just replaced, and
`Message()`/`Update()`/`Remove()` self-heal by rebuilding the index when an
offset stops verifying, so a restart is belt-and-braces rather than strictly
required.
