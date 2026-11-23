# golog

A from-scratch rewrite of [ELOG](https://elog.psi.ch/elog) (`elogd`), the
electronic logbook server, in Go. It keeps ELOG's configuration file format,
on-disk message format and HTTP/URL interface, so existing logbooks and
configurations work, and adds what a server in 2026 needs: TLS 1.2+, HTTP/2,
LDAP/AD and OpenID Connect login, signup approval, UTF-8 storage and more.

**Status:** it builds, vets and passes its test suite (including race tests and
security regression tests) for Linux and Windows on 386, amd64 and arm64. It
has had little production use yet: try it on a copy of your logbooks first, and
read the [security review notes](#security) before exposing it.

## Quick start

```sh
go build -trimpath -ldflags='-s -w' -o gologd ./cmd/gologd   # vendored, no network needed
./gologd sample-config -o golog.cfg                          # documented starter configuration
./gologd -c golog.cfg                                        # serves the demo logbook on port 8080
```

- `gologd sample-config [-o file] [-f]` prints or writes a commented
  configuration with a freshly generated random salt (commented out).
- `gologd config-update -c golog.cfg [-n]` adds options introduced by newer
  versions as commented-out entries, keeps everything you have, and leaves a
  timestamped backup next to the file.
- `gologd convert` converts legacy-codepage logbooks to UTF-8 once (dry run by
  default); see [docs/encoding.md](docs/encoding.md).
- Service files for systemd, OpenRC, sysv, FreeBSD, launchd and Windows are in
  [docs/service/](docs/service/); fail2ban filters in [docs/fail2ban/](docs/fail2ban/).

## What it does beyond ELOG

- **UTF-8 only storage.** New entries are always written as UTF-8. Legacy
  logbooks are read through the `Legacy codepage` option and shown as UTF-8
  on the fly; `gologd convert` migrates them for good.
- **Transport.** HTTPS with the full certificate chain, TLS 1.2+ only, HTTP/2,
  client certificates with CA directories and CRLs, optional HTTP-to-HTTPS
  redirect and HSTS. No QUIC/HTTP/3.
- **Login.** Password file (scales to thousands of users), LDAP/Active
  Directory, OpenID Connect SSO ([docs/oidc.md](docs/oidc.md)), trusted-header
  and external-helper authentication; fail2ban-style login bans and throttling.
- **Signup.** Mandatory administrator approval and a CAPTCHA; optional password
  lifetime and reuse history.
- **Hardening.** Central access gate, CSRF protection for state-changing
  commands, a restricted footer (only `a`, `i`, `u`, `b`, `img`), safe
  attachment serving, mail and shell-injection fixes.
- **Attachments.** With a `Salt` configured, new attachments are stored under
  an unguessable base32 SHA-256 name without extension and the original file
  name is kept for display; legacy attachments keep working. Thumbnails are
  made in pure Go (no ImageMagick, also on Windows).
- **Deployment.** `Base path` serves golog in a URL subdirectory (also behind a
  reverse proxy that strips the prefix); system logging to journal, syslog,
  file or the Windows Event Log; graceful shutdown, systemd notification and a
  native Windows service.
- **Look.** A per-instance and per-logbook `Logo`, with a favicon derived from
  it, and a built-in default logo (`Logo = none` removes it).

Not implemented: remote synchronisation (`-C`, `-m`, `-M`), QUIC/HTTP/3,
Kerberos and PAM (use header or external-helper authentication), and skins:
the default look is still the classic ELOG one. The user-visible names still
say "elog" in many places.

## Building and testing

```sh
go vet ./... && go test ./...
go test -race ./internal/golog
GOOS=windows GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o gologd.exe ./cmd/gologd
```

The binary is statically linked, about 10 MB, and has no runtime dependencies.
CI runs on GitHub Actions; version tags (`v*`) build the six release binaries
and publish them with checksums.

## Security

Two security reviews have been done and most findings fixed, each with a
regression test (`internal/golog/security_test.go`, `access_test.go` and
others). A third full review is in progress. Report problems privately to the
maintainer rather than in a public issue.

## Design documents

[ARCHITECTURE.md](ARCHITECTURE.md), [contract.md](contract.md) and
[notes.md](notes.md) are working documents from the initial LLM-generated port
and are historical: where they disagree with the code or this file, the code
wins.

## Attribution

golog is a derivative work of **ELOG** by **Stefan Ritt** (Paul Scherrer
Institute, PSI) and the ELOG contributors, <https://elog.psi.ch/elog>,
source at <https://gitea.psi.ch/ELOG/elog>. Behaviour, configuration format
and message format are taken from the original C implementation, which
golog was written against.

It also carries over five local fixes made to upstream ELOG (MIME/UTF-8
headers, closing of `multipart/related`, shell-quoting of file names,
RSS text truncation, a stack buffer overflow).

## Licence

ELOG is licensed under the GNU General Public License, version 2. golog, as a
derivative work, is distributed under the same terms: see [COPYING](COPYING).
There is no warranty.

## Acknowledgements

Many thanks to [MetaCentrum](https://metacentrum.cz/) for the LLM service used for the AI-assisted development of golog.

golog was developed with [Claude Code](https://claude.com/claude-code) (Anthropic's Claude), which wrote, merged and fixed much of the code under the direction of the maintainer.
