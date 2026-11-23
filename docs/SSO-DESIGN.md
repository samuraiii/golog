# SSO support for golog — design document

Status: **design only.** No code in this tree is changed by it. Anything written as `code`
and marked **proposed** is new; every other name exists in `internal/golog` today (checked
against the sources and against `API-internal-golog.txt`).

Scope: single sign-on for `gologd`, the Go rewrite of `elogd`. The daemon must keep behaving
exactly as it does now when no SSO key is present: file authentication, LDAP authentication,
the trusted-proxy header back end and the external helper all stay as they are, and
`Authentication = File` must remain a complete configuration.

---

## 0. Executive summary and recommendation

**Recommendation.** Add one SSO mechanism natively — an OpenID Connect / OAuth 2.0 relying
party using the authorization code flow with PKCE — and add a small policy-driven
client-certificate login mapping on top of the TLS work that already exists. Do **not** build
a SAML 2.0 service provider and do **not** build native Kerberos/SPNEGO in Go: for both, the
existing trusted-proxy header back end in `authheader.go` is the right and cheaper answer, and
it is already the answer the code gives today (`authTypeAliases` maps `Negotiate`, `SPNEGO`,
`KRB5`, `Kerberos` and `SSO` onto `AuthHeader`, and the header comment of `authheader.go`
records why).

| mechanism | decision | why |
|---|---|---|
| OIDC / OAuth2 code+PKCE | **build it** (§2) | the standard library can do it safely; every target IdP (Entra ID, Keycloak, Okta, Google) speaks it; it answers the SAML request in almost every site that raises SAML for OIDC-compatible reasons |
| SAML 2.0 SP | **do not build**; delegate (§3) | XML Signature is the most-abused part of the format; a correct implementation is a multi-week security project with a large attack surface. Delegate to the proxy, or to the IdP's own OIDC bridge |
| Kerberos / SPNEGO | **do not build**; delegate to `Header` (§4) | no Kerberos module is vendored; the header back end is what production AD installations already run; the code says so and explains the cost |
| Client-certificate login | **build a small mapping layer** (§5) | the TLS plumbing (client CA, CRL, `SSL client auth`) exists, but the login mapping in `(*Request).authenticate` takes `PeerCertificates[0].Subject.CommonName` with no verification and no policy — the one existing hole worth closing |

**Shape of the work.** OIDC is an `Authenticator` plus a browser redirect, not a new
authentication system. The pieces that decide *who* a caller is (`Authenticator`, `AuthChain`,
`(*Server).AuthenticateLogin`), *what a session is* (`SessionStore`, `(*Request).newSession`,
`(*Server).SetLoginCookie`) and *what he may do* (`(*Server).userAllowed`,
`(*Server).commandAllowed`, `(*Server).userIn`, `(*Server).IsLogbookAllowed`,
`(*Server).CanEdit`) stay unchanged. An SSO login ends where a password login ends: an
`Identity`, then `(*Server).finishLogin`, then a session cookie, then the ordinary permission
checks.

**Ranked implementation order** (effort in §8.6; every step is independently shippable):

1. **P1 — OIDC core** (~13 person-days): discovery + JWKS + ID-token validation + the two
   handlers (`cmd=OidcLogin`, `cmd=OidcCallback`), the server-side flow store, single-provider
   login, the "Sign in with …" button on the login page, forced mode.
2. **P2 — mapping, JIT, logout, multi-provider** (~7 days): claims → `Identity`,
   `Group map` / `Super admin group` integration, `OIDC create user`, RP-initiated and
   back-channel logout, status-page lines, several providers side by side.
3. **P3 — client-certificate login** (~5 days): replace the `CommonName` shortcut in
   `(*Request).authenticate` with a verified-chain, policy-matched `Cert` back end.
4. **P4 — operator surface** (~4 days): `SSO mode`, per-logbook opt-out,
   `LoginMethod()`/`AuthStatus()` reporting, the redaction test, documentation, both worked
   examples verified end to end.
5. **P5 — optional, only if the human insists** — native SAML (≥ 31 days, needs a new module,
   §3.6) and native Kerberos (≥ 27 days, needs a new module, §4.6). Both are recommended
   against; the numbers are here so that "no" is a costed no.

**Dependencies.** P1–P4 need **no new third-party module**: `encoding/json`, `crypto/rsa`,
`crypto/ecdsa`, `crypto/sha256`, `math/big`, `net/http` and `time` suffice for the JWT/JWKS
work, and `crypto/rand` plus the existing `randomHex` (`rand.go`) give the state, nonce and
verifier. The module question, including the one candidate worth discussing
(`github.com/coreos/go-oidc/v3`, BSD-2-Clause), is Appendix A.

**The three requirements that are not really about SSO** — the parts of this document worth
implementing even if SSO never is:

* **R1** — `(*Server).dispatch`'s `Login` case calls `(*Server).login`, which uses
  `checkPassword` (the password file) and never the `AuthChain`. `cmd=Login` therefore already
  ignores LDAP and the header back end. Route it to `(*Server).LoginHandler`.
* **R2** — the `redir` parameter flows unvalidated from `cmd=Login` through `showLoginPage`
  into `finishLogin`'s redirect: an open redirect in the existing login page. The
  `safeSsoTarget` predicate SSO needs closes it.
* **R3** — `(*Request).authenticate` logs a caller in as
  `q.R.TLS.PeerCertificates[0].Subject.CommonName` without consulting
  `q.R.TLS.VerifiedChains`: with `SSL client auth = request` any self-signed certificate
  becomes any user.

---

## 1. What already exists (the integration surface)

This section is the ground truth the rest of the document stands on. Every name in it exists
today.

### 1.1 The authentication seam (`authiface.go`)

```go
type Authenticator interface {
        Name() string
        Authenticate(ctx AuthContext) (Identity, error)
}
```

`Identity` is what a back end returns: `Name`, `FullName`, `Email`, `Groups`, `AuthType`,
`Admin`, `Created`, `Principal`. `AuthContext` is what it is given: `User`, `Password`,
`RemoteIP`, `Header http.Header`, `S *Server`, `Req *http.Request`. The contract is documented
in the file and every SSO back end must obey it:

* the three refusals are `ErrUnknownUser`, `ErrBadPassword`, and — for "I could not be
  consulted" — `ErrAuthUnavailable` (built with `AuthUnavailablef`). The distinction is
  load-bearing: a refusal is counted by the throttle and the ban list, an unreachable back end
  must not be, "or one dead directory locks every operator out";
* a back end never logs the password and never writes to the response.

`AuthChain` (`NewAuthChain`, `List`, `Len`, `Name`, `Authenticate`) tries members in order,
skips and counts the unavailable ones, returns `ErrNoAuthenticator` for an empty chain and
`AuthUnavailablef("every configured method (%s) was unreachable", …)` when all were down. It
fills `Identity.Name` from `AuthContext.User` and `Identity.AuthType` from `Name()` when the
back end left them empty.

Selection is `NewAuthenticators(s *Server, cfg ConfigScope) (AuthChain, error)`, driven by
`authenticationValue`, which reads the new `Authentication` key and falls back to the C
daemon's `Auth type`. Its four rules matter for SSO and must not be broken:

1. absent key → the file back end alone;
2. **the file back end is appended last unless the key names it** — the local emergency account
   keeps working when a directory or an IdP is configured;
3. an unknown value is logged and skipped, never silently treated as `File`, "so a typo shows
   up in the log instead of silently changing who may log in";
4. `Authentication = none` is logged as not honoured and still leaves the file back end.

Back ends self-register in `init()` through the unexported
`registerAuthenticator(canonicalName string, f func(ctx AuthContext) Authenticator)`, keyed in
the `newAuthenticator` map; `RegisteredAuthenticators()` lists the names for the unknown-value
log line. The canonical names are the constants `AuthFile`, `AuthLDAP`, `AuthNTLM`,
`AuthHeader`, `AuthExternal`, and `authTypeAliases(name string) string` folds the spellings
onto them — including `header`, `proxy`, `negotiate`, `spnego`, `sso`, `krb5`, `kerberos` onto
`AuthHeader`. **That is an existing behaviour to preserve, not a placeholder to overwrite**: an
operator who wrote `Authentication = SSO` today got the header back end, and any site that did
so must keep working.

Caching and reload: `(*Server).Authenticators()` memoises one `AuthChain` per server in
`authChainCache`; `(*Server).ResetAuthenticators()` drops it, calls `Close() error` on members
that have it, then `InvalidateTrustedProxyCache(s)` and `ReloadLoginGuards(s)`. **An OIDC back
end must therefore implement `Close`**, because it owns an HTTP client and a key-set refresh
timer — and it gets configuration-reload behaviour for free by doing so.

The single entry point is

```go
func (s *Server) AuthenticateLogin(r *http.Request, user, password string) (Identity, error)
```

which, in order: trims the name, resolves the source address with `s.loginSourceIPFor(r)` →
`s.LoginSourceIP(r)`, consults `s.loginBlocked(user, ip)` **before** any back end runs, runs
the chain, and on the way out calls `s.recordLoginFailure(user, ip)` (`FailBanLogFailure` →
`FailBanFailure` → `LoginThrottleFailure`) or `s.recordLoginSuccess(user, ip)`
(`FailBanSuccess` → `LoginThrottleSuccess`), applies `LoginThrottleDelay(s)` on the failure
path only, and logs `"golog auth: login ok for %s from %s via %s"`. The error taxonomy a
handler branches on is `LoginBlocked(err)`, `LoginWait(err)`, `IsAuthUnavailable(err)`,
`LoginErrorMessage(err)` and `LoginHTTPStatus(err)` (`authhttp.go` / `authext.go`), which
answer 429 / 503 / 401.

Identity → rights, both in `authiface.go`:

* `(*Server).GroupsForUser(name string, asserted []string) []string` merges the groups the back
  end asserted with the configuration key **`Group map`**, spelled
  `GroupA = jdoe, jsmith; GroupB = *@corp.example` (`;` between groups, `,` between members, a
  trailing `*` is a prefix match, compared with the existing `matchName`). Its doc comment
  states why groups cannot live in the password file: `PwdUser` has no group element and
  inventing one would change the on-disk format.
* `(*Server).IdentityIsAdmin(id Identity) bool` is `id.Admin` or membership of
  **`Super admin group`**.

`AuthenticationSummary(s *Server) string` renders the chain (`"LDAP+File"`), and
`(*Server).IsTrustedProxy(addr string) bool` is the exported predicate the header back end and
the status pages ask for.

### 1.2 The back ends that already plug in

| file | back end | what it proves today |
|---|---|---|
| `authfile.go` | `AuthFile` | the XML password file, `VerifyStoredPassword`, the local emergency account; also embedded as `fileBackedAuthenticator` for the "then try the password file too" fallback |
| `ldapauth.go`, `ldapconn.go` | `AuthLDAP` | an LDAP/AD simple bind, user filters and templates, `memberOf` extraction, `CloseLdapPools()`; the three-way distinction "no such user" / "wrong password" / "directory down" is already implemented |
| `authheader.go` | `AuthHeader` | an assertion from a **trusted proxy** (§1.4); registers through `registerAuthenticator(AuthHeader, newHeaderAuthenticator)` |
| `authexternal.go` | `AuthExternal` | a helper program |
| `authhttp.go`, `authext.go` | — | the HTTP login path, the cookie, the status lines (§1.3, §1.5) |

`authheader.go` deserves attention because this design leans on it twice. Its file header
explains at length why there is no Kerberos in golog (no Kerberos package in
`vendor/modules.txt`; `github.com/Azure/go-ntlmssp` is client-side only; SPNEGO from scratch is
"several thousand lines of security-critical protocol code") and what it implements instead:
IIS `RequestHeader set X-Remote-User "%LOGON_USER%"`, Apache `mod_auth_gssapi`, nginx
`proxy_set_header X-Remote-User $remote_user`. Its options are read per attempt by
`readHeaderOptions(c *Config, scope ConfigScope) headerOptions`:

| key (exact spelling) | default | effect |
|---|---|---|
| `Header user header` | `X-Remote-User` | the header carrying the asserted name |
| `Header groups header` | "" | comma-separated groups |
| `Header fullname header` (alias `Header name header`) | "" | display name |
| `Header email header` (alias `Header mail header`) | "" | address |
| `Header strip domain` | **true** | `CORP\jdoe`, `jdoe@corp` → `jdoe` |
| `Header lowercase user` | false | |
| `Header login group` | "" | required asserted group |
| `Header admin group` | "" | sets `Identity.Admin` |
| `Header create user` | **true** | `s.ensurePwdUser(name, id.FullName, id.Email, true, true)` |
| `Header require password` | false | also demand the local password |
| `Header trusted proxies` | — | extra proxy list |
| `Header max length` | 256 (floor 16) | bound on an asserted value |

The order of checks in `(a *headerAuthenticator).Authenticate` **is** the security of the
arrangement, and it is the model for every SSO back end: (1) is the peer in
`trustedProxyNets(s)` — if not, the header is **ignored** and the attempt is logged, "not
'believed with a warning'"; (2) is there an assertion at all, else abstain, so a login form
still works on a server normally behind the proxy; (3) sanity — a header sent twice is an
error, the length bound applies, control characters are refused (`readHeaderAsserted`);
(4) `Header login group` via `headerHasGroup` (exact, first-RDN, or after-`\` matching, with no
substring matching), then `Header admin group`; (5) the optional local password through
`fileBackedAuthenticator`; then the optional user creation. Its `AuthDescription()` — found
through the unexported `describable` interface by `(*Server).AuthStatus()` — ends with the
sentence that belongs on the wall of every installation using it: *"checks no password: whoever
reaches this port directly and sends the header is in, so keep the port closed"*.

### 1.3 The two HTTP login paths (must be reconciled)

There are two, and today they do not agree.

*The chain-aware path*, `authhttp.go`: `(*Server).LoginHandler(q *Request)` reads
`q.Param("unm")` / `q.Param("upwd")`; with either empty it calls
`s.showLoginPage(q, q.Param("redir"), false)`; otherwise it calls
`s.AuthenticateLogin(q.R, user, pass)` and on success `s.finishLogin(q, id)`. On failure it
branches `LoginBlocked(err)` → `s.loginDenied(q, LoginErrorMessage(err), …)` (429 plus
`Retry-After`), `IsAuthUnavailable(err)` → `s.loginUnavailable(q, …)` (503), else logs, calls
`FailBanLogFailure(s, user, ip)` and `s.showLoginPage(q, q.Param("redir"), true)`.

`(*Server).finishLogin(q *Request, id Identity)` is **the** place a login becomes a session: it
refuses an empty `id.Name` ("a back end accepted an empty user name"), sets `q.User`, calls
`s.ensurePwdUser(id.Name, id.FullName, id.Email, true, true)` with an unguessable generated
password when `s.Pwd != nil`, then `q.fillIdentity()`, `q.newSession()`, `s.logLoginOK(q, id)`
and `s.redirect(q, orText(q.Param("redir"), s.BasePath+"/"+q.Cfg.Group+"/"))`. `s.logLoginOK`
appends `" as " + id.Principal` when the principal differs from the name and
`" (local user record created)"` when `id.Created`.

*The legacy path*, `request.go`: `(*Server).login(q *Request)` — reached from
`(*Server).serve`'s logbook-independent switch (`case "login": s.login(q)`) and from
`(*Server).dispatch` through `case s.sameCommand(c, "Login")` — does, in essence,

```go
if !s.checkPassword(user, pass) { … }
```

`checkPassword` is the password file only: it never consults the chain, the throttle or the
ban, so `cmd=Login` today cannot log in an LDAP user. `(*Server).dispatch` also has
`case s.sameCommand(c, "Logout"): s.logout(q)`, while `authhttp.go` has the newer
`(*Server).LogoutHandler(q *Request)`; the two differ in that `LogoutHandler` uses
`s.LoginCookieName()`, `s.ClearLoginCookie(q.W, q.R)` and logs.

**Design requirement R1:** OIDC and certificate logins finish through `(*Server).finishLogin`,
never through `(*Server).login`, and the `Login` case in `dispatch` must route to
`s.LoginHandler` — the comment at the top of `authhttp.go` already describes this as "a one-line
redirect in each of three places". Until that line changes, an operator can pass LDAP and still
be refused by the legacy `cmd=Login` route; SSO would otherwise inherit and multiply that
divergence.

### 1.4 Sessions, cookies, source addresses

The pipeline is `(*Server).serve` → `q.decodePath()` → `q.parseParams()` → `q.authenticate()`
→ the two gates (`userAllowed`, `commandAllowed`) → `s.dispatch(q)`, with a small
logbook-independent switch (`logout`, `login`, `status`, `help`, `showSelectionPage`) taken
before the gates when `q.LB == nil`. `(*Server).serve` also handles
`q.rel == "/robots.txt"` and `favicon.ico` ahead of the gates, and `s.httpsRedirect(r)` ahead of
everything — the precedent for a session-less, logbook-less endpoint (§2.6).

`(*Request).authenticate()` resolves `q.User` in this order:

1. the session cookie (`q.R.Cookie(q.S.SessionCookie)` → `q.S.Sessions.Check(c.Value, ip)`,
   `ip` being `q.ClientIP()`);
2. HTTP Basic (`q.R.BasicAuth()` → `q.S.checkPassword`);
3. the `unm` / `upwd` parameters;
4. the `wpwd` logbook password against `Config.GetString(q.Cfg, "User password")` — **falling
   back to `q.User = "master"`** when the key is absent;
5. finally, the TLS client certificate:

   ```go
   if q.R.TLS != nil && len(q.R.TLS.PeerCertificates) > 0 {
           q.User = q.R.TLS.PeerCertificates[0].Subject.CommonName
           q.fillIdentity()
   }
   ```

   That last branch is §5's subject. It does not look at `q.R.TLS.VerifiedChains`, so with
   `SSL client auth = request` (which the code maps to `tls.VerifyClientCertIfGiven`) an
   *unverified*, attacker-chosen certificate yields a logged-in identity; it has no allowlist;
   it bypasses the chain, the throttle and the ban; it produces no audit line; and it is the
   **last** branch, so a request that merely *has* a certificate is logged in. The `master`
   fallback in branch 4 is the second thing a security review will ask about (§6.2 S-11).

* `(*Request).newSession()` calls `q.S.Sessions.New(q.User, q.ClientIP())` and sets the cookie
  with `Path: q.S.CookiePath()`, `HttpOnly: true`, `Secure: q.R.TLS != nil`,
  `SameSite: http.SameSiteLaxMode`. Note that `Secure` is **not** proxy aware, unlike
  `(*Server).LoginCookieSecure(r)` in `authext.go` (§8.1 R-4).
* `authext.go` holds the proxy-aware cookie half: `LoginCookieName()` (the configured
  `s.SessionCookie`, falling back to `"gologlsid"`; `request.go` also declares
  `const CookieName = "sessionid"` for elogd compatibility), `StartLoginSession(r, user, hostIP)`
  (documented: pass `q.ClientIP()` as `hostIP`, because the store ties a session to the address
  it was created from), `SetLoginCookie(w, r, value)` (`HttpOnly` always, `SameSite=Lax` always,
  `Secure` from `LoginCookieSecure`), `ClearLoginCookie(w, r)`, `Logout(r)`, and
  `hostOnlyOrAll(id)`, which keeps session ids out of the log because "session ids are bearer
  credentials".
* `trustedproxy.go` is the single authority for "whom do I blame, whom do I believe":
  `const defaultTrustedProxyList = "127.0.0.0/8, ::1/128"`, `ParseTrustedProxies` (CIDR, bare
  address, or a network-interface name), `ipInNets`, `hostOnly`, `trustedProxyNets(s)` cached
  per `*Server` keyed on the `*Config` and invalidated by `InvalidateTrustedProxyCache(s)`,
  `TrustedProxyList(s)` for display, and `(*Server).LoginSourceIP(r)` = the peer address,
  **unless** the peer is a trusted proxy, in which case the **leftmost** `X-Forwarded-For` (or
  RFC 7239 `for=`, or `X-Real-IP`). `proxyEntries` reads `Trusted proxy`, `Trusted proxies` and
  `Header trusted proxies`. Every SSO code path takes the client address from here and nowhere
  else.
* `LoginCookieSecure(r)` reads `X-Forwarded-Proto` / `Forwarded proto=` **only** when
  `s.IsTrustedProxy(r.RemoteAddr)`. That is the pattern for computing the SSO redirect URI
  behind a proxy (§2.7) and for deciding `Secure` (§8.1 R-4).
* `q.ClientIP()` is `clientIP(q.R, q.S.RealIP)`: the **peer** address, honouring
  `X-Forwarded-For` only when `Server.RealIP` (the `-f` flag) is on, because "trusting that
  header lets any client hijack somebody else's session". So the *session key* and the *guard
  key* are two different notions of "who" — see the note in §8.1.

### 1.5 Rights: unchanged by this design

`(*Server).userAllowed(q *Request, cmd string) bool` allows `login`, `logout`, `main`, `home`,
`help`, `status` and `""` for anybody, then `s.IsLogbookAllowed(q.Cfg.Group, q.User)`, then the
`Read-only` switch, then `s.commandClass(cmd)` → `s.userIn(q.Cfg, "Read"|"Edit"|"Delete"|"Admin",
q.User)`. `userIn` reads `"<Verb> users"`, then `"<Verb> allow"`, then `"<Verb> user"`;
absent or empty means everybody; a leading comma means "anonymous plus these"; `*` matches all.
`(*Server).commandAllowed` checks the logbook's `Allowed commands` list (compared case- and
space-insensitively through `sameCommand`, defaulting to `DefaultAllowedCommands`, with a
hardcoded set of internal commands always allowed). `(*Server).IsLogbookAllowed(logbook, user
string) bool` honours `Hidden` and the `Read` list; `(*Server).CanEdit(scope ConfigScope, user
string) bool` honours `Read-only` and the `Edit` list. `(*Server).CheckFormPassword(q *Request)`
is the per-logbook `wpwd` / `User password` check, compared with `constantTimeEqualString` and
counted against `formPasswordUser(q)` (the user name or `"(form-password)"`) in the same guards.

**Consequence, and the principle of this whole design:** SSO decides *who*, the logbook
configuration decides *what*. An OIDC group never grants or denies an entry, a submission or a
configuration edit directly — it becomes `Identity.Groups`, then `GroupsForUser`, then the
ordinary `<Verb> user` lists. No SSO back end may write a response, and no SSO back end may set
`q.User` itself; `finishLogin` does that.

---

## 2. OpenID Connect / OAuth 2.0 relying party

### 2.1 Standards profile — what is implemented and what is not

| feature | decision |
|---|---|
| OAuth 2.0 authorization code flow | **yes**, the only flow |
| PKCE (RFC 7636), `S256` | **yes, always**, even for a confidential client; Entra, Okta and Google recommend it and it removes the "code intercepted on a shared host" class |
| implicit flow (`response_type=id_token token`) | **no**, never: it puts tokens in the URL fragment and it is deprecated |
| ROPC (`grant_type=password`) | **no**; it would mean golog holding IdP passwords |
| `client_secret_post` / `client_secret_basic` | **yes**, chosen by `OIDC auth style` (`auto`/`basic`/`post`) |
| `private_key_jwt` client authentication | **no** in phase 1 (an extra key plus an extra assertion surface); revisit only for a site that cannot use a secret |
| refresh tokens | **optional, off by default** (§2.8) |
| RP-initiated logout (`end_session_endpoint`) | **yes**, phase 2 |
| back-channel logout (`logout_token`) | **yes**, phase 2 — a server-to-server POST, no browser, small amount of code, and the only way an IdP-side "revoke everybody" actually reaches golog |
| front-channel logout | no (an iframe plus an unbound GET; back-channel covers the same need with less surface) |
| JWT signature algorithms | an allow-list, default `RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512`; `none` and every MAC algorithm are refused in code, not by configuration (§2.4) |
| encrypted `id_token` (`enc=RSA1_5…`) | **no**; refuse an encrypted ID token with a clear log line rather than silently ignoring it |
| userinfo endpoint | **optional**, only when `OIDC use userinfo = 1`, and only to *add* claims to an already-validated `id_token` |
| hybrid flow | no |
| `form_post` response mode | **yes** (Entra and Keycloak answer this way when the request is large), so the callback must read `code`/`state`/`error` from the POST body as well as the query — `(*Request).parseParams` already folds the body into one table and `Param` lets the body win, which makes this a flag on the endpoint rather than new parsing |
| discovery (`/.well-known/openid-configuration`) | **yes**, with a cached document and static overrides |
| static/manual metadata (no discovery) | **yes**, `OIDC metadata file`, for an air-gapped IdP or a fixed JWK set |

golog is a **confidential client** (it has a secret and a server-side session) and an
**internal** client — the redirect URI set is operator-configured, not self-service. That
removes much of the multi-tenant confused-deputy surface; it does not remove the mix-up and
mix-in classes, which §6.3 handles.

### 2.2 The two pieces: a back end and a browser flow

OIDC is unusual in this code base because the credential is not typed into a golog form. It
therefore splits into two pieces that live in two different places:

1. **A browser flow** — new commands on the existing dispatcher: `cmd=OidcLogin` (start),
   `cmd=OidcCallback` (return), `cmd=OidcLogout`, plus a path endpoint `/OidcBackchannel`. These
   are HTTP handlers, not `Authenticator` implementations.
2. **An `Authenticator`** — `oidcAuthenticator` (**proposed**), registered with
   `registerAuthenticator(AuthOIDC, newOidcAuthenticator)`, where `AuthOIDC = "OIDC"` is a new
   canonical name (**proposed**) beside `AuthFile`/`AuthLDAP`/`AuthHeader`, and
   `authTypeAliases` gains `case "oidc", "openid", "openid connect", "oauth2", "azure", "entra": return AuthOIDC`.

Why keep an `Authenticator` at all if the token arrives on a callback URL? Three reasons, and
all three are why the design stays inside the existing seam:

* `NewAuthenticators` then lists OIDC in `AuthenticationSummary` and in
  `(*Server).AuthStatus()`, and `describable`/`AuthDescription()` can print the resolved issuer,
  client id and key-set age — exactly what an operator reads when "the button does nothing";
* the callback's token validation flows into the same `Identity` shape through the same
  `AuthContext` (with `RemoteIP` and `Req` set), so `AuthChain`'s unavailable-versus-refusal
  accounting applies to "the IdP is down" exactly as it does to "the directory is down", and
  `Authentication = OIDC` means what the operator typed;
* `NewAuthenticators`'s "file back end last" rule then applies to SSO automatically, which is
  what keeps the emergency account alive.

The important subtlety: **`Authenticate(ctx)` must not be reachable as a "log in with this
token" oracle from anywhere but the callback.** The back end accepts only an assertion that the
flow store says was issued for *this server, this browser and this in-flight flow* (§2.6).
Concretely, `AuthContext` gains one field, `SSO *SsoAssertion`, and
`oidcAuthenticator.Authenticate` returns `ErrUnknownUser` immediately when `ctx.SSO == nil` — so
a caller arriving from `cmd=Login` with a password is not answered by the OIDC back end, and
`AuthChain` moves on to the file back end just as it does today when the header back end finds
no header.

```go
// proposed, additive only; existing fields and behaviour unchanged
const AuthOIDC = "OIDC"   // beside AuthFile, AuthLDAP, AuthNTLM, AuthHeader, AuthExternal

type AuthContext struct { /* existing fields */ ; SSO *SsoAssertion }

type SsoAssertion struct {              // produced by the callback, consumed by Authenticate
        Provider     string             // provider name, for multi-provider (§2.14) and the log prefix
        IdToken      string             // raw; already validated once by the flow
        AccessToken  string             // may be empty; memory only
        RefreshToken string             // only when "OIDC refresh" is on
        Claims       map[string]any     // from the validated id_token (+ userinfo)
        Issuer       string
        Subject      string
        AuthTime     time.Time
        Expiry       time.Time
        Source       string             // "code" | "refresh" | "backchannel"
}
```

`SsoAssertion` is deliberately *not* an `Identity`: the mapping step (§2.5) stays inside the
back end, where `GroupsForUser` and `IdentityIsAdmin` are applied, so no code path can invent an
identity while skipping the normalisation.

### 2.3 Discovery, JWKS caching and rotation

**Discovery.** On first use (and after `ResetAuthenticators`), fetch `OIDC issuer` +
`/.well-known/openid-configuration`, unless `OIDC discovery url` overrides the path or
`OIDC metadata file` replaces the fetch entirely. Validate the document before using it:

* the returned `issuer` must equal `OIDC issuer` by exact string match under the OIDC §4.1.1
  trailing-slash rule — **not** prefix, **not** case-insensitive. This is the discovery-injection
  defence: an attacker who can write the discovery document still cannot point `jwks_uri` at his
  own keys and keep tokens that validate against a different `iss`;
* `authorization_endpoint`, `token_endpoint` and `jwks_uri` must be `https`, or loopback so the
  `httptest` fake IdP and a lab IdP work — never cleartext to a routable address;
* `id_token_signing_alg_values_supported` must intersect the configured allow-list, else the back
  end reports `AuthUnavailablef` at start-up rather than at the first login.

Cache the document the way `trustedProxyCache` does — a `sync.Map` keyed on the `*Server`, each
entry holding the `*Config` it was built from — so a configuration reload picks up a new issuer
without a restart. Re-fetch on a TTL (`OIDC metadata refresh`, default 24 h) and on a `kid` miss.
Log the resolved endpoints once per fetch: they are not secret and they are the first thing
needed in a support thread.

**JWKS.** Fetch `jwks_uri` into `oidcKeySet` (**proposed**), a `map[kid]` of parsed public keys
built from `encoding/json`, `encoding/base64.RawURLEncoding`, `math/big`, `crypto/rsa`,
`crypto/ecdsa` — no new module. Rules:

| rule | value / behaviour |
|---|---|
| refresh interval | `OIDC jwks refresh`, default 6 h |
| refresh on unknown `kid` | allowed but **rate-limited**: at most one fetch per `OIDC jwks refresh skew` (default 5 min) per issuer. Without the limit, one forged token per second with a random `kid` is a free DoS amplifier against the IdP |
| stale-while-revalidate | a failed refresh keeps serving the previous set for up to `OIDC jwks stale` (default 72 h) with a warning; after that the back end becomes `ErrAuthUnavailable`, so logins fail loudly instead of an old key being trusted forever |
| key retirement | a key works only while it is in the fetched set, so a retired key stops working at the next fetch. That *is* what rotation means here and must be documented: rotate the IdP's signing key before golog's stale window expires |
| algorithm binding | a key is used only with an algorithm in the allow-list **and** permitted by its type (an RSA key never verifies an ECDSA signature; `kty=oct` is refused outright) |
| `use` / `key_ops` | an entry whose `use` is not `sig` is ignored |
| size limits | the document is read through `io.LimitReader` up to `OIDC jwks max bytes` (default 256 KiB); a token part above `OIDC max token bytes` (default 16 KiB) is refused |
| TLS | verified against the system roots, or `OIDC ca file` for an internal CA (the same shape as `SSL client CA`). `OIDC proxy` is deliberately **not** supported in phase 1: an outbound proxy for IdP calls is a site policy decision, not a daemon decision |
| HTTP client | one `http.Client` per back end with `Timeout: OIDC http timeout` (default 10 s), closed by the `Close() error` that `ResetAuthenticators` already calls on chain members |

Every fetch (discovery, JWKS, token, userinfo) is bounded in size and follows at most
`OIDC max redirects` (default 3) — and the JWKS and discovery requests carry no credential,
because they are anonymous by specification.

### 2.4 ID-token validation — the exact list

`(*Server).validateOidcToken` (**proposed**, in `oidcproto.go`), run by the callback before an
`SsoAssertion` is built **and** re-asserted inside `oidcAuthenticator.Authenticate`, so a future
caller cannot skip it. Each step has its own log reason; the browser always gets the same generic
sentence. In order:

1. **Structure**: three dot-separated base64url segments; header and payload parse as JSON.
2. **`alg`**: present, in the allow-list, not `none`, not `HS*` (§6.3 T-4).
3. **`kid` → key**: present in the current set (else one rate-limited refresh, then refuse).
4. **Signature** over the exact ASCII `header.payload` bytes using the raw, undecoded segments —
   never a re-serialised form.
5. **`iss`** equals `OIDC issuer` exactly (or one of `OIDC issuer alt`, for a tenant migration).
6. **`aud`** contains `OIDC client id`; if `aud` has more than one value, `azp` (or
   `authorized_party`) must equal it — otherwise a token minted for another application in the
   same tenant is accepted. `OIDC audience` can require an additional audience.
7. **`exp`**, **`nbf`**, **`iat`** with `OIDC clock skew` (default 120 s, hard cap 300 s); an
   `exp` before `iat` is refused.
8. **`nonce`** equals the flow record's nonce; a token without `nonce` when one was sent is
   refused.
9. **`at_hash`**: when an access token is present, the left half of `SHA-256(access_token)` in
   base64url must equal it. This is what binds the access token to the ID token.
10. **`auth_time`** / `acr` / `amr`: optionally required, and optionally bounded by
    `OIDC max auth age` for sites that want "must have re-authenticated within N hours".
11. **`sub`** non-empty and ≤ 255 characters; `OIDC require email = 1` additionally requires
    `email`.
12. Anything after this point is policy — claim mapping, §2.5 — not validation.

`OIDC clock skew` is a first-class key because real failures are clock failures: an Entra token
rejected on a host whose clock drifted three minutes reads as "SSO is broken". The 120 s default
matches mainstream RPs; the cap exists so nobody sets 3600 and turns `exp` into decoration.

### 2.5 Claim and group mapping to golog users and logbook access

Mapping is a pure function, `mapOidcIdentity` (**proposed**), so it is unit-testable without a
network. It deliberately mirrors `readHeaderOptions`/`normalise` so the two "asserted identity"
paths — proxy header, IdP claim — behave alike.

| `Identity` field | source, first non-empty wins | key |
|---|---|---|
| `Name` | `preferred_username`, `upn`, `email`, `sub` | `OIDC claim user` |
| `FullName` | `name` | `OIDC claim fullname` |
| `Email` | `email` | `OIDC claim email` |
| `Groups` | `groups`; a scalar string counts as a one-element list; a dotted path (`resource_access.golog.roles`) is resolved through the claim tree, which is how Keycloak client roles arrive | `OIDC claim groups` |
| `Principal` | `iss` + `\|` + `sub` — never displayed; used by `logLoginOK`'s `" as "` branch and by the link file | fixed |
| `AuthType` | `strings.ToLower(AuthOIDC)` → `via oidc` in the audit line | fixed |
| `Admin` | matched against `Groups` | `OIDC admin group` |
| `Created` | from `s.ensurePwdUser(...)` | `OIDC create user` |

Then the two existing rights helpers take over, unchanged:

* `id.Groups = s.GroupsForUser(id.Name, id.Groups)` — the **single** place the configuration's
  `Group map` (`GroupA = jdoe, jsmith; GroupB = *@corp.example`) joins the IdP's groups. A site
  can keep group membership in `elogd.cfg`, in the IdP, or in both, and no new concept appears.
* `id.Admin = s.IdentityIsAdmin(id)` — so `Super admin group` works for OIDC exactly as for LDAP.
  `OIDC admin group` only sets the back end's `Admin` flag, the same job `Header admin group`
  does.
* Login gating: `OIDC login group` is required and checked like `Header login group` (through
  `headerHasGroup`, which already does exact / first-RDN / after-`\` matching), refused with
  `ErrUnknownUser` — counted by the guards, no detail to the browser.
* Normalisation keys copied from the header back end so operators learn one set of rules:
  `OIDC strip domain` (default **false** — unlike `CORP\jdoe`, an IdP's UPN domain is often
  meaningful), `OIDC lowercase user` (default **true**, because Entra returns
  `preferred_username` with inconsistent case and `jdoe`/`JDOE` must not become two identities —
  precisely the concern `Identity.Name`'s own doc comment raises), and `OIDC max length`
  (default 256, floor 16 — the value lands in a log line, a session record and the password
  file, which is the same reasoning behind `Header max length`).

**Group filtering.** Entra can return 200+ groups, and past its claim limit it returns
`_claim_names`/`_sources` pointing at a URL instead of the list. Design: match
`OIDC login group`/`OIDC admin group` **before** any truncation; refuse the over-limit form with
a log line that names the fix (a filtered groups claim, an optional claim, or app-role
assignment); cap the stored list at `OIDC max groups` (default 256) and log the capping.
`Identity.Groups` is what a session carries, so an unbounded list is a per-session memory problem
as well as a log problem.

**Logbook access: no new mechanism.** A group is not a logbook right. `Read user`, `Edit user`,
`Delete user`, `Admin user` (through `(*Server).userIn`) and `Hidden` plus the `Read` list
(through `(*Server).IsLogbookAllowed`) stay exactly as they are. If a site insists on
group-based logbook ACLs, that is a *different* feature — `Read group`/`Edit group` keys read by
`userIn`, which changes the ACL model for every back end — and is deliberately out of scope;
§9 Q3 asks whether the human wants it scheduled.

### 2.6 The browser flow: state, nonce, PKCE, CSRF

New commands, handled where the existing ones are: in `(*Server).serve`'s logbook-independent
switch (the one that already handles `logout`, `login`, `status`, `help` before any gate) and,
for the logbook-scoped form, in `(*Server).dispatch` through `s.sameCommand` so translated
command names keep working:

```
cmd=OidcLogin[&p=<provider>]   start: build the authorization URL, 302 to the IdP
cmd=OidcCallback               return: state check, code exchange, validation, finishLogin
cmd=OidcLogout                 RP-initiated logout (§2.9)
/OidcBackchannel               back-channel logout: a path, not a cmd — a server-to-server
                               POST form with no session and no logbook context
```

Two gates must be told about the new names or the button fails confusingly:
`(*Server).userAllowed` (which today allows `login`, `logout`, `main`, `home`, `help`, `status`
and `""` for anybody) and `(*Server).commandAllowed`, whose internal-command set is always
allowed while everything else needs a place in `Allowed commands`. **`OidcLogin`,
`OidcCallback` and `OidcLogout` must be added to both**, and the back-channel endpoint must be
routed before logbook resolution — the `q.rel == "/robots.txt"` early-out in `(*Server).serve`
is the precedent. Otherwise a logbook with a short `Allowed commands` list answers its own SSO
button with *"Command OidcLogin is not allowed"*, which would be the most likely "SSO does not
work here" bug.

**Start (`cmd=OidcLogin`).**

1. Refuse unless the provider is configured and usable (`AuthUnavailablef` → the 503 page via
   `loginUnavailable`, rather than a redirect to an IdP that will reject it).
2. If `q.User != ""` (a session already exists), do **not** silently re-map the identity: show
   "you are already signed in as X" (the session-fixation variant S-2, §6.2).
3. Generate 32 random bytes each for `state`, `nonce` and `verifier` with `randomHex`
   (`rand.go`), the package's existing CSPRNG helper.
4. `challenge = base64url(SHA256(verifier))`, `code_challenge_method=S256`.
5. Record the flow in `oidcFlowStore` (**proposed**):
   `{state, nonce, verifier, provider, target, created, boundIP, used}`; TTL
   `OIDC flow ttl` (default 5 min), capped at `OIDC flow max` (default 10 000 entries), swept on
   access and on the same ticker that refreshes the key set, guarded by a mutex the way
   `SessionStore` is.
6. Build the URL: `response_type=code`, `client_id`, `redirect_uri` (§2.7), `scope`
   (`openid profile email groups` by default; `offline_access` only with `OIDC refresh`),
   `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`; `prompt` accepted from the
   request **only** if it is one of `none|consent|login|select_account`; `login_hint` from
   configuration only, never from an unvalidated query parameter (§6.2 S-6); vendor extras
   (`domain_hint`, `acr_values`, `kc_idp_hint`) from the repeatable `OIDC extra param`.
7. `302` with `Cache-Control: no-store`.

**Nothing about the flow goes into a cookie.** The state → (nonce, verifier, target) map is
server-side. That is a deliberate departure from the oauth2-proxy/library habit of encoding state
in an `oauth_state` cookie, and it is worth the small extra code because (i) it removes the
"attacker plants a state cookie whose flow he can complete himself" fixation variant entirely,
(ii) it works when the browser sends no cookies across the redirect, and (iii) no secret appears
in a `Set-Cookie` header that a front-end access log may record. The cost is a bounded in-memory
table — the same category of state the daemon already keeps in `SessionStore`.

**Callback (`cmd=OidcCallback`).** In this order; the order is part of the security.

1. `error` in the request → log the `error` code only (never `error_description`, which can carry
   a URI or a token), render the SSO failure page with the local login link. Never redirect
   onward from here.
2. `state`: present, ≤ 512 bytes, hex-shaped; look it up. Unknown, expired or already `used` →
   refuse. **Mark it used atomically before any network call**, so a callback URL fetched twice
   (browser prefetch, antivirus link scanner, user pressing Back) cannot spend the code twice —
   which is also what makes code-replay detection meaningful (T-2).
3. Bind the attempt to the browser: compare `boundIP` with `q.ClientIP()` — the same value the
   session will be keyed on, so a flow cannot succeed and then hand out a session the browser
   cannot use. `OIDC bind flow ip` turns the check off where the two requests legitimately arrive
   from different addresses (§9 Q5).
4. Re-check the recorded target against §2.7's rules (it was checked at start; the configuration
   may have changed since).
5. Exchange the code at `token_endpoint`: `grant_type=authorization_code`, `code`,
   `redirect_uri` (byte-identical to the authorization request), `client_id`, `code_verifier`,
   plus client authentication per `OIDC auth style`. HTTPS-or-loopback only, no redirect
   following, and the `Authorization` header is sent only to that endpoint's own host. The tokens
   in the response are never logged, never placed in a URL, never written to disk: they live only
   in memory (`SsoAssertion`, then `ssoSessionStore`).
6. Check the token response's own `iss` (when present) against the configured issuer — the
   mix-up defence (§6.3 T-9).
7. Validate the `id_token` (§2.4), including the nonce against the flow record.
8. Verify `at_hash` if an access token came back.
9. Optionally call `userinfo_endpoint` (`OIDC use userinfo`), merge claims with the `id_token`
   winning, and require its `sub` to equal the `id_token`'s.
10. Resolve the user name from the validated claims, then
    `id, err := s.AuthenticateLogin(q.R, name, "")` with `ctx.SSO` set. One call gives the SSO
    path, for free, the guard pre-check, the chain order (so a site may put `File` first for one
    emergency account), the throttle/ban bookkeeping and the standard `login ok … via oidc` audit
    line. `AuthenticateLogin`'s empty-name check is precisely why the name must already come from
    validated claims.
11. Success → `finishLogin` has set `q.User`, refreshed the identity, issued a **new** session and
    redirected to the recorded target. Attach the SSO state to the new session id in
    `ssoSessionStore` (§2.8).
12. Failure → the same generic page `LoginHandler` would produce (`LoginHTTPStatus`,
    `LoginErrorMessage`, `Retry-After` when blocked), and **no** target preserved: a failure page
    must not be a redirect oracle.

**CSRF summary.** Three independent bindings: a single-use server-side `state` compared before any
network I/O; a `nonce` inside the token, so a token minted for another flow cannot be replayed
into this one; and the code → (`redirect_uri`, `code_verifier`) binding the IdP enforces. The
login form keeps whatever CSRF posture it has today; SSO does not weaken it, and §6.2 S-4 records
the one new consideration — the callback is a state-changing request triggered by a third party,
which is exactly what `state` is for.

### 2.7 Redirect URIs, `BasePath` and the reverse proxy

The redirect URI is computed once at configuration time and compared exactly; it is never derived
from a request header unless explicitly told to be.

* `OIDC redirect uri` (**proposed**, recommended, repeatable): an absolute URL, e.g.
  `https://logbooks.corp.example/golog/cmd=OidcCallback`. When set it is used verbatim in both the
  authorization request and the token exchange — the two must be byte-identical or the IdP refuses
  the exchange. Several values are allowed (`http://127.0.0.1:PORT/…` for tests, a second hostname
  for a site with two names).
* `OIDC external url`: the externally visible `scheme://host[:port][/base]`, used only to
  *construct* a redirect URI when `OIDC redirect uri` is absent. Behind a TLS-terminating proxy
  this is the key the operator has to set; without it golog would build
  `http://127.0.0.1:8080/…` from its own socket and be rejected by the IdP — a confusing failure
  the start-up log must name. Fallback order, logged at start-up: `OIDC redirect uri` →
  `OIDC external url` → `https://` + `Host` when `(*Server).LoginCookieSecure(r)` is true (TLS, or
  a trusted proxy said `proto=https`) → refuse to start that provider with an error naming the key
  to set.
* `X-Forwarded-Host` is never used for a redirect URI from an untrusted peer, and only when
  `OIDC trust forwarded host = 1` even from a trusted one. `X-Forwarded-Proto` is read only
  through `LoginCookieSecure`, which already requires `s.IsTrustedProxy`.
* `BasePath` (`s.BasePath`, used by `decodePath`, `CookiePath` and the `finishLogin` redirect) is
  honoured: the callback URL is emitted and matched after the same
  `TrimPrefix(p, s.BasePath)` handling `decodePath` uses, so golog under `/golog` and golog at `/`
  both work. `CookiePath()` must be right too, or the session cookie lands on a path the browser
  will not send back.
* `state` (and the provider selector `p`) ride on the query string. No user identifier rides in the
  callback path.

**The open-redirect rule**, stated once and implemented once as
`safeSsoTarget(s *Server, raw string) string` (**proposed**, unit-testable on its own):

1. The target is only ever what the flow record stored; the callback never reads it from the
   request.
2. At start, accept (a) `""` → the default `s.BasePath + "/" + q.Cfg.Group + "/"`, exactly what
   `finishLogin` already defaults to; (b) a path beginning with `s.BasePath + "/"` containing no
   `//`, no `\`, no CR/LF, no `@` before the first `/` and no scheme; (c) an absolute URL whose
   origin equals `OIDC external url`'s or one listed in `OIDC allowed target` (repeatable, exact
   origin match, for multi-hostname sites).
3. Anything else → drop it, use the default, log at verbose level. Never bounce the user to the
   rejected value: reject-and-default is what makes the class unexploitable instead of "mostly
   safe".
4. `s.redirect(q, location)` stays the only emitter (it is what `finishLogin` uses) and must keep
   refusing CR/LF in a location.

`cmd=Login`'s existing `redir` parameter has the same problem today:
`showLoginPage(q, q.Param("redir"), …)` and `finishLogin`'s `orText(q.Param("redir"), …)` pass it
through unchecked. **R2: apply `safeSsoTarget` to `redir` too** — same predicate, one call site
each — which closes an existing open redirect in the local login path. It is a security fix rather
than an SSO feature, so §7.6 lists it in the migration table and §9 Q1 asks for it explicitly, so
that it is not dropped if SSO is cut.

### 2.8 Session lifetime, refresh, and what the session holds

golog's session model is unchanged: `SessionStore` maps a random id to
`{user, hostIP, expiry, touched, lastPage}` with `NewSessionStore(expiryHours float64)`,
`New(user, ip)`, `Check(id, hostIP)` (which rejects an id presented from a different address and
honours the expiry), `Remove(id)` and `Count()`, and `q.newSession()` issues the cookie. SSO adds
a *parallel* small store, because `SessionStore` has no room for tokens and inventing one would
change the shape of every user's session record:

```go
// proposed
type ssoSessionState struct {
        provider, subject, issuer string    // for the audit line and for logout
        idToken, refreshToken     string    // memory only; never logged, never persisted
        expiry                    time.Time
        groups                    []string  // as last asserted, for a later revalidation
        lastCheck                 time.Time
}
// ssoSessionStore is keyed by SHA-256(session id), not by the session id itself
```

Lifetime rules, spelled out because "how long am I signed in" is the first question users ask:

* **The session lifetime stays what the daemon already enforces** — `Login expiration` →
  `NewSessionStore(expiryHours)`, which `(*Server).setupAuth` wires (the same place that computes
  `SessionCookie` from `Password file cookie`). SSO never lengthens it. `OIDC session max age` can
  only **shorten** it per provider: the effective expiry is
  `min(store expiry, OIDC session max age)`.
* **No silent background refresh by default** (`OIDC refresh = 0`). The IdP's `exp` then governs
  only the initial assertion; when the golog session expires the user goes through
  `cmd=OidcLogin` again, and a live IdP session turns that into a silent 302 round trip — no
  prompt, no password. That is how most internal RPs behave, it needs no refresh-token storage,
  and it removes the "long-lived secret in memory" problem completely.
* `OIDC refresh = 1` for sites that must call the IdP, or that need revocation to bite in minutes:
  keep the token in `ssoSessionStore`, refresh when `expiry - now < OIDC refresh skew`
  (default 60 s) **at the moment the session is used** (no goroutine per session), single-flight
  per session, and a failed refresh must **not** end the golog session — log and let it expire
  normally, because an IdP outage must not be a mass logout. This is the same principle that keeps
  `ErrAuthUnavailable` out of the throttle.
* **Revalidation** (`OIDC revalidate`, default off): a `prompt=none` check every N minutes.
  Deferred — a `prompt=none` round trip involves the user's browser and its own redirect chain,
  and deserves a page of its own design rather than being smuggled in.
* **No new idle timer**: `SessionStore` already tracks `touched`, and `fillIdentity` stamps
  `PwdUser.TouchActivity` and honours `Inactive`. A second idle notion beside those two would give
  two answers to one question.
* **Back-channel logout** looks sessions up by `iss`+`sub` and calls `s.Sessions.Remove(id)` plus
  the `ssoSessionStore` drop. It is the only mechanism that makes an IdP-side revoke bite before
  expiry.

### 2.9 Logout

Four kinds; this design does the first two and one of the two "IdP-side" kinds.

1. **Local logout (exists).** `cmd=Logout` → `(*Server).LogoutHandler(q)` → `s.Sessions.Remove`
   plus `s.ClearLoginCookie`. For an SSO user this must also drop the `ssoSessionStore` entry (one
   line in `LogoutHandler` and in `(*Server).Logout(r)`), or the token outlives the session it
   belonged to.
2. **RP-initiated logout (phase 2).** `cmd=OidcLogout`: local logout **first**, then 302 to
   `end_session_endpoint` with `id_token_hint` from `ssoSessionStore` (omit the hint when there is
   none), `state` from a short single-use record like the flow store, and
   `post_logout_redirect_uri` taken from `OIDC post logout uri` — exact match against a configured
   value, never from a request parameter. If the provider publishes no `end_session_endpoint`,
   render a page that says plainly "golog has ended your session; your single sign-on session at
   `<issuer>` is still active", with `OIDC issuer logout url`. Saying that is better than
   pretending. `OIDC logout confirm = 1` puts a "really log out?" page in front, cheap insurance
   against a prefetched or hotlinked logout link ending a session (§6.4).
3. **Back-channel logout (phase 2).** `POST /OidcBackchannel`,
   `application/x-www-form-urlencoded`, `logout_token`. Validated as an ID token by the same §2.4
   machinery with these additions: `events` contains
   `http://schemas.openid.net/event/backchannel-logout`; **`nonce` must be absent** (its presence
   means this is not a back-channel token); `iss` and `sub` match a session golog actually has;
   `iat` within skew; signature from that provider's keys. Reply `200` with
   `Cache-Control: no-store`, or `400 invalid_logout_token` with no detail. Rate-limited per source
   address rather than per user name (there is no user name), and each accepted token ends exactly
   the sessions of that `iss`+`sub` — never a wildcard.
4. **Front-channel logout: not implemented.** An iframe plus a GET is a CSRF-shaped request with
   no `state` and no binding; back-channel covers the same operational need with less surface.

`logout_token` verification is strict for one specific reason: it is an unauthenticated POST to a
URL that can end sessions, i.e. a denial-of-service primitive if validation is loose.

### 2.10 Coexistence with the file/LDAP login page

`SSO mode` (**proposed**), global:

| value | behaviour |
|---|---|
| `off` (default) | today's page exactly; no button; no OIDC back end is built |
| `button` | today's page **plus** one button per provider above the user/password form, with an optional one-line hint. The form keeps working, which is what keeps the always-appended `File` emergency account usable |
| `forced` | an unauthenticated request for a protected page 302s to `cmd=OidcLogin` instead of showing the form. The form stays reachable at `cmd=Login&local=1` **only** if `SSO local login = 1`, and `SSO allow local user` narrows which names may use it — that is the break-glass path. `forced` must **not** intercept: `cmd=OidcCallback`, `/OidcBackchannel`, `cmd=Login&local=1`, machine commands (`Raw`, `XML`, `JSON`, `CSV`, `RSS`, `RSSfull`, `New entry`, `Post attachment` — they authenticate differently and are dispatched by `dispatch`, not by the browser), attachment URLs fetched by scripts or DAQ machines, `POST` submissions, `robots.txt`, `favicon.ico`, and any request that already carries a valid session cookie |
| hide the form once a user has used SSO | **not proposed**: cute, and a lockout generator. Recorded so that it is consciously excluded |

Rendering is a small change in `(*Server).showLoginPage` (`pages.go`): one
`<form method="post" action="…"><input type="hidden" name="cmd" value="OidcLogin">…` per provider,
above the existing form, whose `unm`/`upwd`/`redir` field names stay unchanged so `LoginHandler`,
the legacy `login` and any scripted login keep working. The menu's Login/Logout link needs no
change, because an SSO session *is* the ordinary session and the same "Logout" is the right link;
`SSO logout url` can point it at `cmd=OidcLogout`.

`LoginMethodInfo` / `WriteLoginMethod` (`authhttp.go`) gain one line per provider — issuer, client
id, key-set age, `SSO mode` — and `oidcAuthenticator.AuthDescription()` is where that text comes
from. Following the header back end's precedent it must also state what is *not* checked, e.g.
"refresh tokens not used; session length is set by Login expiration".

### 2.11 Account linking and automatic user creation

The problem: the same human is `jdoe` in the password file (with entries he authored) and
`Jdoe.Smith@corp.example` in Entra. Whichever name `mapOidcIdentity` picks decides whose old
entries he sees.

The code tries these in order:

1. **Direct name match.** The mapped `Name` exists in `s.Pwd` — via the existing case-insensitive
   lookup the header back end already uses (`pwdUserFold`) — so it is used, subject to
   `u.IsInactive()`: an expired account stays expired, because `fillIdentity` already blanks an
   inactive user and the SSO path must agree with it.
2. **Email match.** `s.Pwd.UserByEmail(claim email)` when `OIDC link by email = 1` (default 1) —
   and the log line says so, because linking on an address the IdP asserts is a real privilege
   transfer: if the IdP lets users edit their own unverified `email`, that is an
   account-takeover primitive. Hence the key exists, and hence the recommendation to pair it with
   `OIDC require email = 1` and, where the IdP can assert it, a verified flag.
3. **Stored subject link.** `OIDC link file = sso-links.txt` (**proposed**): lines of
   `iss|sub = localuser`, written on the first successful login of a new subject, consulted on
   every login, editable by an operator to repair a bad link. It survives a rename in the IdP and
   a change of normalisation rule. The syntax is one `key = value` per line, i.e. the same shape as
   a `Group map` entry, so it can also be inlined as repeatable `OIDC link = …` keys if the human
   would rather not add a file (§9 Q3).
4. **Create.** `OIDC create user = 1` (default, mirroring `Header create user`) →
   `s.ensurePwdUser(name, fullName, email, true, true)`, whose generated password is unguessable so
   the new record is not a second way in — existing `finishLogin` and header behaviour, not new.
   With `OIDC create user = 0` an unknown subject is refused with `ErrUnknownUser`, which is the
   posture a site with a curated user list wants.
5. **Never** merge or rename a password-file record automatically, and **never** let an SSO login
   set a usable local password. Switching to local authentication is a deliberate act by the user
   or an administrator on the existing user page.

`Identity.Created` comes from step 4, which is what makes `logLoginOK` print
`"(local user record created)"` — the audit feed for "who just appeared out of the IdP".

### 2.12 Audit trail and log lines

Reused verbatim, so existing fail2ban filters and log scrapers keep working:

| line | source |
|---|---|
| `golog auth: login ok for %s from %s via %s` | `AuthenticateLogin`; `logLoginOK` appends `" as <principal>"` and `" (local user record created)"` |
| `golog auth: login refused before any back end (%s)` | `loginBlocked` |
| `golog auth: %s not usable, trying the next method: %v` | `AuthChain.Authenticate` |
| the fail2ban audit line | `FailBanLogFailure` |
| the cookie/logout lines | `SetLoginCookie` (`secure cookie on login: yes`), `Logout` |

`via oidc` needs no schema change: `id.AuthType` is `strings.ToLower(AuthOIDC)`. New lines
(**proposed**), all prefixed `golog auth: oidc`, all single-line (`safeLine`, as `safeUserForLog`
does) and all secret-free:

```
golog auth: oidc[<provider>]: discovery ok issuer=%s auth=… token=… jwks=…
golog auth: oidc[<provider>]: key set reloaded: %d keys, next refresh %s
golog auth: oidc[<provider>]: key set refresh deferred (rate limit)
golog auth: oidc[<provider>]: flow started from %s
golog auth: oidc[<provider>]: callback refused: unknown or expired state from %s
golog auth: oidc[<provider>]: callback refused: state already used from %s
golog auth: oidc[<provider>]: token refused: %s            (= alg|kid|sig|iss|aud|exp|nonce|at_hash|sub)
golog auth: oidc[<provider>]: token endpoint refused client authentication for %s
golog auth: oidc[<provider>]: token endpoint error code=%s
golog auth: oidc[<provider>]: mapped %s -> %s (groups %d, admin %t, created %t)
golog auth: oidc[<provider>]: linked subject %s to local user %s by email; review if unexpected
golog auth: oidc[<provider>]: login refused for %s: not a member of %q
golog auth: oidc[<provider>]: groups claim over limit; configure a filtered groups claim
golog auth: oidc[<provider>]: back-channel logout ended %d session(s) for %s
golog auth: oidc[<provider>]: target %q rejected, using %q
```

**Never logged**, and §8.4 test 4 enforces it mechanically: `code`, `code_verifier`, `state`,
`nonce` — single-use authorisation secrets, and a logged code is a live code to anyone who can
read the log; `id_token`, `access_token`, `refresh_token` — bearer credentials, the reasoning
already in `hostOnlyOrAll`; client secrets; the raw `error_description` (it can contain a URI or a
token); the whole claim set (PII, and a group list can be huge); session ids (already handled by
`hostOnlyOrAll`). Logged instead: the reason token, the `iss`+`sub` pair (an opaque identifier, not
a secret, and the only stable audit join key — not the display name alone), the provider name, the
source address from `LoginSourceIP`, the group *count*, and booleans for admin and created.

### 2.13 Failure UX

One page, four sentences — the discipline `LoginErrorMessage` already imposes.

| situation | browser | log | status |
|---|---|---|---|
| IdP unreachable, discovery failed, key set stale, client authentication refused | "Login is not possible at the moment; please try again shortly." + the local login link | the endpoint and the error | 503 (`loginUnavailable` / `SendLoginFailure`) |
| token refused, for any reason | "Sign-in was not accepted." + local login link | the single reason token | 401 |
| throttled or banned | "Too many failed logins. Try again later." + `Retry-After` | `loginBlocked` | 429 |
| refused by group policy | "Sign-in was not accepted." | which group was required | 401 |
| state/flow problem | "Sign-in did not complete. Try again." + a link that starts a **fresh** flow (not the old target) | source address and reason | 401 |

The local login link is always offered in `button` mode, and in `forced` mode when
`SSO local login = 1`. With local login disabled the page offers only a retry and the issuer's own
status URL from configuration — and §6.5 item 5 explains why that combination should never be a
default. An operator must never be locked out by an IdP outage with no way back; that is the same
argument `NewAuthenticators` makes by always appending the file back end.

One existing wart to fix while touching this: `(*Server).SendLoginFailure` emits hardcoded
`href="/logbooks"` and `href="/login"` links. Under a `BasePath` those are wrong; the SSO failure
page must use `s.BasePath`, and the existing function should be corrected in the same pass.

### 2.14 More than one provider

Sites do have two (staff IdP plus a contractor IdP, or a migration between two). The chain is
already a list, so this is configuration rather than architecture:

* `Authentication = OIDC` → the single implicit provider, `OIDC …` keys.
* `Authentication = OIDC, OIDC` would be ambiguous, so the second form is
  **`OIDC providers = entra, okta`** (**proposed**) with each provider's keys prefixed
  `SSO <name> …` in `[global]` (`SSO okta issuer`, `SSO okta client id`, …). The flow record
  carries the provider name and the callback's `p` parameter is validated **against the record**,
  never used to select a provider before the record is found.
* Each provider gets its own `oidcAuthenticator`, so `AuthenticationSummary` would print
  `OIDC+OIDC+File`; each member's `Name()` therefore returns `OIDC[entra]`, which `AuthChain.Name()`
  concatenates without any change to it.
* Chain order is attempt order: the first provider whose flow completes wins, and the file back end
  is still appended last by `NewAuthenticators`.
* Cross-provider name collision (two `jdoe`s) is resolved by the `iss`+`sub` link file (§2.11) and,
  if the operator wants, `OIDC name prefix = entra-` — a blunt instrument that is offered because
  sites ask for it, with the warning written into the documentation that enabling it *after* the
  fact changes the Author field of everything a user posts.

---

## 3. SAML 2.0 service provider

### 3.1 The question, answered directly

**Is it worth building? No.** For every site that raises SAML, one of these is true: (a) the IdP
also speaks OIDC — Entra ID, Keycloak, Okta, Ping, Authentik, Gluu all do — so OIDC gets the same
users at a fraction of the risk; (b) the site already runs a SAML SP somewhere (Apache with
`mod_auth_mellon`, a Shibboleth SP, a commercial gateway) and asserting the name to golog through
the existing `Header` back end is two lines of that product's configuration; or (c) someone wants
SAML because "the institution requires SAML", which is a requirement on the institution's *other*
service providers, not on golog.

**Recommendation: do not build; delegate.** A SAML 2.0 Web SSO SP that is *correct* is 31+
person-days of security-critical code plus an external review (§3.6), and it needs either a new
module or a hand-rolled XML-DSig implementation — the one thing in this document that would make
`golog` a package other people must audit. The delegated path costs no code, and `authheader.go`
already implements the trust rules that matter (the peer-address test against `trustedProxyNets`,
the twice-sent-header refusal, length and control-character bounds, group gating through
`headerHasGroup`, the optional second factor through `fileBackedAuthenticator`,
`Header create user`) with the reasoning written into its comments.

### 3.2 If it is nevertheless required: the minimal profile

Recorded so that "we chose the minimal profile deliberately" is on paper.

| element | minimal choice |
|---|---|
| profiles | Web Browser SSO only; SLO and artifact resolution only if forced |
| bindings | incoming HTTP-POST (assertions) and HTTP-Redirect (logout); outgoing HTTP-Redirect with a deflated, base64 `SAMLRequest`, signed when the IdP demands it |
| name ID | `persistent` preferred, `emailAddress` accepted, `transient` refused for linking — a transient name can only be used per session, never as an account key |
| signing | **assertion** signature required, not merely a response signature; both verified when both are present; each signature must reference the element it is attached to |
| digest | per-reference digests verified; SHA-256/SHA-512 only, SHA-1 allowed only during a dated transition |
| canonicalization | **only** `http://www.w3.org/2001/10/xml-exc-c14n#` and `#WithComments` — the inclusive-versus-exclusive confusion is one of the two classic wrap enablers |
| signature algorithm | RSA-SHA1 (legacy), RSA-PSS, ECDSA-P256-SHA256; the enveloped-signature transform is **required** on every reference; the XSLT and XPath-additional-reference transforms are refused outright |
| conditions | `AudienceRestriction` must contain golog's entity ID; `SubjectConfirmationData` must carry `Recipient` equal to the exact ACS URL and `InResponseTo` equal to the request golog sent (when it sent one); `NotBefore`/`NotOnOrAfter` honoured with ≤ 120 s skew |
| replay | assertion `ID` cache, TTL = `NotOnOrAfter` + skew, per issuer |
| metadata | consume IdP metadata (entities descriptor, signing certificate(s), SSO endpoints); publish golog metadata (entity ID, ACS URL, SLO URL, our certificate). Certificate rotation follows the `certReloader` pattern in `tlsserve.go` |
| XML parsing | `encoding/xml` with a strict, allow-listed struct schema; DTDs refused; no `XInclude`; values read only from allow-listed positions. Go's parser does not resolve external entities, which is an argument *for* Go here — and not a licence to relax anything else |
| attribute mapping | the same `Identity` mapping as §2.5: `SAML claim user = NameID, uid, email`, groups from a named attribute, `SAML login group`, `SAML admin group`, `SAML create user` |
| size | `SAML max bytes` (default 256 KiB) on the **decompressed** document — an incoming deflated redirect is a decompression-bomb candidate |

### 3.3 The XML-signature risk, concretely

The recommendation is strong because the attack class is a property of the format, not a bug
someone might happen to avoid:

1. **Signature wrapping.** The signed element and the consumed element are different nodes; a
   verifier that asks "does this document contain a valid signature somewhere" accepts an
   attacker's unsigned assertion sitting next to a legitimately signed one. The variants that have
   failed repeatedly in the wild: verifying by reference URI alone (`#ID`), resolving `ID`
   attributes without requiring them to be declared `xs:ID` in the signed subtree, and verifying
   the *response* signature and then reading attributes from any *assertion* in the response.
2. **Transform trickery.** `Transforms` is attacker-controlled data *inside* the signed element; an
   XSLT transform can rewrite the document so that the signature is valid over the rewritten bytes.
   Comment and canonicalization variants (`#` versus `#WithComments`, inclusive versus exclusive
   with `xml:inherit`) change what is actually signed.
3. **Reference ambiguity.** Several `Reference` elements, or an empty `URI` meaning "the whole
   document", against a verifier that checks only the first.
4. **Namespace archaeology.** The `2000/09/xmldsig` versus `2001/04/xmldsig` families let an
   attacker build two parse trees that hash the same.
5. **`KeyInfo` trust.** Verifying with the key named *inside the assertion* instead of only with the
   key from that issuer's metadata turns any signing-capable third party into an identity issuer.
   This one is genuinely tempting in a code base that wants to be helpful about certificate
   rotation.
6. **Confirmation-data laxness.** Ignoring `Recipient` (an assertion minted for another SP's ACS URL
   works here — the mix-up attack, §6.3 T-9, in XML form), ignoring `InResponseTo` (unsolicited
   assertions become a phishing primitive), or skipping `NotOnOrAfter` "for compatibility with a
   certain IdP".
7. **Audience and name-ID confusion in multi-tenant IdPs**, including a `transient` name being
   treated as `persistent` and thereby becoming a permanent account link.

Nearly every published SAML vulnerability family of the last decade — in mainstream libraries, not
hobby code — is an instance of 1, 2, 5 or 6. The Go standard library has no XML-DSig support at
all: `encoding/xml` gives parsing and nothing else. So golog would be writing the most
security-sensitive component in the tree from scratch, in a package whose author is writing this
document.

### 3.4 Delegation options compared

| route | what the operator runs | what golog needs | trust boundary | verdict |
|---|---|---|---|---|
| **Apache + `mod_auth_mellon`** | Apache as the SAML SP in front of golog | nothing new: `Authentication = Header`, `Header user header = X-Remote-User`, `Header trusted proxies = <apache address>` | Apache must be the only route to golog's port, and must **set** (not append to) the header | **recommended for a SAML-only site**: mature, audited, one config file |
| **Shibboleth SP (`shibd`) + Apache/nginx** | the academic-federation SP daemon | the same `Header` keys; `Header groups header` for entitlements | same | **recommended for a university or federation site** — WAYF, discovery and entitlements are exactly what shibd does |
| **oauth2-proxy / Authelia / Authentik / a commercial gateway** | a proxy that is the SAML SP *and* an OIDC provider | `Authentication = OIDC` (§2), or `Header` | the proxy's own session cookie alongside golog's | **recommended where OIDC would also be acceptable**: one component, and golog gets the modern path |
| **Keycloak identity brokering** | Keycloak in front of the SAML IdP, exposing OIDC downstream | `Authentication = OIDC` | Keycloak → golog over loopback or a trusted proxy | best where Keycloak is already deployed |
| **native SAML SP in golog** | nothing extra | ≥ 31 days, a review, a new dependency or hand-rolled XML-DSig | the whole XML-DSig attack surface lands inside the daemon | **not recommended** |

One rule applies to every delegated route and `authheader.go` already enforces it: the front end
must **set** the assertion header and golog's port must be unreachable except from that front end,
because the header back end's own `AuthDescription` says what the consequence is. `Trusted proxy`
is the mechanism; a site that writes `0.0.0.0/0` there has not configured SSO, it has configured no
authentication (R6, §6.4).

### 3.5 What this design therefore says about SAML

* No SAML code in golog in any phase.
* `authheader.go`'s file header — which already explains the Kerberos decision — gains a paragraph,
  "SAML without writing SAML", with the three concrete recipes (mellon, shibd, Keycloak brokering →
  OIDC) and the header-stripping warning.
* If a hard requirement forces native SAML, it is a **separate design document** with its own threat
  model, and it must use a vetted library (Appendix A names the only semi-plausible candidate, its
  licence, and why it is still not recommended) rather than hand-rolled XML-DSig.

### 3.6 Effort if forced (for the record)

| item | person-days |
|---|---|
| metadata parse + publish, entity configuration | 3 |
| `AuthnRequest` build, HTTP-Redirect/deflate, `InResponseTo` store | 3 |
| ACS endpoint, strict response/assertion parse | 5 |
| XML-DSig verification (transforms, c14n, digests, key from metadata only) | 10 |
| conditions, subject confirmation, replay cache, name-ID policy | 3 |
| attribute → `Identity` mapping, JIT, tests against real IdP metadata | 3 |
| a signed / wrapped / forged-assertion test corpus | 4 |
| **total** | **31, plus an external review** |

---

## 4. Kerberos / SPNEGO ("Negotiate")

### 4.1 What the code already decided

`authheader.go`'s file header *is* the existing decision, and this design **confirms** it:

* `vendor/modules.txt` contains `github.com/go-ldap/ldap/v3` (plus `asn1-ber`, `google/uuid`),
  `golang.org/x/{net,sys,text}`, `golang.org/x/crypto` reduced to **`md4`** (LDAP simple-bind
  hashing), and `github.com/Azure/go-ntlmssp`. There is no Kerberos or GSS-API package.
* `github.com/Azure/go-ntlmssp` is a **client**-side NTLM implementation: it builds type 1 and type
  3 messages and consumes type 2. A server must issue the type 2 challenge and verify a type 3
  response against a stored password hash, which that package does not export. The one vendored
  authentication module is therefore not a shortcut to anything here.
* Writing SPNEGO means ASN.1/DER for `NegotiationToken` (`NegTokenInit`/`NegTokenResp`) and the
  mechanism OIDs, GSS-API per-message tokens (the Kerberos MIC keyed from the service ticket's
  session key, with the right key usage per enctype), keytab parsing, an `AS-REQ`/`TGS-REQ` client
  with pre-auth and enctype negotiation, and NTLM as a fallback mechanism — "several thousand lines
  of security-critical protocol code", the least reviewable path in the whole programme.

`authTypeAliases` folds `Negotiate`, `SPNEGO`, `KRB5`, `Kerberos`, `SSO`, `proxy` and `header` onto
`AuthHeader` so the operator who types the word he knows lands on the thing that works. That
mapping is a documented decision, not a stub, and it must stay behaviour-compatible — which is why
§8.4 test 5 asserts it as a behaviour under test.

### 4.2 Feasibility in pure Go, if it were attempted

| piece | pure-Go status | notes |
|---|---|---|
| `401` + `WWW-Authenticate: Negotiate`, reading `Authorization: Negotiate` | trivial | `net/http` gives it |
| the SPNEGO ASN.1 layer | doable, ~1500 lines | Go has `encoding/asn1` but no SPNEGO types anywhere in the tree |
| AP-REQ parsing, service-ticket decryption, keytab | **needs a module** | `github.com/jcmturner/gokrb5/v8` (Apache-2.0) is the only credible Go option; it is primarily a *client* library whose server-side service-ticket and AP-REQ paths exist but are far less exercised |
| replay cache | module plus own code | a correct replay cache is shared per service principal across processes; a purely in-memory one breaks the moment a second gologd instance runs behind a balancer, which is how a subtle double-hop bug is born |
| GSS-API message tokens / mutual authentication | module, thin | needed only if golog wanted an integrity-protected context rather than consuming one token |
| **PAC → groups** | module, partial, plus custom code | the MS-PAC blob carries SIDs and group membership; checking its logon-server signature needs the KRBTGT or the service key, and that library's PAC support is not a stable API. **The good design instead**: take the account name from the ticket, then get the groups the way `ldapauth.go`/`ldapconn.go` already do (bind and read `memberOf`) — Kerberos for the name, LDAP for the groups, reusing code that exists |
| **Windows / SSPI** | **no** | there is no keytab on Windows in practice: a Windows service must call SSPI (`AcceptSecurityContext`) to consume the ticket under the machine's credentials, i.e. `secur32.dll` calls through `golang.org/x/sys/windows`. Doable without cgo, but it is a second, Windows-only, hard-to-test implementation of the same protocol, and `windows/386` is a corner nobody exercises |
| Linux keytab | yes | the normal case: `/etc/golog/golog.keytab`, AES128/AES256-CTS-HMAC-SHA1-96, RC4-HMAC legacy |
| SPN and DNS rules | yes, manual | the SPN must match the hostname the browser used (`HTTP/logbooks.corp.example`); a CNAME, a hosts-file alias or a load-balancer hostname breaks it silently, and browsers differ about which hosts may send `Negotiate` at all |

### 4.3 What the trusted-header mode already covers, and what it cannot

**Covers** — and this is the arrangement production AD installations actually run, per the comment
block in `authheader.go`:

* IIS with Windows Authentication → `RequestHeader set X-Remote-User "%LOGON_USER%"`;
* Apache + `mod_auth_gssapi` (`mod_auth_kerb` is deprecated) →
  `RequestHeader set X-Remote-User "%{REMOTE_USER}s"`;
* nginx + a Kerberos auth module, or `auth_request` against an auth daemon →
  `proxy_set_header X-Remote-User $remote_user`.

golog then gets, and enforces, exactly §1.2: the peer-address test against `trustedProxyNets(s)`,
the twice-sent-header refusal, length and control-character bounds, `Header strip domain` for
`CORP\jdoe` and `jdoe@corp`, `Header login group` / `Header admin group`, the optional
`Header require password` second factor, and `Header create user`. Groups come from
`Header groups header` or from `Group map` through `GroupsForUser`.

**Cannot** cover:

1. **Verifying the credential per request.** With a proxy, golog trusts the proxy for every request;
   natively it would verify the ticket itself. The trust is transferred, not removed. The
   mitigation is the one the back end already shouts about: close the port, list only the proxy in
   `Trusted proxy`.
2. **Outbound or delegated authentication.** golog talks to no Kerberos service (its LDAP bind is a
   simple bind), so nothing here needs it. If a future feature needed to forward the caller's
   credentials, only the native path could.
3. **Per-request cost** — a native implementation validates a ticket on every request (or
   establishes and tracks a security context), while the proxy establishes the context once per
   connection. With HTTP keep-alives and golog's session cookie this is usually moot: one Negotiate
   per session.
4. **Everything that is browser-hostile stays browser-hostile either way**: `401` challenges are not
   sent cross-origin, the browser's intranet-zone list gates the whole feature, non-Windows browsers
   need their own configuration, and `Negotiate` only survives a front end that forwards
   `Authorization` untouched. Those operational facts are why many sites abandon `Negotiate`; they
   are not arguments against golog.
5. **Logout.** Kerberos has none, and neither does proxy mode. Say so in the documentation rather
   than promising an SSO logout that cannot exist.

### 4.4 Recommendation

**Do not implement native Kerberos/SPNEGO.** Lift the proxy recipe from `authheader.go`'s header
comment into the operator documentation, keep the `authTypeAliases` spellings pointing at
`AuthHeader`, and if a future requirement forces the native path:

* `github.com/jcmturner/gokrb5/v8` (Apache-2.0) — Appendix A;
* Linux and keytab only, **no** Windows SSPI path. That single constraint should decide it on its
  own: golog must cross-compile to `windows/386`, `windows/amd64` and `windows/arm64`, and "works on
  Linux, silently absent on Windows" is the worst possible property for an authentication method;
* name from the ticket, **groups from LDAP** by reusing `ldapauth.go`/`ldapconn.go` instead of
  parsing the PAC;
* every validation failure is `ErrAuthUnavailable` or `ErrUnknownUser`, never a detail to the
  browser;
* guard accounting from `LoginSourceIP`, with a documentation note that behind a load balancer that
  may be the balancer's address unless `Trusted proxy` names it;
* its own design document and its own review, like SAML.

### 4.5 A note on NTLM

`AuthNTLM = "NTLM"` exists as a canonical name and `github.com/Azure/go-ntlmssp` is vendored. The
same analysis applies: a server-side NTLM needs the NT hash of every account (which means
harvesting hashes into golog or calling a domain controller), and NTLM is being switched off by
every security team that can manage it. **No SSO work should extend it.** If the NTLM back end is
not actually implemented, `NewAuthenticators` should keep reporting the value as unknown and
skipped rather than pretending; §9 Q8 asks whether the human wants the name removed from the
selector with an explicit log line, which would be the honest move.

### 4.6 Effort if forced (for the record)

| item | person-days |
|---|---|
| SPNEGO layer (ASN.1 in/out, mechanism list, NTLM fallback negotiation) | 8 |
| AP-REQ / service ticket / keytab integration | 6 |
| replay cache, context cache, multi-instance behaviour | 4 |
| group acquisition by reusing the LDAP code, mapping to `Identity` | 4 |
| browser/SPN documentation and a real AD test rig | 5 |
| Windows: explicit "unsupported" (0) or an SSPI implementation (12) | 0 / 12 |
| **total, Linux only** | **27** |

---

## 5. Client-certificate login mapping

### 5.1 The current state, precisely

`(*Server).tlsSetup()` (`tlsserve.go`) builds the server's `tls.Config` from the global scope:
`SSL chain`, `SSL min version` (floor TLS 1.2, cannot be lowered), `SSL client CA`,
`SSL client CRL`, `SSL client CRL strict` (default on), `SSL client auth` =
`none|request|require` mapped to `tls.VerifyClientCertIfGiven` / `tls.RequireAndVerifyClientCert`,
plus `SSL HSTS`, `SSL redirect port` and `HTTP2 cleartext`. `readCertPool` reads a PEM bundle or a
directory (including OpenSSL hash links); `readCRLs` reads PEM or DER lists;
`crlSet.check(chain, now)` walks the chain comparing serial numbers against the CRL whose
`RawIssuer` matches the issuer's `RawSubject` and whose signature verifies, installed as
`cfg.VerifyConnection`; `certReloader` reloads certificates and CRLs on change (`watchCertificates`,
10 s poll) and `(*Server).ReloadTLS()` re-runs the whole setup. **The TLS layer is not the
problem** — it is a good, complete foundation, and revocation is enforced in the handshake.

The problem is the one-branch consumer in `(*Request).authenticate()`:

```go
if q.R.TLS != nil && len(q.R.TLS.PeerCertificates) > 0 {
        q.User = q.R.TLS.PeerCertificates[0].Subject.CommonName
        q.fillIdentity()
}
```

| defect | consequence |
|---|---|
| `VerifiedChains` is never consulted | with `SSL client auth = request` → `tls.VerifyClientCertIfGiven`, a certificate that failed path validation (unknown CA, expired, self-signed) still arrives in `PeerCertificates`, and `VerifiedChains` is empty for it. **Anyone who can reach the port with any self-signed certificate is any user.** |
| no policy beyond "the chain was accepted" | a corporate CA that issues client certificates to five thousand people, printers and service accounts grants golog login to all of them, and the logbook's `Read user`/`Edit user` lists are then matched against a string the client chose in its own CSR |
| no mapping rule at all | the identity is whatever `Subject.CommonName` says |
| bypasses `AuthChain`, `AuthenticateLogin`, the throttle, the ban and `logLoginOK` | no audit line; a brute-force probe against this path is invisible to fail2ban |
| it is the **last** branch in the function | a request that merely *has* a client certificate is logged in, even where a session, Basic or `wpwd` path was intended |
| `PeerCertificates[0]`, not the verified leaf | `[0]` is what the client chose to send first; the verified leaf is `VerifiedChains[0][0]` |

This is the one existing authentication shortcut that SSO work should close, and it is worth closing
**even if nothing else in this document is built** (§9 Q1).

### 5.2 Design: a `Cert` back end, policy-driven, opt-in

New canonical name `AuthCert = "Cert"` (**proposed**), registered the same way as the others
(`registerAuthenticator(AuthCert, newCertAuthenticator)` in the new file's `init()`), with
`authTypeAliases` gaining `case "cert", "certificate", "client cert", "clientcert", "x509":
return AuthCert`. It produces an `Identity` and nothing else; it never sets `q.User`.

A certificate is not something the user types, so the back end reads it from
`AuthContext.Req.TLS` — which is what `AuthContext.Req` is documented for — and, like the header
back end, abstains when there is no certificate so that `Authentication = Cert, File` still shows a
working login form. Two ways it is reached:

1. **Chain path** (`Authentication` names `Cert`): consulted by `(*Server).AuthenticateLogin`, i.e.
   from the login page. This is what makes the status page, `AuthDescription` and the guard
   bookkeeping work.
2. **Per-request path**: the `(*Request).authenticate()` branch is replaced by a call into the
   **same** matcher, then `q.newSession()` and `q.fillIdentity()` as today.

One function implements both, so the policy cannot diverge between them.

### 5.3 Matching policy

```
Cert login                    = 0     # master switch; see R3 — 0 REMOVES the CN branch
Cert match                    = san:email, dn      # which fields are considered, in order
Cert user pattern             = …                  # repeatable: the allow-list, table below
Cert ca file                  = …                  # optional subset of SSL client CA
Cert require verified chain   = 1     # present for diagnostics only; the code always
                                      # requires it, and = 0 logs a security-downgrade warning
Cert allow any EKU            = 0     # without this, a server or code-signing cert from the
                                      # same CA authenticates a user
Cert user claim               = san:email | san:upn | cn | dn-cn-local | literal:<name>
Cert strip domain             = 0
Cert lowercase user           = 1
Cert login group              =       # and Cert admin group
Cert groups from              = none  # ext:<oid> | ou | none
Cert max length               = 256
Cert create user              = 1
Cert conflict                 = keep  # keep | deny, when a certificate disagrees with the session
```

`Cert user pattern` is the allow-list, evaluated before any mapping, first match wins; no match ⇒
refusal, logged with the subject so the operator can add the right line:

| form | matches | note |
|---|---|---|
| `san:email=jdoe@corp.example` | an RFC 822 SAN, exact (case-insensitive) | the normal case |
| `san:upn=…` / `san:other:<oid>=…` | the UPN other-name or another other-name OID | AD user templates put the UPN here |
| `san:dns=…` | a DNS SAN | machine certificates, for a DAQ host that posts automatically |
| `dn=CN=jdoe,OU=Staff,DC=corp,DC=example` | the whole subject, DN-normalised (RFC 4514 value/order comparison, not raw bytes) | |
| `prefix=jdoe` | the *email local part*, never a substring — the same "no substring matching" rule `headerHasGroup` states for groups | maps `jdoe@corp.example` → `jdoe` |
| `dnregex=^CN=[a-z]+,OU=Staff,` | **offered but discouraged**; refused unless anchored | a regex against a DN is where subtle bypasses live |
| `oidc-sub=<sub>` | binds a certificate to one IdP subject, so a smart-card login can only produce the account that card belongs to | the answer to "our PKI also issues cards to contractors"; phase 2 |

`Identity.Name` then comes from `Cert user claim`, followed by `Cert strip domain`,
`Cert lowercase user` and `Cert max length` — the same normalisation vocabulary as
`readHeaderOptions`/`normalise`, so an operator keeps one mental model for "an asserted name"
whether it arrived from a proxy, an IdP or a certificate.

**Groups.** X.509 has no standard group extension, so `Cert groups from` defaults to `none` and group
decisions come from `Group map` via `s.GroupsForUser(name, nil)` and from `Super admin group` via
`s.IdentityIsAdmin(id)` — the "the credential supplies the identity, the configuration supplies the
groups" model `GroupsForUser`'s comment already describes. If a site's PKI really does carry group
OIDs, `ext:<oid>` reads a raw extension as an ASCII string list, with a documented warning that this
is a private convention.

**A certificate is accepted only when all of these hold:**

1. `q.R.TLS != nil` and `len(q.R.TLS.VerifiedChains) > 0` — the single most important line, and the
   one missing today;
2. the leaf is `VerifiedChains[0][0]`, not `PeerCertificates[0]`;
3. `Cert login = 1`;
4. the chain is permitted by `Cert ca file` when that key is set — a subset of `SSL client CA`, so a
   site can say "the whole corporate CA may authenticate to us, but only the staff sub-CA may log
   in";
5. the leaf is not expired *now* (a long-lived connection can outlive a certificate, and
   `tls.ConnectionState` is not re-evaluated mid-connection); the handshake's `VerifyConnection`
   already enforced `SSL client CRL` and the back end must not weaken it;
6. the leaf carries `id-kp-clientAuth` unless `Cert allow any EKU = 1`;
7. a `Cert user pattern` entry matches;
8. `Cert login group`, if set, is satisfied.

Refusals are `ErrBadPassword`/`ErrUnknownUser` — so they reach `(*Server).recordLoginFailure` and the
fail2ban line, because they travel through `AuthenticateLogin` — with the reason in the log only.
`ErrAuthUnavailable`, built with `AuthUnavailablef`, is reserved for "the configuration is
unusable" (`Cert login = 1` with no `SSL client CA`), mirroring how `headerAuthenticator` reports an
unusable header name.

### 5.4 Per-request identity, and the interaction with the session

`(*Request).authenticate()` runs before the gates, so with `SSL client auth = require` there are two
possible answers and the design picks one:

* **`Cert login = 1` (default)**: a verified, matched certificate *is* a login. The branch becomes:
  match → `q.User = name` → `q.newSession()` → `q.fillIdentity()`, plus — new — an audit line and
  the guard bookkeeping. This is what people expect from client certificates.
* **`Cert login = 2` ("assert only")**: the certificate must *agree* with an existing session
  (`q.User` from the cookie equals the mapped name) and is otherwise ignored — for a site that wants
  the certificate as a second factor for selected pages rather than as a login. Cheap after phase 1,
  not required in it.

Hard rules either way:

* if a session cookie resolves **and** the certificate maps to a *different* name, the certificate
  does not override the session; the mismatch is logged, and `Cert conflict = deny` refuses the
  request. Silent identity switching on an existing session is a session-fixation variant (§6.2
  S-9);
* a failed or unmatched certificate must **not** clear an existing session — the behaviour has to be
  specified, not discovered;
* `Secure` on the cookie comes from `(*Server).LoginCookieSecure(r)` rather than `q.R.TLS != nil`
  when the SSO work touches `newSession` (§8.1 R-4); a certificate login is by definition on a TLS
  connection, so that is a non-regression.

### 5.5 What must never happen here

* Never take `PeerCertificates[0].Subject.CommonName` as an identity without `VerifiedChains` and a
  configured pattern. That is today's behaviour and this design removes it. **R3**: with
  `Cert login = 0` (the default) the branch is *removed*, not preserved — a site that relied on the
  undocumented CN behaviour stops working and must set `Cert login = 1` plus at least one
  `Cert user pattern`. This is a deliberate, documented behavioural break, because keeping it means
  keeping a "any certificate is any user" path. It is announced at start-up (a log line when
  `SSL client auth` is set while `Cert login = 0`), listed in the migration table (§7.6), and needs
  the human's explicit approval (§9 Q1).
* Never log the public key or the DER blob. Log
  `subject=<RFC 4514> serial=<hex> sha256fp=<first 8 hex>`: enough to identify, small enough to
  grep, none of it secret.
* Never let a certificate imply `Admin`. "It has a certificate from our CA" is not an administrative
  credential; `Cert admin group` or `Super admin group` must say so.

---

## 6. Security analysis

The format is threat → answer, because that is what a reviewer can check. "Control" means either an
existing mechanism (named) or a design requirement (R-number), placed in a specific function so the
implementer cannot put it somewhere more convenient.

### 6.1 Threat model

| actor | can | cannot |
|---|---|---|
| **A1 anonymous network client** | reach golog's port (or the front end's), read any public logbook, send arbitrary headers, POST any form | read the log file, read server memory, break TLS |
| **A2 unprivileged authenticated user** | a valid session (password, LDAP, header or OIDC), read his logbooks, post entries | read a logbook he is not in, edit the configuration, mint tokens |
| **A3 attacker with a stolen session cookie** | present the cookie | use it from a different address (`SessionStore.Check`), or after the store forgot it |
| **A3′ attacker who can read the daemon's log** | read user names, subjects, addresses | find a token, a code, a nonce, a secret, a password |
| **A4 attacker who sees a URL** | browser history, a `Referer`, a front-end access log, an antivirus link scanner, a browser prefetch of a link on an error page | replay anything single-use |
| **A5 on-path attacker on the client↔front-end link** | read and modify cleartext, when TLS is terminated in front and the last hop is cleartext | break the TLS between the IdP and golog |
| **A6 malicious or misconfigured IdP — or an IdP the operator did not mean to trust** | mint tokens for any subject; control the discovery document and the JWKS it publishes | pass an `iss` that is not configured; pass an `aud` that is not configured |
| **A7 operator of the reverse proxy** | assert any name — that *is* the design | be invisible: the proxy's address appears in every auth log line |
| **A8 attacker with a valid-but-unrelated certificate** | present any certificate from any CA he can obtain | match a `Cert user pattern`; get through `VerifiedChains` against `SSL client CA` |
| **A9 the logbook's own users** | post text containing a URL an administrator will click | make the daemon fetch it (golog does not fetch links); an administrator can still be诱导ed to click a crafted `cmd=OidcLogin` link, which is why the flow is inert without its own state (§2.6) |

**Asset ranking.** (1) the integrity of the audit trail — the whole value of an ELOG logbook is "who
wrote this, when", so *identity confusion is the worst outcome this design can produce*; (2) read
confidentiality of restricted logbooks (`Hidden`, `Read user`); (3) availability of the daemon; (4)
the operator's own access — lockout is treated as a security failure throughout, which is why
`ErrAuthUnavailable` is never counted against a caller, why `NewAuthenticators` always appends the
file back end, and why `SSO local login` exists.

### 6.2 Session and browser threats

| id | threat | answer |
|---|---|---|
| **S-1** | **Session fixation** — attacker obtains a session id, plants it on the victim, waits for the victim to authenticate, then rides the authenticated id | The id is minted by `newSessionID()` server-side and returned only by `SessionStore.New`; nothing accepts a caller-supplied id, and `q.newSession()` **replaces** the cookie on every successful login rather than reusing the presented one. **R5**: the SSO callback must reach the session through `finishLogin` (so through `q.newSession()`) and must never adopt a session id that was present on the callback request; and if `q.User != ""` when `cmd=OidcLogin` starts, the flow must not silently re-map the identity (§2.6 start step 2) |
| **S-2** | Attacker starts a flow with *his* IdP account and tricks a victim into completing it, so the victim's browser ends up holding the attacker's session | `state`, `nonce` and PKCE make the attacker's token unusable in a flow the victim started; they do not stop the reverse direction. Answers: (a) `finishLogin` mints a **fresh** session, so there is no pre-existing id the attacker knows; (b) the flow record binds the source address from the moment of start; (c) with `SSO mode = button`, `OidcLogin` refuses when a session already exists. Residual risk (documented, not eliminated): the victim still has to complete at the IdP a login the attacker initiated, which shows the victim the attacker's own account name on the IdP's page |
| **S-3** | Cookie attributes: a session cookie set without `Secure` behind a TLS-terminating proxy is transmitted in cleartext to the browser | `SetLoginCookie` already derives `Secure` from `(*Server).LoginCookieSecure(r)`, which is proxy aware. `(*Request).newSession()` sets `Secure: q.R.TLS != nil`, which is not. **R-4**: make `newSession` use `LoginCookieSecure(r)`. Pre-existing, small, and made permanent by SSO, so it belongs in the same change |
| **S-4** | **CSRF on the callback** — the callback is by construction a state-changing request triggered by a third party | the single-use server-side `state` check, performed before any network I/O; an unknown or used state cannot create a session (§2.6 step 2). The login form's own CSRF posture is unchanged by this design |
| **S-5** | **Open redirect** through the login target | **R2**: `safeSsoTarget` (§2.7), applied to the SSO target *and* to the existing `redir` parameter that `showLoginPage`/`finishLogin` pass through unchecked today |
| **S-6** | Parameter injection into the IdP URL (`login_hint`, `prompt`, `scope`, `acr_values`) | §2.6 step 6: `prompt` from a fixed four-value allow-list, `login_hint` from configuration only, `scope` from configuration only, every value URL-encoded, no concatenation of a request parameter into the authorization URL |
| **S-7** | Token or secret leakage in URLs | no URL golog generates contains a token; the callback query carries `code` + `state`, which is precisely why both are single-use and short-lived (§6.4) |
| **S-8** | `X-Forwarded-Host` / `X-Forwarded-Proto` spoofing producing a wrong redirect URI or a wrong `Secure` flag | `LoginCookieSecure` reads the proto header only when `s.IsTrustedProxy(r.RemoteAddr)`; the redirect URI comes from configuration, not from a header (§2.7); `LoginSourceIP` reads forwarded headers only from a trusted peer and takes the **leftmost** entry, which is the documented rule in `trustedproxy.go` |
| **S-9** | A client certificate disagreeing with the session identity | §5.4: a certificate never overrides a resolved session; the mismatch is logged and `Cert conflict = deny` refuses |
| **S-10** | A session id reaching the log | `hostOnlyOrAll(id)` already replaces any id with `"presented session (id not logged)"` because "session ids are bearer credentials"; every new path must use it and must never interpolate `c.Value` |
| **S-11** | The `wpwd` branch of `(*Request).authenticate` grants the user name **`master`** when the logbook has no `User password`, and that branch has no guard bookkeeping (unlike `(*Server).CheckFormPassword`, which implements the same check *with* `formPasswordUser` accounting) | Out of SSO's scope, but any SSO review will find it, so it is recorded here. Recommendation: keep the behaviour for elogd compatibility, add `User password user` (**proposed**) so the implied name is not `master` by accident, and route the `authenticate` copy through the same accounting as `CheckFormPassword`. §9 Q6 |

### 6.3 Token and protocol threats

| id | threat | answer |
|---|---|---|
| **T-1** | Authorization-code interception (a malicious app on the device, a referrer, a proxy log) | PKCE `S256` binds the code to a verifier that never leaves the server; the exchange is server-to-server over TLS; the redirect URI is an exact configured match (§2.7) |
| **T-2** | **Code replay** — a scanner, a prefetch or an attacker replays the callback URL | the flow record is marked used atomically **before** the exchange, so the second presentation of the same `state` fails; the replayed code itself fails at the IdP (single-use, bound to `redirect_uri`, and to a verifier already spent); the log line is `state already used`, which an operator should treat as an incident signal rather than noise |
| **T-3** | **ID-token replay** — a token captured out of band, or valid for another flow | `nonce` is compared with the flow record, so a token minted for flow A is invalid in flow B; `aud`+`azp` bind it to this client; `exp`/`iat`/`auth_time` bound its life; and there is no path by which a token reaches `oidcAuthenticator.Authenticate` at all, because `ctx.SSO` is only ever constructed by the callback |
| **T-4** | **`alg=none` and algorithm confusion** (an `HS256` token signed with the public JWKS key as the secret) | the `alg` allow-list is applied *before* the key is looked up, and `none`/`HS*` are refused in code with no configuration able to re-enable them; a `kty=oct` JWKS entry is refused; a key is used only with an algorithm its own type supports (§2.4 steps 2–4) |
| **T-5** | Signature valid over one payload, a different payload consumed | the signature is verified over the raw ASCII `header.payload` bytes, never over a re-marshalled form. That is exactly how "valid signature, different claims" bugs are born, and §8.4 has a test named after it |
| **T-6** | **`iss` mismatch** — a token from another tenant or realm signed by a key golog happens to trust, or a discovery-injected document | exact `iss` match against `OIDC issuer` (OIDC §4.1.1 rules), plus the discovery document's own `issuer` must equal the configured one before anything from it is used (§2.3) |
| **T-7** | **Audience / cross-client confusion** — a token minted for another application in the same tenant | `aud` must contain the configured client id; a multi-valued `aud` requires `azp`/`authorized_party` to match; `OIDC audience` can require an additional audience |
| **T-8** | Expired / not-yet-valid tokens, and clock skew | `exp`, `nbf`, `iat` with `OIDC clock skew` (default 120 s, hard cap 300 s), `exp` before `iat` refused. The key exists so operators fix a real clock problem by tuning a number instead of disabling validation |
| **T-9** | **Mix-up attack** — a buggy or malicious IdP returns a code or token issued for a *different* client or issuer; or two configured providers share endpoints | (a) the token response's own `iss` is compared with the configured issuer; (b) `client_id` and `redirect_uri` are sent on every exchange and enforced by the IdP; (c) the flow record stores the provider name and the callback validates it **against the record**, never selecting a provider from the request; (d) with several providers each has its own `client_id`, its own key set and its own `oidcAuthenticator`, so a token from provider B cannot satisfy provider A's `iss`/`aud` checks. In SAML the equivalent attack is a missing `Recipient` check — which is one of the reasons §3 exists |
| **T-10** | **JWKS abuse** — a `kid` storm as a free DoS amplifier, or an oversized document | one rate-limited refresh per issuer per `OIDC jwks refresh skew`; `io.LimitReader` on the document and a size cap on the token; stale-while-revalidate bounded by `OIDC jwks stale`, after which the back end becomes unavailable rather than permissive |
| **T-11** | An access token not bound to the ID token it arrived with | `at_hash` verified when an access token is present; a userinfo response must carry the same `sub` as the `id_token` |
| **T-12** | Refresh-token theft | refresh is off by default (§2.8); when on, tokens are memory-only, never logged, never persisted, keyed by a hash of the session id, and dropped by `LogoutHandler`, `Logout` and back-channel logout |
| **T-13** | Back-channel logout abused as a session-killing DoS | strict `logout_token` validation (§2.9) including the *absence* of `nonce` and the required `events` claim; per-address rate limiting; only the sessions of the validated `iss`+`sub` end |
| **T-14** | Key/algorithm mismatch (an ECDSA public key used as RSA) | per-key-type verification dispatch (§2.3) |
| **T-15** | SAML signature wrapping | **not applicable, because SAML is not implemented.** The row is here so the document states that the risk was evaluated and removed by a decision, rather than mitigated by hope (§3.3) |
| **T-16** | Kerberos ticket forgery and replay | likewise not implemented natively; the delegated form moves that risk to `mod_auth_gssapi`/IIS plus the trusted-proxy rule (§4.3) |

### 6.4 Leakage, headers, and the guards

**Tokens and secrets in logs and URLs (A3′).** The rules, with a mechanical test behind them
(§8.4 test 4):

* Never logged: `code`, `code_verifier`, `state`, `nonce` (single-use authorisation secrets — a
  logged code is a live code); `id_token`, `access_token`, `refresh_token` (bearer credentials — the
  reasoning already behind `hostOnlyOrAll`); client secrets; `upwd` and `wpwd` (already true:
  `AuthContext.Password`'s comment says the package never logs it, and `dumpParams` masks
  `upwd`/`wpwd`/`password` on the status page); the IdP's `error_description`; whole claim sets;
  session ids.
* Logged instead: the reason token, `iss`+`sub`, the provider name, the source address from
  `LoginSourceIP`, the group *count*, booleans for admin and created.
* URLs: the only SSO URL golog emits that carries anything is the callback with `code&state`.
  `Cache-Control: no-store` on every SSO response and `Referrer-Policy: no-referrer` (**proposed**)
  on the SSO pages, so the callback URL cannot leak onward through `Referer`.
* If the hit log records query strings, strip `code`, `state`, `logout_token`, `id_token`, `upwd`
  and `wpwd` from the value before writing it — one function at the point where the line is built,
  not one per call site.

**Header spoofing.** Every assertion path in golog must satisfy: *either the peer is a trusted proxy,
or the value came out of a cryptographic token.* In detail:

* the header back end refuses a non-proxy peer outright **and logs it** ("… carried an asserted name
  that was ignored"), which is the correct verb: not "believed with a warning";
* `defaultTrustedProxyList` is loopback, and `ParseTrustedProxies` reports unusable entries rather
  than silently dropping them. Both existing, both worth preserving;
* **R6** (new): a start-up and status-page warning when an asserting back end (`Header`, `Cert`) is
  configured while `Trusted proxy` contains something wider than `/16` — and a loud one for
  `0.0.0.0/0`. Listing the internet as a proxy should not be reachable by an accident;
* the front end must **set** the identity header, not append to it. `readHeaderAsserted` refuses a
  header that appears twice, which only helps if the proxy overwrites — hence a documentation
  requirement on every recipe in §3.4 and §4.3;
* SSO adds no new code that reads an unauthenticated header. The redirect URI comes from
  configuration; the `Secure` decision comes from a trusted-proxy-gated read (§2.7, S-8).

**Interaction with the throttle and the ban.** The invariant: *an SSO login the user could have
succeeded at but did not is counted like a wrong password; an SSO login that failed because
infrastructure broke is not counted at all.*

| SSO outcome | counted? | why |
|---|---|---|
| unknown/used `state`; token refused (sig / iss / aud / exp / nonce / alg) | **yes** → `recordLoginFailure` | someone is presenting forged or replayed material at this server; ten times from one address should throttle, and `FailBan` should ban; `FailBanLogFailure` gives fail2ban its line |
| group policy refused (`OIDC login group`, `Header login group`, a `Cert user pattern` miss) | **yes** | it is a refusal about an identity, exactly like `ErrUnknownUser` from the header back end |
| IdP unreachable, discovery failed, key set stale, `invalid_client` at the token endpoint | **no** → `ErrAuthUnavailable` | otherwise a single IdP outage bans every user behind one office NAT address. This is the documented reason `ErrAuthUnavailable` exists at all |
| `loginBlocked` before the flow starts | already counted — `AuthenticateLogin`'s existing pre-check, reached because the callback calls `AuthenticateLogin` |
| successful SSO login | `recordLoginSuccess` (existing) |
| back-channel logout | **not** an authentication attempt; rate-limited separately |
| repeated `cmd=OidcLogin` with no session | not an attempt (it starts a flow), but bounded by `OIDC flow max` and a per-address start rate, so a client cannot fill the flow store. A memory DoS that can take down the login page is a lockout, and lockout is in scope (§6.1) |

Two guard notes: (i) the throttle keys on (user, address), so for SSO the "user" is the mapped name
once claims are known and `"(oidc)"` before that — the same trick `formPasswordUser` plays with
`"(form-password)"`; (ii) `LoginThrottleDelay(s)` sleeps inside `AuthenticateLogin` on the failure
path, so the callback inherits the sleep. That is desirable, but it means a slow IdP plus an active
throttle can hold a request goroutine, which deserves a sentence in the operator documentation.

**What the status page must show.** `LoginMethod().Chain`, `.Guards` and `.Proxies` already answer
"is SSO in the chain and who may assert". The SSO additions are issuer, client id, key-set age and
`SSO mode` — none of them secret — and never the client secret, which `AuthStatus`'s own doc comment
already promises ("Passwords are never included") and which the configuration page must not echo to
an administrator either.

### 6.5 Residual risks, named and accepted

1. **A trusted proxy is a root of trust.** Whoever can write the proxy's configuration, or spoof its
   address, is any user. Mitigated by `Trusted proxy`, the loopback default, R6 and "keep the port
   closed" — not eliminated. It is the trade every `REMOTE_USER` deployment makes, and the header
   back end's `AuthDescription` already says it out loud.
2. **An OIDC group is only as trustworthy as the IdP's administration.** A self-service group is a
   self-service grant of whatever it maps to. Documentation requirement: map only groups the operator
   knows are administrator-managed, and prefer `Group map` and the `<Verb> user` lists for anything
   sensitive.
3. **Session ids are bearer credentials inside one address.** `SessionStore.Check` binds a session to
   an address, which stops casual cookie theft but not an attacker behind the same corporate NAT.
   Pre-existing property; unchanged here; the fix (user-agent hashing or a per-session JS token) is a
   separate change (§9 Q9).
4. **An attacker who can read the log** still sees names, subjects and addresses. The rules above keep
   credentials out of it, not activity.
5. **`forced` mode is an availability risk.** With `SSO mode = forced` and `SSO local login = 0`, an
   IdP outage means nobody logs in. Never a default, warned about at start-up, and the
   `cmd=Login&local=1` break-glass URL must appear in the documentation with the emergency account
   named in it.
6. **Multiple gologd instances behind a balancer** need sticky sessions while the flow store is in
   memory (§9 Q5).
7. **`AuthDescription` is honest, which is a feature with a cost**: the status page tells an
   authenticated administrator which header is trusted and which proxies are believed. That is
   information an attacker would like. It is kept because `AuthStatus` exists precisely so a human
   can debug a login, and the pages behind it are already administrator-gated by `userAllowed`'s Admin
   class — but it is worth a conscious yes (§9 Q11).

---

## 7. Configuration surface

### 7.1 Rules the new keys must follow (all inherited from the existing parser)

* All SSO keys live in **`[global]`**. Authentication is process-wide in this code base —
  `AuthContext`'s scope is the global scope — and a per-logbook SSO switch would create "log in to
  logbook A and you are logged in to B". The single non-global key is the opt-out
  `SSO required = 0` (§7.5).
* Keys are ASCII case-insensitive, values are trimmed, lists are comma-separated
  (`Config.SplitList`), booleans accept `1/0/yes/no/true/false/on/off`
  (`Config.GetFlag`/`GetFlagDefault`), and durations use Go duration strings (`5m`, `24h`) as the
  newer keys do rather than elogd's bare seconds.
* **Every new key defaults to "absent ⇒ today's behaviour exactly".** The only exceptions are R2
  (`safeSsoTarget` on `redir`) and R3 (the client-certificate `CommonName` branch), each listed in
  §7.6 and in the open questions.
* A key naming an unreadable file, an unparseable duration or an unresolvable issuer is reported
  once at start-up **and** in `AuthStatus`, and makes that back end `ErrAuthUnavailable` rather than
  "silently switched off" — `NewAuthenticators`'s rule for unknown `Authentication` values ("so a
  typo shows up in the log instead of silently changing who may log in") applied one level down.
* A secret is never the only option: every secret key has a `… file` and a `… env` variant, and no
  secret is ever echoed by `AuthDescription`, `AuthStatus`, `WriteLoginMethod` or the configuration
  page.

### 7.2 General SSO keys (proposed)

| key | type | default | meaning |
|---|---|---|---|
| `SSO mode` | `off`/`button`/`forced` | `off` | §2.10 |
| `SSO button label` | text | `Single sign-on` | button text; per provider as `SSO <name> button label` |
| `SSO local login` | flag | `1` | the user/password form stays reachable (`button` always keeps it) |
| `SSO allow local user` | list | (all) | in `forced` mode, which names may still use the local form — the break-glass list |
| `SSO login page text` | text | "" | one line under the button ("Staff accounts only") |
| `SSO logout url` | token | `cmd=Logout` | whether the menu's Logout points at `cmd=Logout` or `cmd=OidcLogout` |
| `SSO required` | flag | `1` | **per logbook**; only meaningful when the global mode is `forced` (§7.5) |

### 7.3 OIDC keys (proposed)

Required:

| key | notes |
|---|---|
| `OIDC issuer` | the `iss` matched exactly; also the discovery base |
| `OIDC client id` | the `aud` required |
| `OIDC client secret` / `OIDC client secret file` / `OIDC client secret env` | the last two are the recommended form: a secret in a world-readable `elogd.cfg` is a copy of the credential into every backup and every support attachment |
| `OIDC redirect uri` | exact URI, repeatable; strongly preferred over derivation (§2.7) |

Flow and endpoints: `OIDC discovery url`, `OIDC metadata file`, `OIDC jwks uri`,
`OIDC external url`, `OIDC trust forwarded host` (`0`), `OIDC auth style`
(`auto`/`basic`/`post`), `OIDC scopes` (`openid profile email groups`), `OIDC response mode`,
`OIDC extra param` (repeatable `k=v`), `OIDC http timeout` (`10s`), `OIDC ca file`,
`OIDC max redirects` (`3`).

Validation: `OIDC algorithms` (the default allow-list of §2.1), `OIDC clock skew` (`2m`, cap `5m`),
`OIDC issuer alt`, `OIDC audience`, `OIDC require email` (`0`), `OIDC max auth age` (`0`),
`OIDC max token bytes` (`16384`).

There is deliberately **no** `OIDC validate token = 0`. Operators will ask for it; the answer is that
a site that cannot reach its IdP may point `OIDC metadata file` and `OIDC jwks uri` at a static,
pre-agreed key set — a supported, auditable configuration — but signature validation itself is not
switchable off, because a build flag that turns identity verification off is a permanent hole with a
config file in front of it.

Mapping and accounts, mirroring the `Header …` keys one-for-one so there is one vocabulary for "an
asserted identity": `OIDC claim user`, `OIDC claim fullname`, `OIDC claim email`,
`OIDC claim groups`, `OIDC login group`, `OIDC admin group`, `OIDC strip domain` (`0`),
`OIDC lowercase user` (`1`), `OIDC max length` (`256`), `OIDC max groups` (`256`),
`OIDC create user` (`1`), `OIDC link by email` (`1`), `OIDC link file`, `OIDC link` (repeatable
alternative), `OIDC name prefix`, `OIDC use userinfo` (`0`).

Lifetime and flow: `OIDC flow ttl` (`5m`), `OIDC flow max` (`10000`), `OIDC bind flow ip` (`1`),
`OIDC session max age` (`0`), `OIDC refresh` (`0`), `OIDC refresh skew` (`60s`),
`OIDC jwks refresh` (`6h`), `OIDC jwks refresh skew` (`5m`), `OIDC jwks stale` (`72h`),
`OIDC jwks max bytes` (`262144`), `OIDC metadata refresh` (`24h`), `OIDC providers`.

Logout: `OIDC post logout uri`, `OIDC issuer logout url`, `OIDC logout confirm` (`0`),
`OIDC backchannel logout` (`1`).

Presentation: `OIDC name` (the label used in the button and the log prefix), `OIDC verbose`.

The certificate keys are in §5.3. Nothing here needs a change to `config.go`; the back-end file
reads its own keys, as `readHeaderOptions` does.

### 7.4 Complete example — Microsoft Entra ID (single tenant)

**On the Entra side**, named so the reviewer can check it: an app registration *golog-logbooks*,
supported account types *this organizational directory only*; **Authentication → Redirect URI**,
platform *Web*, `https://logbooks.corp.example/golog/cmd=OidcCallback`; **Client credentials** → a
secret with a lifetime of at most six months (note that it is a *secret*, hence
`OIDC client secret file`); **Token configuration → Add groups claim**, *Group memberships: Security
groups*; **API permissions** `User.Read` (delegated) and nothing else; **Enterprise application →
Assignment required = Yes** if access is controlled by assignment. Two Entra specifics this design
leans on: `preferred_username` is the UPN, and the groups claim contains **group object IDs**, not
names — so `OIDC login group` and `OIDC admin group` are matched against object IDs and `Group map`
is where a human-friendly name is attached.

```ini
# ---- /etc/golog/elogd.cfg ----
[global]
# ... existing keys (logbook directory, SMTP, SSL cert, ...) unchanged ...

Authentication     = OIDC, LDAP, File     # File is appended anyway; spelled out anyway
Super admin group  = golog-admins         # existing key, read by IdentityIsAdmin
Group map          = golog-admins = jdoe, jsmith; golog-all = *@corp.example

# --- presentation ---
SSO mode             = button
SSO button label     = Log in with corp SSO
SSO local login      = 1
SSO allow local user = root, svc-backup   # the accounts that must work when Entra is down

# --- provider ---
OIDC name               = Entra ID
OIDC issuer             = https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0
OIDC client id          = 8a7c0f5e-1234-5678-9abc-def012345678
OIDC client secret file = /etc/golog/secrets/golog-client-secret     # 0600, gologd:root
OIDC redirect uri       = https://logbooks.corp.example/golog/cmd=OidcCallback
OIDC external url       = https://logbooks.corp.example/golog
OIDC scopes             = openid profile email groups
OIDC algorithms         = RS256 RS384 RS512
OIDC clock skew         = 2m

# --- mapping ---
OIDC claim user     = preferred_username, upn, mail, sub
OIDC claim email    = mail
OIDC claim groups   = groups
OIDC lowercase user = 1
OIDC strip domain   = 1                     # jdoe@corp.example -> jdoe, matching the password file
OIDC login group    = 44444444-5555-6666-7777-888888888888   # "Logbook users"
OIDC admin group    = 33333333-4444-5555-6666-777777777777   # "Logbook admins"
OIDC create user    = 1
OIDC link by email  = 1
OIDC require email  = 1
OIDC max groups     = 200

# --- lifetime ---
Login expiration     = 12                   # existing key, hours: the session ceiling
OIDC session max age = 8h
OIDC refresh         = 0                     # no refresh tokens: re-auth is a silent 302
OIDC flow ttl        = 5m

# --- logout ---
SSO logout url         = cmd=OidcLogout
OIDC post logout uri   = https://logbooks.corp.example/golog/
OIDC issuer logout url = https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/logout

# --- nginx terminates TLS on the same host ---
Trusted proxy = 127.0.0.0/8                 # governs LoginSourceIP and LoginCookieSecure
```

What that yields for `jdoe@corp.example` who is a member of *Logbook users*:

```
Identity{ Name:"jdoe", FullName:"John Doe", Email:"jdoe@corp.example",
          Groups:["44444444-5555-6666-7777-888888888888", "golog-all"],  # claim + Group map
          AuthType:"oidc", Admin:false, Created:false,
          Principal:"https://login.microsoftonline.com/1111…/v2.0|00000000-0000-0000-…" }
```

and one audit line: `golog auth: login ok for jdoe from 192.0.2.7 via oidc as <principal>`.

The failure modes of this exact configuration, which is what a reviewer should check: Entra down →
the button leads to a 503 page **and the local form still works**; the names in
`SSO allow local user` still reach it even in `forced` mode; a user outside `OIDC login group` gets
the generic refusal page plus one log line naming the group, and that refusal counts against the
throttle and produces the fail2ban line; an expired client secret becomes `invalid_client` →
`ErrAuthUnavailable`, **not** counted against the user, with a log line naming the client id and the
endpoint, and a status page that says `oidc[Entra ID]: token endpoint refused client
authentication`; logout ends the golog session first, then bounces through Entra's logout endpoint
back to `OIDC post logout uri`.

### 7.5 Complete example — Keycloak (realm with groups)

**On the Keycloak side**: realm `corp`; client `golog`, protocol `openid-connect`, *Client
authentication = On*, *Standard flow = On*, *Direct access grants = Off*; **Valid redirect URIs**
`https://logbooks.corp.example/golog/cmd=OidcCallback` (exact — no wildcard in production); **Web
origins** `https://logbooks.corp.example`; the secret from the *Credentials* tab; the built-in
`email` and `profile` client scopes; plus a client-scoped mapper of type *Group Membership* with
token claim name `groups` and **full group path off**, so the claim holds `logbook-users` and not
`/logbook/logbook-users`. Realm roles work too and arrive at `resource_access.golog.roles`, which
the dotted claim path of §2.5 resolves.

```ini
[global]
Authentication      = OIDC, File
Super admin group   = golog-admins
Group map           = golog-admins = jdoe; golog-all = *@lab.example

SSO mode         = button
SSO button label = Log in with lab SSO
SSO local login  = 1

OIDC name              = Keycloak
OIDC issuer            = https://sso.lab.example/realms/corp
OIDC discovery url     = /.well-known/openid-configuration
OIDC client id         = golog
OIDC client secret env = GOLOG_OIDC_SECRET          # systemd EnvironmentFile=
OIDC redirect uri      = https://logbooks.corp.example/golog/cmd=OidcCallback
OIDC external url      = https://logbooks.corp.example/golog
OIDC scopes            = openid profile email groups
OIDC algorithms        = RS256 ES256                # RS256 by default, ES256 optional
OIDC ca file           = /etc/pki/lab/ca-bundle.pem # a private CA signs sso.lab.example

OIDC claim user     = preferred_username, email, sub
OIDC claim groups   = groups
OIDC login group    = logbook-users
OIDC admin group    = logbook-admins
OIDC lowercase user = 1
OIDC create user    = 1
OIDC max groups     = 256

OIDC session max age = 10h
OIDC jwks refresh    = 3h                           # Keycloak rotates realm keys on a schedule
OIDC flow ttl        = 3m

# Keycloak is on another host; golog itself serves TLS behind a TCP-only balancer
Trusted proxy = 10.0.0.0/30                          # only the balancer's /30, for X-Forwarded-For
```

The per-logbook opt-out, and the one key that is not global:

```ini
[kiosk-runlog]            # posted to from a shared terminal on the floor
SSO required = 0          # this logbook does not redirect to the IdP and shows no button

[hidden-proton]           # restricted logbook, SSO as usual
Read user = jdoe, mkurzi, beamline-team     # existing key, read by userIn / IsLogbookAllowed
Hidden    = 0
```

`SSO required = 0` does **not** create a separate login: sessions are global in golog. It means (a)
in `forced` mode this logbook does not redirect, and (b) its pages show no button. "SSO mandatory
here, optional there" is not offerable without per-logbook sessions, which golog does not have, and
the limitation should be documented rather than worked around with a half-measure.

One trap worth putting in the example rather than a footnote: with full group path left **on**, the
claim holds `/logbook/logbook-admins`, while `headerHasGroup`-style matching compares exactly, the
first RDN and the part after a `\` — so `OIDC admin group = logbook-admins` silently never matches.
Either turn the full path off or write the key as the path. This is the most likely Keycloak support
ticket.

### 7.6 Migration path for existing users

| existing setup | after this design | what the operator does |
|---|---|---|
| `Authentication` absent, passwords only | unchanged, byte for byte | nothing (no SSO key ⇒ `SSO mode = off`, no OIDC back end built) |
| `Auth type = ldap` (elogd spelling) | unchanged — `authenticationValue` still reads `Auth type` | nothing |
| `Authentication = File, LDAP` | unchanged | nothing |
| `Authentication = SSO`, meaning "I want single sign-on" | **still the header back end**, exactly as `authTypeAliases` does today | nothing; and the status page now prints `Header` with its `AuthDescription`, naming the header and the proxy list |
| `Authentication = Header` behind a proxy | unchanged | nothing |
| `Authentication = Kerberos` / `SPNEGO` / `Negotiate` | unchanged: they alias to `Header`, and §4 recommends they keep doing so | optionally switch the spelling to `Header` for clarity; the documentation says why `Kerberos` does not mean native Kerberos |
| client certificates with `SSL client auth = require`, relying on the CN branch | **breaks**: `Cert login` defaults to `0`, and with `0` the CN branch is gone (R3) | set `Cert login = 1` plus at least one `Cert user pattern`. The start-up log says so when `SSL client auth` is set while `Cert login = 0`, so the breakage is announced, not discovered |
| anyone using `redir` to an absolute URL on another host | now falls back to the default target (R2) | add the host to `OIDC allowed target`, or fix the link |
| users created by LDAP or header logins | unchanged: OIDC uses the same `ensurePwdUser` | nothing |
| a person who exists locally and in the IdP under a different name | linked by email (§2.11 step 2) or by the link file | confirm `OIDC link by email = 1`, or add a line to `sso-links.txt` **before** the cutover, so his old entries follow him |
| `passwords.xml` | untouched. OIDC never writes a usable password, only `ensurePwdUser`'s unguessable one | after a month of SSO, expire local accounts on the existing `Expire` page (`fillIdentity` already honours `Inactive`, and `Expire user`/`Save expire user` are dispatched commands) — but keep those names in `SSO allow local user` |
| LDAP `memberOf`-based groups | still work: `Group map` merges with whatever the back end asserts | nothing; optionally move the mapping into the IdP later |

Rollout order in which every step is reversible: (1) deploy with `SSO mode = off` and confirm nothing
changed; (2) `SSO mode = button` with one test account, the local form still the default; (3) pilot
group; (4) `SSO mode = forced` with `SSO local login = 1` and `SSO allow local user` naming the
break-glass accounts; (5) consider `SSO local login = 0` only after an IdP-outage drill, and never
without the break-glass list documented off-box. Rollback is one key plus `ResetAuthenticators`
(SIGHUP): no data migration and no user-record change to undo.

---

## 8. Code structure, hook points, tests, effort

### 8.1 Files and functions to change (the hook points, by name)

Ten edits carry the whole programme. Each is small because the seams already exist; the column
"why so small" is the argument that this is an extension rather than a rewrite.

| # | file | function / place | change | why so small |
|---|---|---|---|---|
| H1 | `authiface.go` | `AuthContext` | add `SSO *SsoAssertion`, `Cert *x509.Certificate` (or reuse `Req.TLS`), `Attempt int`. Documented as "set by the daemon, read-only for back ends, never logged" | the struct already carries `Req` for out-of-band evidence, and `Password`'s comment already establishes the never-logged rule |
| H2 | `authiface.go` | `Identity` | add `Subject string`, `Issuer string`, `Groups []string`, `Admin bool`, `Created bool` | `Identity` is a data struct with no behaviour; `Principal` already exists as an opaque display string and its comment already anticipates the use |
| H3 | `authiface.go` | `AuthType` | add `AuthOIDC = "OIDC"`, `AuthCert = "Cert"`; extend `authTypeAliases` with `oidc`, `openid`, `azure`, `entra`, `idp`, `sso-oidc` → `AuthOIDC` and `cert`, `certificate`, `client cert`, `x509` → `AuthCert` | the selector is already a normalise-plus-alias function and unknown values already degrade to a log line and a skip |
| H4 | `auth.go` | `(*Server).setupAuth` | after `NewSessionStore` / before `NewAuthenticators`: build the `SSO` config object, start the discovery/key-set manager, register the two paths in `(*Server).watchPaths` (`OIDC ca file`, the link file) | every other global object (`pwdUsers`, `throttle`, `failban`, `tlsConfig`) is built here |
| H5 | `auth.go` | `GroupsForUser` | signature `GroupsForUser(name string, asserted []string) []string`; merge asserted groups with `Group map`, dedupe, keep order | every caller is inside this package and the only non-test caller today is `fillIdentity` |
| H6 | `auth.go` | `IdentityIsAdmin` | consult `id.Admin` **before** the `Super admin group` test; keep `userIn` for name lists | it already receives the whole `Identity`, so no plumbing is needed |
| H7 | `auth.go` | `(*Server).fillIdentity` | copy `id.Groups`/`id.Admin` into `PwdUser.Groups`/`PwdUser.Admin` instead of leaving both zero — they exist today with the comment "not used yet" | the rights code (`userIn`, `userAllowed`, `IsLogbookAllowed`, `CanEdit`) already reads those fields; SSO is what finally fills them |
| H8 | `authhttp.go` | `finishLogin` | accept the identity from `AuthenticateLogin` instead of discarding it (`_ = id` today); carry the assertion to `ssoSessionStore`; keep `redir` through `safeSsoTarget` | `finishLogin` already returns the session id; the SSO session state is one map insert next to `s.Sessions.New` |
| H9 | `authhttp.go` | `(*Server).serve` command switch, `(*Server).dispatch` | route `OidcLogin`/`OidcCallback`/`OidcLogout` (through `s.sameCommand`), and the `/OidcBackchannel` path before logbook resolution | the two switch statements are the canonical place, and `userAllowed`/`commandAllowed` must list the names |
| H10 | `request.go` | `(*Request).authenticate` | replace the client-certificate `CommonName` branch with the `Cert` matcher plus `q.newSession()`/`q.fillIdentity()` | the branch already exists; only the decision inside it changes |
| H11 | `request.go` | `(*Request).newSession` | `Secure: s.LoginCookieSecure(q.R)` instead of `q.R.TLS != nil` | R-4; one expression |
| H12 | `pages.go` | `(*Server).showLoginPage` | render the SSO button(s) above the existing form; keep `unm`/`upwd`/`redir` unchanged | `showLoginPage` already takes a `redir` argument and is the only login page |
| H13 | `pages.go` | `(*Server).AuthStatus`, `WriteStatusPage` | print the SSO section (issuer, client id, key-set age, mode) via `WriteLoginMethod`/`LoginMethodInfo` | `authiface.go` already renders the whole authentication picture from `RegisteredAuthenticators()` and `AuthenticationSummary` |
| H14 | `authhttp.go` | `LogoutHandler`, `(*Server).Logout` | drop the `ssoSessionStore` entry | two lines, prevents a token outliving its session |
| H15 | `server.go` | `Server` struct | one field `sso *SSO` (**proposed**), nil when SSO is off — so every SSO code path is guarded by a nil check rather than by a flag, and `gologd` without SSO config allocates nothing new | the pattern `s.tlsConfig` / `s.crlSet` / `s.throttle` already uses |

Plus the two security edits that are worth doing regardless of the SSO decision: **R2**
(`safeSsoTarget` applied to `redir`) and **R3** (the client-certificate branch), and the pre-existing
hardcoded `/logbooks` / `/login` links in `(*Server).SendLoginFailure`, which are wrong under a
`BasePath`.

### 8.2 New files

| file | contents | ~lines |
|---|---|---|
| `internal/golog/oidcauth.go` | `AuthOIDC` registration, `oidcAuthenticator`, `newOidcAuthenticator`, `AuthDescription`, `readOidcOptions` (**proposed**), `mapOidcIdentity`, `ssoIdentity`, `oidcClaimValue`, the `SSO`/`SsoAssertion` types | 700 |
| `internal/golog/oidcproto.go` | discovery fetch + issuer check + endpoint validation, metadata cache and file override, `oidcKeySet` (fetch, parse, refresh policy, stale window, size cap), JWT decode, the §2.4 validation list, `at_hash`, base64url helpers | 850 |
| `internal/golog/oidcflow.go` | `oidcFlowStore` (single-use state/nonce/verifier, TTL, cap, sweep), authorization-URL builder, `safeSsoTarget`, the token-endpoint client (no redirect following, size limit, auth styles), `ssoSessionStore` | 600 |
| `internal/golog/oidchttp.go` | `OidcLoginHandler`, `OidcCallbackHandler`, `OidcLogoutHandler`, `OidcBackchannelHandler`, the SSO failure page, the login-page button renderer | 650 |
| `internal/golog/certauth.go` | `AuthCert`, `certAuthenticator`, `readCertOptions`, `matchCertUser`, `certIdentityOf`, the `(*Request).authenticate` helper | 450 |
| `internal/golog/ssosecurity_test.go` | §8.4 tests 1–12 | 900 |
| `internal/golog/oidctest_test.go` | fake IdP (`httptest`), end-to-end login, JWKS rotation, expiry, forced mode | 700 |
| `internal/golog/certauth_test.go` | chain-verification matrix, pattern table, EKU, session conflict | 450 |
| `docs/sso/README.md` | operator documentation, including the mellon/shibd/nginx recipes moved out of `authheader.go`'s header comment | 400 |

No new directory, no new package: everything stays in `internal/golog`, where `Server`, `Request` and
the auth back ends already live, so no existing identifier has to be exported to make SSO work —
which matters because `contract.md` and `README.md` advertise `internal/golog` as a non-public
package.

### 8.3 Interfaces: reused, extended, added

**Reused unchanged:** `Authenticator` (all five methods), `AuthResult`, `AuthChain`,
`registerAuthenticator`, `RegisteredAuthenticators`, `AuthenticationSummary`, `AuthStatus`,
`AuthDescription`, `LoginHTTPStatus`, `LoginErrorMessage`, `SendLoginFailure`, `loginUnavailable`,
`AuthUnavailablef`, `ErrUnknownUser`, `ErrBadPassword`, `ErrAuthUnavailable`,
`(*Server).AuthenticateLogin`, `(*Server).recordLoginFailure`, `(*Server).recordLoginSuccess`,
`logLoginOK`, `loginBlocked`, `LoginSourceIP`, `IsTrustedProxy`, `LoginCookieSecure`,
`randomHex`, `safeLine`, `hostOnlyOrAll`, `pwdUserFold`, `(*Server).ensurePwdUser`,
`(*Server).userIn`, `(*Server).userAllowed`, `(*Server).commandAllowed`, `(*Server).IsLogbookAllowed`,
`(*Server).CanEdit`, `(*Server).redirect`, `s.sameCommand`, `SessionStore`, `Config` accessors,
`certReloader`, `readCertPool`, `readCRLs`, `crlSet`.

**Extended (source-compatible within the package):** `AuthContext`, `Identity`, `AuthType` +
`authTypeAliases`, `GroupsForUser`, `IdentityIsAdmin`, `fillIdentity`, `finishLogin`,
`setupAuth`, `showLoginPage`, `LogoutHandler`/`Logout`, `(*Request).authenticate`,
`(*Request).newSession`, the `serve`/`dispatch` switches, `LoginMethodInfo` (one more field is
appended, so the struct literal in `authhttp.go` must be updated — it is the only construction site).

**Added:** the types and functions marked **proposed** in §2, §5 and §8.2, i.e. `SSO`,
`SsoAssertion`, `oidcAuthenticator`, `certAuthenticator`, `oidcKeySet`, `oidcFlowStore`,
`ssoSessionStore`, `safeSsoTarget`, the four OIDC handlers, `readOidcOptions`, `readCertOptions`,
`mapOidcIdentity`, `matchCertUser`.

The one rule that keeps all of this reviewable: **no new file writes an HTTP response to a
requesting browser except the four handlers in `oidchttp.go`, and none of them creates a session
except by calling `finishLogin`.** That single sentence is the review checklist for the whole
programme: grep for `SetLoginCookie`, `q.User =`, `NewSessionStore` and `Sessions.New` outside the
existing files, and the set must be `{oidchttp.go → finishLogin, certauth.go → q.newSession}`.

### 8.4 Test strategy

No network, no browser, no IdP. `httptest` is the whole harness, which is also the reason a fake IdP
is cheap here: golog's own `Server` can be started in-process with a `Config` built from a string, and
`Config.Set(scope, key, value)` makes a configuration in a test literal.

**A fake IdP** (`oidctest_test.go`): an `httptest.Server` that serves
`/.well-known/openid-configuration` and `/openidsigms` (the OIDC conformance-suite naming, so the
tests read like the spec), signs with an in-test RSA key generated once per suite, and exposes knobs
as fields: `signWith(kid, alg, key)`, `omitKid`, `unknownKid`, `wrongIss`, `wrongAud`,
`wrongNonce`, `expired(d)`, `notYet(d)`, `badAlg("none")`, `algHS256WithPublicKey`,
`includeLogoutToken`, `rotateKeys()`, `tokenError(code)`, `slow(delay)`, `hugeBody()`,
`redirectLoop()`. It must also be able to *skip* discovery and serve a static metadata file, to
exercise `OIDC metadata file`.

| # | test | asserts |
|---|---|---|
| 1 | **happy path, no browser** | drive the real handlers with an `http.Client{Jar: …, CheckRedirect: func(…) error { record; return http.ErrUseLastResponse }}`: `cmd=OidcLogin` → 302; parse the location; call the IdP stub to mint a code; `cmd=OidcCallback?code&state` → 302 to the target with a session cookie; then a request to a restricted page with that cookie returns the page, and the log contains `login ok for jdoe … via oidc` |
| 2 | **forgery matrix** (one sub-test per row) | `alg=none`; `HS256` signed with the public JWKS key as secret; a signature made by a *second* key while the header names the first `kid`; `iss` = the v1.0 URL while `OIDC issuer` is the v2.0 one; `aud` absent; `aud` multi-valued with a wrong `azp`; `exp` past skew; `nbf` in the future; `iat` after `exp`; wrong `nonce`; a token for flow B replayed into flow A; a truncated `at_hash`; an empty `sub`; a `sub` of 300 characters; a `kid` not in the set with no refresh possible; a 3 MB token; a claim set of 4000 groups — every case ends in a refusal **and no session and no `q.User`** |
| 3 | **JWKS rotation** | kid A only → kid B token refused → after the refresh interval (or with the interval set to 0) kid B accepted and a revoked kid A token refused → an unknown kid refreshes at most once per `OIDC jwks refresh skew` (assert the IdP's request count, which is the DoS guard) → with the IdP down and the set older than `OIDC jwks stale`, every token is refused and the log says unavailable |
| 4 | **nothing secret is logged** | capture the log buffer, run case 1 plus a `LoginErrorMessage` call, and assert the buffer contains no `code`, `state`, `nonce`, `code_verifier` value, no token, no client secret, and no bearer cookie value — the mechanical guard for §6.4, and the test that keeps staying true after refactors |
| 5 | **behaviour, not text** | `NewAuthenticators(cfg, s)` with `Authentication = SSO` yields a chain whose `Name()` is `Header+File` and whose header member's `AuthDescription()` names the header — so the alias decision of `authheader.go` survives a refactor of `authTypeAliases`. Same shape for the new `OIDC`/`Cert` spellings, and for `Kerberos` still being `Header` |
| 6 | **header trust unchanged** | table-driven over: non-proxy peer with the header (refused), two headers (refused), over-long, control characters, `Header strip domain`, `Header login group`, group membership forms, `Header require password` against a real `passwords.xml` in a `t.TempDir()`, and `Header create user` both ways — a regression net for the back end SSO must not disturb |
| 7 | **flow store** | state unknown; state expired; state used twice; `OIDC flow max` reached (the store refuses rather than evicting live entries); no session is created on any of those |
| 8 | **`safeSsoTarget`** | `/golog/logbooks/x/` accepted under `BasePath=/golog`; `//evil`, `https://evil`, `/\evil`, `/../../etc`, a CR in the path, `%09`, `mailto:`, an absolute URL to another host refused and the default used; the same table applied to `cmd=Login&redir=…` (R2) |
| 9 | **modes and break-glass** | `SSO mode` `off`/`button`/`forced`; a session cookie present; `cmd=Login&local=1` with `SSO local login` `1`/`0`; `SSO allow local user` containing and not containing the name; `SSO required = 0` in one logbook; and that `cmd=Raw` / `cmd=New entry` / `POST` are **not** redirected in `forced` mode — the list in §2.10, each item one sub-test |
| 10 | **groups and admin** | claim groups + `Group map` merged and deduped by `GroupsForUser`; `OIDC admin group` sets `Identity.Admin` and `IdentityIsAdmin` agrees; an `Admin:false` identity in `Super admin group` is still admin; `OIDC login group` refusal counts against the throttle and calls `FailBanLogFailure` |
| 11 | **unavailability never counts** | with the fake IdP closed, ten logins produce no throttle growth, no ban, no fail2ban line, and 503s — the invariant of §6.4, asserted rather than hoped for |
| 12 | **logout** | `cmd=Logout` clears the cookie, the `SessionStore` entry and the `ssoSessionStore` entry; a valid `logout_token` ends the sessions of exactly that `iss`+`sub` and leaves another user's session alive; a `logout_token` **with** a `nonce` is refused; a missing `events` claim is refused; `400` carries no detail |
| 13 | **client-certificate matrix** | build certificates in-process (`crypto/x509`, `rsa`/`ecdsa`) and use `httptest.NewUnstartedServer` with a `tls.Config` mirroring `(*Server).tlsSetup` (the existing `tlsserve_test.go` already shows this pattern); assert that an *unverified* certificate from an unknown CA is refused (the R3 regression test), a verified chain against `SSL client CA` is accepted only with a matching `Cert user pattern`, a leaf with no `id-kp-clientAuth` is refused unless `Cert allow any EKU`, a chain revoked by a CRL in `SSL client CRL` never reaches the back end, `PeerCertificates[0]` ordering cannot choose the identity, and a certificate that disagrees with a session does not switch identity |
| 14 | **existing behaviour is frozen** | run the current suite unchanged (`encoding_test.go`, `tlsserve_test.go`, `mailer_test.go`) plus the existing auth tests, with no SSO key set: `Authentication` absent still means file passwords, the login page has no button and no OIDC code path is reached (assert `s.sso == nil`) |
| 15 | **cross-compile** | `GOOS=linux GOARCH={386,amd64,arm64}` and `GOOS=windows GOARCH={386,amd64,arm64}` `go build ./...` and `go vet ./...`, in CI, for the whole programme |

Also worth having: a `//go:build !race`-free rule (the flow store and the key set are shared state, so
`go test -race` must be part of the run), and one deliberately *slow* test with a real TLS
`httptest.Server` behind `httputil.ReverseProxy` to prove `BasePath` + proxy + callback URI assembly
works end to end — that combination is where deployments actually break.

### 8.5 Constraints honoured

| constraint | how |
|---|---|
| standard library + vendored modules only | §2.11: zero new modules for OIDC and for client certificates. The only candidate module is for SAML/Kerberos, both declined (§3, §4), with the exact module, licence and rationale recorded in Appendix A so the decision is auditable |
| no cgo | all new code is pure Go: `crypto/rsa`, `crypto/ecdsa`, `crypto/sha256`, `crypto/sha512`, `crypto/x509`, `encoding/json`, `encoding/base64`, `net/http`. Nothing in this design needs a system library, unlike a native Kerberos path which would want GSS-API |
| cross-compile to linux/windows × 386/amd64/arm64 | no platform-specific files are added. Two things to watch: `httptest` TLS tests must not assume platform trust stores (they already don't — `tlsserve_test.go` uses explicit pools); and 386 means no `math/bits` tricks and no reliance on 64-bit atomics for the flow-store counters — use a mutex, as `SessionStore` does |
| keep working standalone with file/LDAP | R1: `SSO mode = off` by default; no SSO key ⇒ no OIDC back end is even constructed; the `File` back end stays appended by `NewAuthenticators`; `Authentication = File` alone remains a complete configuration, asserted by test 14 |
| GPL v2, derivative of ELOG | new files start with the same header block as the existing ones; the upstream C++ is consulted for *behaviour* only (§8.7), and no upstream code is translated into these files, so there is no new derivative surface beyond what the project already has |
| `contract.md` / `notes.md` | `contract.md` documents the behavioural contract the rewrite must keep; §8.6 lists the lines to add to it. `notes.md` records open decisions, so the §9 questions belong there too once answered |

### 8.6 Effort estimate

Realistic staff-days for one engineer who knows this tree, at the pace the existing package suggests
(34 000 lines with tests and comments, so roughly 150–250 finished lines/day is the honest number for
security-sensitive code with tests). **Design** days are already spent and are not counted; **test**
days include the fake IdP.

| phase | item | design | code | test | doc | total |
|---|---|---|---|---|---|---|
| **P0** | H1/H2/H3/H5/H6/H7 identity groundwork (`Groups`/`Admin` finally filled), no behaviour change | 1 | 2 | 2 | 0.5 | **5.5** |
| **P0** | R2 `safeSsoTarget` applied to `redir` + tests | 0.5 | 1 | 1.5 | 0.5 | **3.5** |
| **P0** | R-4 `newSession` → `LoginCookieSecure`, `SendLoginFailure` `BasePath` fix | 0.2 | 0.5 | 1 | 0.2 | **1.9** |
| **P1** | discovery + metadata + key-set manager (`oidcproto.go`) | 2 | 5 | 4 | 1 | **12** |
| **P1** | JWT validation incl. `at_hash`, alg allow-list, size caps | 1.5 | 4 | 5 | 0.5 | **11** |
| **P1** | flow store + URL builder + token client (`oidcflow.go`) | 1.5 | 3.5 | 3 | 0.5 | **8.5** |
| **P1** | `oidcauth.go`: options, mapping, claim paths, link file, group gating | 1.5 | 4 | 3.5 | 1 | **10** |
| **P1** | `oidchttp.go`: login/callback/logout handlers, failure page, H9/H8/H12 wiring | 2 | 5 | 5 | 1 | **13** |
| **P1** | login-page button + status page + `LoginMethodInfo` | 0.5 | 2 | 1.5 | 1 | **5** |
| **P1** | docs: README section, `contract.md` lines, `notes.md` answers | 0.5 | 0 | 0 | 3 | **3.5** |
| **P1** | live-IdP smoke test against real Entra **and** Keycloak (the part CI cannot do) | 0 | 1 | 3 | 1 | **5** |
| **P2** | RP-initiated logout | 0.5 | 2 | 2 | 0.5 | **5** |
| **P2** | back-channel logout + `ssoSessionStore` lookup index | 1 | 2.5 | 2.5 | 0.5 | **6.5** |
| **P2** | refresh tokens + `OIDC session max age` | 1 | 2.5 | 2.5 | 1 | **7** |
| **P2** | multiple providers | 1 | 2 | 2 | 1 | **6** |
| **P2** | `oidc-sub` certificate binding (needs P1 and P3) | 0.5 | 1.5 | 1.5 | 0.5 | **4** |
| **P3** | `certauth.go`: options, matcher, verified-chain rule, H10/H14 | 1.5 | 3.5 | 4 | 1 | **10** |
| **P3** | CRL/EKU/`Cert ca file` interaction tests with generated CA + CRL | 0.5 | 0.5 | 3.5 | 0.5 | **5** |
| **P4** | delegated-SSO operator documentation (mellon, shibd, nginx+auth_request, Keycloak brokering → OIDC) | 0.5 | 0 | 1 | 3 | **4.5** |
| **P4** | `authheader.go` comment paragraph "SAML and Kerberos without writing SAML/Kerberos" | 0 | 0 | 0 | 0.5 | **0.5** |
| declined | native SAML SP (§3.6) | 5 | 16 | 10 | 2 | **33 + external review** |
| declined | native Kerberos/SPNEGO, Linux only (§4.6) | 4 | 14 | 8 | 3 | **29** (+12 for an SSPI path) |

**Totals.** P0 **10.9 d** (independent of SSO — three real security fixes). P1 core OIDC **69 d**;
with the P0 fixes it is 80 days and stands on its own if nothing else is built. P2 **+28.5 d**
cumulative **108.5 d**. P3 **+15 d** cumulative **123.5 d**. P4 **+5 d** cumulative **128.5 d**.
Declining the two native protocols saves 62 days plus a review, and is the main financial argument in
this document.

### 8.7 What must not change

`contract.md` already states the rules for the rewrite; these three lines should be added to it (and
`README.md`'s feature list updated once SSO exists):

* With no SSO key set, the authentication behaviour is byte-identical to today, including the
  `Authentication = SSO` → `Header` alias.
* An SSO back end never writes a response and never sets `q.User`; only `finishLogin` creates a
  session from a login, and `certAuthenticator` is the only other path that may mint a session.
* Tokens, codes, nonces, state, secrets and passwords never reach a log line, a URL golog generates,
  or a page.
