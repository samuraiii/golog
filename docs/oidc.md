# Single sign-on with OpenID Connect

golog is an OpenID Connect relying party (authorization code flow with PKCE,
confidential client). Design and security analysis: [SSO-DESIGN.md](SSO-DESIGN.md).

Register `https://logbooks.example/golog/oidc/callback` as the redirect URI at the
provider (Entra ID, Keycloak, Okta, Google, ...), then in `golog.cfg`:

```ini
[global]
Authentication      = OIDC, LDAP, File
SSO mode            = button                 # off | button | forced
OIDC name           = Corporate SSO
OIDC issuer         = https://login.microsoftonline.com/<tenant>/v2.0
                      # Keycloak: https://sso.example/realms/<realm>
OIDC client id      = <application id>
OIDC client secret file = /etc/golog/oidc-secret        # mode 0600
OIDC external url   = https://logbooks.example/golog    # derives the redirect URI
OIDC claim user     = preferred_username, email, sub
OIDC strip domain   = 1                      # jdoe@corp.example -> jdoe
OIDC login group    = <group id or name>     # optional: required membership
OIDC admin group    = <group id or name>     # optional: becomes administrator
```

* `button` adds "Sign in with ..." to the login page; `forced` sends every login to
  the provider, and `?cmd=Login&local=1` stays reachable as a break-glass form
  (`SSO local login = 0` closes it).
* The ID token must be signed with an algorithm from `OIDC algorithms` (default
  RS256 and ES256; `none` and HS* are never accepted) and carry the configured
  issuer, audience and the nonce of the login. There is no switch that turns the
  signature check off.
* Failures are logged as `golog auth: OIDC login refused for ...` and count
  towards the login ban (see `docs/fail2ban`).
* The routes `/oidc/login` and `/oidc/callback` shadow a logbook named `oidc`.

Not implemented yet: refresh tokens, RP-initiated and back-channel logout, the
UserInfo endpoint, several providers at once, group-name mapping beyond the two
groups above. See section 8 of the design.
