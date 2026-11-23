package golog

// LDAP and Active Directory authentication for golog.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.
//
// Where this comes from
// ---------------------
//
// The C daemon grew LDAP support as a single ldap_initialize()/
// ldap_unbind_ext_s() pair around a one-line search (src/auth.cxx,
// authenticate_user_ldap()), configured through "Auth type = ldap" plus
// "Password file = ldap://host/base?filter?attrs"; the login page even carries a
// commented-out "Authentication = MXML" block. That is enough for a working
// lookup and not enough for a domain: no service account, no group mapping, no
// nested groups, no TLS options, no timeout, one new TLS handshake per login.
//
// golog keeps the spirit ("Authentication = LDAP" and a handful of "Ldap ..."
// keys) and adds what an Active Directory site needs. The keys are named like the
// C keys where an equivalent exists and are listed in docs/authentication.md.
//
// The design has two halves:
//
//   - this file: the options, the pure helpers (filters, bind identities, group
//     and attribute mapping, the account-status test) and the authentication
//     logic. Everything that can be decided without a network is here, and the
//     tests run the whole decision path against a fake directory through the
//     LdapDir interface;
//   - ldapconn.go: the real client and its small connection pool, with the
//     vendored github.com/go-ldap/ldap/v3 hidden behind that same interface.
//
// Rules this file keeps to:
//
//   - a password is never logged and never put into an error string;
//   - every value that came from a user or from the configuration goes through
//     ldap.EscapeFilter before it enters a filter;
//   - the user's own bind runs on a dedicated connection that is closed
//     immediately, so a successful login cannot leave the caller's credentials
//     behind in a pooled connection;
//   - referrals are never followed: a base DN that does not exist here is
//     reported, not chased to another server with the service account's
//     credentials;
//   - a directory problem is reported as ErrAuthUnavailable, never as "wrong
//     password". That distinction is what keeps an outage from being counted as a
//     thousand failed logins and locking every operator out.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

// ldapOptions is the [global] configuration of the LDAP back end. One struct,
// read once per chain build; everything the authentication path decides is in it.
type ldapOptions struct {
	// urls is "Ldap url": one or more ldap:// or ldaps:// URLs, tried in order.
	urls []string
	// baseDN is "Ldap base dn", the search base.
	baseDN string
	// baseScope is "Ldap scope": subtree (default), one/onelevel, or base.
	baseScope int
	// userAttr is "Ldap user attribute": the attribute holding the login name
	// (uid on OpenLDAP, sAMAccountName on AD).
	userAttr string
	// userFilter is "Ldap user filter": a complete filter with %s for the
	// escaped name; it replaces the default OR-filter when set.
	userFilter string
	// bindDN and bindPassword are the service account ("Ldap bind dn" / "Ldap
	// bind password") that performs the lookup search. Without one the search
	// runs on the caller's own bind, which only works on directories that let an
	// account read itself.
	bindDN       string
	bindPassword string
	// bindAsName builds the bind identity from the typed name and a suffix
	// instead of searching first, so that an AD site needs no service account.
	bindAsName bool
	bindSuffix string
	// domain is used for the userPrincipalName and DOMAIN\user bind forms;
	// upnSuffix overrides it for the UPN only.
	domain    string
	upnSuffix string
	// groupAttrs are the membership attributes of the user entry.
	groupAttrs []string
	// groupBaseDN, when set, is searched for group objects that hold this user
	// ("group search base"). Needed by servers that do not maintain memberOf,
	// and it is the only way to see a group whose name is not a DN.
	groupBaseDN     string
	groupMemberAttr string
	// nestedGroups turns the membership test into the Active Directory
	// transitive match rule 1.2.840.113556.1.4.1941.
	nestedGroups bool
	// loginGroup gates logins; adminGroup marks the golog administrators.
	loginGroup string
	adminGroup string
	// nameAttr and mailAttr map the directory entry onto the display name and
	// the address; extraAttrs are additionally requested.
	nameAttr   string
	mailAttr   string
	extraAttrs []string
	// createUser writes the local password-file record on first login, so that
	// the user page and the subscription lists have something to show.
	createUser bool

	// The timeouts keep the connection handling bounded: a directory that stops
	// answering must not be able to pin login goroutines.
	dialTimeout time.Duration
	ioTimeout   time.Duration
	idleTimeout time.Duration
	poolSize    int

	// TLS.
	startTLS   bool
	caFile     string
	skipVerify bool
	serverName string

	// dial replaces the real dialer in tests; nil means ldapDialURL.
	dial ldapDialFunc
}

// readLDAPOptions reads the "Ldap ..." keys from the global scope. The error says
// that the configuration is unusable: the caller logs it and lets every login
// report "unavailable" rather than quietly falling back to the password file,
// because a silently disabled directory is how a site loses its account system.
func readLDAPOptions(c *Config) (ldapOptions, error) {
	var o ldapOptions
	if c == nil {
		c = ParseConfig("")
	}
	g := ConfigScope{Group: "global"}

	raw := TrimSpaceASCII(c.GetString(g, "Ldap url", ""))
	if raw == "" {
		// The C spelling: a "Password file" that is really an ldap URL. Read it,
		// but tell the operator the supported spelling, because the C form also
		// carries the filter and the attribute list in the URL and this
		// implementation reads those from their own keys.
		if alt := TrimSpaceASCII(c.GetString(g, "Password file", "")); HasPrefixFold(alt, "ldap") {
			logS(currentServer(), "golog auth: an ldap:// password file is not read; use \"Ldap url\" with \"Ldap base dn\"")
		}
	}
	o.urls = ldapURLList(raw)
	if len(o.urls) == 0 {
		return o, AuthUnavailablef(`authentication = LDAP needs "Ldap url" (ldap://host:389 or ldaps://host:636)`)
	}
	for _, u := range o.urls {
		lu := strings.ToLower(u)
		if !HasPrefixFold(lu, "ldap://") && !HasPrefixFold(lu, "ldaps://") {
			return o, AuthUnavailablef("ldap url %q must start with ldap:// or ldaps://", u)
		}
	}
	if bad, why := ldapBadCharacters(raw); bad != "" {
		return o, AuthUnavailablef("ldap url contains %s: %q", why, bad)
	}

	o.baseDN = TrimSpaceASCII(c.GetString(g, "Ldap base dn", c.GetString(g, "Ldap basedn", "")))
	switch strings.ToLower(TrimSpaceASCII(c.GetString(g, "Ldap scope", "subtree"))) {
	case "one", "onelevel", "single", "level":
		o.baseScope = ldap.ScopeSingleLevel
	case "base", "object", "zero":
		o.baseScope = ldap.ScopeBaseObject
	default:
		o.baseScope = ldap.ScopeWholeSubtree
	}
	if o.baseDN == "" && !c.GetFlag(g, "Ldap bind as name") {
		return o, AuthUnavailablef(`authentication = LDAP needs "Ldap base dn" (the search base)`)
	}

	o.userAttr = TrimSpaceASCII(c.GetString(g, "Ldap user attribute", "uid"))
	o.userFilter = TrimSpaceASCII(c.GetString(g, "Ldap user filter", ""))
	o.bindDN = TrimSpaceASCII(c.GetString(g, "Ldap bind dn", c.GetString(g, "Ldap service account", "")))
	o.bindPassword = c.GetString(g, "Ldap bind password", c.GetString(g, "Ldap service password", ""))
	if o.bindDN != "" && o.bindPassword == "" {
		return o, AuthUnavailablef(`"Ldap bind dn" is set but "Ldap bind password" is empty`)
	}
	o.bindAsName = c.GetFlag(g, "Ldap bind as name")
	o.bindSuffix = TrimSpaceASCII(c.GetString(g, "Ldap bind suffix", ""))
	o.domain = TrimSpaceASCII(c.GetString(g, "Ldap domain", ""))
	o.upnSuffix = TrimSpaceASCII(c.GetString(g, "Ldap upn suffix", o.domain))

	o.groupAttrs = nil
	for _, a := range SplitList(c.GetString(g, "Ldap group attribute", "memberOf"), ",", false) {
		if a = TrimSpaceASCII(a); a != "" {
			o.groupAttrs = append(o.groupAttrs, a)
		}
	}
	if len(o.groupAttrs) == 0 {
		o.groupAttrs = []string{"memberOf"}
	}
	o.groupBaseDN = TrimSpaceASCII(c.GetString(g, "Ldap group base dn", ""))
	o.groupMemberAttr = TrimSpaceASCII(c.GetString(g, "Ldap group member attribute", "member"))
	o.nestedGroups = c.GetFlagDefault(g, "Ldap nested groups", true)
	o.loginGroup = TrimSpaceASCII(c.GetString(g, "Ldap login group", ""))
	o.adminGroup = TrimSpaceASCII(c.GetString(g, "Ldap admin group", ""))

	o.nameAttr = TrimSpaceASCII(c.GetString(g, "Ldap name attribute",
		c.GetString(g, "Ldap fullname attribute", "displayName")))
	o.mailAttr = TrimSpaceASCII(c.GetString(g, "Ldap email attribute",
		c.GetString(g, "Ldap mail attribute", "mail")))
	for _, a := range SplitList(c.GetString(g, "Ldap extra attributes", ""), ",", false) {
		if a = TrimSpaceASCII(a); a != "" {
			o.extraAttrs = append(o.extraAttrs, a)
		}
	}
	o.createUser = c.GetFlag(g, "Ldap create user")

	o.poolSize = orRange(c.GetInt(g, "Ldap pool size", 4), 1, 64)
	o.dialTimeout = ldapDuration(c, "Ldap connect timeout", 10*time.Second)
	o.ioTimeout = ldapDuration(c, "Ldap timeout", 15*time.Second)
	o.idleTimeout = ldapDuration(c, "Ldap idle timeout", time.Minute)
	o.startTLS = c.GetFlag(g, "Ldap starttls")
	o.caFile = TrimSpaceASCII(c.GetString(g, "Ldap ca file", ""))
	o.skipVerify = c.GetFlag(g, "Ldap insecure skip verify")
	o.serverName = TrimSpaceASCII(c.GetString(g, "Ldap tls server name", ""))
	if c.GetFlag(g, "Ldap ca insecure") {
		// The C client has LDAP_OPT_X_TLS_REQUIRE_CERT; the nearest golog
		// equivalent is "Ldap ca file" with a bundle of your own CA. Relaxing the
		// check is a different key and says so in its name.
		logS(currentServer(), "golog auth: \"Ldap ca insecure\" does nothing: verification is off only with "+
			"\"Ldap insecure skip verify\", which you should not use")
	}
	if o.skipVerify {
		logS(currentServer(), "golog auth: WARNING \"Ldap insecure skip verify\" is on: directory server certificates are not checked")
	}
	if c.GetFlag(g, "Ldap follow referrals") {
		logS(currentServer(), "golog auth: \"Ldap follow referrals\" is ignored: golog never follows a referral, "+
			"because it would send the service account to a server the configuration does not name")
	}
	return o, nil
}

// ldapDuration reads a timeout key: a plain number is seconds (the rule every
// other elogd duration key follows), a suffixed value is taken as written.
func ldapDuration(c *Config, key string, def time.Duration) time.Duration {
	v := c.GetDuration(ConfigScope{Group: "global"}, key, def)
	if v <= 0 {
		return def
	}
	return v
}

// orRange clamps a configured count into the range that keeps the daemon healthy.
func orRange(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ldapBadCharacters reports the first character that must not appear in a
// configured URL: a URL is printable ASCII, and a control character or a quote in
// it is a configuration mistake at best.
func ldapBadCharacters(raw string) (string, string) {
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\'' {
			lo := i - 8
			if lo < 0 {
				lo = 0
			}
			return raw[lo : i+1], "a control or quote character"
		}
	}
	return "", ""
}

// ldapURLList splits the "Ldap url" value on blanks, commas and semicolons. A
// piece without a scheme is not a URL and is dropped; the caller's validation
// catches the case where nothing is left.
func ldapURLList(raw string) []string {
	raw = TrimSpaceASCII(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '\n' || r == '\r'
	}) {
		p = TrimSpaceASCII(p)
		if p == "" {
			continue
		}
		if HasPrefixFold(p, "ldap://") || HasPrefixFold(p, "ldaps://") {
			out = append(out, p)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// filters, names and DNs: pure functions, tested without a directory
// ---------------------------------------------------------------------------

// ldapUserFilter is the search filter that finds the account of name.
//
// The name goes through ldap.EscapeFilter without exception, including inside a
// custom "Ldap user filter": a filter is not a place where a user name belongs,
// and the characters that break a value out of a comparison are exactly the ones
// an attacker types ("*", ")", "\00", ")(cn=").
func ldapUserFilter(o ldapOptions, name string) string {
	esc := ldap.EscapeFilter(TrimSpaceASCII(name))
	if o.userFilter != "" {
		if strings.Contains(o.userFilter, "%s") {
			return strings.ReplaceAll(o.userFilter, "%s", esc)
		}
		// A filter without the placeholder is a static list of accounts; legal,
		// and the name is then not part of the lookup at all.
		return o.userFilter
	}
	attr := o.userAttr
	if attr == "" {
		attr = "uid"
	}
	// One filter that answers on a domain controller and on an OpenLDAP server:
	// the configured attribute first, then the names each system really uses.
	// The objectClass test keeps groups, computers and contacts out of the
	// result, which matters because the first match wins.
	return "(&(|(" + attr + "=" + esc + ")(sAMAccountName=" + esc +
		")(userPrincipalName=" + esc + ")(uid=" + esc + ")(cn=" + esc +
		"))(|(objectClass=user)(objectClass=person)(objectClass=inetOrgPerson)(objectClass=organizationalPerson)))"
}

// ldapGroupMemberFilter finds the members of a group by its DN. With nested
// groups - the default, and the only spelling that is right on AD - the
// transitive match rule 1.2.840.113556.1.4.1941 is used, so that a member of a
// nested group counts too; the plain form is kept for servers without that rule
// and for the deliberate "direct members only" case.
func ldapGroupMemberFilter(o ldapOptions, groupDN string) string {
	esc := ldap.EscapeFilter(groupDN)
	attr := o.groupMemberAttr
	if attr == "" {
		attr = "member"
	}
	if o.nestedGroups {
		return "(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))(" +
			attr + ":1.2.840.113556.1.4.1941:=" + esc + "))"
	}
	return "(&(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))(" +
		attr + "=" + esc + "))"
}

// ldapGroupValueFilter matches the membership attributes of an entry against one
// group name, which is what a site whose access lists hold plain group names
// rather than DNs needs.
func ldapGroupValueFilter(o ldapOptions, groupName string) string {
	esc := ldap.EscapeFilter(groupName)
	var parts []string
	for _, a := range o.groupAttrs {
		if o.nestedGroups {
			parts = append(parts, "("+a+":1.2.840.113556.1.4.1941:="+esc+")")
			continue
		}
		parts = append(parts, "("+a+"="+esc+")")
	}
	switch len(parts) {
	case 0:
		return "(objectClass=*)"
	case 1:
		return parts[0]
	}
	return "(|" + strings.Join(parts, "") + ")"
}

// ldapBindNames builds the identities a typed name can be bound as, in the order
// to try. An LDAP bind needs a DN; a domain controller also accepts the
// userPrincipalName and the down-level logon name DOMAIN\user, so those are
// offered - but only the forms the configuration actually describes, so an
// OpenLDAP server is never asked to bind as "CORP\jdoe".
func ldapBindNames(o ldapOptions, name string) []string {
	name = TrimSpaceASCII(name)
	if name == "" {
		return nil
	}
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, x := range out {
			if EqualFold(x, s) {
				return
			}
		}
		out = append(out, s)
	}
	switch {
	case strings.Contains(name, "="):
		// A full DN: pass it through. The quoting rules of a DN must not be
		// second-guessed here; the directory is the parser.
		add(name)
		return out
	case strings.Contains(name, "@"):
		// Already a UPN (or an e-mail, which a domain controller also accepts).
		add(name)
		return out
	}
	if o.bindSuffix != "" {
		switch {
		case strings.Contains(o.bindSuffix, "%s"):
			add(strings.ReplaceAll(o.bindSuffix, "%s", name))
		case strings.Contains(o.bindSuffix, "%u"):
			add(strings.ReplaceAll(o.bindSuffix, "%u", name))
		default:
			// "CN=Users,DC=corp,DC=x" style: the account's own RDN is built from
			// the configured user attribute so that uid and sAMAccountName sites
			// both work. EscapeDN quotes the characters that would otherwise
			// split the RDN.
			attr := o.userAttr
			if attr == "" {
				attr = "uid"
			}
			add(attr + "=" + ldap.EscapeDN(name) + "," + o.bindSuffix)
		}
	}
	if o.upnSuffix != "" {
		add(name + "@" + o.upnSuffix)
	} else if o.domain != "" {
		add(name + "@" + o.domain)
	}
	if o.domain != "" {
		add(o.domain + "\\" + name)
	}
	if len(out) == 0 {
		add(name)
	}
	return out
}

// ldapEntryName is the account name to use for an entry: the attribute the site
// calls the login name, falling back to the first RDN of the DN. Normalising the
// name matters because the session and the "Author" field carry it, so typing
// "JDOE" against a directory that stores "jdoe" must not create two identities in
// the logbook.
func ldapEntryName(o ldapOptions, e *ldap.Entry, typed string) string {
	if e != nil {
		for _, a := range []string{o.userAttr, "sAMAccountName", "uid", "cn"} {
			if a == "" {
				continue
			}
			if v := TrimSpaceASCII(e.GetAttributeValue(a)); v != "" {
				return v
			}
		}
		if rdn := ldapFirstRDNValue(e.DN); rdn != "" {
			return rdn
		}
	}
	return TrimSpaceASCII(typed)
}

// ldapFirstRDNValue is the value of the first RDN of a DN ("CN=John,OU=..." ->
// "John"), "" when the DN cannot be parsed.
func ldapFirstRDNValue(dn string) string {
	d, err := ldap.ParseDN(dn)
	if err != nil || d == nil || len(d.RDNs) == 0 {
		return ""
	}
	atv := d.RDNs[0].Attributes
	if len(atv) == 0 {
		return ""
	}
	return atv[0].Value
}

// ldapGroupNames collects the group names of an entry from the membership
// attributes: the first RDN value of each DN value ("CN=g,OU=x" -> "g"), and a
// plain value as it stands. Sorted and de-duplicated so that the result can be
// compared in a test and shown on a status page.
func ldapGroupNames(o ldapOptions, e *ldap.Entry) []string {
	if e == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, attr := range o.groupAttrs {
		for _, v := range e.GetAttributeValues(attr) {
			name := v
			if rdn := ldapFirstRDNValue(v); rdn != "" {
				name = rdn
			}
			name = TrimSpaceASCII(name)
			if name == "" || seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ldapGroupMatches says whether an access-list entry names one of the groups of
// an entry. Comparison is ASCII case-insensitive (a group name written in a
// configuration file and the same name in a directory differ in case all the
// time) and a DN in the list is compared by its first RDN, so that both spellings
// of a group work.
func ldapGroupMatches(groups []string, want string) bool {
	want = TrimSpaceASCII(want)
	if want == "" {
		return false
	}
	if rdn := ldapFirstRDNValue(want); rdn != "" {
		want = rdn
	}
	wl := strings.ToLower(want)
	for _, g := range groups {
		if strings.ToLower(TrimSpaceASCII(g)) == wl {
			return true
		}
	}
	return false
}

// ldapPrimaryGroupAttr is the attribute a domain controller uses for the
// single-valued primary group, which memberOf does not contain. Turning the
// numeric id into a name needs a domain SID lookup, which is out of scope here;
// the raw id is offered to an access list as "<id>" of that attribute.
const ldapPrimaryGroupAttr = "primaryGroupID"

// ldapUserDisabled is the account-status test: the attributes a directory uses to
// say "this account may not log in", and the values that mean it. There is no C
// equivalent (the C code has no LDAP), so the rules are Active Directory's
// userAccountControl bit 2 (ACCOUNTDISABLE) and the shadow/inetOrgPerson style
// attributes other sites use.
func ldapUserDisabled(e *ldap.Entry) (bool, string) {
	if e == nil {
		return false, ""
	}
	if v := TrimSpaceASCII(e.GetAttributeValue("userAccountControl")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n&2 != 0 {
			return true, "userAccountControl has the ACCOUNTDISABLE bit"
		}
	}
	// shadowExpire=0 and shadowFlag with the expired bit both mean the password
	// may not be used any more.
	if v := TrimSpaceASCII(e.GetAttributeValue("shadowExpire")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n == 0 {
			return true, "shadowExpire is 0 (account expired)"
		}
	}
	if v := TrimSpaceASCII(e.GetAttributeValue("shadowFlag")); v != "" {
		if n, err := strconv.ParseUint(v, 16, 32); err == nil && n&0x0020 != 0 {
			return true, "shadowFlag marks the password as expired"
		}
	}
	for _, a := range []string{"accountStatus", "eduPersonPrincipalStatus", "gidStatus"} {
		v := TrimSpaceASCII(e.GetAttributeValue(a))
		if v == "" {
			continue
		}
		switch strings.ToLower(v) {
		case "inactive", "disabled", "pending", "deleted", "expired", "denied":
			return true, a + " = " + v
		}
	}
	return false, ""
}

// ldapIdentityFromEntry maps a directory entry onto a golog identity: the login
// name, the display name, the address, the group list and the administrator flag
// from "Ldap admin group".
func ldapIdentityFromEntry(o ldapOptions, e *ldap.Entry, typed, url string) Identity {
	id := Identity{
		AuthType: AuthLDAP,
		Groups:   ldapGroupNames(o, e),
	}
	if e == nil {
		id.Name = TrimSpaceASCII(typed)
		return id
	}
	id.Name = ldapEntryName(o, e, typed)
	id.FullName = TrimSpaceASCII(e.GetAttributeValue(o.nameAttr))
	if id.FullName == "" {
		id.FullName = TrimSpaceASCII(e.GetAttributeValue("cn"))
	}
	id.Email = TrimSpaceASCII(e.GetAttributeValue(o.mailAttr))
	if id.Email == "" {
		if upn := TrimSpaceASCII(e.GetAttributeValue("userPrincipalName")); strings.Contains(upn, "@") {
			id.Email = upn
		}
	}
	if id.Name == "" {
		id.Name = TrimSpaceASCII(typed)
	}
	id.Principal = e.DN
	if id.Principal == "" {
		id.Principal = url
	}
	if o.adminGroup != "" && ldapGroupMatches(id.Groups, o.adminGroup) {
		id.Admin = true
	}
	return id
}

// ldapSearchAttributes is the attribute list of the lookup search: everything the
// mapping and the access decision need, always including the membership
// attributes so that no second round trip is needed.
func ldapSearchAttributes(o ldapOptions) []string {
	attrs := []string{"cn", "name", ldapPrimaryGroupAttr, "userAccountControl",
		"sAMAccountName", "userPrincipalName", "displayName", "mail"}
	add := func(a string) {
		a = TrimSpaceASCII(a)
		if a == "" || EqualFold(a, "dn") {
			return // "dn" is not an attribute a server returns: Entry.DN has it
		}
		for _, x := range attrs {
			if EqualFold(x, a) {
				return
			}
		}
		attrs = append(attrs, a)
	}
	add(o.userAttr)
	add(o.nameAttr)
	add(o.mailAttr)
	for _, a := range o.groupAttrs {
		add(a)
	}
	for _, a := range o.extraAttrs {
		add(a)
	}
	return attrs
}

// ---------------------------------------------------------------------------
// the back end
// ---------------------------------------------------------------------------

// ldapAuthenticator is the Authenticator of "Authentication = LDAP".
type ldapAuthenticator struct {
	o   ldapOptions
	dir LdapDir // nil in production: the pool of the options is used
}

// init registers the back end under the canonical name, so that
// "Authentication = LDAP" (and its aliases) selects it.
func init() { registerAuthenticator(AuthLDAP, newLDAPAuthenticator) }

// newLDAPAuthenticator builds the back end from the configuration. A
// configuration error becomes an authenticator that reports every login as
// "unavailable" and says why in the log: the login page then tells the operator
// something is broken instead of telling users their password is wrong.
func newLDAPAuthenticator(ctx AuthContext) Authenticator {
	a := &ldapAuthenticator{}
	o, err := readLDAPOptions(ctx.config())
	if err != nil {
		logS(ctx.S, "golog auth: ldap is not usable: %v", err)
		a.dir = brokenDir{err: err}
		return a
	}
	a.o = o
	return a
}

// Name is the configuration keyword of the back end.
func (a *ldapAuthenticator) Name() string { return AuthLDAP }

// enabled says whether the back end can be consulted at all.
func (a *ldapAuthenticator) enabled() bool {
	return a.dir != nil || len(a.o.urls) > 0
}

// Authenticate looks the account up and then verifies the password by binding as
// it.
//
// The order is deliberate: the lookup (with the service account) also produces
// the group list, so the expensive part - the caller's own bind, on a fresh
// connection - is the last thing done, and on a directory that is merely slow the
// login fails without holding a worker.
func (a *ldapAuthenticator) Authenticate(ctx AuthContext) (Identity, error) {
	var id Identity
	if !a.enabled() {
		return id, AuthUnavailablef("ldap is not configured")
	}
	name := TrimSpaceASCII(ctx.User)
	if name == "" {
		return id, ErrUnknownUser
	}
	if ctx.Password == "" {
		// Never send an empty password: on a directory that accepts it that is an
		// unauthenticated bind, i.e. a login.
		return id, ErrBadPassword
	}
	dir := a.dir
	if dir == nil {
		p, err := getLdapPool(a.o)
		if err != nil {
			return id, err
		}
		dir = p
	}
	return a.login(dir, ctx.S, name, ctx.Password)
}

// login is Authenticate with the directory injected, so that the tests can run
// the whole decision path against a fake directory.
func (a *ldapAuthenticator) login(dir LdapDir, s *Server, user, password string) (Identity, error) {
	var id Identity
	o := a.o
	name := TrimSpaceASCII(user)

	// 1. Find the entry, with its groups.
	entry, url, err := ldapFindUser(o, dir, name)
	if err != nil {
		return id, err
	}

	// 2. Bind as that entry, on a connection that is closed on the way out so
	//    that nothing here keeps the caller's secret.
	bindDN := entry.DN
	if bindDN == "" {
		names := ldapBindNames(o, name)
		if len(names) == 0 {
			return id, AuthUnavailablef("the ldap entry of %s has no distinguish name", ldapLogToken(name))
		}
		bindDN = names[0]
	}
	bc, err := dir.BindFresh(url, bindDN, password)
	if err == nil && bc != nil {
		_ = bc.Close()
	}
	if err != nil {
		if o.bindAsName {
			// Without a search the DN was guessed; try the other spellings the
			// configuration describes (UPN, DOMAIN\user, the suffix's RDN).
			for _, cand := range ldapBindNames(o, name) {
				if EqualFold(cand, bindDN) {
					continue
				}
				alt, err2 := dir.BindFresh(url, cand, password)
				if err2 == nil {
					if alt != nil {
						_ = alt.Close()
					}
					bindDN, err = cand, nil
					break
				}
				if isBadPasswordError(err2) {
					err = err2
					continue
				}
				if err == nil || !isBadPasswordError(err) {
					err = err2
				}
			}
		}
		if err != nil {
			if isBadPasswordError(err) {
				return id, ErrBadPassword
			}
			return id, err
		}
	}

	// 3. Account status, then the group gate. The status is checked after the
	//    bind on purpose: a disabled account with the right password is reported
	//    as "not allowed here" (which is true and which the operator can act on),
	//    while an account with the wrong password stays "wrong password".
	if off, why := ldapUserDisabled(entry); off {
		logS(s, "golog auth: ldap account %s may not log in: %s", ldapLogToken(name), why)
		return id, ErrUnknownUser
	}
	id = ldapIdentityFromEntry(o, entry, name, url)
	if o.loginGroup != "" && !id.Admin {
		groups := id.Groups
		if o.groupBaseDN != "" {
			// memberOf is not maintained everywhere; the group base is the
			// fallback, and it is also how a site whose groups are plain names
			// (posixGroup style) expresses membership.
			if extra, err := ldapGroupsFromBase(o, dir, id, entry); err == nil {
				groups = mergeGroups(groups, extra)
			} else {
				logS(s, "golog auth: ldap group search failed for %s: %v", ldapLogToken(name), err)
			}
		}
		if !ldapGroupMatches(groups, o.loginGroup) {
			// The password is right but this site does not want the account in
			// golog. Saying "unknown user" keeps the reason in the log rather
			// than in the browser.
			logS(s, "golog auth: ldap user %s is not a member of the login group %s",
				ldapLogToken(name), ldapLogToken(o.loginGroup))
			return id, ErrUnknownUser
		}
		id.Groups = groups
	}
	if s != nil {
		if id.Admin = s.IdentityIsAdmin(id); false {
			id.Admin = false
		}
	}
	return id, nil
}

// isBadPasswordError reports the two spellings of "the directory rejected this
// secret": the sentinel and the service-account error built by the dialer.
func isBadPasswordError(err error) bool {
	return errors.Is(err, ErrBadPassword)
}

// ldapGroupsFromBase searches the group base for groups that hold this user, and
// returns their names. The user is matched by DN, which is what the member
// attribute holds, and by login name, which is what a posixGroup holds.
func ldapGroupsFromBase(o ldapOptions, dir LdapDir, id Identity, entry *ldap.Entry) ([]string, error) {
	var parts []string
	if entry != nil && entry.DN != "" {
		parts = append(parts, "("+o.groupMemberAttr+"="+ldap.EscapeFilter(entry.DN)+")")
	}
	if id.Name != "" {
		parts = append(parts, "(memberUid="+ldap.EscapeFilter(id.Name)+")")
	}
	if len(parts) == 0 {
		return nil, nil
	}
	filter := "(|" + strings.Join(parts, "") + ")"
	entries, err := dir.Search(o.groupBaseDN, filter, ldap.ScopeWholeSubtree,
		[]string{"cn", "name", "gid", o.groupMemberAttr, "memberUid"})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e == nil {
			continue
		}
		name := TrimSpaceASCII(e.GetAttributeValue("cn"))
		if name == "" {
			name = TrimSpaceASCII(e.GetAttributeValue("name"))
		}
		if name == "" {
			name = ldapFirstRDNValue(e.DN)
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

// mergeGroups joins two group lists, keeping the order of the first and
// de-duplicating case-insensitively.
func mergeGroups(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{a, b} {
		for _, g := range list {
			g = TrimSpaceASCII(g)
			if g == "" || seen[strings.ToLower(g)] {
				continue
			}
			seen[strings.ToLower(g)] = true
			out = append(out, g)
		}
	}
	return out
}

// ldapFindUser finds the entry of a user name, with the service account when one
// is configured and with the caller's own bind otherwise. It returns the entry and
// the URL it was found on, so that the user's bind goes to the same server.
func ldapFindUser(o ldapOptions, dir LdapDir, name string) (*ldap.Entry, string, error) {
	if o.bindAsName {
		// No search at all: the bind identity says it all. A synthetic entry
		// carries the typed name so that the mapping has something to work on;
		// groups and account status are not available in this mode, which the
		// login group gate then cannot use - and says so.
		names := ldapBindNames(o, name)
		if len(names) == 0 {
			return nil, "", AuthUnavailablef("cannot build an ldap bind identity for %s", ldapLogToken(name))
		}
		url := ""
		if len(o.urls) > 0 {
			url = o.urls[0]
		}
		return ldap.NewEntry(names[0], map[string][]string{}), url, nil
	}
	if o.baseDN == "" {
		return nil, "", AuthUnavailablef(`the ldap lookup needs "Ldap base dn"`)
	}
	s := newDirSearcher(o, dir)
	entries, url, err := s.search(o.baseDN, ldapUserFilter(o, name), o.baseScope, ldapSearchAttributes(o))
	if err != nil {
		return nil, "", err
	}
	switch {
	case len(entries) == 0:
		return nil, "", ErrUnknownUser
	case len(entries) == 1:
		return entries[0], url, nil
	}
	// Several accounts match (an alias, or a UPN in one tree plus a
	// sAMAccountName in another). Prefer the one whose login attribute equals the
	// typed name; anything else is a coin toss and must not pick an account.
	best := ldapPickBestEntry(o, entries, name)
	if best == nil {
		return nil, "", AuthUnavailablef("the ldap search for %s is ambiguous (%d entries)",
			ldapLogToken(name), len(entries))
	}
	return best, url, nil
}

// ldapPickBestEntry picks the entry whose login attribute equals the typed name;
// nil when none does (the caller then reports the ambiguity rather than guessing).
func ldapPickBestEntry(o ldapOptions, entries []*ldap.Entry, name string) *ldap.Entry {
	var first *ldap.Entry
	for _, e := range entries {
		if e == nil || e.DN == "" {
			continue
		}
		if first == nil {
			first = e
		}
		for _, attr := range []string{o.userAttr, "sAMAccountName", "uid", "userPrincipalName", "cn"} {
			if attr == "" {
				continue
			}
			for _, v := range e.GetAttributeValues(attr) {
				if EqualFold(TrimSpaceASCII(v), name) {
					return e
				}
			}
		}
	}
	n := 0
	for _, e := range entries {
		if e != nil && e.DN != "" {
			n++
		}
	}
	if n == 1 {
		return first
	}
	return nil
}

// dirSearcher runs a search on a directory: dial (at most once per URL), bind the
// service account when there is one, search, close. It remembers which URL
// answered so that the caller's bind goes to the same server.
type dirSearcher struct {
	o     ldapOptions
	dir   LdapDir
	bound string
	url   string
}

func newDirSearcher(o ldapOptions, dir LdapDir) *dirSearcher {
	return &dirSearcher{o: o, dir: dir}
}

// search tries the URLs in order. A pooled implementation returns the entries
// through the pool; the searcher never keeps the connection.
func (s *dirSearcher) search(baseDN, filter string, scope int, attrs []string) ([]*ldap.Entry, string, error) {
	var last error
	for _, url := range s.o.urls {
		if s.o.bindDN != "" {
			// The service account has to be in force for this search. The pool
			// keeps one connection per bind identity, so this is one borrow, not
			// a handshake.
			if err := s.dir.Bind(s.o.bindDN, s.o.bindPassword); err != nil {
				if isBadPasswordError(err) {
					// The service account's own password is wrong: no other
					// server of the forest will like it either.
					return nil, "", AuthUnavailablef("ldap service account %s: wrong password",
						ldapLogToken(s.o.bindDN))
				}
				last = err
				continue
			}
			s.bound = s.o.bindDN
		}
		entries, err := s.dir.Search(baseDN, filter, scope, attrs)
		if err != nil {
			if ldapResultCode(err) == ldap.LDAPResultNoSuchObject {
				// A base DN that does not exist on this server is the most common
				// configuration mistake by a wide margin, so it is named.
				return nil, "", AuthUnavailablef("ldap base %s not found on %s",
					ldapLogToken(baseDN), ldapLogToken(url))
			}
			last = err
			continue
		}
		s.url = url
		return entries, url, nil
	}
	if last == nil {
		last = AuthUnavailablef("no ldap server answered")
	}
	return nil, "", last
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

// ldapError maps a directory error onto a login error: "that secret is wrong" to
// ErrBadPassword, everything else to ErrAuthUnavailable with a message that is
// useful in the log and contains nothing sensitive.
func ldapError(err error) error {
	if err == nil {
		return nil
	}
	if isLdapBadCreds(err) {
		return fmt.Errorf("%w: %v", ErrBadPassword, err)
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		switch le.ResultCode {
		case ldap.LDAPResultInvalidCredentials,
			ldap.LDAPResultStrongAuthRequired,
			ldap.LDAPResultAuthMethodNotSupported,
			ldap.LDAPResultAuthUnknown,
			ldap.LDAPResultConstraintViolation,
			ldap.LDAPResultUnwillingToPerform:
			// An empty password, a server that demands a signed or encrypted
			// bind, an unsupported mechanism. None of them is "wrong password",
			// and saying so is what stops an operator from disabling an account
			// that is perfectly fine.
			return AuthUnavailablef("ldap bind refused: %s (result %d) - if the account has no password, give it one; "+
				"if the server demands a secure bind, use ldaps:// or Ldap starttls",
				ldapResultName(le.ResultCode), le.ResultCode)
		case ldap.LDAPResultNoSuchObject:
			return ErrUnknownUser
		case ldap.LDAPResultInsufficientAccessRights:
			return AuthUnavailablef("the ldap search is not allowed for the configured bind dn (result %d)",
				le.ResultCode)
		case ldap.LDAPResultOperationsError,
			ldap.LDAPResultNoSuchAttribute,
			ldap.LDAPResultInvalidDNSyntax,
			ldap.LDAPResultFilterError,
			ldap.LDAPResultAttributeOrValueExists,
			ldap.LDAPResultObjectClassViolation:
			return AuthUnavailablef("the ldap request was rejected: %s (result %d) - check the filter and attribute configuration",
				ldapResultName(le.ResultCode), le.ResultCode)
		}
	}
	return AuthUnavailablef("ldap error: %v", err)
}

// isLdapBadCreds says that the directory answered "that password is wrong" - and
// nothing else. Only result code 49 whose message carries no explanation counts:
// every 49 that does carry one (password expired, account locked, account
// disabled, must change password) is something an operator has to see, and
// turning it into a wrong-password message would tell the user to keep typing.
func isLdapBadCreds(err error) bool {
	var le *ldap.Error
	if !errors.As(err, &le) || le == nil || le.ResultCode != ldap.LDAPResultInvalidCredentials {
		return false
	}
	msg := ""
	if le.Err != nil {
		msg = le.Err.Error()
	}
	msg += " " + le.MatchedDN
	low := strings.ToLower(msg)
	for _, marker := range []string{"data ", "constraint", "expired", "locked", "disabled",
		"changed", "notice", "reason", "000002", "v14", "v22", "v512", "v513", "v701", "v773", "v775"} {
		if strings.Contains(low, marker) {
			return false
		}
	}
	return true
}

// ldapResultCode is the result code of an LDAP error, or 0.
func ldapResultCode(err error) uint16 {
	var le *ldap.Error
	if errors.As(err, &le) && le != nil {
		return le.ResultCode
	}
	return 0
}

// ldapResultName is the human name of a result code, from the vendored package.
func ldapResultName(code uint16) string {
	if n, ok := ldap.LDAPResultCodeMap[code]; ok && n != "" {
		return n
	}
	return "unknown result"
}

// ldapLogToken makes a value safe for one log line: no blanks and no control
// characters, so that a user name typed at the login form cannot inject a second
// line into the daemon log (which is what fail2ban reads).
func ldapLogToken(s string) string { return failBanToken(s) }

// AuthDescription is the one-line summary of the back end for the status page. It
// names the servers, the base and the filter, and never a password: the bind
// password and the CA bundle path's contents stay out of the page.
func (a *ldapAuthenticator) AuthDescription() string {
	if !a.enabled() {
		if a.dir != nil {
			if b, ok := a.dir.(brokenDir); ok && b.err != nil {
				return b.err.Error()
			}
		}
		return "not configured"
	}
	parts := []string{
		"servers " + strings.Join(a.o.urls, " "),
		`base "` + a.o.baseDN + `"`,
		"user attribute " + a.o.userAttr,
	}
	if a.o.bindDN != "" {
		parts = append(parts, "service account "+ldapLogToken(a.o.bindDN))
	} else if a.o.bindAsName {
		parts = append(parts, "bind without search")
	} else {
		parts = append(parts, "anonymous lookup")
	}
	if a.o.loginGroup != "" {
		parts = append(parts, "login group "+ldapLogToken(a.o.loginGroup))
	}
	if a.o.adminGroup != "" {
		parts = append(parts, "admin group "+ldapLogToken(a.o.adminGroup))
	}
	if a.o.nestedGroups {
		parts = append(parts, "nested groups yes")
	}
	if a.o.startTLS {
		parts = append(parts, "StartTLS")
	}
	if a.o.skipVerify {
		parts = append(parts, "certificate checks OFF")
	}
	parts = append(parts, "timeouts "+a.o.dialTimeout.String()+"/"+a.o.ioTimeout.String())
	return strings.Join(parts, ", ")
}

// Close releases the connections this back end borrowed from the pool. The pool
// itself is shared and stays; it is closed when the last user goes away, see
// CloseLdapPools.
func (a *ldapAuthenticator) Close() error { return nil }

// ldapPoolCacheKey identifies the pool of one directory configuration. Two logbook
// scopes that name the same directory share one pool; a different service account
// is a different pool, because a pooled connection carries that identity.
func ldapPoolCacheKey(o ldapOptions) string {
	return strings.Join(o.urls, " ") + "|" + strings.ToLower(TrimSpaceASCII(o.bindDN))
}
