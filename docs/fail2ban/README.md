# golog fail2ban filter

gologd can do two things for fail2ban:

1. **Log every rejected login in one fixed spelling** so that fail2ban can count
   them itself. This is always on; nothing has to be configured.
2. **Ban by itself** (`Fail ban = 1`), in which case it also prints the same lines
   plus a line when it bans somebody. The golog ban is in-process; a fail2ban ban
   is a firewall rule, which is what you want in front of a reverse proxy.

## The log lines

Both go to the daemon log (stderr, or the file given with `-l`, and on Windows to
the event log when gologd is installed as a service):

```
2026-02-14 10:11:12: golog auth: login failed user=admin ip=203.0.113.7
2026-02-14 10:11:20: golog auth: banned ip=203.0.113.7 for 15m0s
2026-02-14 10:11:20: golog auth: refused login from 203.0.113.7: too many failed logins for ip 203.0.113.7
2026-02-14 10:12:01: golog auth: login throttled ip=203.0.113.7 for 10m0s after 5 failures
```

* `user=` is lower-case, blank-free and control-character-free (spaces become `_`);
  it is `-` when the attempt carried no name.
* `ip=` is the canonical address text (`-` when the daemon could not parse the
  peer address, e.g. a Unix socket).
* One rejected login is exactly one line.

## filter.d/golog-auth.conf

Put this in `/etc/fail2ban/filter.d/golog-auth.conf`:

```ini
[Definition]

# "golog auth: login failed user=<u> ip=<ip>" - emitted for every rejected login.
failregex = ^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}: golog auth: login failed user=\S* ip=<ADDR>\s*$

# Count the bans golog itself issued as well, so that fail2ban blocks at the
# firewall what golog only refuses at the application layer. Comment this line
# out if you run golog behind a proxy and only want the application log counted.
failregex = ^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}: golog auth: banned ip=<ADDR> for \S+\s*$

ignoreregex =

datepattern = ^%%Y-%%d-%%m %%H:%%M:%%S
```

`%%` is fail2ban's escape for a literal `%` in `datepattern`. If the daemon log is
wrapped by a supervisor that adds its own prefix, anchor the regexes with
`.*?` at the front instead of `^`.

## jail.d/golog-auth.conf

`/etc/fail2ban/jail.d/golog-auth.conf`:

```ini
[golog-auth]
enabled  = true
port     = 8080,8081
filter   = golog-auth
logpath  = /var/log/golog/gologd.log
maxretry = 5
findtime = 10m
bantime  = 1h
# gologd's own throttle/ban already protects the login form; the firewall ban is
# the outer layer, so it may be more generous.
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1w
# Never lock out the monitoring host or the reverse proxy.
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8
```

Test before enabling:

```sh
fail2ban-regex /var/log/golog/gologd.log /etc/fail2ban/filter.d/golog-auth.conf
```

## Which log file?

`logpath` must point at the file that contains the daemon's standard error:

* `gologd -l /var/log/golog/gologd.log ...` writes it there.
* With systemd, use `logpath = /var/log/journal/golog` (journal access) or
  `backend = systemd` in the jail.
* With `Authentication = Header` behind nginx or Apache, the *proxy* is the peer
  of gologd, so the addresses in the golog log are the proxy's. Either run the
  proxy's own fail2ban jail, or give gologd
  `Config real IP from proxy = 0` (then it logs the proxy address) and ban on the
  proxy, or set `Fail ban whitelist` to the proxy address so gologd never bans it
  and add the proxy's `X-Forwarded-For` handling (`Config real IP from proxy = 1`)
  so the *throttle* and the *ban* key on the real client - in that mode the log
  line shows the real client address too, and the filter above works unchanged.

## Relationship to the golog-internal layers

| layer | scope | survives restart | blocks before |
|---|---|---|---|
| login throttle (`Login throttle`) | in memory, minutes | no | any back end is contacted |
| fail ban (`Fail ban`) | JSON file in the data directory, hours | yes | any back end is contacted |
| fail2ban | firewall | yes (its own state) | the TCP connection |

They are independent and can be combined; all three count *rejected logins*, never
broken images or slow pages.
