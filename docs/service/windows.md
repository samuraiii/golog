# Running golog as a Windows service

Supported: Windows 11 and Windows Server 2016, 2019, 2022 and 2025 (the Go
versions golog is built with do not run on older releases). Builds exist for
386, amd64 and arm64.

From an elevated (Administrator) prompt:

```bat
mkdir C:\golog
copy gologd.exe C:\golog\
rem the arguments after "install" are the service's command line
C:\golog\gologd.exe service install -c C:\golog\golog.cfg -p 8080 -S
C:\golog\gologd.exe service start
C:\golog\gologd.exe service status
C:\golog\gologd.exe service stop
C:\golog\gologd.exe service remove
```

* The service is registered as `golog`, start type automatic, and is restarted
  after a crash (after 5 s, 30 s, 5 min).
* Give it a dedicated account with write access to the logbook directory only:
  `sc.exe config golog obj= "NT SERVICE\golog"` (a virtual account) or a managed
  service account, then grant that account Modify on the data directory.
* `-D` (detach) does not exist on Windows; the Service Control Manager is the
  supervisor. `Stop` and system shutdown shut the daemon down gracefully.
* TLS: put certificate and key in a directory only the service account can
  read; the certificate is re-read when the files change (no SIGHUP on Windows).
* Open the port in Windows Defender Firewall:
  `netsh advfirewall firewall add rule name="golog" dir=in action=allow protocol=TCP localport=8080`

NSSM or the Task Scheduler also work, but are not needed.

## Logging

A service has no console, so golog writes to the **Windows Event Log**
(Application log, source `golog`) unless `Log target` says otherwise. The source
is registered by `gologd service install`. To use a file as well:

```
[global]
Log target = eventlog, file
Log file = C:\golog\golog.log
```
