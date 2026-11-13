package main

// The SMTP password written by -t <pwd> into the configuration file.
//
// The C program does
//
//	do_crypt(str, smtp_pwd, sizeof(smtp_pwd));      // elogd.cxx main()
//	create_password("global", "SMTP Password", smtp_pwd);
//
// where do_crypt() is elogd's wrapper around the bundled sha256-crypt:
//
//	void do_crypt(const char *s, char *d, int size) {
//	   strlcpy(d, sha256_crypt(s, "$5$") + 4, size);   // "$5$" prefix dropped
//	}
//
// so the value stored in elogd.cfg is "<salt>$<hash>" of the sha256-crypt
// scheme - which is exactly what elog.DoCrypt produces, so a configuration
// written by either program is read by the other. The reader also accepts a
// plain-text value (which is what a hand-written configuration normally has), so
// a deployment is not forced to encrypt anything to get started.
//
// This is obfuscation, not protection: the file must not be world-readable for
// the "SMTP Password" key to mean anything, which is also true of the original.

import (
	"github.com/samuraiii/golog/internal/elog"
)

// storeSMTPPassword is the -t action: hash the password the way the C program
// does and write it into [global] as "SMTP Password".
func storeSMTPPassword(cfg *elog.Config, cfgPath, pwd string) error {
	if err := cfg.SetParam("global", "SMTP Password", elog.DoCrypt(pwd)); err != nil {
		return err
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	elog.Logf("SMTP password written to %s", cfgPath)
	return nil
}
