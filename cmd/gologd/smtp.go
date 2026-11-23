// ELOG rewritten in Go - the -t switch: store the SMTP password.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/samuraiii/golog/internal/golog"
)

// smtpPwdKey is the parameter -t writes. Upstream elogd calls it "SMTP pwdd"
// and keeps it in the configuration file (store_pwd() in elogd.cxx rewrites the
// file in place and chmods it to 0600 because the value is a credential).
const smtpPwdKey = "SMTP pwdd"

// storeSMTPPassword writes the clear-text password given with -t into the
// configuration file, then run() returns and the program exits the way the C
// program does - no logbook is opened and no port is bound.
//
// The write goes through Config.Set/Config.Save, which re-emits the file from
// the parsed model. That loses the comments of the operator's file (the C
// program splices the single line in place), so the original file is copied to
// <name>.orig first: an operator who runs -t on a hand-annotated configuration
// can still get the comments back.
func storeSMTPPassword(cfg *golog.Config, cfgPath, pwd string) error {
	if cfg == nil {
		return errors.New("no configuration loaded")
	}
	if pwd == "" {
		return errors.New("empty password")
	}
	if old, err := os.ReadFile(cfgPath); err == nil {
		// Best effort: a failure to keep the backup must not lose the new
		// password, so the error is reported but does not abort the write.
		if err := os.WriteFile(cfgPath+".orig", old, 0o600); err != nil {
			golog.Logf("warning: cannot write %s.orig: %v", cfgPath, err)
		}
	}
	cfg.Set("global", smtpPwdKey, pwd)
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("cannot write %s: %w", cfgPath, err)
	}
	// The file now holds a credential: it becomes readable by the owner only,
	// which is what store_pwd() does in the original.
	if err := os.Chmod(cfgPath, 0o600); err != nil {
		golog.Logf("warning: cannot chmod %s: %v", cfgPath, err)
	}
	golog.Logf("SMTP password written to %s", cfgPath)
	return nil
}
