// ELOG rewritten in Go - the few entry helpers that are used across files but
// do not belong to the storage layer itself.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"strconv"
	"strings"
)

// The accessor aliases the pages use (Get2, SetHeader, AttrValue, Attr, IDnum,
// IDstr, Date) live in compat.go; only the helpers that have no other home are
// here, so that each name is declared exactly once in the package.

// IDNumber is the numeric message ID, spelled out for call sites where a bare
// e.ID() reads awkwardly.
func (e *Entry) IDNumber() int { return e.ID() }

// IDString is the plain decimal message ID as it appears in URLs.
func (e *Entry) IDString() string { return strconv.Itoa(e.ID()) }

// LockedByName is the human-readable form of the edit lock that
// display_lock_message() prints ("Jan Novak (novak)"). Two spellings occur in
// the wild: the transient "LockedByName:" header this build sets while rendering,
// and the "Locked by:" line some other builds store in the message file. Both
// are read, in that order, so a tree migrated from either shows the holder.
func (e *Entry) LockedByName() string {
	if v, ok := e.Get("LockedByName"); ok && TrimSpaceASCII(v) != "" {
		return v
	}
	if v, ok := e.Get("Locked by"); ok && TrimSpaceASCII(v) != "" {
		return v
	}
	return e.LockedBy()
}

// entryInt64 reads a numeric header such as "Attachment_size".
func entryInt64(e *Entry, key string) (int64, bool) {
	if e == nil {
		return 0, false
	}
	v, ok := e.Get(key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
