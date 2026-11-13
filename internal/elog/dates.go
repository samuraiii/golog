// ELOG rewritten in Go - dates and the on-disk file-name conventions derived
// from them.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package elog

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Month names are used in the fixed-width date formats below; elogd parses
// dates by byte offset and compares 3-letter month names, so the tables are
// part of the wire format, not of the display.
var monthNames = [...]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

var dayNames = [...]string{
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
}

// FormatRFC2822 is get_rfc2822_date(): "Tue, 30 Apr 2024 12:34:56 +0200".
// It is the format stored in the "Date:" attribute of the message files, so it
// must stay byte-identical for existing entries to keep parsing.
func FormatRFC2822(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	_, offset := t.Zone()
	sign := '+'
	if offset < 0 {
		sign = '-'
		offset = -offset
	}
	return fmt.Sprintf("%s, %02d %s %04d %02d:%02d:%02d %c%02d%02d",
		dayNames[int(t.Weekday())], t.Day(), monthNames[int(t.Month())-1], t.Year(),
		t.Hour(), t.Minute(), t.Second(), sign, offset/3600, (offset/60)%60)
}

// FormatCTime is C's asctime()/ctime() layout without the newline:
// "Tue Apr 30 12:34:56 2024". elogd accepts either this or the RFC 2822 form
// and decides which one by string length (>25 => RFC 2822), so both keep their
// exact widths.
func FormatCTime(t time.Time) string {
	return fmt.Sprintf("%s %s %02d %02d:%02d:%02d %04d",
		dayNames[int(t.Weekday())], monthNames[int(t.Month())-1], t.Day(),
		t.Hour(), t.Minute(), t.Second(), t.Year())
}

// ParseDate is date_to_ltime(): it understands both stored forms (chosen by
// length, exactly like the original), plus, to be forgiving the way elogd is,
// anything net/http can parse and ISO-8601.
func ParseDate(s string) (time.Time, bool) {
	s = TrimSpaceASCII(s)
	if s == "" {
		return time.Time{}, false
	}
	// RFC 2822: "Tue, 30 Apr 2024 12:34:56 +0200" - 31 chars.
	if len(s) > 25 {
		for _, layout := range []string{
			"Mon, 02 Jan 2006 15:04:05 -0700",
			"Mon, 02 Jan 2006 15:04:05 -0700 (MST)",
			"Mon, 2 Jan 2006 15:04:05 -0700",
		} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.Local(), true
			}
		}
		if t, err := http.ParseTime(s); err == nil {
			return t.Local(), true
		}
	}
	// ctime(): "Tue Apr 30 12:34:56 2024"
	for _, layout := range []string{
		"Mon Jan _2 15:04:05 2006", "Mon Jan  2 15:04:05 2006", "Mon Jan 02 15:04:05 2006",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	// Tolerate the ISO forms used by the JSON/XML APIs and by elconv.
	for _, layout := range []string{
		"2006-01-02T15:04:05Z07:00", "2006-01-02T15:04:05", "2006-01-02 15:04:05",
		"2006-01-02", "02.01.2006 15:04:05", "02.01.2006",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// MustParseDate is ParseDate with the epoch as fallback, mirroring the many
// places where elogd carries on with a zero time.
func MustParseDate(s string) time.Time {
	if t, ok := ParseDate(s); ok {
		return t
	}
	return time.Unix(0, 0)
}

// FormatDate renders a date with an elogd strftime()-style format (the
// "Date format"/"Time format" configuration keys). Only the conversions the
// original supports are translated; unknown %x sequences are passed through,
// again like strftime on glibc would.
//
// There is no fixed output buffer here: the C version formatted into
// comment[256] and one of the applied patches was precisely about that buffer
// overflowing for a long user-supplied format string. In Go the result is a
// string, so the only limit is memory.
func FormatDate(format string, t time.Time) string {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			b.WriteByte(format[i])
			continue
		}
		i++
		switch format[i] {
		case 'a':
			b.WriteString(dayNames[int(t.Weekday())])
		case 'A':
			b.WriteString(fullDayName(t))
		case 'b', 'h':
			b.WriteString(monthNames[int(t.Month())-1])
		case 'B':
			b.WriteString(fullMonthName(t))
		case 'c':
			b.WriteString(FormatCTime(t))
		case 'd':
			b.WriteString(fmt.Sprintf("%02d", t.Day()))
		case 'e':
			b.WriteString(fmt.Sprintf("%2d", t.Day()))
		case 'H':
			b.WriteString(fmt.Sprintf("%02d", t.Hour()))
		case 'I':
			h := t.Hour() % 12
			if h == 0 {
				h = 12
			}
			b.WriteString(fmt.Sprintf("%02d", h))
		case 'j':
			b.WriteString(fmt.Sprintf("%03d", t.YearDay()))
		case 'k':
			b.WriteString(fmt.Sprintf("%2d", t.Hour()))
		case 'm':
			b.WriteString(fmt.Sprintf("%02d", int(t.Month())))
		case 'M':
			b.WriteString(fmt.Sprintf("%02d", t.Minute()))
		case 'p':
			if t.Hour() < 12 {
				b.WriteString("AM")
			} else {
				b.WriteString("PM")
			}
		case 'S':
			b.WriteString(fmt.Sprintf("%02d", t.Second()))
		case 'U', 'W':
			b.WriteString(fmt.Sprintf("%02d", (t.YearDay()+6-int(t.Weekday()))/7))
		case 'w':
			b.WriteString(fmt.Sprintf("%d", int(t.Weekday())))
		case 'x':
			b.WriteString(t.Format("01/02/06"))
		case 'X':
			b.WriteString(t.Format("15:04:05"))
		case 'y':
			b.WriteString(fmt.Sprintf("%02d", t.Year()%100))
		case 'Y':
			b.WriteString(fmt.Sprintf("%04d", t.Year()))
		case 'Z':
			z, _ := t.Zone()
			b.WriteString(z)
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(format[i])
		}
	}
	return b.String()
}

func fullMonthName(t time.Time) string {
	idx := [][2]int{
		{0, 7}, {7, 12}, {12, 17}, {17, 22}, {22, 25}, {25, 29}, {29, 33},
		{33, 39}, {39, 48}, {48, 55}, {55, 62}, {62, 70},
	}
	const names = "JanuaryFebruaryMarchAprilMayJuneJulyAugustSeptemberOctoberNovemberDecember"
	i := int(t.Month()) - 1
	if i < 0 || i >= len(idx) {
		return ""
	}
	return names[idx[i][0]:idx[i][1]]
}

func fullDayName(t time.Time) string {
	idx := [][2]int{
		{0, 6}, {6, 12}, {12, 19}, {19, 28}, {28, 36}, {36, 42}, {42, 48},
	}
	const names = "SundayMondayTuesdayWednesdayThursdayFridaySaturday"
	i := int(t.Weekday())
	if i < 0 || i >= len(idx) {
		return ""
	}
	return names[idx[i][0]:idx[i][1]]
}

// DateToFileName is the message-file name elogd derives from the entry date:
//
//	snprintf(file_name, ..., "%c%c%02d%c%ca.log",
//	         date1[14], date1[15], month, date1[5], date1[6]);
//
// where date1 is the RFC 2822 string "Tue, 30 Apr 2024 12:34:56 +0200":
// date1[14..15] are the last two digits of the year and date1[5..6] the two
// digits of the day of the month. So the file name is YYMMDDa.log - one file
// per calendar day, and "a" is a literal. The name starts with the two-digit
// year because generate_subdir_name() derives the sub-directory from those
// first two characters.
func DateToFileName(t time.Time) string {
	return fmt.Sprintf("%02d%02d%02da.log", t.Year()%100, int(t.Month()), t.Day())
}

// SubdirForFile is generate_subdir_name(): entry and attachment file names both
// start with the two-digit year, and the original maps that to the single
// sub-directory "20YY/" (or "19YY/" for years >= 80), with a trailing
// separator. Files whose name does not start with two digits cannot be
// sharded; the C code computes garbage from the raw characters in that case,
// whereas this implementation puts them in the data directory itself. That is
// the one deliberate behaviour difference in the storage layer and it only
// affects files that elogd could not have created.
func SubdirForFile(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if len(name) < 2 || name[0] < '0' || name[0] > '9' || name[1] < '0' || name[1] > '9' {
		return ""
	}
	year := int(name[0]-'0')*10 + int(name[1]-'0')
	if year < 80 {
		return "20" + strconv.Itoa(year) + "/"
	}
	return "19" + strconv.Itoa(year) + "/"
}

// FileNameTime recovers the timestamp encoded in an attachment file name
// (YYMMDD_HHMMSS_...), which the list page uses when an entry carries no Date.
func FileNameTime(name string) (time.Time, bool) {
	if !IsAttachmentName(name) {
		return time.Time{}, false
	}
	y := Atoi(name[0:2])
	mon := Atoi(name[2:4])
	d := Atoi(name[4:6])
	hh := Atoi(name[7:9])
	mm := Atoi(name[9:11])
	ss := Atoi(name[11:13])
	if y < 70 {
		y += 2000
	} else {
		y += 1900
	}
	if mon < 1 || mon > 12 || d < 1 || d > 31 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(mon), d, hh, mm, ss, 0, time.Local), true
}

// ---------------------------------------------------------------------------
// The timestamp prefix of a stored attachment name
// ---------------------------------------------------------------------------
//
// A stored attachment is named
//
//	YYMMDD_HHMMSS_<sanitised original name>
//
// which is fifteen characters of prefix, the last of them an underscore
// (the C original builds it as
//
//	sprintf(fn, "%02d%02d%02d_%02d%02d%02d_%s", yy, mo, dd, hh, mi, ss, name)
//
// and its display code shows fn + 15). attachmentPrefixLen in text.go is the
// same constant; it is repeated here only so that this file can be read on its
// own, and the two are asserted to agree by the comment below rather than by a
// second source of truth in the code.

// attachmentStampLen is len("YYMMDD_HHMMSS_").
const attachmentStampLen = attachmentPrefixLen

// IsAttachmentName recognises the timestamped form. The C code tests
// name[6]=='_' && name[13]=='_' && isdigit(name[0]) && isdigit(name[1]); this
// checks every digit position, because a name that merely looks like the form
// but holds nonsense (month 42) would otherwise round-trip through
// FileNameTime() and produce a bogus date.
func IsAttachmentName(name string) bool {
	if len(name) < attachmentStampLen {
		return false
	}
	for _, i := range []int{0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12} {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return name[6] == '_' && name[13] == '_'
}

// AttachmentName is the stored name of a new upload: the timestamp prefix plus
// the sanitised original name (the caller has already run it through
// MakeFilenamePortable, see (*Logbook).SaveAttachment in attachments.go).
func AttachmentName(stem string, when time.Time) string {
	return fmt.Sprintf("%02d%02d%02d_%02d%02d%02d_%s",
		when.Year()%100, int(when.Month()), when.Day(),
		when.Hour(), when.Minute(), when.Second(), stem)
}

// OriginalAttachmentName strips the timestamp prefix again, which is the name a
// page, a link title or a notification mail shows. Names that do not carry the
// prefix - a logbook migrated from a very old ELOG stores them as
// "<message-file name>_<name>" - keep the part after the first underscore,
// which is what the original displays for those too.
func OriginalAttachmentName(stored string) string {
	if IsAttachmentName(stored) {
		return stored[attachmentStampLen:]
	}
	if i := strings.IndexByte(stored, '_'); i > 0 && i < len(stored)-1 {
		head := stored[:i]
		if len(head) == 9 || len(head) == 11 { // 970101a.log / 20970101a.log
			if strings.HasSuffix(head, ".log") {
				return stored[i+1:]
			}
		}
	}
	return stored
}

// NextAttachmentName avoids clobbering an existing file: the original appends
// "_1" to the stem when the name is taken. exists is consulted for every
// candidate, so the caller decides what "taken" means (a stat in the data
// directory).
func NextAttachmentName(base string, exists func(string) bool) string {
	if !exists(base) {
		return base
	}
	ext := extOf(base)
	stem := strings.TrimSuffix(base, ext)
	for n := 1; n < 10000; n++ {
		cand := fmt.Sprintf("%s_%d%s", stem, n, ext)
		if !exists(cand) {
			return cand
		}
	}
	return fmt.Sprintf("%s_%d%s", stem, time.Now().UnixNano(), ext)
}

// extOf is the extension of a stored attachment name, empty when the last
// component has no dot (so that a name like "archive.tar" gains its "_1"
// before the dot, and "no_extension" gains it at the end).
func extOf(name string) string {
	slash := strings.LastIndexByte(name, '/')
	dot := strings.LastIndexByte(name, '.')
	if dot <= slash {
		return ""
	}
	return name[dot:]
}
