// ELOG rewritten in Go - mail transport.
//
// The composition of a notification and its delivery live in mailer.go (the
// canonical owner of the mail API in this package) and in smtp.go (the SMTP
// client with STARTTLS, AUTH LOGIN/PLAIN, implicit TLS and CA pinning, and
// the sendmail pipe). This compilation unit used to hold a second copy of
// that code; it carries no declarations.
//
// Copyright (c) the ELOG authors, 2000-2025.
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version. See the file COPYING for details.

package golog
