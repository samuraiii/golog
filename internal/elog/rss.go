package elog

import (
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// RSS 2.0 feeds ("?cmd=RSS" and "?cmd=RSSfull")
// ---------------------------------------------------------------------------
//
// elogd emits RSS with display_message() in "feed mode": the item description
// is the entry text, the item title is the entry subject and the item link is
// the display URL. Two details that the C code got wrong and that the local
// patches fixed are deliberately handled here:
//
//   - the description used to be cut at a fixed byte count, which sliced
//     multi-byte UTF-8 characters in half and produced invalid XML (the parser
//     then dropped every item after the first non-ASCII entry). Every cut goes
//     through ShortenUTF8(), which backs off to the previous rune boundary;
//   - the whole feed is emitted as UTF-8 ("<?xml ... encoding=\"UTF-8\"?>")
//     and every value is XML-escaped, so an entry containing "<" or "&" does
//     not break the feed either.
//
// "cmd=RSS" gives the short description (first paragraph, truncated), "cmd=RSS
// full" the complete text; both are capped by the "RSS items" configuration
// key (default 20) so that a feed of a 1600-entry logbook stays small.

// showRSS renders the feed. full selects the complete entry text.
func (s *Server) showRSS(q *Request, full bool) {
	n := s.Config.GetInt(q.Cfg, "RSS items", 20)
	if n <= 0 {
		n = 20
	}
	limit := s.Config.GetInt(q.Cfg, "RSS description length", 800)
	if limit <= 0 {
		limit = 800
	}

	title := s.logbookTitle(q.Cfg.Group)
	desc := s.Config.GetString(q.Cfg, "Description", title)
	base := s.requestBaseURL(q.R)
	link := base + s.BasePath + "/" + q.Cfg.Group + "/"

	w := q.W
	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	fmt.Fprintf(w, "<rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\">\n<channel>\n")
	fmt.Fprintf(w, "  <title>%s</title>\n", xmlEscape(title))
	fmt.Fprintf(w, "  <link>%s</link>\n", xmlEscape(link))
	fmt.Fprintf(w, "  <atom:link href=%q rel=\"self\" type=\"application/rss+xml\"/>\n", xmlEscape(link))
	fmt.Fprintf(w, "  <description>%s</description>\n", xmlEscape(desc))
	fmt.Fprintf(w, "  <generator>elog %s</generator>\n", xmlEscape(Version))
	if img := s.Config.GetString(q.Cfg, "Logo", ""); img != "" {
		fmt.Fprintf(w, "  <image><url>%s</url><title>%s</title><link>%s</link></image>\n",
			xmlEscape(s.absURL(base, img)), xmlEscape(title), xmlEscape(link))
	}

	all := q.LB.Messages()
	// Newest first, like the list page.
	var shown []*Entry
	for i := len(all) - 1; i >= 0 && len(shown) < n; i-- {
		shown = append(shown, all[i])
	}
	if len(shown) > 0 {
		fmt.Fprintf(w, "  <lastBuildDate>%s</lastBuildDate>\n",
			FormatRFC2822(shown[0].DateValue()))
	}
	for _, e := range shown {
		url := base + s.entryURL(q.Cfg.Group, e.ID())
		fmt.Fprintf(w, "  <item>\n")
		fmt.Fprintf(w, "    <title>%s</title>\n", xmlEscape(orText(e.Title(), "(no subject)")))
		fmt.Fprintf(w, "    <link>%s</link>\n", xmlEscape(url))
		fmt.Fprintf(w, "    <guid isPermaLink=\"true\">%s</guid>\n", xmlEscape(url))
		fmt.Fprintf(w, "    <pubDate>%s</pubDate>\n", FormatRFC2822(e.DateValue()))
		if a := e.Author(); a != "" {
			fmt.Fprintf(w, "    <author>%s</author>\n", xmlEscape(a))
		}
		text := e.Text
		if !full {
			text = firstParagraph(text)
		}
		// The truncation bug fix: never cut inside a UTF-8 character.
		if !full {
			text = ShortenUTF8(text, limit)
		}
		fmt.Fprintf(w, "    <description>%s</description>\n", xmlEscape(strings.ToValidUTF8(text, "\uFFFD")))
		// Attributes become categories, which is what the original's
		// "Display in List"/RSS mapping effectively exposes.
		for _, a := range s.Config.AttributeNames(q.Cfg) {
			for _, v := range e.GetAll(a) {
				if strings.TrimSpace(v) != "" {
					fmt.Fprintf(w, "    <category>%s</category>\n", xmlEscape(v))
				}
			}
		}
		fmt.Fprintf(w, "  </item>\n")
	}
	fmt.Fprintf(w, "</channel>\n</rss>\n")
}

// firstParagraph is the part of an entry the short feed shows: everything up to
// the first blank line, with the HTML of an "Encoding: HTML" entry reduced to
// something readable.
func firstParagraph(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if i := strings.Index(text, "\n\n"); i >= 0 {
		text = text[:i]
	}
	return strings.TrimSpace(stripTags(text))
}

// stripTags is a deliberately small HTML remover for feed descriptions: it
// drops everything between '<' and '>', collapses blanks and turns <br>/<p>
// into line breaks. A logbook entry is not a web page; trying to be a full
// HTML parser here would only add failure modes.
func stripTags(s string) string {
	var b strings.Builder
	skip := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			skip = true
			// <br> and </p> end a line
			rest := strings.ToLower(s[i:])
			if strings.HasPrefix(rest, "<br") || strings.HasPrefix(rest, "</p") || strings.HasPrefix(rest, "<p") {
				b.WriteByte('\n')
			}
		case '>':
			skip = false
		default:
			if !skip {
				b.WriteByte(s[i])
			}
		}
	}
	out := HTMLUnescape(b.String())
	for strings.Contains(out, "  ") {
		out = strings.ReplaceAll(out, "  ", " ")
	}
	return out
}

// absURL turns a configuration value that may be a bare "/styles/logo.gif"
// into an absolute URL for the RSS <image> element.
func (s *Server) absURL(base, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	return base + "/" + strings.TrimPrefix(href, "/")
}

// atomTime is the W3C form used by the JSON/Atom endpoints; kept as a helper so
// the date formats live in one file.
func atomTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
