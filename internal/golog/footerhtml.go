package golog

import (
	"html"
	"regexp"
	"strings"
)

// footerHint is shown wherever the Footer setting is edited or listed.
const footerHint = "only the tags <a href>, <b>, <i>, <u> and <img src> are kept in the footer; " +
	"any other tag is shown as text and any other attribute is dropped"

// sanitizeFooterHTML lets the "Footer" setting carry the few tags a page footer
// needs and nothing else: <a href>, <b>, <i>, <u> and <img src>. Anything else
// (scripts, styles, forms, event handlers, other attributes, other tags) is
// written out as plain text, so it is visible but cannot run.
//
//	a    href (http, https, mailto or a path on this site), title
//	img  src (http, https or a path on this site), alt, title, width, height
//	b i u  no attributes
func sanitizeFooterHTML(in string) string {
	var out strings.Builder
	rest := in
	for {
		i := strings.IndexByte(rest, '<')
		if i < 0 {
			out.WriteString(HTMLEscape(rest))
			break
		}
		out.WriteString(HTMLEscape(rest[:i]))
		rest = rest[i:]
		m := footerTag.FindStringSubmatch(rest)
		if nil == m {
			out.WriteString("&lt;")
			rest = rest[1:]
			continue
		}
		whole, closing, name, attrs := m[0], "/" == m[1], strings.ToLower(m[2]), m[3]
		rest = rest[len(whole):]
		switch name {
		case "b", "i", "u":
			if closing {
				out.WriteString("</" + name + ">")
			} else {
				out.WriteString("<" + name + ">")
			}
		case "a":
			if closing {
				out.WriteString("</a>")
				continue
			}
			out.WriteString("<a" + footerAttrs(attrs, map[string]bool{"href": true, "title": true}) + ">")
		case "img":
			if closing {
				continue
			}
			out.WriteString("<img" + footerAttrs(attrs, map[string]bool{"src": true, "alt": true, "title": true, "width": true, "height": true}) + ">")
		default:
			out.WriteString(HTMLEscape(whole)) // shown as text
		}
	}
	return out.String()
}

// footerTag matches one complete tag: <name attrs>, </name> or <name attrs/>.
var footerTag = regexp.MustCompile(`^<(/?)([A-Za-z][A-Za-z0-9]*)((?:\s+[^<>]*?)?)\s*/?>`)

var footerAttr = regexp.MustCompile(`([A-Za-z][A-Za-z-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'<>=` + "`" + `]+)`)

// footerAttrs rebuilds the allowed attributes of a tag, with the values escaped
// and the URLs restricted to safe schemes.
func footerAttrs(raw string, allowed map[string]bool) string {
	var b strings.Builder
	for _, m := range footerAttr.FindAllStringSubmatch(raw, -1) {
		name := strings.ToLower(m[1])
		if !allowed[name] {
			continue
		}
		// Entities are decoded first, so that "java&#115;cript:" is judged as the
		// "javascript:" it is, and the value is escaped again on output.
		val := html.UnescapeString(strings.Trim(m[2], `"'`))
		switch name {
		case "href":
			if !footerURLOK(val, true) {
				continue
			}
		case "src":
			if !footerURLOK(val, false) {
				continue
			}
		case "width", "height":
			if !regexp.MustCompile(`^[0-9]{1,4}$`).MatchString(val) {
				continue
			}
		}
		b.WriteString(" " + name + `="` + HTMLEscape(val) + `"`)
	}
	return b.String()
}

// footerURLOK accepts http, https (and mailto for links) and a path on this
// site; "javascript:", "data:", "vbscript:" and anything else with a scheme is
// refused, also when it is hidden with entities, control characters or case.
func footerURLOK(u string, allowMail bool) bool {
	u = strings.TrimSpace(u)
	if "" == u || strings.ContainsAny(u, "\x00\r\n\t\\") {
		return false
	}
	l := strings.ToLower(u)
	switch {
	case strings.HasPrefix(l, "http://"), strings.HasPrefix(l, "https://"):
		return true
	case allowMail && strings.HasPrefix(l, "mailto:"):
		return true
	case strings.HasPrefix(u, "//"):
		return false // protocol-relative: leaves the site without a scheme to check
	case strings.HasPrefix(u, "/"):
		return true
	}
	// a relative path: no scheme before the first slash
	if i := strings.IndexAny(u, ":/?#"); i >= 0 && ':' == u[i] {
		return false
	}
	return true
}
