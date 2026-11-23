package golog

import (
	"net/http"
	"net/url"
	"strings"
)

// mutatingCommand reports a command that changes data or configuration. Such a
// command is accepted only as a POST, and (for a request authenticated by the
// session cookie) only from a page of this site.
func mutatingCommand(cmd string) bool {
	c := strings.ToLower(strings.TrimSpace(cmd))
	for _, w := range []string{"submit", "save", "confirm", "expire", "reset", "suppress", "lock", "unlock",
		"signup", "upload", "delete", "revert", "activate", "remove", "rename", "move", "copy", "duplicate",
		"approve", "reject"} {
		if strings.Contains(c, w) {
			// The pages that only ask "really delete?" or show a form have their
			// own commands ("Delete" shows the question, "Confirm delete" acts);
			// everything with one of these words is treated as acting, except
			// the two that merely show a form.
			if "delete" == c || "revert" == c || "duplicate" == c || "signup" == c || "expire" == c || "approve users" == c {
				return false
			}
			return true
		}
	}
	return false
}

// sameSiteRequest decides, from the headers a browser adds itself, whether a
// state-changing request was started by a page of this site: Sec-Fetch-Site
// where the browser sends it, else the Origin or Referer host. A request that
// carries none of them is not from a current browser and is refused.
func sameSiteRequest(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); "" != sfs {
		return "same-origin" == sfs || "none" == sfs
	}
	for _, h := range []string{"Origin", "Referer"} {
		if v := r.Header.Get(h); "" != v && "null" != v {
			u, err := url.Parse(v)
			return err == nil && strings.EqualFold(u.Host, r.Host)
		}
	}
	return false
}

// csrfOK applies the cross-site request rules to a command. It reports false
// after having answered.
func (s *Server) csrfOK(q *Request, cmd string) bool {
	// Any POST made with the session cookie must come from this site (the
	// revert form and others post under commands that also have a GET form).
	post := http.MethodPost == q.R.Method
	if post && q.viaCookie && !sameSiteRequest(q.R) {
		s.errorf(q, http.StatusForbidden, "Cross-site request refused.")
		return false
	}
	if !mutatingCommand(cmd) {
		return true
	}
	if !post {
		s.errorf(q, http.StatusMethodNotAllowed, "The command \"%s\" must be sent with POST.", HTMLEscape(cmd))
		return false
	}
	if q.viaCookie && !sameSiteRequest(q.R) {
		s.errorf(q, http.StatusForbidden, "Cross-site request refused.")
		return false
	}
	return true
}
