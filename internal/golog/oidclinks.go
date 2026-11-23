package golog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// oidcLinks remembers which provider subject ("sub") first logged in under a
// local account name. A later login under the same name must carry the same
// subject: a provider that lets users pick preferred_username, or reuses a
// name, then cannot take over the account.
var oidcLinks struct {
	mu   sync.Mutex
	data map[string]string // "issuer\x00name" -> sub
	path string
}

func (s *Server) oidcLinksPath() string {
	dir := s.DataDir
	if "" == dir && "" != s.ConfigPath {
		dir = filepath.Dir(s.ConfigPath)
	}
	if "" == dir {
		return ""
	}
	return filepath.Join(dir, "oidc-links.json")
}

// oidcCheckLink binds name to sub on first use and refuses a different sub
// afterwards. A local account that exists but was never linked is refused unless
// "OIDC link existing = 1": otherwise any provider user named like an existing
// local account (an administrator, say) would become that account.
func (s *Server) oidcCheckLink(set *oidcSettings, name, sub string) error {
	if "" == sub {
		return errors.New("the token has no subject")
	}
	oidcLinks.mu.Lock()
	defer oidcLinks.mu.Unlock()
	path := s.oidcLinksPath()
	if nil == oidcLinks.data || oidcLinks.path != path {
		oidcLinks.data = map[string]string{}
		oidcLinks.path = path
		if "" != path {
			if b, err := os.ReadFile(path); err == nil {
				_ = json.Unmarshal(b, &oidcLinks.data)
			}
		}
	}
	key := set.Issuer + "\x00" + name
	if have, ok := oidcLinks.data[key]; ok {
		if have != sub {
			return errors.New("the account " + name + " is linked to another provider subject")
		}
		return nil
	}
	if s.Pwd != nil && s.Pwd.User(name) != nil && !s.Config.GetBool(ConfigScope{Group: "global"}, "OIDC link existing") {
		return errors.New("a local account named " + name + " exists and is not linked to this provider (OIDC link existing = 1 links it on first login)")
	}
	oidcLinks.data[key] = sub
	if "" != path {
		if b, err := json.Marshal(oidcLinks.data); err == nil {
			if err := writeFileAtomic(path, b, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}
