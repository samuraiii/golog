package golog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigSaveKeepsComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "golog.cfg")
	orig := `# main config - do not edit by hand
[global]
; the next two are off on purpose
# Authentication = Header
Port = 8080
Comment = old

[demo]
Attributes = Author, Subject
# keep this note
Read users = alice
`
	os.WriteFile(path, []byte(orig), 0o640)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Set("global", "Comment", "new")   // changed
	c.Set("demo", "Page Title", "Demo") // added to an existing section
	c.Set("other", "Attributes", "A")   // a new section
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	got := string(b)
	for _, keep := range []string{"# main config - do not edit by hand", "; the next two are off on purpose", "# Authentication = Header", "# keep this note", "Port = 8080", "Read users = alice"} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %q in:\n%s", keep, got)
		}
	}
	if strings.Contains(got, "Comment = old") || !strings.Contains(got, "Comment = new") {
		t.Errorf("value not rewritten in place:\n%s", got)
	}
	// the added key sits in its section, before the next section starts
	if i, j := strings.Index(got, "Page Title = Demo"), strings.Index(got, "[other]"); i < strings.Index(got, "[demo]") || i > j {
		t.Errorf("new key in the wrong place:\n%s", got)
	}
	// it reads back to the same configuration
	back, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][3]string{{"global", "Comment", "new"}, {"global", "Port", "8080"}, {"demo", "Page Title", "Demo"}, {"other", "Attributes", "A"}, {"demo", "Read users", "alice"}} {
		if v := back.GetString(ConfigScope{Group: kv[0]}, kv[1], "?"); v != kv[2] {
			t.Errorf("[%s] %s = %q, want %q", kv[0], kv[1], v, kv[2])
		}
	}
}
