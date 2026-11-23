package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/samuraiii/golog/internal/golog"
)

// The sample parses, defines the demo logbook and the data directory, and writing
// it to a file refuses to clobber an existing one.
func TestSampleConfig(t *testing.T) {
	var out bytes.Buffer
	if 0 != sampleConfigCommand(nil, &out) || !regexp.MustCompile(`(?m)^# Salt = [a-z2-7]{32}$`).MatchString(out.String()) {
		t.Fatal("printing the sample failed")
	}
	path := filepath.Join(t.TempDir(), "golog.cfg")
	if 0 != sampleConfigCommand([]string{"-o", path}, &out) {
		t.Fatal("writing failed")
	}
	cfg, err := golog.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if v := cfg.GetString(golog.ConfigScope{Group: "global"}, "Logbook dir", ""); "./logbooks" != v {
		t.Errorf("Logbook dir = %q", v)
	}
	if v := cfg.GetString(golog.ConfigScope{Group: "Demo"}, "Attributes", ""); !strings.Contains(v, "Subject") {
		t.Errorf("Demo logbook missing: %q", v)
	}
	if 1 != sampleConfigCommand([]string{"-o", path}, &out) {
		t.Error("an existing file was overwritten without -f")
	}
	os.WriteFile(path, []byte("x"), 0o640)
	if 0 != sampleConfigCommand([]string{"-o", path, "-f"}, &out) {
		t.Error("-f did not overwrite")
	}
}

// config-update adds the options a file does not mention, as comments, leaves
// every existing line alone, keeps a backup and is idempotent.
func TestConfigUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "golog.cfg")
	orig := "# my config\n[global]\nPort = 9000\n# Salt = old-note\nSSL cert = /etc/x.pem\n\n[Demo]\nAttributes = A\n"
	os.WriteFile(path, []byte(orig), 0o640)

	var out bytes.Buffer
	if 0 != configUpdateCommand([]string{"-c", path, "-n"}, &out) {
		t.Fatal("dry run failed")
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Fatal("-n changed the file")
	}
	if 0 != configUpdateCommand([]string{"-c", path}, &out) {
		t.Fatalf("update failed: %s", out.String())
	}
	got, _ := os.ReadFile(path)
	text := string(got)
	// untouched: every original line is still there, in order
	pos := 0
	for _, line := range strings.SplitAfter(orig, "\n") {
		if "" == strings.TrimSpace(line) {
			continue
		}
		i := strings.Index(text[pos:], line)
		if i < 0 {
			t.Fatalf("original line %q lost or moved", line)
		}
		pos += i + len(line)
	}
	// an update switches nothing on: every added option is a comment
	for _, line := range strings.Split(text[strings.Index(text, "options added by"):strings.Index(text, "[Demo]")], "\n") {
		tl := strings.TrimSpace(line)
		if "" != tl && !strings.HasPrefix(tl, "#") && !strings.HasPrefix(tl, "[") && strings.Contains(tl, " = ") {
			t.Errorf("update added an active line: %q", line)
		}
	}
	if !strings.Contains(text, "# Log target = ") || !strings.Contains(text, "# OIDC issuer = ") {
		t.Error("new options not added")
	}
	if strings.Count(text, "Salt =") != 1 || strings.Count(text, "SSL cert =") != 1 || strings.Count(text, "Port =") != 1 {
		t.Errorf("an option the file already had was added again:\n%s", text)
	}
	if strings.Index(text, "# Log target = ") > strings.Index(text, "[Demo]") {
		t.Error("new options went after the logbook sections")
	}
	// the backup is the old file byte for byte
	baks, _ := filepath.Glob(path + ".bak-*")
	if 1 != len(baks) {
		t.Fatalf("backups: %v", baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != orig {
		t.Error("backup differs from the original")
	}
	// it still parses, with the same values
	cfg, err := golog.LoadConfig(path)
	if err != nil || "9000" != cfg.GetString(golog.ConfigScope{Group: "global"}, "Port", "") ||
		"A" != cfg.GetString(golog.ConfigScope{Group: "Demo"}, "Attributes", "") {
		t.Errorf("updated file reads differently: %v", err)
	}
	// second run: nothing to do, no second backup
	out.Reset()
	if 0 != configUpdateCommand([]string{"-c", path}, &out) || !strings.Contains(out.String(), "nothing to add") {
		t.Errorf("second run: %s", out.String())
	}
	if baks, _ = filepath.Glob(path + ".bak-*"); 1 != len(baks) {
		t.Errorf("an unchanged file got a backup: %v", baks)
	}
}
