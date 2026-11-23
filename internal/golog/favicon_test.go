package golog

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The logo is shown in the banner under the Base path, and the favicon is
// derived from it: a 32x32 PNG, per logbook when the logbook has its own logo.
func TestLogoAndFavicon(t *testing.T) {
	s := accessServer(t, "Read users = alice")
	dir := t.TempDir()
	s.ResourceDir = dir
	s.BasePath = "/golog"
	s.Config.Set("global", "Base path", "/golog")
	write := func(name string, w, h int, c color.Color) {
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				img.Set(x, y, c)
			}
		}
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := png.Encode(f, img); err != nil {
			t.Fatal(err)
		}
	}
	write("site.png", 200, 100, color.RGBA{255, 0, 0, 255})
	write("lab.png", 64, 64, color.RGBA{0, 0, 255, 255})
	s.Config.Set("global", "Logo", "site.png")
	s.Config.Set("secret", "Logo", "lab.png")

	alice := sessionFor(s, "alice")
	alice.Path = "/golog"
	body := do(s, "GET", "/golog/secret/", alice).Body.String()
	for _, want := range []string{`src="/golog/lab.png"`, `rel="icon" href="/golog/favicon.png?lb=secret"`} {
		if !strings.Contains(body, want) {
			t.Errorf("logbook page lacks %s", want)
		}
	}
	for _, u := range []string{"/golog/favicon.png", "/golog/favicon.png?lb=secret", "/golog/favicon.ico"} {
		w := do(s, "GET", u)
		if 200 != w.Code || "image/png" != w.Header().Get("Content-Type") {
			t.Fatalf("%s: %d %q", u, w.Code, w.Header().Get("Content-Type"))
		}
		img, err := png.Decode(w.Body)
		if err != nil || 32 != img.Bounds().Dx() || 32 != img.Bounds().Dy() {
			t.Fatalf("%s: not a 32x32 png: %v", u, err)
		}
		r, _, b, _ := img.At(16, 16).RGBA()
		if "/golog/favicon.png?lb=secret" == u && (0 != r || 0 == b) {
			t.Errorf("%s: not the logbook's logo", u)
		}
		if "/golog/favicon.png" == u && (0 == r || 0 != b) {
			t.Errorf("%s: not the instance logo", u)
		}
	}
	// a 2:1 logo is letterboxed on a transparent square
	img, _ := png.Decode(do(s, "GET", "/golog/favicon.png").Body)
	if _, _, _, a := img.At(16, 1).RGBA(); 0 != a {
		t.Error("letterbox not transparent")
	}
	// no local picture: no icon link, no icon route
	s.Config.Set("global", "Logo", "https://example.org/x.png")
	s.Config.Set("secret", "Logo", "")
	if w := do(s, "GET", "/golog/favicon.png"); 200 == w.Code {
		t.Error("favicon served without a local logo")
	}
}

// Without a "Logo" the built-in SVG logo is the banner image and the icon;
// "Logo = none" turns both off.
func TestDefaultLogo(t *testing.T) {
	s := accessServer(t, "Read users = alice")
	s.BasePath = "/golog"
	alice := sessionFor(s, "alice")
	alice.Path = "/golog"
	body := do(s, "GET", "/golog/secret/", alice).Body.String()
	for _, want := range []string{`src="/golog/golog-logo.svg"`, `rel="icon" href="/golog/golog-logo.svg"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	w := do(s, "GET", "/golog/golog-logo.svg")
	if 200 != w.Code || "image/svg+xml" != w.Header().Get("Content-Type") || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("logo route: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	s.Config.Set("global", "Logo", "none")
	body = do(s, "GET", "/golog/secret/", alice).Body.String()
	if strings.Contains(body, "golog-logo.svg") {
		t.Error("Logo = none still shows the default")
	}
}
