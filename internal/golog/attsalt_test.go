package golog

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSaltedNameShape(t *testing.T) {
	n := saltedAttachmentName("Report.PDF", "s3cret-salt", 7, 0)
	if 52 != len(n) || strings.Contains(n, ".") {
		t.Fatalf("name %q: want 52 characters and no extension", n)
	}
	if !IsSaltedName(n) {
		t.Errorf("%q is not recognised as salted", n)
	}
	// the definition: sha256 of file name (extension included) + salt + entry id
	sum := sha256.Sum256([]byte("Report.PDF" + "s3cret-salt" + "7"))
	want := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
	if n != want {
		t.Errorf("name = %q, want %q", n, want)
	}
	// every input matters
	for _, other := range []string{
		saltedAttachmentName("Report.pdf", "s3cret-salt", 7, 0),
		saltedAttachmentName("Report.PDF", "other-salt", 7, 0),
		saltedAttachmentName("Report.PDF", "s3cret-salt", 8, 0),
		saltedAttachmentName("Report.PDF", "s3cret-salt", 7, 1),
	} {
		if other == n {
			t.Error("two different inputs gave the same name")
		}
	}
	// legacy names are never mistaken for salted ones
	for _, legacy := range []string{"240430_123456_photo.jpg", "240430_123456_abcdefghijklmnopqrstuvwxyz234567abcdefgh", "photo.jpg", "x"} {
		if IsSaltedName(legacy) {
			t.Errorf("legacy name %q taken for a salted one", legacy)
		}
	}
	// safe on every file system: lower-case letters and 2-7 only
	if strings.Trim(n, "abcdefghijklmnopqrstuvwxyz234567") != "" {
		t.Errorf("name %q has characters outside a-z2-7", n)
	}
}

func pngBytes(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 99, 255})
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func uploadAs(t *testing.T, s *Server, user string, fields map[string]string, fileName string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("attachment0", fileName)
	fw.Write(content)
	mw.Close()
	r := httptest.NewRequest("POST", "/secret/", &body)
	r.Host = "logbooks.example"
	r.RemoteAddr = "192.0.2.7:4000"
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Origin", "https://logbooks.example")
	r.AddCookie(sessionFor(s, user))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestSaltedUploadEndToEnd(t *testing.T) {
	s := accessServer(t, "Salt = a-long-random-salt-value\nUse thumbs = 1\nThumbnail width = 20\nThumbnail height = 20")
	s.UseThumbs = true
	img := pngBytes(80, 40)
	w := uploadAs(t, s, "alice", map[string]string{"cmd": "Submit", "Author": "alice", "Subject": "pic", "Text": "x", "entry_id": "5"}, "My Photo.PNG", img)
	if 302 != w.Code {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	lb := s.LB("secret")
	e, err := lb.Message(5)
	if err != nil {
		t.Fatal(err)
	}
	refs := AttachmentRefs(e)
	if 1 != len(refs) {
		t.Fatalf("entry has %d attachments", len(refs))
	}
	ref := refs[0]
	want := saltedAttachmentName("My Photo.PNG", "a-long-random-salt-value", 5, 0)
	if ref.Name != want || "My Photo.PNG" != ref.Display {
		t.Fatalf("stored %q shown %q, want %q shown \"My Photo.PNG\"", ref.Name, ref.Display, want)
	}
	if _, err := os.Stat(filepath.Join(lb.DataDirFor(e.Subdir), want)); err != nil {
		t.Errorf("file not on disk under the salted name: %v", err)
	}
	if ents, _ := filepath.Glob(filepath.Join(lb.DataDirFor(e.Subdir), "*My*")); len(ents) > 0 {
		t.Errorf("a file with the original name is on disk: %v", ents)
	}
	alice := sessionFor(s, "alice")
	// the URL carries the salted name and serves the file with the type of the ORIGINAL name
	url := s.AttachmentURL("secret", e, ref)
	if url != "/secret/"+want {
		t.Errorf("AttachmentURL = %q", url)
	}
	g := do(s, "GET", url, alice)
	if 200 != g.Code || !bytes.Equal(g.Body.Bytes(), img) || "image/png" != g.Header().Get("Content-Type") {
		t.Errorf("salted URL: %d type=%q len=%d", g.Code, g.Header().Get("Content-Type"), g.Body.Len())
	}
	if !strings.Contains(g.Header().Get("Content-Disposition"), "My Photo.PNG") {
		t.Errorf("download name: %q", g.Header().Get("Content-Disposition"))
	}
	// the index URL still works, and anonymous visitors get neither
	if g := do(s, "GET", "/secret/5/1", alice); 200 != g.Code || !bytes.Equal(g.Body.Bytes(), img) {
		t.Errorf("index URL: %d", g.Code)
	}
	for _, u := range []string{url, "/secret/5/1"} {
		if g := do(s, "GET", u); bytes.Equal(g.Body.Bytes(), img) {
			t.Errorf("anonymous GET %s got the file", u)
		}
	}
	// a thumbnail is made from the content although the stored name has no extension
	th := do(s, "GET", url+"?thumb=1", alice)
	if 200 != th.Code || "image/png" != th.Header().Get("Content-Type") {
		t.Fatalf("thumbnail: %d %q", th.Code, th.Header().Get("Content-Type"))
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(th.Body.Bytes()))
	if err != nil || 20 != cfg.Width || 10 != cfg.Height {
		t.Errorf("thumbnail %v %dx%d, want 20x10 (aspect kept)", err, cfg.Width, cfg.Height)
	}
	// a second file of the same name in the same entry gets a different name
	w = uploadAs(t, s, "alice", map[string]string{"cmd": "Submit", "Author": "alice", "Subject": "pic", "Text": "x", "message_id": "5"}, "My Photo.PNG", img)
	if 302 != w.Code {
		t.Fatalf("second upload: %d", w.Code)
	}
	e, _ = lb.Message(5)
	if refs = AttachmentRefs(e); 2 != len(refs) || refs[0].Name == refs[1].Name || refs[1].Display != "My Photo.PNG" {
		t.Errorf("same name twice: %+v", refs)
	}
}

// Attachments stored by ELOG or by golog without a salt keep working, whether or
// not a salt is configured now.
func TestLegacyAttachmentsStillServed(t *testing.T) {
	for _, extra := range []string{"", "Salt = a-long-random-salt-value"} {
		s := accessServer(t, "Read users = alice\n"+extra)
		alice := sessionFor(s, "alice")
		g := do(s, "GET", "/secret/1/1", alice)
		if !strings.Contains(g.Body.String(), "ATTACHMENT-SECRET") {
			t.Errorf("%q: legacy attachment not served by index: %d", extra, g.Code)
		}
		e, _ := s.LB("secret").Message(1)
		ref := AttachmentRefs(e)[0]
		if "secret.txt" != ref.Display || "/secret/1/1" != s.AttachmentURL("secret", e, ref) {
			t.Errorf("%q: legacy ref = %+v url %q", extra, ref, s.AttachmentURL("secret", e, ref))
		}
		if g := do(s, "GET", "/secret/230102_000000_secret.txt", alice); strings.Contains(g.Body.String(), "ATTACHMENT-SECRET") {
			t.Errorf("%q: a legacy file is served by its on-disk name", extra)
		}
	}
	_ = strconv.Itoa
	_ = http.StatusOK
}

func TestThumbnailSizes(t *testing.T) {
	for _, c := range []struct{ w, h, tw, th, ew, eh int }{
		{80, 40, 20, 20, 20, 10}, {40, 80, 20, 20, 10, 20}, {10, 10, 100, 100, 10, 10}, {1000, 1, 100, 0, 100, 1},
	} {
		w, h := thumbSize(c.w, c.h, c.tw, c.th)
		if w != c.ew || h != c.eh {
			t.Errorf("thumbSize(%d,%d,%d,%d) = %dx%d, want %dx%d", c.w, c.h, c.tw, c.th, w, h, c.ew, c.eh)
		}
	}
}
