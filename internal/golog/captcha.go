// golog - a self-contained CAPTCHA for the signup form.
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// No third-party service and no cookie is involved. A challenge is a token the
// server can check without storing it:
//
//	token  = base64url( expiry(8) | nonce(12) | HMAC(secret, expiry|nonce)[:16] )
//	answer = 5 characters derived from HMAC(secret, "answer"|nonce)
//
// The page shows the answer as a distorted image (/captcha?t=<token>, rotated
// glyphs, noise lines and dots; no text anywhere in the HTML) and sends the token
// back in a hidden field. The server recomputes the answer from the nonce, so the
// token alone reveals nothing. A token is good for ten minutes and for ONE check
// (a wrong answer burns it too), and images are rate limited per client address.
// The secret is random per process: a restart invalidates open forms, nothing
// else.
//
// An image CAPTCHA keeps out scripts that fill in forms; it is not proof against a
// human or a solving service, which is why signup also needs an administrator's
// approval (see signup).
package golog

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	captchaAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // no 0 O 1 I
	captchaLength   = 5
	captchaTTL      = 10 * time.Minute
)

var captchaState struct {
	once   sync.Once
	secret [32]byte
	mu     sync.Mutex
	used   map[string]time.Time // nonce -> expiry of the token it came from
	hits   map[string]*captchaRate
}

type captchaRate struct {
	start time.Time
	n     int
}

func captchaInit() {
	captchaState.once.Do(func() {
		if _, err := rand.Read(captchaState.secret[:]); err != nil {
			panic("golog: no entropy for the captcha secret: " + err.Error())
		}
		captchaState.used = map[string]time.Time{}
		captchaState.hits = map[string]*captchaRate{}
	})
}

func captchaMAC(parts ...[]byte) []byte {
	m := hmac.New(sha256.New, captchaState.secret[:])
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// captchaAnswer derives the answer of a challenge from its nonce.
func captchaAnswer(nonce []byte) string {
	sum := captchaMAC([]byte("answer"), nonce)
	out := make([]byte, captchaLength)
	for i := range out {
		out[i] = captchaAlphabet[int(sum[i])%len(captchaAlphabet)]
	}
	return string(out)
}

// NewCaptchaToken returns a fresh challenge token.
func NewCaptchaToken(now time.Time) string {
	captchaInit()
	b := make([]byte, 8+12)
	binary.BigEndian.PutUint64(b, uint64(now.Add(captchaTTL).Unix()))
	if _, err := rand.Read(b[8:]); err != nil {
		panic("golog: no entropy for a captcha: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(append(b, captchaMAC(b)[:16]...))
}

// parseCaptchaToken checks the authenticity and the age of a token and returns
// its nonce and expiry.
func parseCaptchaToken(tok string, now time.Time) (nonce []byte, exp time.Time, ok bool) {
	captchaInit()
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || 8+12+16 != len(raw) {
		return nil, time.Time{}, false
	}
	if 1 != subtle.ConstantTimeCompare(captchaMAC(raw[:20])[:16], raw[20:]) {
		return nil, time.Time{}, false
	}
	exp = time.Unix(int64(binary.BigEndian.Uint64(raw)), 0)
	if !now.Before(exp) {
		return nil, time.Time{}, false
	}
	return raw[8:20], exp, true
}

// CheckCaptcha verifies an answer. The token is used up by the check, right or
// wrong: one look at the image is one attempt.
func CheckCaptcha(tok, answer string, now time.Time) bool {
	nonce, exp, ok := parseCaptchaToken(tok, now)
	if !ok {
		return false
	}
	captchaState.mu.Lock()
	for n, e := range captchaState.used { // forget what has expired anyway
		if !now.Before(e) {
			delete(captchaState.used, n)
		}
	}
	key := string(nonce)
	if _, seen := captchaState.used[key]; seen || len(captchaState.used) > 100000 {
		captchaState.mu.Unlock()
		return false
	}
	captchaState.used[key] = exp
	captchaState.mu.Unlock()
	want := captchaAnswer(nonce)
	got := strings.ToUpper(strings.TrimSpace(answer))
	return 1 == subtle.ConstantTimeCompare([]byte(want), []byte(got))
}

// resetCaptchaRate forgets the per-address counters (tests share the process).
func resetCaptchaRate() {
	captchaInit()
	captchaState.mu.Lock()
	captchaState.hits = map[string]*captchaRate{}
	captchaState.mu.Unlock()
}

// captchaAllow rate limits the image: 40 per client address and minute.
func captchaAllow(ip string, now time.Time) bool {
	captchaInit()
	captchaState.mu.Lock()
	defer captchaState.mu.Unlock()
	r := captchaState.hits[ip]
	if nil == r || now.Sub(r.start) > time.Minute {
		if len(captchaState.hits) > 50000 {
			captchaState.hits = map[string]*captchaRate{}
		}
		r = &captchaRate{start: now}
		captchaState.hits[ip] = r
	}
	r.n++
	return r.n <= 40
}

// ---------------------------------------------------------------------------
// the image
// ---------------------------------------------------------------------------

// glyphs is a 5x7 bitmap font for captchaAlphabet.
var glyphs = map[byte][7]string{
	'2': {".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"},
	'3': {"####.", "....#", "....#", ".###.", "....#", "....#", "####."},
	'4': {"...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."},
	'5': {"#####", "#....", "####.", "....#", "....#", "#...#", ".###."},
	'6': {".###.", "#....", "#....", "####.", "#...#", "#...#", ".###."},
	'7': {"#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."},
	'8': {".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."},
	'9': {".###.", "#...#", "#...#", ".####", "....#", "....#", ".###."},
	'A': {".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"},
	'B': {"####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."},
	'C': {".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."},
	'D': {"####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."},
	'E': {"#####", "#....", "#....", "####.", "#....", "#....", "#####"},
	'F': {"#####", "#....", "#....", "####.", "#....", "#....", "#...."},
	'G': {".###.", "#...#", "#....", "#.###", "#...#", "#...#", ".####"},
	'H': {"#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"},
	'J': {"..###", "...#.", "...#.", "...#.", "...#.", "#..#.", ".##.."},
	'K': {"#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"},
	'L': {"#....", "#....", "#....", "#....", "#....", "#....", "#####"},
	'M': {"#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"},
	'N': {"#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#", "#...#"},
	'P': {"####.", "#...#", "#...#", "####.", "#....", "#....", "#...."},
	'Q': {".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"},
	'R': {"####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"},
	'S': {".####", "#....", "#....", ".###.", "....#", "....#", "####."},
	'T': {"#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."},
	'U': {"#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."},
	'V': {"#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."},
	'W': {"#...#", "#...#", "#...#", "#.#.#", "#.#.#", "##.##", "#...#"},
	'X': {"#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"},
	'Y': {"#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."},
	'Z': {"#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"},
}

// CaptchaPNG renders the challenge of a token as a distorted PNG; ok is false for
// an invalid or expired token.
func CaptchaPNG(tok string, now time.Time) ([]byte, bool) {
	nonce, _, ok := parseCaptchaToken(tok, now)
	if !ok {
		return nil, false
	}
	text := captchaAnswer(nonce)
	// The pictures of one token are the same every time (the noise is derived from
	// the nonce), so reloading the image does not give a second look.
	rnd := newCaptchaRand(captchaMAC([]byte("noise"), nonce))

	const scale, cellW, w, h = 5, 5 * 5, 190, 64
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			v := uint8(225 + rnd.intn(30))
			img.Set(x, y, color.RGBA{v, v, uint8(225 + rnd.intn(30)), 255})
		}
	}
	for i := 0; i < 4; i++ { // noise lines
		x0, y0, x1, y1 := rnd.intn(w), rnd.intn(h), rnd.intn(w), rnd.intn(h)
		c := color.RGBA{uint8(80 + rnd.intn(120)), uint8(80 + rnd.intn(120)), uint8(80 + rnd.intn(120)), 255}
		drawLine(img, x0, y0, x1, y1, c)
	}
	x := 14
	for i := 0; i < len(text); i++ {
		g := glyphs[text[i]]
		ang := (float64(rnd.intn(31)) - 15) * math.Pi / 180 // -15..+15 degrees
		cy := float64(h)/2 + float64(rnd.intn(11)) - 5
		cx := float64(x) + cellW/2
		ink := color.RGBA{uint8(rnd.intn(90)), uint8(rnd.intn(90)), uint8(rnd.intn(90)), 255}
		sin, cos := math.Sin(ang), math.Cos(ang)
		for py := int(cy) - 26; py <= int(cy)+26; py++ {
			for px := int(cx) - 20; px <= int(cx)+20; px++ {
				// inverse rotation into the glyph grid
				dx, dy := float64(px)-cx, float64(py)-cy
				gx := (dx*cos+dy*sin)/scale + 2.5
				gy := (-dx*sin+dy*cos)/scale + 3.5
				ix, iy := int(math.Floor(gx)), int(math.Floor(gy))
				if ix >= 0 && ix < 5 && iy >= 0 && iy < 7 && '#' == g[iy][ix] && px >= 0 && px < w && py >= 0 && py < h {
					img.Set(px, py, ink)
				}
			}
		}
		x += cellW + 8 + rnd.intn(4)
	}
	for i := 0; i < 140; i++ { // dots over the text
		img.Set(rnd.intn(w), rnd.intn(h), color.RGBA{uint8(rnd.intn(160)), uint8(rnd.intn(160)), uint8(rnd.intn(160)), 255})
	}
	for i := 0; i < 2; i++ { // lines over the text as well
		drawLine(img, rnd.intn(w), rnd.intn(h), rnd.intn(w), rnd.intn(h), color.RGBA{110, 110, 110, 255})
	}
	enc := &pngBuffer{}
	if err := png.Encode(enc, img); err != nil {
		return nil, false
	}
	return enc.b, true
}

type pngBuffer struct{ b []byte }

func (p *pngBuffer) Write(d []byte) (int, error) { p.b = append(p.b, d...); return len(d), nil }

func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx, dy := x1-x0, y1-y0
	n := int(math.Max(math.Abs(float64(dx)), math.Abs(float64(dy))))
	for i := 0; i <= n && n > 0; i++ {
		x, y := x0+dx*i/n, y0+dy*i/n
		img.Set(x, y, c)
		img.Set(x, y+1, c)
	}
}

// captchaRand is a small deterministic generator seeded from a MAC, so that the
// same token always produces the same picture.
type captchaRand struct {
	seed []byte
	n    int
}

func newCaptchaRand(seed []byte) *captchaRand { return &captchaRand{seed: seed} }

func (r *captchaRand) intn(max int) int {
	if max <= 1 {
		return 0
	}
	// a counter-mode stream of HMAC blocks
	blk := captchaMAC(r.seed, []byte{byte(r.n >> 24), byte(r.n >> 16), byte(r.n >> 8), byte(r.n)})
	r.n++
	return int(binary.BigEndian.Uint32(blk)&0x7fffffff) % max
}

// captchaRoute serves /captcha?t=<token> (relative to the base path).
func (s *Server) captchaRoute(q *Request) bool {
	if "/captcha" != strings.TrimRight(q.path, "/") {
		return false
	}
	q.parseParams()
	ip := s.LoginSourceIP(q.R)
	if !captchaAllow(ip, time.Now()) {
		q.W.Header().Set("Retry-After", "60")
		http.Error(q.W, "too many requests", http.StatusTooManyRequests)
		return true
	}
	data, ok := CaptchaPNG(q.Param("t"), time.Now())
	if !ok {
		http.Error(q.W, "not found", http.StatusNotFound)
		return true
	}
	h := q.W.Header()
	h.Set("Content-Type", "image/png")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	q.W.Write(data)
	return true
}
