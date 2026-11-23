// golog - the browser tab icon, derived from the logo.
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// "Logo" (per instance in [global], per logbook in its own section) is the
// picture in the page banner. When the logo is a local PNG, JPEG or GIF file the
// favicon is made from it: scaled to fit 32x32, centred on a transparent square
// and sent as PNG. "Favicon" names a file to use instead of the logo. A real
// favicon.ico in the resource directory still wins, as before.
package golog

import (
	"bytes"
	_ "embed"
	"errors"
	"image"
	"image/draw"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The built-in logo, used when "Logo" is not set ("Logo = none" shows no logo).
//
//go:embed assets/logo.svg
var defaultLogoSVG []byte

const (
	defaultLogoName = "golog-logo.svg"
	faviconSide     = 32
)

type faviconEntry struct {
	mod  time.Time
	size int64
	png  []byte
}

var (
	faviconMu    sync.Mutex
	faviconCache = map[string]faviconEntry{}
)

// isRemoteImage reports whether v is a full URL or data URI rather than a file.
func isRemoteImage(v string) bool {
	lv := strings.ToLower(v)
	return strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") || strings.HasPrefix(lv, "data:image/")
}

// faviconFile finds the local picture the favicon is made from for a scope.
func (s *Server) faviconFile(scope ConfigScope) (string, bool) {
	for _, key := range []string{"Favicon", "Logo"} {
		v := strings.TrimSpace(s.Config.GetString(scope, key, ""))
		if "" == v || isRemoteImage(v) {
			continue
		}
		v = strings.TrimPrefix(v, "/")
		if p, ok := s.findResource(v); ok {
			return p, true
		}
		if p, ok := s.staticFile(v); ok {
			return p, true
		}
	}
	return "", false
}

// faviconHref is the <link rel="icon"> target for a scope, or "" for none.
func (s *Server) faviconHref(scope ConfigScope) string {
	if _, ok := s.findResource("favicon.ico"); ok {
		return s.BasePath + "/favicon.ico"
	}
	if _, ok := s.faviconFile(scope); ok {
		href := s.BasePath + "/favicon.png"
		if "" != scope.Group && "global" != scope.Group {
			href += "?lb=" + url.QueryEscape(scope.Group)
		}
		return href
	}
	for _, key := range []string{"Favicon", "Logo"} {
		if v := strings.TrimSpace(s.Config.GetString(scope, key, "")); isRemoteImage(v) {
			return v
		}
	}
	if strings.EqualFold(strings.TrimSpace(s.Config.GetString(scope, "Logo", "")), "none") {
		return ""
	}
	if "" == strings.TrimSpace(s.Config.GetString(scope, "Logo", "")) {
		return s.BasePath + "/" + defaultLogoName // the built-in SVG logo
	}
	return ""
}

// faviconPNG returns the derived icon of a source file, cached until the file changes.
func faviconPNG(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	faviconMu.Lock()
	e, ok := faviconCache[path]
	faviconMu.Unlock()
	if ok && e.mod.Equal(st.ModTime()) && e.size == st.Size() {
		return e.png, nil
	}
	if st.Size() > maxThumbSourceBytes {
		return nil, errors.New("favicon source too large")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return nil, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxThumbSourcePixel {
		return nil, errors.New("favicon source too large")
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	img, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	b := img.Bounds()
	flat := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(flat, flat.Bounds(), img, b.Min, draw.Src)
	tw, th := thumbSize(b.Dx(), b.Dy(), faviconSide, faviconSide)
	small := scaleArea(flat, tw, th)
	canvas := image.NewRGBA(image.Rect(0, 0, faviconSide, faviconSide))
	off := image.Pt((faviconSide-tw)/2, (faviconSide-th)/2)
	draw.Draw(canvas, image.Rectangle{Min: off, Max: off.Add(image.Pt(tw, th))}, small, image.Point{}, draw.Src)
	var buf bytes.Buffer
	if err := png.Encode(&buf, canvas); err != nil {
		return nil, err
	}
	faviconMu.Lock()
	faviconCache[path] = faviconEntry{mod: st.ModTime(), size: st.Size(), png: buf.Bytes()}
	faviconMu.Unlock()
	return buf.Bytes(), nil
}

// serveFavicon answers /favicon.png (and /favicon.ico when no such file exists)
// for the instance, or for the logbook named by ?lb=. It reports whether it did.
func (s *Server) serveFavicon(q *Request) bool {
	if defaultLogoName == q.lbName && "" == q.rel {
		h := q.W.Header()
		h.Set("Content-Type", "image/svg+xml")
		h.Set("Cache-Control", "public, max-age=86400")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		if http.MethodHead != q.R.Method {
			_, _ = q.W.Write(defaultLogoSVG)
		}
		return true
	}
	if ("favicon.png" != q.lbName && "favicon.ico" != q.lbName) || "" != q.rel || 0 != q.msgID {
		return false
	}
	if _, real := s.findResource("favicon.ico"); real && "favicon.ico" == q.lbName {
		return false // a real icon file is served by the static route
	}
	scope := ConfigScope{Group: "global"}
	if lb := q.R.URL.Query().Get("lb"); "" != lb && s.hasLogbookSection(lb) {
		scope = ConfigScope{Group: lb, TopGroup: lb}
	}
	p, ok := s.faviconFile(scope)
	if !ok {
		return false
	}
	data, err := faviconPNG(p)
	if err != nil {
		return false
	}
	h := q.W.Header()
	h.Set("Content-Type", "image/png")
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("X-Content-Type-Options", "nosniff")
	if http.MethodHead != q.R.Method {
		_, _ = q.W.Write(data)
	}
	return true
}
