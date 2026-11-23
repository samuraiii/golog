// golog - thumbnails of image attachments, made in Go.
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// ELOG runs ImageMagick's convert(1) and identify(1). golog does not run any
// program for this: it decodes PNG, JPEG and GIF (the first frame) with the
// standard library, scales with an area average and writes a PNG. Reasons:
//
//   - nothing to install, on Linux or on Windows, where "convert" is not
//     ImageMagick at all but the file system converter of the operating system;
//   - no external process parses a file an anonymous visitor may have uploaded;
//   - the image type is decided from the content, not from the file name, which
//     matters for attachments stored without an extension (see attsalt.go).
//
// Other types (TIFF, BMP, PDF, ...) get no thumbnail; the page shows the link.
package golog

import (
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/gif" // registers the GIF decoder
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
)

// Limits that keep a hostile file from using the machine: the file size, and
// the pixel count of the decoded picture (decoding needs about 4 bytes per
// pixel, so 40 million pixels are 160 MB at the most).
const (
	maxThumbSourceBytes = 64 << 20
	maxThumbSourcePixel = 40_000_000
)

var (
	_ = gif.Decode
	_ = jpeg.Decode
)

// thumbSize is the size of the thumbnail: the picture scaled to fit width and
// height (0 = unlimited), never enlarged, at least 1x1.
func thumbSize(w, h, width, height int) (int, int) {
	if width <= 0 {
		width = 100
	}
	scale := float64(width) / float64(w)
	if height > 0 && float64(h)*scale > float64(height) {
		scale = float64(height) / float64(h)
	}
	if scale > 1 {
		scale = 1
	}
	tw, th := int(float64(w)*scale+0.5), int(float64(h)*scale+0.5)
	if tw < 1 {
		tw = 1
	}
	if th < 1 {
		th = 1
	}
	return tw, th
}

// makeThumbnail writes dst, a PNG thumbnail of the image in src.
func makeThumbnail(src, dst string, width, height int) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > maxThumbSourceBytes {
		return errors.New("source too large for a thumbnail")
	}
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxThumbSourcePixel {
		return errors.New("picture too large for a thumbnail")
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	img, _, err := image.Decode(f)
	if err != nil {
		return err
	}
	b := img.Bounds()
	tw, th := thumbSize(b.Dx(), b.Dy(), width, height)

	// Flatten onto white (the original used "-background white"), then average.
	flat := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(flat, flat.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	draw.Draw(flat, flat.Bounds(), img, b.Min, draw.Over)
	out := scaleArea(flat, tw, th)

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".thumb.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := png.Encode(tmp, out); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, dst)
}

// scaleArea shrinks src to w x h by averaging the source pixels each output
// pixel covers (a box filter: no aliasing, and exact for whole-number ratios).
func scaleArea(src *image.RGBA, w, h int) *image.RGBA {
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		y0, y1 := y*sh/h, (y+1)*sh/h
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < w; x++ {
			x0, x1 := x*sw/w, (x+1)*sw/w
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, bl, a, n uint32
			for yy := y0; yy < y1; yy++ {
				row := src.Pix[yy*src.Stride:]
				for xx := x0; xx < x1; xx++ {
					p := row[xx*4 : xx*4+4]
					r += uint32(p[0])
					g += uint32(p[1])
					bl += uint32(p[2])
					a += uint32(p[3])
					n++
				}
			}
			o := out.Pix[y*out.Stride+x*4:]
			o[0], o[1], o[2], o[3] = uint8(r/n), uint8(g/n), uint8(bl/n), uint8(a/n)
		}
	}
	return out
}
