package elog

import "crypto/rand"

// crandRead is crypto/rand.Read under a local name, so the files that need a
// few random bytes (session ids, mail boundaries, salts) do not each import the
// package under their own alias.
func crandRead(b []byte) (int, error) { return rand.Read(b) }

// RandomToken is n random hex characters (2n bytes of output from n bytes of
// entropy). It never fails: with no entropy available it falls back to the
// clock, which is what the C code effectively had (it used rand() seeded with
// the time) and is preferable to refusing to log somebody in.
func RandomToken(n int) string {
	if n <= 0 {
		return ""
	}
	if n > 64 {
		n = 64 // a token this long is already beyond any use here
	}
	b := make([]byte, (n+1)/2)
	if _, err := crandRead(b); err != nil {
		t := timestampNano()
		for i := range b {
			b[i] = byte(t >> (8 * (i % 8)))
		}
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, v := range b {
		out[2*i] = hexDigits[v>>4]
		out[2*i+1] = hexDigits[v&0xf]
	}
	return string(out[:n])
}
