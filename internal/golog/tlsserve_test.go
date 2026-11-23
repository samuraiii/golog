package golog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// certSerial hands out distinct serial numbers: the clock alone is not enough,
// on Windows time.Now() ticks in ~0.5 ms steps so two certificates made in a row
// got the same serial and a "good" certificate looked revoked.
var certSerial atomic.Int64

func mkCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + certSerial.Add(1)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		DNSNames:              []string{"localhost"},
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A cert file holding leaf + intermediate, and a separate "SSL chain" file
// holding the root-side intermediate, must be sent as leaf, intermediate.
func TestLoadCertificateChain(t *testing.T) {
	root, rootKey, _ := mkCert(t, "root", nil, nil, true)
	inter, interKey, interPEM := mkCert(t, "inter", root, rootKey, true)
	_, leafKey, leafPEM := mkCert(t, "leaf", inter, interKey, false)
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	cf, kf, chf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), filepath.Join(dir, "ch.pem")
	os.WriteFile(cf, leafPEM, 0o600)
	os.WriteFile(kf, keyPEM, 0o600)
	os.WriteFile(chf, interPEM, 0o600)

	c, err := LoadCertificateChain(cf, kf, chf)
	if err != nil {
		t.Fatal(err)
	}
	if 2 != len(c.Certificate) {
		t.Fatalf("chain has %d certificates, want 2 (leaf + intermediate)", len(c.Certificate))
	}
	if "leaf" != c.Leaf.Subject.CommonName {
		t.Errorf("leaf = %q", c.Leaf.Subject.CommonName)
	}
	// Verify the way a client does, trusting only the root.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	ic, _ := x509.ParseCertificate(c.Certificate[1])
	inters.AddCert(ic)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, DNSName: "localhost"}); err != nil {
		t.Errorf("chain does not verify: %v", err)
	}

	rl, err := newCertReloader(cf, kf, chf)
	if err != nil {
		t.Fatal(err)
	}
	if rl.changed() {
		t.Error("changed() before any change")
	}
	if got, err := rl.getCertificate(&tls.ClientHelloInfo{}); err != nil || nil == got {
		t.Errorf("getCertificate: %v", err)
	}
}

// A CA directory is read file by file, and a CRL listing a client certificate's
// serial makes crlSet.check refuse the chain; a good certificate passes.
func TestClientCADirAndCRL(t *testing.T) {
	ca, caKey, caPEM := mkCert(t, "ca", nil, nil, true)
	good, _, _ := mkCert(t, "good", ca, caKey, false)
	bad, _, _ := mkCert(t, "bad", ca, caKey, false)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a certificate"), 0o644)
	pool, err := readCertPool(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := good.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("good cert does not verify against the CA directory: %v", err)
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: bad.SerialNumber, RevocationTime: time.Now().Add(-time.Second)},
		},
	}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	crlDir := t.TempDir()
	os.WriteFile(filepath.Join(crlDir, "ca.crl"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0o644)
	lists, err := readCRLs(crlDir)
	if err != nil || 1 != len(lists) {
		t.Fatalf("readCRLs: %v, %d lists", err, len(lists))
	}
	set := &crlSet{lists: lists, strict: true}
	if err := set.check([]*x509.Certificate{good, ca}, time.Now()); err != nil {
		t.Errorf("good certificate refused: %v", err)
	}
	if err := set.check([]*x509.Certificate{bad, ca}, time.Now()); err == nil {
		t.Error("revoked certificate accepted")
	}
	// strict: an expired CRL refuses everything; lenient: it still refuses the
	// revoked serial but lets the others through.
	later := time.Now().Add(2 * time.Hour)
	if err := set.check([]*x509.Certificate{good, ca}, later); err == nil {
		t.Error("strict mode accepted a chain whose CRL has expired")
	}
	set.strict = false
	if err := set.check([]*x509.Certificate{good, ca}, later); err != nil {
		t.Errorf("lenient mode refused: %v", err)
	}
	if err := set.check([]*x509.Certificate{bad, ca}, later); err == nil {
		t.Error("lenient mode accepted a revoked serial")
	}
}
