// golog - TLS serving: certificate chain, reload, client CA, HTTP/2.
//
// golog is a Go rewrite of ELOG (https://elog.psi.ch/elog) by Stefan Ritt (PSI).
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License version 2 or later; see COPYING.
//
// Configuration (all in [global], names keep the elogd spelling where it had one):
//
//	SSL = 1                    serve HTTPS (implied by "SSL cert")
//	SSL cert = <file>          server certificate, PEM; may hold the whole chain
//	                           (leaf first, then the intermediates)
//	SSL key = <file>           private key, PEM (may live in the cert file)
//	SSL chain = <file>         extra intermediates, PEM, appended after the cert file
//	SSL min version = 1.2      1.2 (default) or 1.3
//	SSL client CA = <file|dir> CA bundle, or a directory of CA certificates
//	                           (*.pem, *.crt, *.cer, OpenSSL hash links), used to
//	                           verify client certificates
//	SSL client auth = none|request|require   (default none)
//	SSL client CRL = <file|dir> certificate revocation lists (PEM or DER) checked
//	                           for every client certificate; re-read with the
//	                           certificate. A client certificate whose issuer has
//	                           no current CRL is refused unless
//	SSL client CRL strict = 0  is set (then a missing/expired CRL is only logged)
//	SSL HSTS = <seconds>       send Strict-Transport-Security with that max-age
//	SSL redirect port = <port> also listen on this plain port and redirect to https
//	HTTP2 cleartext = 1        accept HTTP/2 without TLS (h2c) on a plain listener
//
// A certificate is re-read when its files change (checked every few seconds)
// and on SIGHUP (unix) without restarting the listener. HTTP/2 over TLS is
// negotiated by ALPN; net/http does the rest.
package golog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// certReloader holds the certificate chain currently served and knows how to
// re-read it from the files it came from.
type certReloader struct {
	certFile, keyFile, chainFile string

	cur atomic.Pointer[tls.Certificate]
	// Client revocation lists, reloaded together with the certificate.
	crlPath  string
	crls     *crlSet
	crlStamp string
	mu       sync.Mutex
	stamp    string // modification times of the files, to notice changes
}

func newCertReloader(certFile, keyFile, chainFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, chainFile: chainFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// LoadCertificateChain reads a certificate (leaf first, intermediates after it),
// an optional file of further intermediates and the key, and returns the
// tls.Certificate that sends the whole chain. The key may be in the cert file.
func LoadCertificateChain(certFile, keyFile, chainFile string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("SSL cert: %w", err)
	}
	if chainFile != "" {
		extra, err := os.ReadFile(chainFile)
		if err != nil {
			return nil, fmt.Errorf("SSL chain: %w", err)
		}
		certPEM = append(append(certPEM, '\n'), extra...)
	}
	keyPEM := certPEM
	if keyFile != "" {
		if keyPEM, err = os.ReadFile(keyFile); err != nil {
			return nil, fmt.Errorf("SSL key: %w", err)
		}
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("SSL cert/key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("SSL cert: %w", err)
	}
	cert.Leaf = leaf
	return &cert, nil
}

func fileStamp(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil {
			b.WriteString(st.ModTime().Format(time.RFC3339Nano))
			b.WriteString(strconv.FormatInt(st.Size(), 10))
		}
		b.WriteByte(';')
	}
	return b.String()
}

// Reload re-reads the files; on error the previous certificate stays in use.
func (r *certReloader) Reload() error {
	c, err := LoadCertificateChain(r.certFile, r.keyFile, r.chainFile)
	if err != nil {
		return err
	}
	r.cur.Store(c)
	r.mu.Lock()
	r.stamp = fileStamp(r.certFile, r.keyFile, r.chainFile)
	r.mu.Unlock()
	return nil
}

// reloadCRLs re-reads the client revocation lists (the set is swapped under
// the lock so a handshake never sees a half-loaded list).
func (r *certReloader) reloadCRLs() error {
	if "" == r.crlPath || nil == r.crls {
		return nil
	}
	lists, err := readCRLs(r.crlPath)
	if err != nil {
		return err
	}
	r.crls.mu.Lock()
	r.crls.lists = lists
	r.crls.mu.Unlock()
	if files, err := pathsOf(r.crlPath); err == nil {
		r.mu.Lock()
		r.crlStamp = fileStamp(files...)
		r.mu.Unlock()
	}
	return nil
}

func (r *certReloader) changed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fileStamp(r.certFile, r.keyFile, r.chainFile) != r.stamp {
		return true
	}
	if "" != r.crlPath {
		files, err := pathsOf(r.crlPath)
		return err == nil && fileStamp(files...) != r.crlStamp
	}
	return false
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := r.cur.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("no certificate loaded")
}

// pathsOf expands a file or a directory into the regular files to read; in a
// directory every non-hidden file counts (OpenSSL hash links resolve to files).
func pathsOf(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{path}, nil
	}
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		full := filepath.Join(path, e.Name())
		if fi, err := os.Stat(full); err == nil && fi.Mode().IsRegular() {
			out = append(out, full)
		}
	}
	sort.Strings(out)
	return out, nil
}

// readCertPool loads CA certificates from a PEM bundle or from a directory of
// PEM (or single DER) files; files without a certificate are skipped in a
// directory and are an error for a plain file.
func readCertPool(path string) (*x509.CertPool, error) {
	files, err := pathsOf(path)
	if err != nil {
		return nil, err
	}
	st, _ := os.Stat(path)
	isDir := st != nil && st.IsDir()
	pool := x509.NewCertPool()
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		got := 0
		for rest := data; ; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if "CERTIFICATE" != blk.Type {
				continue
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			pool.AddCert(c)
			got++
		}
		if 0 == got {
			if c, err := x509.ParseCertificate(data); err == nil { // DER
				pool.AddCert(c)
				got++
			}
		}
		if 0 == got && !isDir {
			return nil, fmt.Errorf("%s: no certificate found", f)
		}
		n += got
	}
	if 0 == n {
		return nil, fmt.Errorf("%s: no certificate found", path)
	}
	return pool, nil
}

// crlSet is the set of revocation lists of the client CAs.
type crlSet struct {
	mu     sync.RWMutex
	lists  []*x509.RevocationList
	strict bool
}

// readCRLs loads every CRL (PEM "X509 CRL" or raw DER) from a file or directory.
func readCRLs(path string) ([]*x509.RevocationList, error) {
	files, err := pathsOf(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.RevocationList
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		found := false
		for rest := data; ; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if "X509 CRL" != blk.Type {
				continue
			}
			crl, err := x509.ParseRevocationList(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			out = append(out, crl)
			found = true
		}
		if !found {
			if crl, err := x509.ParseRevocationList(data); err == nil {
				out = append(out, crl)
			}
		}
	}
	return out, nil
}

// check refuses a chain in which a certificate is revoked. For every
// certificate that has an issuer in the chain, the CRL signed by that issuer
// (matched by issuer name and verified with its key) is consulted.
func (c *crlSet) check(chain []*x509.Certificate, now time.Time) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		var crl *x509.RevocationList
		for _, l := range c.lists {
			if string(l.RawIssuer) == string(issuer.RawSubject) && l.CheckSignatureFrom(issuer) == nil {
				crl = l
				break
			}
		}
		if nil == crl || (!crl.NextUpdate.IsZero() && now.After(crl.NextUpdate)) {
			if c.strict {
				return fmt.Errorf("no current revocation list for %q", issuer.Subject.CommonName)
			}
			if nil == crl {
				continue
			}
		}
		for _, e := range crl.RevokedCertificateEntries {
			if 0 == e.SerialNumber.Cmp(cert.SerialNumber) {
				return fmt.Errorf("client certificate %q (serial %s) is revoked", cert.Subject.CommonName, cert.SerialNumber)
			}
		}
	}
	return nil
}

// tlsSetup builds the tls.Config of the HTTPS listener from the configuration.
func (s *Server) tlsSetup() (*tls.Config, *certReloader, error) {
	g := ConfigScope{Group: "global"}
	chain := ""
	if v := s.Config.GetString(g, "SSL chain", ""); v != "" {
		chain = s.Abs(v)
	}
	rl, err := newCertReloader(s.SSLCert, s.SSLKey, chain)
	if err != nil {
		return nil, nil, err
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: rl.getCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	}
	// TLS 1.2 is the floor and cannot be lowered: older protocol versions are
	// never offered. "SSL min version = 1.3" raises it.
	switch v := strings.TrimSpace(s.Config.GetString(g, "SSL min version", "1.2")); v {
	case "1.3":
		cfg.MinVersion = tls.VersionTLS13
	case "1.2", "":
	default:
		Logf("golog: SSL min version %q ignored: TLS 1.2 is the lowest supported version", v)
	}
	if ca := s.Config.GetString(g, "SSL client CA", ""); ca != "" {
		pool, err := readCertPool(s.Abs(ca))
		if err != nil {
			return nil, nil, fmt.Errorf("SSL client CA: %w", err)
		}
		cfg.ClientCAs = pool
		if crlPath := s.Config.GetString(g, "SSL client CRL", ""); crlPath != "" {
			strict := true
			switch strings.ToLower(strings.TrimSpace(s.Config.GetString(g, "SSL client CRL strict", "1"))) {
			case "0", "no", "false", "off":
				strict = false
			}
			set := &crlSet{strict: strict}
			rl.crlPath = s.Abs(crlPath)
			rl.crls = set
			if err := rl.reloadCRLs(); err != nil {
				return nil, nil, fmt.Errorf("SSL client CRL: %w", err)
			}
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				for _, ch := range cs.VerifiedChains {
					if err := rl.crls.check(ch, time.Now()); err != nil {
						return err
					}
				}
				return nil
			}
		}
		mode := strings.ToLower(strings.TrimSpace(s.Config.GetString(g, "SSL client auth", "none")))
		if "request" != mode && "require" != mode {
			Logf("golog: \"SSL client CA\" is set but \"SSL client auth\" is %q: client certificates are neither requested nor used (set it to request or require)", mode)
		}
		switch mode {
		case "request":
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		case "require":
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return cfg, rl, nil
}

// hstsHandler adds Strict-Transport-Security to every answer.
func hstsHandler(h http.Handler, maxAge int) http.Handler {
	v := "max-age=" + strconv.Itoa(maxAge)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", v)
		h.ServeHTTP(w, r)
	})
}

// ReloadTLS re-reads the certificate files now (SIGHUP, or the file watcher).
func (s *Server) ReloadTLS() error {
	s.mu.Lock()
	rl := s.certs
	s.mu.Unlock()
	if rl == nil {
		return nil
	}
	if err := rl.reloadCRLs(); err != nil {
		Logf("golog: CRL reload failed, keeping the old lists: %v", err)
	}
	if err := rl.Reload(); err != nil {
		Logf("golog: certificate reload failed, keeping the old one: %v", err)
		return err
	}
	Logf("golog: certificate reloaded from %s", s.SSLCert)
	return nil
}

func (s *Server) watchCertificates(rl *certReloader, stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if rl.changed() {
				_ = s.ReloadTLS()
			}
		}
	}
}

// redirectHandler sends a plain-HTTP request to the https URL of the same page.
func redirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if "443" != httpsPort {
			host = net.JoinHostPort(host, httpsPort)
		}
		code := http.StatusMovedPermanently
		if http.MethodGet != r.Method && http.MethodHead != r.Method {
			code = http.StatusPermanentRedirect
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), code)
	})
}

// ReadyHook, when set, is called once the listener is bound and the server is
// about to accept connections (the systemd notification uses it).
var ReadyHook func()

// Serve runs the daemon on an existing listener until Shutdown or a listener
// failure. With "SSL cert" configured the listener speaks TLS (HTTP/2 via ALPN);
// otherwise plain HTTP, and HTTP/2 cleartext when "HTTP2 cleartext" is set.
func (s *Server) Serve(ln net.Listener) error {
	g := ConfigScope{Group: "global"}
	s.mu.Lock()
	s.listener = ln
	l := s.logger
	s.mu.Unlock()

	var h http.Handler = s.Handler()
	srv := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          l,
	}
	stop := make(chan struct{})
	defer close(stop)
	tlsOn := "" != s.SSLCert
	if tlsOn {
		cfg, rl, err := s.tlsSetup()
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.certs = rl
		s.mu.Unlock()
		srv.TLSConfig = cfg
		if secs, err := strconv.Atoi(strings.TrimSpace(s.Config.GetString(g, "SSL HSTS", "0"))); err == nil && secs > 0 {
			h = hstsHandler(h, secs)
		}
		go s.watchCertificates(rl, stop)
		if p := strings.TrimSpace(s.Config.GetString(g, "SSL redirect port", "")); p != "" {
			_, port, _ := net.SplitHostPort(ln.Addr().String())
			go func() {
				plain := &http.Server{Addr: net.JoinHostPort(s.Addr, p), Handler: redirectHandler(port), ReadHeaderTimeout: 10 * time.Second}
				s.mu.Lock()
				s.redirSrv = plain
				s.mu.Unlock()
				if err := plain.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					Logf("golog: redirect listener on %s: %v", p, err)
				}
			}()
		}
	} else if s.Config.GetBool(g, "HTTP2 cleartext") {
		h = h2c.NewHandler(h, &http2.Server{})
	}
	srv.Handler = h
	s.mu.Lock()
	s.httpSrv = srv
	s.mu.Unlock()

	if ReadyHook != nil {
		ReadyHook()
	}
	var err error
	if tlsOn {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting connections and waits up to 15 seconds for the
// requests in flight; after that the remaining connections are closed.
func (s *Server) Shutdown() {
	s.mu.Lock()
	srv, redir, ln := s.httpSrv, s.redirSrv, s.listener
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if redir != nil {
		_ = redir.Shutdown(ctx)
	}
	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
		}
		return
	}
	if ln != nil {
		_ = ln.Close()
	}
}
