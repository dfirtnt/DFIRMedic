// internal/probe/probe_test.go
package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newCA returns a self-signed CA certificate and key.
func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// leafSignedBy returns a tls.Certificate for a server leaf signed by ca.
// No SAN on purpose: Velociraptor's internal CA issues certs the default
// verifier would reject on name, and the probe must not care.
func leafSignedBy(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "VelociraptorServer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve starts a TLS listener presenting cert and returns ip, port.
func serve(t *testing.T, cert tls.Certificate) (string, int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				c.Close()
			}(c)
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestVerifyAcceptsLeafSignedByPinnedCA(t *testing.T) {
	ca, caKey, caPEM := newCA(t, "Velociraptor CA")
	ip, port := serve(t, leafSignedBy(t, ca, caKey))
	fp, err := TLS{IP: ip, Port: port, CAPEM: caPEM, Timeout: 5 * time.Second}.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 {
		t.Fatalf("leaf fingerprint should be 64 hex chars, got %q", fp)
	}
}

func TestVerifyRejectsLeafFromOtherCA(t *testing.T) {
	_, _, pinnedPEM := newCA(t, "Pinned CA")
	otherCA, otherKey, _ := newCA(t, "Other CA")
	ip, port := serve(t, leafSignedBy(t, otherCA, otherKey))
	_, err := TLS{IP: ip, Port: port, CAPEM: pinnedPEM, Timeout: 5 * time.Second}.Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pinned CA") {
		t.Fatalf("expected pinned-CA failure, got %v", err)
	}
}

func TestVerifyRejectsPlainTCPListener(t *testing.T) {
	_, _, caPEM := newCA(t, "CA")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) // a captive portal, roughly
			c.Close()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if _, err := (TLS{IP: host, Port: port, CAPEM: caPEM, Timeout: 5 * time.Second}).Verify(context.Background()); err == nil {
		t.Fatal("plain TCP must not verify")
	}
}

func TestVerifyTimesOutOnSilentPeer(t *testing.T) {
	_, _, caPEM := newCA(t, "CA")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { time.Sleep(10 * time.Second); c.Close() }(c) // never handshakes
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	start := time.Now()
	_, err := TLS{IP: host, Port: port, CAPEM: caPEM, Timeout: 500 * time.Millisecond}.Verify(context.Background())
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("probe did not honor its timeout: %v", time.Since(start))
	}
}

func TestVerifyRejectsUnusableCA(t *testing.T) {
	if _, err := (TLS{IP: "127.0.0.1", Port: 1, CAPEM: []byte("garbage")}).Verify(context.Background()); err == nil {
		t.Fatal("expected error for unusable CA")
	}
}
