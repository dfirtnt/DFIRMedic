// Package probe answers one question for the victim host: is the thing at
// server_ip:port *our* Velociraptor server? It dials, completes a TLS
// handshake, and verifies the presented certificate chains to the CA shipped
// in the client config. It is the only in-process network code in the kit
// (spec 2026-09-05 §7) and speaks no protocol above TLS.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

type Prober interface {
	Verify(ctx context.Context) (leafFingerprint string, err error)
}

type TLS struct {
	IP      string
	Port    int
	CAPEM   []byte
	Timeout time.Duration // default 10s
}

func (p TLS) Verify(ctx context.Context) (string, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(p.CAPEM) {
		return "", errors.New("probe: no usable CA certificate")
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(p.IP, strconv.Itoa(p.Port)))
	if err != nil {
		return "", fmt.Errorf("probe: %w", err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	var leafFP string
	cfg := &tls.Config{
		// Velociraptor's internal CA issues server certs without a SAN for the
		// bare IP, so Go's default verifier would fail on the name check.
		// InsecureSkipVerify disables ONLY that; the chain check below is
		// mandatory and aborts the handshake on failure.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no certificate presented")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, rc := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(rc); err == nil {
					inter.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				return fmt.Errorf("certificate not signed by the pinned CA: %w", err)
			}
			sum := sha256.Sum256(rawCerts[0])
			leafFP = hex.EncodeToString(sum[:])
			return nil
		},
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("probe: %w", err)
	}
	_ = tc.Close()
	return leafFP, nil
}
