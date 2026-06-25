package mail

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// LoadOrGenerateCert returns the broker's STARTTLS certificate, loading it from
// dir if present, otherwise generating a self-signed cert for hosts and
// persisting it (so the cert is stable across broker restarts — beams inject the
// matching CA, and a restart must not invalidate it). dir == "" generates an
// ephemeral cert (not persisted). Returns the keypair and the public cert PEM
// (which beamhalld injects to beams as SMTP_CA).
//
// The broker SMTP listener stays on a private beamhall bridge, so this cert
// exists to satisfy clients that refuse plaintext AUTH (Go's net/smtp), not to
// defend confidentiality on an untrusted network. A self-signed cert the app
// pins via SMTP_CA is the right weight.
func LoadOrGenerateCert(dir string, hosts []string) (tls.Certificate, []byte, error) {
	if len(hosts) == 0 {
		hosts = []string{"bh-mail", "localhost"}
	}
	certPath := filepath.Join(dir, "broker-cert.pem")
	keyPath := filepath.Join(dir, "broker-key.pem")

	if dir != "" {
		cpem, cerr := os.ReadFile(certPath)
		kpem, kerr := os.ReadFile(keyPath)
		if cerr == nil && kerr == nil {
			if cert, err := tls.X509KeyPair(cpem, kpem); err == nil {
				return cert, cpem, nil
			}
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("mail: build keypair: %w", err)
	}
	if dir != "" {
		// Best-effort persist; an unwritable dir degrades to an ephemeral cert.
		_ = os.WriteFile(certPath, certPEM, 0o644)
		_ = os.WriteFile(keyPath, keyPEM, 0o600)
	}
	return cert, certPEM, nil
}
