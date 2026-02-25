// Package tlsutil provides TLS certificate generation utilities
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// GenerateSelfSignedCert creates a self-signed TLS certificate valid for 10 years
func GenerateSelfSignedCert(certPath, keyPath string) error {
	log.Printf("TLS: Generating self-signed certificate...")

	// Generate ECDSA private key (P-256)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(3650 * 24 * time.Hour) // 10 years validity

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Private Network Reporter"},
			CommonName:   "pnr-self-signed",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "pnr"},
		// Fixed IP addresess included - future enhancement could be to detect PNR IP dynamically
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.ParseIP("172.17.0.2"), net.ParseIP("192.168.88.1")},
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	log.Printf("TLS: Self-signed certificate generated successfully")
	log.Printf("TLS: Certificate: %s", certPath)
	log.Printf("TLS: Private Key: %s", keyPath)
	log.Printf("TLS: Valid until: %s", notAfter.Format(time.RFC3339))

	return nil
}

// EnsureCertificate checks if TLS cert/key exist, generates if missing
func EnsureCertificate(certPath, keyPath string) error {
	certExists := false
	keyExists := false

	if _, err := os.Stat(certPath); err == nil {
		certExists = true
	}
	if _, err := os.Stat(keyPath); err == nil {
		keyExists = true
	}

	if certExists && keyExists {
		log.Printf("TLS: Using existing certificate: %s", certPath)
		return nil
	}

	if certExists != keyExists {
		return fmt.Errorf("TLS: certificate and key must both exist or both be missing (cert=%v, key=%v)", certExists, keyExists)
	}

	// Generate new self-signed certificate
	return GenerateSelfSignedCert(certPath, keyPath)
}
