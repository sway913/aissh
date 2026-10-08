package aissh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

//go:embed default-ca.pem
var defaultCA []byte

func TrustPEM(path string) ([]byte, error) {
	if path != "" {
		return os.ReadFile(path)
	}
	if len(defaultCA) == 0 {
		return nil, fmt.Errorf("server trust certificate missing")
	}
	return defaultCA, nil
}
func ClientTLS(ca []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid server trust certificate")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
func InitTLS(dir, host string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if _, e := os.Stat(certPath); e == nil {
		return fmt.Errorf("certificate already exists; refusing to overwrite")
	}
	if _, e := os.Stat(keyPath); e == nil {
		return fmt.Errorf("key already exists; refusing to overwrite")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "aissh server"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if ip := net.ParseIP(host); ip != nil {
		c.IPAddresses = append(c.IPAddresses, ip)
	} else {
		c.DNSNames = append(c.DNSNames, host)
	}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		return e
	}
	kb, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0600); e != nil {
		return e
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}
