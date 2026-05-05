package gokrazy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/renameio/v2"
)

const (
	defaultPermTLSCertPath               = "/perm/ssl/gokrazy-web.pem"
	defaultPermTLSKeyPath                = "/perm/ssl/gokrazy-web.key.pem"
	defaultRootTLSCertPath               = "/etc/ssl/gokrazy-web.pem"
	defaultRootTLSKeyPath                = "/etc/ssl/gokrazy-web.key.pem"
	defaultRootTLSUsePermPath            = "/etc/ssl/gokrazy-web.use-perm"
	defaultRootTLSGenerateSelfSignedPath = "/etc/ssl/gokrazy-web.generate-self-signed"
)

var (
	permTLSCertPath               = defaultPermTLSCertPath
	permTLSKeyPath                = defaultPermTLSKeyPath
	rootTLSCertPath               = defaultRootTLSCertPath
	rootTLSKeyPath                = defaultRootTLSKeyPath
	rootTLSUsePermPath            = defaultRootTLSUsePermPath
	rootTLSGenerateSelfSignedPath = defaultRootTLSGenerateSelfSignedPath
)

func setupTLS() error {
	certPath, keyPath, err := tlsCertificatePaths()
	if err != nil {
		return err
	}
	if certPath == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed loading certificate: %v", err)
	}
	useTLS = true
	tlsConfig = &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// required for http/2
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			// See https://cipherlist.eu/
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	return nil
}

func tlsCertificatePaths() (certPath, keyPath string, err error) {
	rootCertExists, err := fileExists(rootTLSCertPath)
	if err != nil {
		return "", "", err
	}
	if !rootCertExists {
		return "", "", nil // Nothing to set up
	}

	usePerm, err := fileExists(rootTLSUsePermPath)
	if err != nil {
		return "", "", err
	}
	if !usePerm {
		return rootTLSCertPath, rootTLSKeyPath, nil
	}

	permCertExists, err := fileExists(permTLSCertPath)
	if err != nil {
		return "", "", err
	}
	if permCertExists {
		return permTLSCertPath, permTLSKeyPath, nil
	}

	generateSelfSigned, err := fileExists(rootTLSGenerateSelfSignedPath)
	if err != nil {
		return "", "", err
	}
	if generateSelfSigned {
		if err := generateAndPersistTLSCertificate(); err != nil {
			log.Printf("generating TLS certificate in /perm failed: %v", err)
			return rootTLSCertPath, rootTLSKeyPath, nil
		}
		return permTLSCertPath, permTLSKeyPath, nil
	}

	if err := persistRootTLSCertificate(); err != nil {
		log.Printf("persisting TLS certificate in /perm failed: %v", err)
		return rootTLSCertPath, rootTLSKeyPath, nil
	}
	return permTLSCertPath, permTLSKeyPath, nil
}

func fileExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	return false, nil
}

func persistRootTLSCertificate() error {
	if err := os.MkdirAll(filepath.Dir(permTLSCertPath), 0755); err != nil {
		return err
	}
	cert, err := os.ReadFile(rootTLSCertPath)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(rootTLSKeyPath)
	if err != nil {
		return err
	}
	if err := writeFileAtomically(permTLSKeyPath, key, 0600); err != nil {
		return err
	}
	return writeFileAtomically(permTLSCertPath, cert, 0644)
}

func generateAndPersistTLSCertificate() error {
	if err := os.MkdirAll(filepath.Dir(permTLSCertPath), 0755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: strings.TrimSpace(hostname),
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if strings.TrimSpace(hostname) != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, strings.TrimSpace(hostname))
	}
	if addrs, err := PrivateInterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := writeFileAtomically(permTLSKeyPath, keyPEM, 0600); err != nil {
		return err
	}
	return writeFileAtomically(permTLSCertPath, certPEM, 0644)
}

func writeFileAtomically(path string, data []byte, perm os.FileMode) error {
	return renameio.WriteFile(path, data, perm)
}
