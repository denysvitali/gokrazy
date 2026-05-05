package gokrazy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSCertificatePathsPrefersPerm(t *testing.T) {
	withTLSPaths(t)

	if err := os.MkdirAll(filepath.Dir(permTLSCertPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permTLSCertPath, []byte("perm cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permTLSKeyPath, []byte("perm key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(rootTLSCertPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootTLSCertPath, []byte("root cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootTLSKeyPath, []byte("root key"), 0600); err != nil {
		t.Fatal(err)
	}

	certPath, keyPath, err := tlsCertificatePaths()
	if err != nil {
		t.Fatal(err)
	}
	if certPath != permTLSCertPath || keyPath != permTLSKeyPath {
		t.Fatalf("tlsCertificatePaths() = (%q, %q), want (%q, %q)", certPath, keyPath, permTLSCertPath, permTLSKeyPath)
	}
}

func TestTLSCertificatePathsRequiresRootCertificate(t *testing.T) {
	withTLSPaths(t)

	if err := os.MkdirAll(filepath.Dir(permTLSCertPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permTLSCertPath, []byte("perm cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permTLSKeyPath, []byte("perm key"), 0600); err != nil {
		t.Fatal(err)
	}

	certPath, keyPath, err := tlsCertificatePaths()
	if err != nil {
		t.Fatal(err)
	}
	if certPath != "" || keyPath != "" {
		t.Fatalf("tlsCertificatePaths() = (%q, %q), want empty paths", certPath, keyPath)
	}
}

func TestTLSCertificatePathsPersistsRootCertificate(t *testing.T) {
	withTLSPaths(t)

	if err := os.MkdirAll(filepath.Dir(rootTLSCertPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootTLSCertPath, []byte("root cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootTLSKeyPath, []byte("root key"), 0600); err != nil {
		t.Fatal(err)
	}

	certPath, keyPath, err := tlsCertificatePaths()
	if err != nil {
		t.Fatal(err)
	}
	if certPath != permTLSCertPath || keyPath != permTLSKeyPath {
		t.Fatalf("tlsCertificatePaths() = (%q, %q), want (%q, %q)", certPath, keyPath, permTLSCertPath, permTLSKeyPath)
	}
	assertFileContent(t, permTLSCertPath, "root cert")
	assertFileContent(t, permTLSKeyPath, "root key")
}

func TestTLSCertificatePathsGeneratesPermCertificateWhenRequested(t *testing.T) {
	withTLSPaths(t)

	if err := os.MkdirAll(filepath.Dir(rootTLSCertPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootTLSCertPath, []byte("root cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootTLSKeyPath, []byte("root key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootTLSGenerateSelfSignedPath, nil, 0644); err != nil {
		t.Fatal(err)
	}

	certPath, keyPath, err := tlsCertificatePaths()
	if err != nil {
		t.Fatal(err)
	}
	if certPath != permTLSCertPath || keyPath != permTLSKeyPath {
		t.Fatalf("tlsCertificatePaths() = (%q, %q), want (%q, %q)", certPath, keyPath, permTLSCertPath, permTLSKeyPath)
	}
	assertGeneratedCertificate(t, permTLSCertPath)
	if _, err := tls.LoadX509KeyPair(permTLSCertPath, permTLSKeyPath); err != nil {
		t.Fatal(err)
	}
}

func TestTLSCertificatePathsNoCertificate(t *testing.T) {
	withTLSPaths(t)

	certPath, keyPath, err := tlsCertificatePaths()
	if err != nil {
		t.Fatal(err)
	}
	if certPath != "" || keyPath != "" {
		t.Fatalf("tlsCertificatePaths() = (%q, %q), want empty paths", certPath, keyPath)
	}
}

func withTLSPaths(t *testing.T) {
	t.Helper()

	permDir := t.TempDir()
	rootDir := t.TempDir()
	oldPermCertPath := permTLSCertPath
	oldPermKeyPath := permTLSKeyPath
	oldRootCertPath := rootTLSCertPath
	oldRootKeyPath := rootTLSKeyPath
	oldRootGenerateSelfSignedPath := rootTLSGenerateSelfSignedPath
	t.Cleanup(func() {
		permTLSCertPath = oldPermCertPath
		permTLSKeyPath = oldPermKeyPath
		rootTLSCertPath = oldRootCertPath
		rootTLSKeyPath = oldRootKeyPath
		rootTLSGenerateSelfSignedPath = oldRootGenerateSelfSignedPath
	})

	permTLSCertPath = filepath.Join(permDir, "ssl", "gokrazy-web.pem")
	permTLSKeyPath = filepath.Join(permDir, "ssl", "gokrazy-web.key.pem")
	rootTLSCertPath = filepath.Join(rootDir, "ssl", "gokrazy-web.pem")
	rootTLSKeyPath = filepath.Join(rootDir, "ssl", "gokrazy-web.key.pem")
	rootTLSGenerateSelfSignedPath = filepath.Join(rootDir, "ssl", "gokrazy-web.generate-self-signed")
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("os.ReadFile(%q) = %q, want %q", path, got, want)
	}
}

func assertGeneratedCertificate(t *testing.T, path string) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(got)
	if block == nil {
		t.Fatalf("pem.Decode(%q) failed", path)
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block type = %q, want CERTIFICATE", block.Type)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
}
