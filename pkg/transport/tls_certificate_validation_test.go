package transport

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestValidateCertificates_ValidCert(t *testing.T) {
	logger := zap.NewNop()

	// Create a certificate info that's valid
	cert := &CertificateInfo{
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
		IsExpired:    false,
		DaysUntilExp: 365,
	}

	certs := []*CertificateInfo{cert}
	err := ValidateCertificates(certs, logger)

	if err != nil {
		t.Errorf("Expected no error for valid certificate, got: %v", err)
	}
}

func TestValidateCertificates_ExpiredCert(t *testing.T) {
	logger := zap.NewNop()

	// Create an expired certificate info
	cert := &CertificateInfo{
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Now().Add(-2 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		DNSNames:     []string{"test.example.com"},
		IsExpired:    true,
		DaysUntilExp: -1,
	}

	certs := []*CertificateInfo{cert}
	err := ValidateCertificates(certs, logger)

	if err == nil {
		t.Error("Expected error for expired certificate")
	}

	if err != nil && err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}

func TestValidateCertificates_NotYetValidCert(t *testing.T) {
	logger := zap.NewNop()

	// Create a certificate that's not yet valid
	cert := &CertificateInfo{
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Now().Add(1 * time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		DNSNames:     []string{"test.example.com"},
		IsExpired:    false,
		DaysUntilExp: 1,
	}

	certs := []*CertificateInfo{cert}
	err := ValidateCertificates(certs, logger)

	if err == nil {
		t.Error("Expected error for not-yet-valid certificate")
	}

	if err != nil && err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}

func TestValidateCertificates_ExpiringWithin30Days(t *testing.T) {
	logger := zap.NewNop()

	// Create a certificate expiring in 15 days
	cert := &CertificateInfo{
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(15 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
		IsExpired:    false,
		DaysUntilExp: 15,
	}

	certs := []*CertificateInfo{cert}
	err := ValidateCertificates(certs, logger)

	// Should not error for valid cert that's expiring soon (but may log warning)
	if err != nil {
		t.Errorf("Expected no error for valid but expiring cert, got: %v", err)
	}
}

func TestCertificateInfo_Basic(t *testing.T) {
	cert := &CertificateInfo{
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
		IsExpired:    false,
		DaysUntilExp: 365,
	}

	if cert.Subject == "" {
		t.Error("Expected non-empty subject")
	}

	if cert.Issuer == "" {
		t.Error("Expected non-empty issuer")
	}

	if cert.NotBefore.IsZero() {
		t.Error("Expected non-zero NotBefore")
	}

	if cert.NotAfter.IsZero() {
		t.Error("Expected non-zero NotAfter")
	}

	if cert.DaysUntilExp <= 0 {
		t.Error("Expected positive DaysUntilExp")
	}

	if len(cert.DNSNames) == 0 {
		t.Error("Expected non-empty DNSNames")
	}
}

func TestCertificateBundle_Creation(t *testing.T) {
	bundle := &CertificateBundle{
		SystemCAs:   nil,
		CustomCerts: []*CertificateInfo{},
		IsValid:     true,
	}

	if !bundle.IsValid {
		t.Error("Expected valid bundle")
	}

	if len(bundle.CustomCerts) != 0 {
		t.Error("Expected empty custom certs")
	}
}

func TestLogCertificateBundleSummary(t *testing.T) {
	config := zap.NewDevelopmentConfig()
	logger, err := config.Build()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	cert := &CertificateInfo{
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
		IsExpired:    false,
		DaysUntilExp: 365,
	}

	bundle := &CertificateBundle{
		SystemCAs:   nil,
		CustomCerts: []*CertificateInfo{cert},
		IsValid:     true,
		LoadedCount: 1,
	}

	// Should not panic
	logCertificateBundleSummary(bundle, logger)
}
