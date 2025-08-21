package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// ValidateRootCAFile validates that a file contains proper root CA certificate(s)
// Supports both single certificates and CA bundles
func ValidateRootCAFile(rootCAFile string) error {
	certData, err := os.ReadFile(rootCAFile)
	if err != nil {
		return fmt.Errorf("failed to read root CA file: %w", err)
	}

	// Try to parse as multiple certificates first
	certs, err := parseAllCertificates(certData)
	if err != nil {
		return fmt.Errorf("failed to parse certificates: %w", err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates found in file")
	}

	// If single certificate, validate it as a root CA
	if len(certs) == 1 {
		return validateSingleRootCA(certs[0])
	}

	// Multiple certificates - validate as CA bundle
	return validateCABundle(certs)
}

// validateSingleRootCA validates a single certificate as a root CA
func validateSingleRootCA(cert *x509.Certificate) error {
	// Check if it's self-signed (root CA property)
	if !isCertSelfSigned(cert) {
		return fmt.Errorf("certificate is not self-signed (this appears to be an intermediate CA--not a root CA): Subject=%q, Issuer=%q", cert.Subject, cert.Issuer)
	}

	// Check if it has CA capabilities
	if !cert.IsCA {
		return fmt.Errorf("certificate does not have CA capabilities (Basic Constraints CA:FALSE)")
	}

	// Check key usage for certificate signing
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate does not have certificate signing capability")
	}

	// Verify self-signature
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("certificate signature verification failed: %w", err)
	}

	return nil
}

// validateCABundle validates a bundle of certificates
func validateCABundle(certs []*x509.Certificate) error {
	rootCount := 0
	intermediateCount := 0
	invalidCount := 0

	for _, cert := range certs {
		if !cert.IsCA {
			invalidCount++
			continue
		}

		if isCertSelfSigned(cert) {
			// Verify it's a valid self-signed certificate
			if err := cert.CheckSignatureFrom(cert); err != nil {
				invalidCount++
				continue
			}
			rootCount++
		} else {
			intermediateCount++
		}
	}

	if rootCount == 0 {
		return fmt.Errorf("CA bundle contains %d certificates but no valid root CAs (found %d intermediate CAs, %d invalid certificates)", len(certs), intermediateCount, invalidCount)
	}

	// Bundle is valid - log summary
	logger.Info("CA bundle validation passed", 
		"total_certificates", len(certs),
		"root_cas", rootCount,
		"intermediate_cas", intermediateCount,
		"invalid_certificates", invalidCount,
	)

	return nil
}

// parseAllCertificates parses all certificates from PEM data (handles bundles)
func parseAllCertificates(certData []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	remaining := certData

	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			remaining = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Log warning but continue parsing other certificates
			logger.Warn("Failed to parse certificate in bundle", "error", err)
			remaining = rest
			continue
		}

		certificates = append(certificates, cert)
		remaining = rest
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no valid certificates found in PEM data")
	}

	return certificates, nil
}

// parseCertificate parses a single certificate from PEM data
func parseCertificate(certData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM certificate block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// isCertSelfSigned checks if a certificate is self-signed (subject equals issuer)
func isCertSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}
