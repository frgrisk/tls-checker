package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate certificate files and configurations",
	Run:   runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(_ *cobra.Command, _ []string) {
	certFile := viper.GetString("cert")
	rootCAFile := viper.GetString("ca")

	logger.Info("Validating certificate configuration...")

	// Validate root CA
	if err := validateRootCA(rootCAFile); err != nil {
		logger.Fatal("Root CA validation failed", "file", rootCAFile, "error", err)
	}

	logger.Info("✅ Root CA validation passed", "file", rootCAFile)

	// Validate server certificate
	if err := validateServerCert(certFile); err != nil {
		logger.Fatal("Server certificate validation failed", "file", certFile, "error", err)
	}

	logger.Info("✅ Server certificate validation passed", "file", certFile)

	// Validate certificate chain relationship
	if err := validateCertificateChain(certFile, rootCAFile); err != nil {
		logger.Fatal("Certificate chain validation failed", "error", err)
	}

	logger.Info("✅ Certificate chain validation passed")

	logger.Info("🎉 All validations passed successfully!")
}

// validateRootCA checks if the provided certificate is actually a root CA.
func validateRootCA(rootCAFile string) error {
	return ValidateRootCAFile(rootCAFile)
}

// validateServerCert checks if the server certificate is valid.
func validateServerCert(certFile string) error {
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read server certificate file: %w", err)
	}

	cert, err := parseCertificate(certData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if it's NOT a CA (server certs should not be CAs)
	if cert.IsCA {
		logger.Warn("Server certificate has CA capabilities. This may be a security risk.")
	}

	// Check key usage for server authentication
	if len(cert.ExtKeyUsage) > 0 {
		hasServerAuth := slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		if !hasServerAuth {
			return errors.New("certificate does not have server authentication capability")
		}
	}

	return nil
}

// validateCertificateChain checks if the server certificate can be validated against the root CA(s).
func validateCertificateChain(certFile, rootCAFile string) error {
	// Load certificate chain (may contain server cert + intermediates)
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Parse all certificates from the chain file
	chainCerts, err := parseAllCertificates(certData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate chain: %w", err)
	}

	if len(chainCerts) == 0 {
		return errors.New("no certificates found in certificate file")
	}

	// First certificate should be the server certificate
	serverCert := chainCerts[0]

	// Load root CA(s) - handle both single certificates and bundles
	rootCAData, err := os.ReadFile(rootCAFile)
	if err != nil {
		return fmt.Errorf("failed to read root CA: %w", err)
	}

	// Parse all certificates from the CA file (handles bundles)
	rootCACerts, err := parseAllCertificates(rootCAData)
	if err != nil {
		return fmt.Errorf("failed to parse root CA certificates: %w", err)
	}

	// Create certificate pool with all root CAs
	rootCAPool := x509.NewCertPool()
	for _, cert := range rootCACerts {
		rootCAPool.AddCert(cert)
	}

	// Create intermediate pool if there are intermediate certificates in the chain
	intermediatePool := x509.NewCertPool()

	if len(chainCerts) > 1 {
		for i := 1; i < len(chainCerts); i++ {
			intermediatePool.AddCert(chainCerts[i])
			logger.Debug("Added intermediate certificate", "subject", chainCerts[i].Subject.String())
		}
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         rootCAPool,
		Intermediates: intermediatePool,
	}

	chains, err := serverCert.Verify(opts)
	if err != nil {
		// Check if this is because of an intermediate CA
		var unknownAuthorityError x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthorityError) {
			return fmt.Errorf("certificate chain verification failed (this may indicate a missing intermediate CA): %w", err)
		}

		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	if len(chains) == 0 {
		return errors.New("no valid certificate chains found")
	}

	logger.Info("Certificate chain verified successfully", "chain_length", len(chains[0]))

	return nil
}
