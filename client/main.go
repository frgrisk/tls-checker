package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	// Load root CA certificate
	rootCA, err := os.ReadFile("rootCA.crt")
	if err != nil {
		log.Fatalf("failed to read root CA certificate: %v", err)
	}

	// Create a certificate pool from the root CA
	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM(rootCA); !ok {
		log.Fatalf("failed to append root CA certificate to pool")
	}

	// Configure TLS with the client certificate and root CA pool
	tlsConfig := &tls.Config{
		RootCAs:            rootCAPool,
		InsecureSkipVerify: false, // Ensure server certificate is verified
	}

	// Create an HTTPS client with the TLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Make a request to the server
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Read and print the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}
	fmt.Printf("Server response: %s\n", body)
}
