package main

import (
	"crypto/tls"
	"log"
	"net/http"
)

func main() {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load server certificate and key: %v", err)
	}

	// Configure TLS with the server certificate and root CA pool
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create an HTTPS server with the TLS configuration
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, TLS client!"))
		}),
	}

	log.Println("Starting TLS server on port 8443...")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
