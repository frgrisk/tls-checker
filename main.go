package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	// Define command-line flags
	isServer := flag.Bool("server", false, "Run in server mode (default: client mode)")
	certFile := flag.String("cert", "cert.pem", "Path to certificate file")
	keyFile := flag.String("key", "key.pem", "Path to private key file")
	rootCAFile := flag.String("ca", "rootCA.pem", "Path to root CA certificate")
	addr := flag.String("addr", "localhost:8443", "Address to serve on or connect to")
	flag.Parse()

	if *isServer {
		runServer(*certFile, *keyFile, *addr)
	} else {
		runClient(*rootCAFile, *addr)
	}
}

func runServer(certFile, keyFile, addr string) {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate and key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, TLS client!"))
		}),
	}

	log.Printf("Starting TLS server on %s...", addr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func runClient(rootCAFile, addr string) {
	// Load root CA certificate
	rootCA, err := os.ReadFile(rootCAFile)
	if err != nil {
		log.Fatalf("failed to read root CA certificate: %v", err)
	}

	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM(rootCA); !ok {
		log.Fatalf("failed to append root CA certificate to pool")
	}

	tlsConfig := &tls.Config{
		RootCAs:            rootCAPool,
		InsecureSkipVerify: false,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	url := fmt.Sprintf("https://%s", addr)
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err)
	}
	fmt.Printf("Server response: %s\n", body)
}
