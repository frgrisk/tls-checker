package cmd

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run in server mode",
	Run:   runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) {
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	addr := viper.GetString("addr")

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
