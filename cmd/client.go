package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Run in client mode",
	Run:   runClient,
}

func init() {
	rootCmd.AddCommand(clientCmd)
}

func runClient(cmd *cobra.Command, args []string) {
	rootCAFile := viper.GetString("ca")
	addr := viper.GetString("addr")

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
