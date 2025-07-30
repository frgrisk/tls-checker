package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	amqp "github.com/rabbitmq/amqp091-go"
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
	clientCmd.Flags().Bool("rabbitmq", false, "Connect to RabbitMQ instead of HTTP server")
}

func runClient(cmd *cobra.Command, _ []string) {
	rootCAFile := viper.GetString("ca")
	addr := viper.GetString("addr")

	useRabbitMQ, _ := cmd.Flags().GetBool("rabbitmq")
	if useRabbitMQ {
		runRabbitMQClient(rootCAFile, addr)
	} else {
		runHTTPClient(rootCAFile, addr)
	}
}

func runHTTPClient(rootCAFile, addr string) {
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
		MinVersion:         tls.VersionTLS12,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	url := "https://" + addr

	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body: %v", err) //nolint:gocritic
	}

	fmt.Printf("Server response: %s\n", body)
}

func runRabbitMQClient(rootCAFile, addr string) {
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
		MinVersion:         tls.VersionTLS12,
	}

	// Connect to RabbitMQ
	url := "amqps://guest:guest@" + addr

	conn, err := amqp.DialTLS(url, tlsConfig)
	if err != nil {
		log.Fatalf("failed to connect to RabbitMQ: %v", err)
	}
	defer conn.Close()

	log.Printf("Successfully connected to RabbitMQ at %s", addr)

	// Keep connection open until interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down RabbitMQ client...")
}
