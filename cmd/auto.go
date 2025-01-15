package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var autoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Automatically test both HTTP and RabbitMQ TLS connections",
	Run:   runAuto,
}

func init() {
	rootCmd.AddCommand(autoCmd)
	autoCmd.Flags().String("host", "localhost", "Host to use for connections")
}

// getRandomPort returns a random available port
func getRandomPort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func runAuto(cmd *cobra.Command, args []string) {
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	rootCAFile := viper.GetString("ca")
	host, _ := cmd.Flags().GetString("host")

	// Load root CA for client connections
	rootCA, err := os.ReadFile(rootCAFile)
	if err != nil {
		log.Fatalf("Failed to read root CA certificate: %v", err)
	}

	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM(rootCA); !ok {
		log.Fatalf("Failed to append root CA certificate to pool")
	}

	// Test HTTP Server
	httpPort, err := getRandomPort()
	if err != nil {
		log.Fatalf("Failed to get random port for HTTP: %v", err)
	}

	httpAddr := fmt.Sprintf("%s:%d", host, httpPort)
	log.Printf("Starting HTTP server on %s", httpAddr)

	server, err := startHTTPServer(certFile, keyFile, httpAddr)
	if err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}

	// Give the server a moment to start
	time.Sleep(time.Second)

	// Test HTTP connection
	clientTLSConfig := &tls.Config{
		RootCAs:    rootCAPool,
		ServerName: host,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
	}

	url := fmt.Sprintf("https://%s", httpAddr)
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("❌ HTTP connection test failed: %v", err)
	} else {
		log.Printf("✅ HTTP connection test successful")
		resp.Body.Close()
	}

	// Clean up HTTP server
	server.Close()

	// Test RabbitMQ
	amqpPort, err := getRandomPort()
	if err != nil {
		log.Fatalf("Failed to get random port for AMQP: %v", err)
	}

	mgmtPortTLS, err := getRandomPort()
	if err != nil {
		log.Fatalf("Failed to get random port for RabbitMQ management TLS: %v", err)
	}

	log.Printf("Starting RabbitMQ server (AMQPS: %d, Management: HTTPS=%d)", amqpPort, mgmtPortTLS)

	amqpAddr := fmt.Sprintf("%s:%d", host, amqpPort)
	containerID, err := startRabbitMQServer(certFile, keyFile, amqpPort, mgmtPortTLS)
	if err != nil {
		log.Fatalf("Failed to start RabbitMQ: %v", err)
	}

	// Give RabbitMQ time to start
	log.Printf("Waiting for RabbitMQ to start...")
	time.Sleep(10 * time.Second)

	// Test RabbitMQ connection
	amqpTLSConfig := &tls.Config{
		RootCAs:    rootCAPool,
		ServerName: host,
	}

	conn, err := amqp.DialTLS(fmt.Sprintf("amqps://guest:guest@%s", amqpAddr), amqpTLSConfig)
	if err != nil {
		log.Printf("❌ RabbitMQ connection test failed: %v", err)
	} else {
		log.Printf("✅ RabbitMQ connection test successful")
		conn.Close()
	}

	// Clean up RabbitMQ container
	cleanupRabbitMQ(containerID)
}
