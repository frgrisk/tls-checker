package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
		logger.Fatal("Failed to read root CA certificate", "error", err)
	}

	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM(rootCA); !ok {
		logger.Fatal("Failed to append root CA certificate to pool")
	}

	// Test HTTP Server
	httpPort, err := getRandomPort()
	if err != nil {
		logger.Fatal("Failed to get random port for HTTP", "error", err)
	}

	httpAddr := fmt.Sprintf("%s:%d", host, httpPort)
	logger.Info("Starting HTTP server", "address", httpAddr)

	server, err := startHTTPServer(certFile, keyFile, httpAddr)
	if err != nil {
		logger.Fatal("Failed to start HTTP server", "error", err)
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
		logger.Error("HTTP connection test failed", "error", err)
	} else {
		logger.Info("✅ HTTP connection test successful")
		resp.Body.Close()
	}

	// Clean up HTTP server
	server.Close()

	// Test RabbitMQ
	amqpPort, err := getRandomPort()
	if err != nil {
		logger.Fatal("Failed to get random port for AMQP", "error", err)
	}

	mgmtPortTLS, err := getRandomPort()
	if err != nil {
		logger.Fatal("Failed to get random port for RabbitMQ management TLS", "error", err)
	}

	logger.Info("Starting RabbitMQ server",
		"amqps_port", amqpPort,
		"management_port", mgmtPortTLS,
	)

	amqpAddr := fmt.Sprintf("%s:%d", host, amqpPort)
	containerID, err := startRabbitMQServer(certFile, keyFile, amqpPort, mgmtPortTLS)
	if err != nil {
		logger.Fatal("Failed to start RabbitMQ", "error", err)
	}

	// Give RabbitMQ time to start
	logger.Info("Waiting for RabbitMQ to start...")
	time.Sleep(10 * time.Second)

	// Test RabbitMQ connection
	amqpTLSConfig := &tls.Config{
		RootCAs:    rootCAPool,
		ServerName: host,
	}

	conn, err := amqp.DialTLS(fmt.Sprintf("amqps://guest:guest@%s", amqpAddr), amqpTLSConfig)
	if err != nil {
		logger.Error("RabbitMQ connection test failed", "error", err)
	} else {
		logger.Info("✅ RabbitMQ connection test successful")
		conn.Close()
	}

	// Clean up RabbitMQ container
	cleanupRabbitMQ(containerID)
}
