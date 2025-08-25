package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/huh/spinner"
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

// getRandomPort returns a random available port.
func getRandomPort() (int, error) {
	listener, err := net.Listen("tcp", ":0") //nolint:gosec
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitForRabbitMQ(addr string, tlsConfig *tls.Config) error {
	return spinner.New().
		Title("Waiting for RabbitMQ to start...").
		Accessible(os.Getenv("ACCESSIBLE") != "").
		ActionWithErr(func(context.Context) error {
			// Try to connect every second until successful or timeout
			start := time.Now()
			for time.Since(start) < 30*time.Second {
				conn, err := amqp.DialTLS("amqps://guest:guest@"+addr, tlsConfig)
				if err == nil {
					conn.Close()
					return nil
				}

				if !strings.Contains(err.Error(), syscall.ECONNREFUSED.Error()) &&
					!strings.Contains(err.Error(), syscall.ECONNRESET.Error()) &&
					err.Error() != io.EOF.Error() {
					return err
				}

				time.Sleep(time.Second)
			}

			return errors.New("timeout waiting for RabbitMQ")
		}).
		Run()
}


func runAuto(cmd *cobra.Command, _ []string) { //nolint:cyclop
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	rootCAFile := viper.GetString("ca")
	host, _ := cmd.Flags().GetString("host")

	// Validate root CA first
	if err := ValidateRootCAFile(rootCAFile); err != nil {
		logger.Warn("⚠️  Root CA validation failed", "file", rootCAFile, "error", err)
		logger.Warn("Proceeding anyway, but this may indicate a configuration issue")
	}

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
		RootCAs:            rootCAPool,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
	}

	url := "https://" + httpAddr

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

	containerID, err := startRabbitMQServer(certFile, keyFile, amqpPort, mgmtPortTLS)
	if err != nil {
		logger.Fatal("Failed to start RabbitMQ", "error", err)
	}

	amqpAddr := fmt.Sprintf("%s:%d", host, amqpPort)

	// Wait for RabbitMQ with spinner
	amqpTLSConfig := &tls.Config{
		RootCAs:            rootCAPool,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}

	if err := waitForRabbitMQ(amqpAddr, amqpTLSConfig); err != nil {
		logger.Fatal("Failed waiting for RabbitMQ", "error", err)
	}

	// Test RabbitMQ connection
	conn, err := amqp.DialTLS("amqps://guest:guest@"+amqpAddr, amqpTLSConfig)
	if err != nil {
		logger.Error("RabbitMQ connection test failed", "error", err)
	} else {
		logger.Info("✅ RabbitMQ connection test successful")
		conn.Close()
	}

	// Clean up RabbitMQ container
	cleanupRabbitMQ(containerID)
}
