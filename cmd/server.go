package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
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
	serverCmd.Flags().Bool("rabbitmq", false, "Run RabbitMQ server instead of HTTP server")
}

func runServer(cmd *cobra.Command, args []string) {
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	addr := viper.GetString("addr")

	useRabbitMQ, _ := cmd.Flags().GetBool("rabbitmq")
	if useRabbitMQ {
		containerID, err := startRabbitMQServer(certFile, keyFile, 5671, 15671)
		if err != nil {
			log.Fatalf("Failed to start RabbitMQ: %v", err)
		}

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		cleanupRabbitMQ(containerID)
	} else {
		server, err := startHTTPServer(certFile, keyFile, addr)
		if err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		if err := server.Close(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	}
}

// startHTTPServer starts an HTTPS server and returns the server instance
func startHTTPServer(certFile, keyFile, addr string) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %v", err)
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

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	log.Printf("Starting TLS server on %s...", addr)
	return server, nil
}

// startRabbitMQServer starts a RabbitMQ server in a Docker container and returns the container ID
func startRabbitMQServer(certFile, keyFile string, amqpPort, mgmtPortTLS int) (string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %v", err)
	}
	defer cli.Close()

	// Get absolute paths for mounting certificates
	certPath, err := filepath.Abs(certFile)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for cert: %v", err)
	}
	keyPath, err := filepath.Abs(keyFile)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for key: %v", err)
	}

	// Create a temporary rabbitmq.conf file
	configContent := fmt.Sprintf(`
listeners.ssl.default = %d

ssl_options.certfile   = /etc/rabbitmq/certs/cert.pem
ssl_options.keyfile    = /etc/rabbitmq/certs/key.pem
ssl_options.verify     = verify_none
ssl_options.fail_if_no_peer_cert = false

management.ssl.port       = %d
management.ssl.certfile   = /etc/rabbitmq/certs/cert.pem
management.ssl.keyfile    = /etc/rabbitmq/certs/key.pem
`, amqpPort, mgmtPortTLS)

	tmpConfigFile, err := os.CreateTemp("", "rabbitmq.*.conf")
	if err != nil {
		return "", fmt.Errorf("failed to create temp config: %v", err)
	}

	if _, err := tmpConfigFile.WriteString(configContent); err != nil {
		return "", fmt.Errorf("failed to write config: %v", err)
	}
	tmpConfigFile.Close()

	// Create container
	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image: "rabbitmq:3-management",
			ExposedPorts: nat.PortSet{
				nat.Port(fmt.Sprintf("%d/tcp", amqpPort)):    {},
				nat.Port(fmt.Sprintf("%d/tcp", mgmtPortTLS)): {},
			},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{
				nat.Port(fmt.Sprintf("%d/tcp", amqpPort)): []nat.PortBinding{
					{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", amqpPort)},
				},
				nat.Port(fmt.Sprintf("%d/tcp", mgmtPortTLS)): []nat.PortBinding{
					{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", mgmtPortTLS)},
				},
			},
			Binds: []string{
				fmt.Sprintf("%s:/etc/rabbitmq/certs/cert.pem:ro", certPath),
				fmt.Sprintf("%s:/etc/rabbitmq/certs/key.pem:ro", keyPath),
				fmt.Sprintf("%s:/etc/rabbitmq/rabbitmq.conf:ro", tmpConfigFile.Name()),
			},
		},
		nil,
		nil,
		"rabbitmq-tls",
	)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %v", err)
	}

	// Start container
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("failed to start container: %v", err)
	}

	log.Printf("Started RabbitMQ container with ID: %s", resp.ID[:12])
	log.Printf("Management UI available at: https://localhost:%d", mgmtPortTLS)
	log.Printf("AMQPS available at: amqps://localhost:%d", amqpPort)

	return resp.ID, nil
}

func cleanupRabbitMQ(containerID string) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Printf("Failed to create Docker client for cleanup: %v", err)
		return
	}
	defer cli.Close()

	timeout := 10
	if err := cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		log.Printf("Failed to stop container: %v", err)
	}

	if err := cli.ContainerRemove(ctx, containerID, container.RemoveOptions{}); err != nil {
		log.Printf("Failed to remove container: %v", err)
	}
}
