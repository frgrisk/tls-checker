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
		runRabbitMQ(certFile, keyFile, addr)
	} else {
		runHTTPServer(certFile, keyFile, addr)
	}
}

func runHTTPServer(certFile, keyFile, addr string) {
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

	// Handle shutdown gracefully
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down HTTP server...")
		if err := server.Close(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	}()

	log.Printf("Starting TLS server on %s...", addr)
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}

func runRabbitMQ(certFile, keyFile, addr string) {
	ctx := context.Background()

	// Create Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatalf("failed to create Docker client: %v", err)
	}
	defer cli.Close()

	// Get absolute paths for mounting certificates
	certPath, err := filepath.Abs(certFile)
	if err != nil {
		log.Fatalf("failed to get absolute path for cert: %v", err)
	}
	keyPath, err := filepath.Abs(keyFile)
	if err != nil {
		log.Fatalf("failed to get absolute path for key: %v", err)
	}

	// Create temporary rabbitmq.conf file
	configContent := fmt.Sprintf(`
listeners.ssl.default = 5671

ssl_options.certfile   = /etc/rabbitmq/certs/cert.pem
ssl_options.keyfile    = /etc/rabbitmq/certs/key.pem
ssl_options.verify     = verify_none
ssl_options.fail_if_no_peer_cert = false

management.ssl.port       = 15671
management.ssl.certfile   = /etc/rabbitmq/certs/cert.pem
management.ssl.keyfile    = /etc/rabbitmq/certs/key.pem
`)

	tmpConfigFile, err := os.CreateTemp("", "rabbitmq.*.conf")
	if err != nil {
		log.Fatalf("failed to create temp config: %v", err)
	}
	defer os.Remove(tmpConfigFile.Name())

	if _, err := tmpConfigFile.WriteString(configContent); err != nil {
		log.Fatalf("failed to write config: %v", err)
	}
	tmpConfigFile.Close()

	// Create container
	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image: "rabbitmq:3-management",
			ExposedPorts: nat.PortSet{
				"5671/tcp":  {}, // AMQPS
				"15671/tcp": {}, // Management HTTPS
				"15672/tcp": {}, // Management HTTP
			},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{
				"5671/tcp":  []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: "5671"}},
				"15671/tcp": []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: "15671"}},
				"15672/tcp": []nat.PortBinding{{HostIP: "0.0.0.0", HostPort: "15672"}},
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
		log.Fatalf("failed to create container: %v", err)
	}

	// Start container
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		log.Fatalf("failed to start container: %v", err)
	}

	log.Printf("Started RabbitMQ container with ID: %s", resp.ID[:12])
	log.Printf("Management UI available at:\n  http://localhost:15672\n  https://localhost:15671")
	log.Printf("AMQPS available at: amqps://localhost:5671")

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down...")

	// Stop and remove container
	timeout := 10 // seconds
	if err := cli.ContainerStop(ctx, resp.ID, container.StopOptions{Timeout: &timeout}); err != nil {
		log.Printf("failed to stop container: %v", err)
	}
	if err := cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{}); err != nil {
		log.Printf("failed to remove container: %v", err)
	}

	log.Println("Cleanup complete")
}
