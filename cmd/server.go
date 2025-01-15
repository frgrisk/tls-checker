package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
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

func runServer(cmd *cobra.Command, _ []string) {
	certFile := viper.GetString("cert")
	keyFile := viper.GetString("key")
	addr := viper.GetString("addr")

	useRabbitMQ, _ := cmd.Flags().GetBool("rabbitmq")
	if useRabbitMQ {
		containerID, err := startRabbitMQServer(certFile, keyFile, 5671, 15671) //nolint:mnd
		if err != nil {
			logger.Fatal("Failed to start RabbitMQ", "error", err)
		}

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		cleanupRabbitMQ(containerID)
	} else {
		server, err := startHTTPServer(certFile, keyFile, addr)
		if err != nil {
			logger.Fatal("Failed to start HTTP server", "error", err)
		}

		// Wait for interrupt
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		if err := server.Close(); err != nil {
			logger.Error("Error during shutdown", "error", err)
		}
	}
}

// startHTTPServer starts an HTTPS server and returns the server instance.
func startHTTPServer(certFile, keyFile, addr string) (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:              addr,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("Hello, TLS client!"))
		}),
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error", "error", err)
		}
	}()

	logger.Info("Starting TLS server", "address", addr)
	return server, nil
}

// ensureImageExists ensures the RabbitMQ image exists, pulling it if necessary.
func ensureImageExists(ctx context.Context, cli *client.Client, imageName string) error {
	_, _, err := cli.ImageInspectWithRaw(ctx, imageName)
	if err != nil {
		if !client.IsErrNotFound(err) {
			return fmt.Errorf("failed to inspect image: %w", err)
		}

		// Image not found, pull it with spinner
		s := spinner.New()
		s.Spinner = spinner.Dot
		s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))

		p := tea.NewProgram(pullSpinnerModel{
			spinner: s,
			client:  cli,
			ctx:     ctx,
			image:   imageName,
		})

		if _, err := p.Run(); err != nil {
			return fmt.Errorf("failed to pull RabbitMQ image: %w", err)
		}
	}
	return nil
}

// createRabbitMQConfig creates a temporary RabbitMQ config file.
func createRabbitMQConfig(amqpPort, mgmtPortTLS int) (string, error) {
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
		return "", fmt.Errorf("failed to create temp config: %w", err)
	}

	if _, err := tmpConfigFile.WriteString(configContent); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}
	tmpConfigFile.Close()
	return tmpConfigFile.Name(), nil
}

// startRabbitMQServer starts a RabbitMQ server in a Docker container and returns the container ID.
func startRabbitMQServer(certFile, keyFile string, amqpPort, mgmtPortTLS int) (string, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", fmt.Errorf("failed to create Docker client: %w", err)
	}
	defer cli.Close()

	imageName := "rabbitmq:3-management"
	if err := ensureImageExists(ctx, cli, imageName); err != nil {
		return "", err
	}

	// Get absolute paths for mounting certificates
	certPath, err := filepath.Abs(certFile)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for cert: %w", err)
	}
	keyPath, err := filepath.Abs(keyFile)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for key: %w", err)
	}

	configPath, err := createRabbitMQConfig(amqpPort, mgmtPortTLS)
	if err != nil {
		return "", err
	}

	// Create container
	resp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image: imageName,
			ExposedPorts: nat.PortSet{
				nat.Port(fmt.Sprintf("%d/tcp", amqpPort)):    {},
				nat.Port(fmt.Sprintf("%d/tcp", mgmtPortTLS)): {},
			},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{
				nat.Port(fmt.Sprintf("%d/tcp", amqpPort)): []nat.PortBinding{
					{HostIP: "0.0.0.0", HostPort: strconv.Itoa(amqpPort)},
				},
				nat.Port(fmt.Sprintf("%d/tcp", mgmtPortTLS)): []nat.PortBinding{
					{HostIP: "0.0.0.0", HostPort: strconv.Itoa(mgmtPortTLS)},
				},
			},
			Binds: []string{
				certPath + ":/etc/rabbitmq/certs/cert.pem:ro",
				keyPath + ":/etc/rabbitmq/certs/key.pem:ro",
				configPath + ":/etc/rabbitmq/rabbitmq.conf:ro",
			},
		},
		nil,
		nil,
		"rabbitmq-tls",
	)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	// Start container
	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	logger.Info("Started RabbitMQ container",
		"container_id", resp.ID[:12],
		"management_ui", fmt.Sprintf("https://localhost:%d", mgmtPortTLS),
		"amqps", fmt.Sprintf("amqps://localhost:%d", amqpPort),
	)

	return resp.ID, nil
}

func cleanupRabbitMQ(containerID string) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		logger.Error("Failed to create Docker client for cleanup", "error", err)
		return
	}
	defer cli.Close()

	// Create and run cleanup spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))

	p := tea.NewProgram(cleanupSpinnerModel{
		spinner:     s,
		containerID: containerID,
		client:      cli,
		ctx:         ctx,
	})

	if _, err := p.Run(); err != nil {
		logger.Error("Failed during cleanup", "error", err)
	}
}

type cleanupSpinnerModel struct {
	spinner     spinner.Model
	containerID string
	client      *client.Client
	ctx         context.Context
	quitting    bool
}

type cleanupMsg struct{ err error }

func (m cleanupSpinnerModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			timeout := 10
			if err := m.client.ContainerStop(m.ctx, m.containerID, container.StopOptions{Timeout: &timeout}); err != nil {
				return cleanupMsg{err}
			}
			if err := m.client.ContainerRemove(m.ctx, m.containerID, container.RemoveOptions{}); err != nil {
				return cleanupMsg{err}
			}
			return cleanupMsg{nil}
		},
	)
}

func (m cleanupSpinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	case cleanupMsg:
		if msg.err != nil {
			logger.Error("Cleanup failed", "error", msg.err)
		}
		m.quitting = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m cleanupSpinnerModel) View() string {
	if m.quitting {
		return ""
	}
	return fmt.Sprintf("\n  %s Cleaning up RabbitMQ container...\n\n", m.spinner.View())
}

type pullSpinnerModel struct {
	spinner  spinner.Model
	client   *client.Client
	ctx      context.Context
	image    string
	quitting bool
}

type pullMsg struct{ err error }

func (m pullSpinnerModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			reader, err := m.client.ImagePull(m.ctx, m.image, image.PullOptions{})
			if err != nil {
				return pullMsg{err}
			}
			defer reader.Close()
			_, _ = io.Copy(io.Discard, reader)
			return pullMsg{nil}
		},
	)
}

func (m pullSpinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	case pullMsg:
		if msg.err != nil {
			logger.Error("Image pull failed", "error", msg.err)
		}
		m.quitting = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m pullSpinnerModel) View() string {
	if m.quitting {
		return ""
	}
	return fmt.Sprintf("\n  %s Pulling RabbitMQ image...\n\n", m.spinner.View())
}
