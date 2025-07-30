package cmd

import (
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

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var spinnerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))

type spinnerMsg struct{ err error }

type spinnerModel struct {
	spinner  spinner.Model
	addr     string
	tls      *tls.Config
	quitting bool
}

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

func waitForRabbitMQ(addr string, tlsConfig *tls.Config) tea.Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle

	return spinnerModel{
		spinner: s,
		addr:    addr,
		tls:     tlsConfig,
	}
}

func (m spinnerModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		func() tea.Msg {
			// Try to connect every second until successful or timeout
			start := time.Now()
			for time.Since(start) < 30*time.Second {
				conn, err := amqp.DialTLS("amqps://guest:guest@"+m.addr, m.tls)
				if err == nil {
					conn.Close()
					return spinnerMsg{nil}
				}

				if !strings.Contains(err.Error(), syscall.ECONNREFUSED.Error()) &&
					!strings.Contains(err.Error(), syscall.ECONNRESET.Error()) &&
					err.Error() != io.EOF.Error() {
					return spinnerMsg{err}
				}

				time.Sleep(time.Second)
			}

			return spinnerMsg{errors.New("timeout waiting for RabbitMQ")}
		},
	)
}

func (m spinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	case spinnerMsg:
		if msg.err != nil {
			m.quitting = true
			return m, tea.Quit
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

func (m spinnerModel) View() string {
	if m.quitting {
		return ""
	}

	return fmt.Sprintf("\n  %s Waiting for RabbitMQ to start...\n\n", m.spinner.View())
}

func runAuto(cmd *cobra.Command, _ []string) { //nolint:cyclop
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

	p := tea.NewProgram(waitForRabbitMQ(amqpAddr, amqpTLSConfig))
	if _, err := p.Run(); err != nil {
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
