# TLS Checker

A command-line tool for testing and validating TLS certificates, private keys, and root CA configurations. It supports testing TLS connections against both HTTP and RabbitMQ servers, ensuring your certificates are properly configured and trusted.

## Features

- Validate TLS certificate chains and trust relationships
- Test certificate/key pairs against HTTP and RabbitMQ servers
- Verify root CA trust configuration
- Auto mode for quick certificate validation with random ports
- Interactive spinners for progress feedback
- Configurable via command line flags or config file
- TLS 1.2+ enforced for security

## Certificate Requirements

The tool expects the following files:

- `cert.pem`: Server certificate
- `key.pem`: Private key for the server certificate
- `rootCA.pem`: Root CA certificate for client verification

All certificates should be in PEM format.

## Installation

### Prerequisites

- Go 1.21 or later
- Docker (for RabbitMQ server functionality)

### Installing from source

```bash
go install github.com/frgrisk/tls-checker@latest
```

## Usage

### Auto Mode (Recommended)

Automatically test both HTTP and RabbitMQ TLS connections with random ports:

```bash
tls-checker auto --cert cert.pem --key key.pem --ca rootCA.pem --host localhost
```

This will:

1. Start an HTTPS server on a random port and test the connection
2. Start a RabbitMQ server with TLS on random ports and test the connection
3. Clean up all servers after testing

### Manual Server Modes

#### Running HTTP Server

```bash
tls-checker server --cert cert.pem --key key.pem --addr localhost:8443
```

#### Running RabbitMQ Server

```bash
tls-checker server --rabbitmq --cert cert.pem --key key.pem
```

### Testing HTTP Connection

```bash
tls-checker client --ca rootCA.pem --addr localhost:8443
```

### Testing RabbitMQ Connection

```bash
tls-checker client --rabbitmq --ca rootCA.pem --addr localhost:5671
```

## Configuration

Configuration can be provided via command-line flags or a config file (`$HOME/.tlsapp.yaml`).

### Command-line Flags

- `--config`: Path to config file (default: `$HOME/.tlsapp.yaml`)
- `--cert`: Path to certificate file (default: `cert.pem`)
- `--key`: Path to private key file (default: `key.pem`)
- `--ca`: Path to root CA certificate (default: `rootCA.pem`)
- `--addr`: Address to serve on or connect to (default: `localhost:8443`)
- `--host`: Host to use for connections in auto mode (default: `localhost`)

### Config File Format

```yaml
cert: "cert.pem"
key: "key.pem"
ca: "rootCA.pem"
addr: "localhost:8443"
```

## Development

### Running Tests

```bash
go test ./...
```

### Linting

The project uses golangci-lint for code quality. To run linters:

```bash
golangci-lint run ./...
```

## Security Notes

- TLS 1.2+ enforced for all connections
- Certificate verification enabled by default
- RabbitMQ server runs in an isolated Docker container
- Temporary files cleaned up automatically
