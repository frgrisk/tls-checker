# TLS Checker

A command-line tool for testing TLS connections with both HTTP and RabbitMQ servers.

## Features

- HTTP server with TLS support
- RabbitMQ server with TLS support (using Docker)
- HTTP client for testing TLS connections
- AMQP client for testing RabbitMQ TLS connections
- Configurable via command line flags or config file
- Auto mode for automated testing of both server types

## Installation

### Prerequisites

- Go 1.19 or later
- Docker (for RabbitMQ server functionality)

### Installing from source

```bash
go install https://github.com/frgrisk/tls-checker@latest
```

## Usage

### Auto Mode (Recommended)

Automatically test both HTTP and RabbitMQ TLS connections:

```bash
tls-checker auto --cert cert.pem --key key.pem --ca rootCA.pem --host localhost
```

This will:
1. Start an HTTPS server on a random port and test the connection
2. Start a RabbitMQ server with TLS on random ports and test the connection
3. Clean up all servers after testing

### Manual Server Modes

### Running HTTP Server

```bash
tls-checker server --cert cert.pem --key key.pem --addr localhost:8443
```

### Running RabbitMQ Server

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

### Server-specific Flags

- `--rabbitmq`: Run RabbitMQ server instead of HTTP server

### Config File Format

```yaml
cert: "cert.pem"
key: "key.pem"
ca: "rootCA.pem"
addr: "localhost:8443"
```

## RabbitMQ Server Details

When running the RabbitMQ server:

- AMQPS port: 5671
- Management UI:
  - HTTP: http://localhost:15672
  - HTTPS: https://localhost:15671
- Default credentials: guest/guest

## Security Notes

- The tool uses TLS 1.2+ for secure communications
- Certificate verification is enabled by default
- RabbitMQ server is run in a Docker container with proper TLS configuration
