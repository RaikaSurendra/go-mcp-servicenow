# MCP-Go-ServiceNow

A Message Communication Protocol (MCP) implementation in Go for ServiceNow integration.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Server Configuration](#server-configuration)
- [Client Configuration](#client-configuration)
- [Server CLI Commands](#server-cli-commands)
- [Client CLI Commands](#client-cli-commands)
- [Environment Variables](#environment-variables)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Introduction

MCP-Go-ServiceNow is a Go implementation of a Message Communication Protocol for ServiceNow integration. It consists of a server component that connects to ServiceNow's REST API and a client component that communicates with the server using an optimized binary protocol.

Key features:
- **Optimized Protocol**: Efficient binary message format for low-latency communication
- **Authentication**: Secure client-server authentication
- **Reconnection**: Automatic reconnection with exponential backoff
- **ServiceNow Integration**: Seamless incident management operations
- **CLI Tools**: Command-line interfaces for both server and client operations

## Installation

### Prerequisites

- Go 1.16 or higher
- ServiceNow instance with REST API access

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-go-servicenow.git
cd mcp-go-servicenow

# Build the server
go build -o bin/mcp-server ./cmd/server

# Build the client
go build -o bin/mcp-client ./cmd/client

# Install (optional)
go install ./cmd/server
go install ./cmd/client
```

## Server Configuration

The server can be configured using a YAML configuration file, environment variables, or command-line flags.

### Generate Default Configuration

```bash
mcp-server config --config /etc/mcp/server.yaml
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `server.address` | Server bind address | `0.0.0.0` |
| `server.port` | Server port | `9090` |
| `server.max_connections` | Maximum number of concurrent client connections | `100` |
| `server.read_timeout` | Read timeout in seconds | `30` |
| `server.write_timeout` | Write timeout in seconds | `30` |
| `server.idle_timeout` | Idle connection timeout in seconds | `300` |
| `servicenow.url` | ServiceNow instance URL | `https://dev123456.service-now.com` |
| `servicenow.username` | ServiceNow username | `admin` |
| `servicenow.password` | ServiceNow password | `password` |
| `servicenow.timeout` | ServiceNow API timeout in seconds | `30` |
| `log.level` | Log level (debug, info, warn, error) | `info` |
| `log.file` | Log file path (empty for stdout) | `""` |
| `debug` | Enable debug mode | `false` |

### Sample Configuration File

```yaml
server:
  address: 0.0.0.0
  port: 9090
  max_connections: 100
  read_timeout: 30
  write_timeout: 30
  idle_timeout: 300
servicenow:
  url: https://dev123456.service-now.com
  username: admin
  password: password
  timeout: 30
log:
  level: info
  file: /var/log/mcp-server.log
debug: false
```

## Client Configuration

The client can be configured using a YAML configuration file, environment variables, or command-line flags.

### Generate Default Configuration

```bash
mcp-client config --config ~/.mcp/client.yaml
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `server.address` | MCP server address (host:port) | `localhost:9090` |
| `client.timeout` | Operation timeout in seconds | `30` |
| `client.output_format` | Output format (human, json) | `human` |
| `client.retry_attempts` | Number of reconnection attempts | `3` |
| `client.retry_wait_time` | Initial wait time between retries in seconds | `2` |
| `client.reconnect_on_fail` | Automatically reconnect on failure | `true` |
| `client.connect_timeout` | Connection timeout in seconds | `10` |
| `auth.username` | MCP server username | `admin` |
| `auth.password` | MCP server password | `password` |
| `log.level` | Log level (debug, info, warn, error) | `info` |
| `log.file` | Log file path (empty for stdout) | `""` |
| `debug` | Enable debug mode | `false` |

### Sample Configuration File

```yaml
server:
  address: localhost:9090
client:
  timeout: 30
  output_format: human
  retry_attempts: 3
  retry_wait_time: 2
  reconnect_on_fail: true
  connect_timeout: 10
auth:
  username: admin
  password: password
log:
  level: info
  file: ~/.mcp/mcp-client.log
debug: false
```

## Server CLI Commands

The server CLI provides commands to manage the MCP server.

### Help

```bash
mcp-server --help
```

### Start Server

```bash
# Start with default configuration
mcp-server start

# Start with custom configuration file
mcp-server start --config /etc/mcp/my-server.yaml

# Start with custom parameters
mcp-server start --addr 127.0.0.1 --port 8080 --max-connections 50 --idle-timeout 600
```

### Generate Configuration

```bash
# Generate default configuration file
mcp-server config

# Generate configuration to a specific path
mcp-server config --config /etc/mcp/my-server.yaml
```

### Display Version

```bash
mcp-server version
```

## Client CLI Commands

The client CLI provides commands to interact with the MCP server and ServiceNow.

### Help

```bash
mcp-client --help
```

### Connect to Server

```bash
# Connect with configuration file credentials
mcp-client connect

# Connect with custom credentials
mcp-client connect --server localhost:9090 --username admin --password password

# Connect and keep connection open
mcp-client connect --keep-open
```

### Get Incidents

```bash
# Get the default number of incidents (10)
mcp-client get-incidents

# Get a specific number of incidents
mcp-client get-incidents --limit 20

# Filter incidents with a query
mcp-client get-incidents --query "priority=1^state=1"

# Get a short summary
mcp-client get-incidents --short

# Output as JSON
mcp-client get-incidents --output json
```

### Get Specific Incident

```bash
# Get an incident by ID
mcp-client get-incident --id abcdef123456789

# Output as JSON
mcp-client get-incident --id abcdef123456789 --output json
```

### Create Incident

```bash
# Create an incident with JSON data
mcp-client create-incident '{"short_desc": "Server Down", "description": "The production server is not responding", "priority": "1", "impact": "1"}'

# Create an incident from a file
cat incident.json | mcp-client create-incident
```

### Update Incident

```bash
# Update an incident with JSON data
mcp-client update-incident --id abcdef123456789 '{"state": "2", "assigned_to": "john.doe"}'

# Update an incident from a file
cat incident_update.json | mcp-client update-incident --id abcdef123456789
```

### Delete Incident

```bash
# Delete an incident by ID
mcp-client delete-incident --id abcdef123456789
```

### Generate Configuration

```bash
# Generate default configuration file
mcp-client config

# Generate configuration to a specific path
mcp-client config --config ~/.mcp/my-client.yaml
```

### Display Version

```bash
mcp-client version
```

## Environment Variables

Both the server and client can be configured using environment variables. The environment variable names are derived from the configuration keys by converting them to uppercase and replacing dots with underscores.

### Server Environment Variables

```bash
# Server Configuration
export MCP_SERVER_ADDRESS=0.0.0.0
export MCP_SERVER_PORT=9090
export MCP_SERVER_MAX_CONNECTIONS=100
export MCP_SERVER_READ_TIMEOUT=30
export MCP_SERVER_WRITE_TIMEOUT=30
export MCP_SERVER_IDLE_TIMEOUT=300

# ServiceNow Configuration
export MCP_SERVICENOW_URL=https://dev123456.service-now.com
export MCP_SERVICENOW_USERNAME=admin
export MCP_SERVICENOW_PASSWORD=password
export MCP_SERVICENOW_TIMEOUT=30

# Logging Configuration
export MCP_LOG_LEVEL=info
export MCP_LOG_FILE=/var/log/mcp-server.log
export MCP_DEBUG=false
```

### Client Environment Variables

```bash
# Server Connection
export MCP_SERVER_ADDRESS=localhost:9090

# Client Configuration
export MCP_CLIENT_TIMEOUT=30
export MCP_CLIENT_OUTPUT_FORMAT=human
export MCP_CLIENT_RETRY_ATTEMPTS=3
export MCP_CLIENT_RETRY_WAIT_TIME=2
export MCP_CLIENT_RECONNECT_ON_FAIL=true
export MCP_CLIENT_CONNECT_TIMEOUT=10

# Authentication
export MCP_AUTH_USERNAME=admin
export MCP_AUTH_PASSWORD=password

# Logging Configuration
export MCP_LOG_LEVEL=info
export MCP_LOG_FILE=~/.mcp/mcp-client.log
export MCP_DEBUG=false
```

## Examples

Here are some common usage examples for the MCP ServiceNow client.

### Basic Workflow

```bash
# Start the server
mcp-server start

# In another terminal, connect to the server
mcp-client connect

# Get the most recent incidents
mcp-client get-incidents --limit 5

# Create a new incident
mcp-client create-incident '{
  "short_desc": "Network outage",
  "description": "Network is down in Building A",
  "priority": "1",
  "category": "network",
  "impact": "2",
  "urgency": "1"
}'

# Update the incident status
mcp-client update-incident --id abcdef123456789 '{
  "state": "2",
  "assigned_to": "network.admin",
  "work_notes": "Investigating the issue"
}'

# Check the updated incident
mcp-client get-incident --id abcdef123456789

# Resolve the incident
mcp-client update-incident --id abcdef123456789 '{
  "state": "6",
  "close_code": "Solved",
  "close_notes": "Network equipment restarted and services restored"
}'
```

### Scripting Example

```bash
#!/bin/bash
# Script to create an incident and process the response

# Create the incident and capture the output
RESPONSE=$(mcp-client create-incident --output json '{
  "short_desc": "Automated alert: Disk space low",
  "description": "Server disk space is below 10%",
  "priority": "2",
  "category": "hardware"
}')

# Extract the incident ID from the JSON response
INCIDENT_ID=$(echo $RESPONSE | jq -r '.sys_id')

# Use the incident ID for further operations
echo "Created incident ID: $INCIDENT_ID"

# Assign the incident to the system admin
mcp-client update-incident --id $INCIDENT_ID '{
  "assigned_to": "system.admin",
  "work_notes": "Auto-assigned for disk cleanup"
}'

echo "Incident assigned to system admin"
```

## Troubleshooting

### Common Issues

#### Server Won't Start

- Check if another process is using the configured port
- Verify ServiceNow credentials and URL
- Check log file for detailed error messages

```bash
# Check if port is in use
lsof -i :9090

# Start server with debug mode for more verbose logging
mcp-server start --debug
```

#### Client Connection Failures

- Ensure the server is running
- Check server address and port
- Verify username and password
- Try with debug logging enabled

```bash
# Test connection with debug mode
mcp-client connect --debug

# Check network connectivity
telnet localhost 9090
```

#### Authentication Issues

- Verify credentials in configuration file or command line
- Check if the user exists on the server
- Ensure the server is properly configured with the same authentication settings

#### Slow Response Times

- Check network latency between client and server
- Verify ServiceNow instance responsiveness
- Consider increasing timeout settings

```bash
# Increase operation timeout
mcp-client get-incidents --timeout 60
```

### Log Files

Check log files for detailed error messages:

- Server log: By default `/var/log/mcp-server.log` or as configured
- Client log: By default `~/.mcp/mcp-client.log` or as configured

### Getting Help

If you encounter issues not covered here:

1. Enable debug mode for more verbose logging
2. Check the logs for detailed error messages
3. Open an issue in the GitHub repository with detailed information

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## API Rate Limiting and Best Practices

ServiceNow implements API rate limiting which can impact the performance of your MCP service. Here are some best practices to optimize your API usage:

### Rate Limit Awareness

- ServiceNow typically imposes limits on API requests (varies by instance)
- MCP Server includes built-in rate limiting to avoid overwhelming the ServiceNow API
- Monitor `X-RateLimit-Remaining` headers in responses to track usage

### Optimizing API Calls

```bash
# Use query filters to limit data returned
mcp-client get-incidents --query "state=1^priority=1" --limit 5

# Request only needed fields
mcp-client get-incident --id abcdef123456789 --fields "number,short_description,state,priority"
```

### Caching Strategies

The MCP server implements several caching strategies:

- Time-based caching: Cache responses for a configurable time period
- Conditional requests: Use ServiceNow's ETag support to reduce data transfer
- Stale-while-revalidate: Serve cached data while updating in the background

Configure caching in server.yaml:

```yaml
cache:
  enabled: true
  ttl: 300  # Time-to-live in seconds
  size: 1000  # Maximum number of cached items
  conditional_requests: true
```

## Security Considerations

### Credential Management

- **Never** hardcode credentials in your application
- Use environment variables or secure credential storage
- Consider using a secrets management solution for production

### Network Security

- The MCP server should be deployed behind a firewall or VPN
- Consider using TLS for server-client communication:

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start server with TLS
mcp-server start --tls --cert-file cert.pem --key-file key.pem

# Connect client with TLS
mcp-client connect --tls --insecure  # For self-signed certs
```

### Authentication

- The MCP server supports multiple authentication methods:
  - Basic authentication (username/password)
  - API key authentication
  - OAuth2 token (recommended for production)

Configure in server.yaml:

```yaml
auth:
  method: oauth2
  token_endpoint: https://your-auth-server.com/token
  client_id: your-client-id
  client_secret: your-client-secret
```

## Performance Tuning

### Server Scaling

- Use resource monitoring to identify bottlenecks
- Adjust connection pool sizes based on load:

```yaml
server:
  max_connections: 500
  worker_pool_size: 50  # Number of worker goroutines
  queue_size: 1000      # Request queue size
```

### Client Optimizations

- Configure optimal timeout values:

```bash
# Increase timeout for large operations
mcp-client get-incidents --limit 100 --timeout 60
```

- Use connection pooling:

```yaml
client:
  max_idle_conns: 10
  max_idle_conns_per_host: 5
  idle_conn_timeout: 90
```

### Monitoring and Profiling

The server supports runtime profiling to diagnose performance issues:

```bash
# Start server with profiling enabled
mcp-server start --profiling

# Access profiling data at http://localhost:6060/debug/pprof/
```

Using Prometheus metrics:

```bash
# Start server with metrics enabled
mcp-server start --metrics

# Access metrics at http://localhost:9090/metrics
```

## Acknowledgments

- ServiceNow for providing comprehensive API documentation
- The Go community for excellent libraries and tools
