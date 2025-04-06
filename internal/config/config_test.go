package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceNowConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *ServiceNowConfig
		expectError bool
	}{
		{
			name: "Valid Config",
			config: &ServiceNowConfig{
				URL:      "https://dev123456.service-now.com",
				Username: "admin",
				Password: "password",
				Timeout:  30,
			},
			expectError: false,
		},
		{
			name: "Missing URL",
			config: &ServiceNowConfig{
				Username: "admin",
				Password: "password",
				Timeout:  30,
			},
			expectError: true,
		},
		{
			name: "Missing Username",
			config: &ServiceNowConfig{
				URL:      "https://dev123456.service-now.com",
				Password: "password",
				Timeout:  30,
			},
			expectError: true,
		},
		{
			name: "Missing Password",
			config: &ServiceNowConfig{
				URL:      "https://dev123456.service-now.com",
				Username: "admin",
				Timeout:  30,
			},
			expectError: true,
		},
		{
			name: "Zero Timeout",
			config: &ServiceNowConfig{
				URL:      "https://dev123456.service-now.com",
				Username: "admin",
				Password: "password",
				Timeout:  0,
			},
			expectError: false, // Should use default
		},
		{
			name: "Negative Timeout",
			config: &ServiceNowConfig{
				URL:      "https://dev123456.service-now.com",
				Username: "admin",
				Password: "password",
				Timeout:  -10,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.expectError {
				t.Errorf("ServiceNowConfig.Validate() error = %v, expectError %v", err, tt.expectError)
			}

			// If timeout is 0, it should be set to default
			if tt.config.Timeout == 0 && err == nil {
				if tt.config.Timeout != 30 { // Assuming 30 is the default
					t.Errorf("ServiceNowConfig.Validate() did not set default timeout, got %d", tt.config.Timeout)
				}
			}
		})
	}
}

func TestMCPServerConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *MCPServerConfig
		expectError bool
	}{
		{
			name: "Valid Config",
			config: &MCPServerConfig{
				Address:        "0.0.0.0",
				Port:           9090,
				MaxConnections: 100,
				ReadTimeout:    30,
				WriteTimeout:   30,
				IdleTimeout:    300,
			},
			expectError: false,
		},
		{
			name: "Missing Address",
			config: &MCPServerConfig{
				Port:           9090,
				MaxConnections: 100,
				ReadTimeout:    30,
				WriteTimeout:   30,
				IdleTimeout:    300,
			},
			expectError: false, // Should use default
		},
		{
			name: "Invalid Port - Zero",
			config: &MCPServerConfig{
				Address:        "0.0.0.0",
				Port:           0,
				MaxConnections: 100,
				ReadTimeout:    30,
				WriteTimeout:   30,
				IdleTimeout:    300,
			},
			expectError: true,
		},
		{
			name: "Invalid Port - Negative",
			config: &MCPServerConfig{
				Address:        "0.0.0.0",
				Port:           -1,
				MaxConnections: 100,
				ReadTimeout:    30,
				WriteTimeout:   30,
				IdleTimeout:    300,
			},
			expectError: true,
		},
		{
			name: "Invalid Port - Too Large",
			config: &MCPServerConfig{
				Address:        "0.0.0.0",
				Port:           70000,
				MaxConnections: 100,
				ReadTimeout:    30,
				WriteTimeout:   30,
				IdleTimeout:    300,
			},
			expectError: true,
		},
		{
			name: "Default MaxConnections",
			config: &MCPServerConfig{
				Address:      "0.0.0.0",
				Port:         9090,
				ReadTimeout:  30,
				WriteTimeout: 30,
				IdleTimeout:  300,
			},
			expectError: false, // Should use default
		},
		{
			name: "Zero Timeouts",
			config: &MCPServerConfig{
				Address:        "0.0.0.0",
				Port:           9090,
				MaxConnections: 100,
				ReadTimeout:    0,
				WriteTimeout:   0,
				IdleTimeout:    0,
			},
			expectError: false, // Should use defaults
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.expectError {
				t.Errorf("MCPServerConfig.Validate() error = %v, expectError %v", err, tt.expectError)
			}

			// Check default values were set
			if tt.config.Address == "" && err == nil {
				if tt.config.Address != "0.0.0.0" { // Assuming this is the default
					t.Errorf("MCPServerConfig.Validate() did not set default address, got %s", tt.config.Address)
				}
			}

			if tt.config.MaxConnections == 0 && err == nil {
				if tt.config.MaxConnections != 100 { // Assuming 100 is the default
					t.Errorf("MCPServerConfig.Validate() did not set default MaxConnections, got %d", tt.config.MaxConnections)
				}
			}

			if tt.config.ReadTimeout == 0 && err == nil {
				if tt.config.ReadTimeout != 30 { // Assuming 30 is the default
					t.Errorf("MCPServerConfig.Validate() did not set default ReadTimeout, got %d", tt.config.ReadTimeout)
				}
			}

			if tt.config.WriteTimeout == 0 && err == nil {
				if tt.config.WriteTimeout != 30 { // Assuming 30 is the default
					t.Errorf("MCPServerConfig.Validate() did not set default WriteTimeout, got %d", tt.config.WriteTimeout)
				}
			}

			if tt.config.IdleTimeout == 0 && err == nil {
				if tt.config.IdleTimeout != 300 { // Assuming 300 is the default
					t.Errorf("MCPServerConfig.Validate() did not set default IdleTimeout, got %d", tt.config.IdleTimeout)
				}
			}
		})
	}
}

func TestMCPClientConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *MCPClientConfig
		expectError bool
	}{
		{
			name: "Valid Config",
			config: &MCPClientConfig{
				DefaultServer:   "localhost:9090",
				ConnectTimeout:  10,
				RequestTimeout:  30,
				ReconnectOnFail: true,
				RetryAttempts:   3,
				RetryWaitTime:   2,
			},
			expectError: false,
		},
		{
			name: "Missing Server",
			config: &MCPClientConfig{
				ConnectTimeout:  10,
				RequestTimeout:  30,
				ReconnectOnFail: true,
				RetryAttempts:   3,
				RetryWaitTime:   2,
			},
			expectError: true,
		},
		{
			name: "Invalid Server Format",
			config: &MCPClientConfig{
				DefaultServer:   "localhost", // Missing port
				ConnectTimeout:  10,
				RequestTimeout:  30,
				ReconnectOnFail: true,
				RetryAttempts:   3,
				RetryWaitTime:   2,
			},
			expectError: true,
		},
		{
			name: "Zero Timeouts",
			config: &MCPClientConfig{
				DefaultServer:   "localhost:9090",
				ConnectTimeout:  0,
				RequestTimeout:  0,
				ReconnectOnFail: true,
				RetryAttempts:   3,
				RetryWaitTime:   2,
			},
			expectError: false, // Should use defaults
		},
		{
			name: "Negative Retry Values",
			config: &MCPClientConfig{
				DefaultServer:   "localhost:9090",
				ConnectTimeout:  10,
				RequestTimeout:  30,
				ReconnectOnFail: true,
				RetryAttempts:   -1,
				RetryWaitTime:   -1,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.expectError {
				t.Errorf("MCPClientConfig.Validate() error = %v, expectError %v", err, tt.expectError)
			}

			// Check default values were set
			if tt.config.ConnectTimeout == 0 && err == nil {
				if tt.config.ConnectTimeout != 10 { // Assuming 10 is the default
					t.Errorf("MCPClientConfig.Validate() did not set default ConnectTimeout, got %d", tt.config.ConnectTimeout)
				}
			}

			if tt.config.RequestTimeout == 0 && err == nil {
				if tt.config.RequestTimeout != 30 { // Assuming 30 is the default
					t.Errorf("MCPClientConfig.Validate() did not set default RequestTimeout, got %d", tt.config.RequestTimeout)
				}
			}

			if tt.config.RetryAttempts == 0 && err == nil {
				if tt.config.RetryAttempts != 3 { // Assuming 3 is the default
					t.Errorf("MCPClientConfig.Validate() did not set default RetryAttempts, got %d", tt.config.RetryAttempts)
				}
			}

			if tt.config.RetryWaitTime == 0 && err == nil {
				if tt.config.RetryWaitTime != 2 { // Assuming 2 is the default
					t.Errorf("MCPClientConfig.Validate() did not set default RetryWaitTime, got %d", tt.config.RetryWaitTime)
				}
			}
		})
	}
}

func TestServiceNowURLFormatting(t *testing.T) {
	tests := []struct {
		name       string
		config     *ServiceNowConfig
		expectURL  string
		expectPath string
	}{
		{
			name: "URL with HTTPS",
			config: &ServiceNowConfig{
				URL:      "https://dev123456.service-now.com",
				Username: "admin",
				Password: "password",
				Timeout:  30,
			},
			expectURL:  "https://dev123456.service-now.com",
			expectPath: "https://dev123456.service-now.com/api/now/table/incident",
		},
		{
			name: "URL with HTTP",
			config: &ServiceNowConfig{
				URL:      "http://dev123456.service-now.com",
				Username: "admin",
				Password: "password",
				Timeout:  30,
			},
			expectURL:  "http://dev123456.service-now.com",
			expectPath: "http://dev123456.service-now.com/api/now/table/incident",
		},
		{
			name: "URL without Protocol",
			config: &ServiceNowConfig{
				URL:      "dev123456.service-now.com",
				Username: "admin",
				Password: "password",
				Timeout:  30,
			},
			expectURL:  "https://dev123456.service-now.com", // Should add https://
			expectPath: "https://dev123456.service-now.com/api/now/table/incident",
		},
		{
			name: "URL with Trailing Slash",
			config: &ServiceNowConfig{
				URL:      "https://dev123456.service-now.com/",
				Username: "admin",
				Password: "password",
				Timeout:  30,
			},
			expectURL:  "https://dev123456.service-now.com", // Should remove trailing slash
			expectPath: "https://dev123456.service-now.com/api/now/table/incident",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != nil {
				t.Fatalf("ServiceNowConfig.Validate() unexpected error = %v", err)
			}

			// Check if URL was formatted correctly
			if tt.config.URL != tt.expectURL {
				t.Errorf("URL formatting failed, got %s, expected %s", tt.config.URL, tt.expectURL)
			}

			// Check if buildPath works correctly
			path := tt.config.BuildAPIPath("incident")
			if path != tt.expectPath {
				t.Errorf("BuildAPIPath() failed, got %s, expected %s", path, tt.expectPath)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create test directory and fixture file
	tempDir := t.TempDir()
	testConfigPath := filepath.Join(tempDir, "test_config.yaml")

	// Create server config fixture
	serverConfig := `
server:
  address: 127.0.0.1
  port: 8080
  max_connections: 50
  read_timeout: 60
  write_timeout: 60
  idle_timeout: 600
servicenow:
  url: https://test-instance.service-now.com
  username: test-user
  password: test-password
  timeout: 45
log:
  level: debug
  file: /tmp/test-server.log
debug: true
`

	// Write server config to file
	err := os.WriteFile(testConfigPath, []byte(serverConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Create client config fixture
	clientConfigPath := filepath.Join(tempDir, "client_config.yaml")
	clientConfig := `
server:
  address: localhost:8080
client:
  timeout: 45
  output_format: json
  retry_attempts: 5
  retry_wait_time: 3
  reconnect_on_fail: true
  connect_timeout: 15
auth:
  username: client-user
  password: client-password
log:
  level: info
  file: /tmp/test-client.log
debug: false
`

	// Write client config to file
	err = os.WriteFile(clientConfigPath, []byte(clientConfig), 0644)
	if err != nil {
		t.Fatalf("Failed to write test client config file: %v", err)
	}

	// Test loading server config
	t.Run("Load Server Config", func(t *testing.T) {
		config, err := LoadServerConfig(testConfigPath)
		if err != nil {
			t.Fatalf("LoadServerConfig() error = %v", err)
		}

		// Verify server config values
		if config.Server.Address != "127.0.0.1" {
			t.Errorf("Expected server address 127.0.0.1, got %s", config.Server.Address)
		}
		if config.Server.Port != 8080 {
			t.Errorf("Expected server port 8080, got %d", config.Server.Port)
		}
		if config.Server.MaxConnections != 50 {
			t.Errorf("Expected max connections 50, got %d", config.Server.MaxConnections)
		}
		if config.Server.ReadTimeout != 60 {
			t.Errorf("Expected read timeout 60, got %d", config.Server.ReadTimeout)
		}
		if config.Server.WriteTimeout != 60 {
			t.Errorf("Expected write timeout 60, got %d", config.Server.WriteTimeout)
		}
		if config.Server.IdleTimeout != 600 {
			t.Errorf("Expected idle timeout 600, got %d", config.Server.IdleTimeout)
		}

		// Verify ServiceNow config values
		if config.ServiceNow.URL != "https://test-instance.service-now.com" {
			t.Errorf("Expected ServiceNow URL https://test-instance.service-now.com, got %s", config.ServiceNow.URL)
		}
		if config.ServiceNow.Username != "test-user" {
			t.Errorf("Expected ServiceNow username test-user, got %s", config.ServiceNow.Username)
		}
		if config.ServiceNow.Password != "test-password" {
			t.Errorf("Expected ServiceNow password test-password, got %s", config.ServiceNow.Password)
		}
		if config.ServiceNow.Timeout != 45 {
			t.Errorf("Expected ServiceNow timeout 45, got %d", config.ServiceNow.Timeout)
		}

		// Verify log config values
		if config.Log.Level != "debug" {
			t.Errorf("Expected log level debug, got %s", config.Log.Level)
		}
		if config.Log.File != "/tmp/test-server.log" {
			t.Errorf("Expected log file /tmp/test-server.log, got %s", config.Log.File)
		}

		// Verify debug mode
		if !config.Debug {
			t.Errorf("Expected debug mode true, got false")
		}
	})

	// Test loading client config
	t.Run("Load Client Config", func(t *testing.T) {
		config, err := LoadClientConfig(clientConfigPath)
		if err != nil {
			t.Fatalf("LoadClientConfig() error = %v", err)
		}

		// Verify client config values
		if config.Server.Address != "localhost:8080" {
			t.Errorf("Expected server address localhost:8080, got %s", config.Server.Address)
		}

		if config.Client.RequestTimeout != 45 {
			t.Errorf("Expected timeout 45, got %d", config.Client.RequestTimeout)
		}
		if config.Client.OutputFormat != "json" {
			t.Errorf("Expected output format json, got %s", config.Client.OutputFormat)
		}
		if config.Client.RetryAttempts != 5 {
			t.Errorf("Expected retry attempts 5, got %d", config.Client.RetryAttempts)
		}
		if config.Client.RetryWaitTime != 3 {
			t.Errorf("Expected retry wait time 3, got %d", config.Client.RetryWaitTime)
		}
		if !config.Client.ReconnectOnFail {
			t.Errorf("Expected reconnect on fail true, got false")
		}
		if config.Client.ConnectTimeout != 15 {
			t.Errorf("Expected connect timeout 15, got %d", config.Client.ConnectTimeout)
		}

		// Verify auth config values
		if config.Auth.Username != "client-user" {
			t.Errorf("Expected username client-user, got %s", config.Auth.Username)
		}
		if config.Auth.Password != "client-password" {
			t.Errorf("Expected password client-password, got %s", config.Auth.Password)
		}

		// Verify log config values
		if config.Log.Level != "info" {
			t.Errorf("Expected log level info, got %s", config.Log.Level)
		}
		if config.Log.File != "/tmp/test-client.log" {
			t.Errorf("Expected log file /tmp/test-client.log, got %s", config.Log.File)
		}

		// Verify debug mode
		if config.Debug {
			t.Errorf("Expected debug mode false, got true")
		}
	})

	// Test non-existent file
	t.Run("Non-existent File", func(t *testing.T) {
		_, err := LoadServerConfig(filepath.Join(tempDir, "nonexistent.yaml"))
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	// Test invalid YAML
	t.Run("Invalid YAML", func(t *testing.T) {
		invalidPath := filepath.Join(tempDir, "invalid.yaml")
		err := os.WriteFile(invalidPath, []byte("invalid: yaml: content:"), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid YAML file: %v", err)
		}

		_, err = LoadServerConfig(invalidPath)
		if err == nil {
			t.Error("Expected error for invalid YAML, got nil")
		}
	})
}

func TestLoadFromEnvironment(t *testing.T) {
	// Save current environment
	savedEnv := make(map[string]string)
	envVars := []string{
		"MCP_SERVER_ADDRESS",
		"MCP_SERVER_PORT",
		"MCP_SERVER_MAX_CONNECTIONS",
		"MCP_SERVER_READ_TIMEOUT",
		"MCP_SERVICENOW_URL",
		"MCP_SERVICENOW_USERNAME",
		"MCP_SERVICENOW_PASSWORD",
		"MCP_LOG_LEVEL",
		"MCP_CLIENT_TIMEOUT",
		"MCP_CLIENT_RETRY_ATTEMPTS",
		"MCP_AUTH_USERNAME",
		"MCP_AUTH_PASSWORD",
	}

	for _, env := range envVars {
		savedEnv[env] = os.Getenv(env)
	}

	// Restore environment after test
	defer func() {
		for env, value := range savedEnv {
			if value == "" {
				os.Unsetenv(env)
			} else {
				os.Setenv(env, value)
			}
		}
	}()

	// Test server configuration from environment
	t.Run("Server Config from Environment", func(t *testing.T) {
		// Set environment variables for server
		os.Setenv("MCP_SERVER_ADDRESS", "192.168.1.10")
		os.Setenv("MCP_SERVER_PORT", "7070")
		os.Setenv("MCP_SERVER_MAX_CONNECTIONS", "200")
		os.Setenv("MCP_SERVER_READ_TIMEOUT", "90")
		os.Setenv("MCP_SERVICENOW_URL", "https://env-test.service-now.com")
		os.Setenv("MCP_SERVICENOW_USERNAME", "env-user")
		os.Setenv("MCP_SERVICENOW_PASSWORD", "env-password")
		os.Setenv("MCP_LOG_LEVEL", "warn")
		os.Setenv("MCP_DEBUG", "true")

		// Load configuration
		config, err := LoadServerConfigFromEnv()
		if err != nil {
			t.Fatalf("LoadServerConfigFromEnv() error = %v", err)
		}

		// Verify values
		if config.Server.Address != "192.168.1.10" {
			t.Errorf("Expected server address 192.168.1.10, got %s", config.Server.Address)
		}
		if config.Server.Port != 7070 {
			t.Errorf("Expected server port 7070, got %d", config.Server.Port)
		}
		if config.Server.MaxConnections != 200 {
			t.Errorf("Expected max connections 200, got %d", config.Server.MaxConnections)
		}
		if config.Server.ReadTimeout != 90 {
			t.Errorf("Expected read timeout 90, got %d", config.Server.ReadTimeout)
		}

		if config.ServiceNow.URL != "https://env-test.service-now.com" {
			t.Errorf("Expected ServiceNow URL https://env-test.service-now.com, got %s", config.ServiceNow.URL)
		}
		if config.ServiceNow.Username != "env-user" {
			t.Errorf("Expected ServiceNow username env-user, got %s", config.ServiceNow.Username)
		}
		if config.ServiceNow.Password != "env-password" {
			t.Errorf("Expected ServiceNow password env-password, got %s", config.ServiceNow.Password)
		}

		if config.Log.Level != "warn" {
			t.Errorf("Expected log level warn, got %s", config.Log.Level)
		}

		if !config.Debug {
			t.Errorf("Expected debug mode true, got false")
