package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config holds the complete application configuration
type Config struct {
	ServiceNow ServiceNowConfig `mapstructure:"servicenow"`
	MCP        MCPConfig        `mapstructure:"mcp"`
	LogLevel   string           `mapstructure:"log_level"`
}

// ServiceNowConfig holds the configuration for ServiceNow integration
type ServiceNowConfig struct {
	Instance string `mapstructure:"instance"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	APIPath  string `mapstructure:"api_path"`
	Timeout  int    `mapstructure:"timeout"`
	URL      string `mapstructure:"url"`
}

// MCPConfig holds the configuration for the MCP server
type MCPConfig struct {
	Server MCPServerConfig `mapstructure:"server"`
	Client MCPClientConfig `mapstructure:"client"`
}

// MCPServerConfig holds server-specific configuration
type MCPServerConfig struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	MaxConnections  int    `mapstructure:"max_connections"`
	ReadTimeout     int    `mapstructure:"read_timeout"`
	WriteTimeout    int    `mapstructure:"write_timeout"`
	ShutdownTimeout int    `mapstructure:"shutdown_timeout"`
	Address         string `mapstructure:"address"`
	IdleTimeout     int    `mapstructure:"idle_timeout"`
}

// MCPClientConfig holds client-specific configuration
type MCPClientConfig struct {
	DefaultServer   string `mapstructure:"default_server"`
	ConnectTimeout  int    `mapstructure:"connect_timeout"`
	RequestTimeout  int    `mapstructure:"request_timeout"`
	RetryAttempts   int    `mapstructure:"retry_attempts"`
	RetryWaitTime   int    `mapstructure:"retry_wait_time"`
	KeepAlive       bool   `mapstructure:"keep_alive"`
	KeepAliveTime   int    `mapstructure:"keep_alive_time"`
	ReconnectOnFail bool   `mapstructure:"reconnect_on_fail"`
}

// LoadConfig loads the configuration from a file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Read the config file if specified
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config in the current directory and home directory
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME")
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	// Environment variables will override config file values
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("MCP")

	// Read the config file
	if err := v.ReadInConfig(); err != nil {
		// It's okay if the config file is not found, but we'll warn about it
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		logrus.Warn("No configuration file found. Using defaults and environment variables")
	} else {
		logrus.Infof("Using config file: %s", v.ConfigFileUsed())
	}

	// Bind environment variables
	bindEnvVariables(v)

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate the configuration
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// setDefaults sets default values for the configuration
func setDefaults(v *viper.Viper) {
	// ServiceNow defaults
	v.SetDefault("servicenow.api_path", "/api/now/table")
	v.SetDefault("servicenow.timeout", 30)

	// MCP Server defaults
	v.SetDefault("mcp.server.host", "localhost")
	v.SetDefault("mcp.server.port", 8080)
	v.SetDefault("mcp.server.max_connections", 100)
	v.SetDefault("mcp.server.read_timeout", 30)
	v.SetDefault("mcp.server.write_timeout", 30)
	v.SetDefault("mcp.server.shutdown_timeout", 10)

	// MCP Client defaults
	v.SetDefault("mcp.client.default_server", "localhost:8080")
	v.SetDefault("mcp.client.connect_timeout", 10)
	v.SetDefault("mcp.client.request_timeout", 30)
	v.SetDefault("mcp.client.retry_attempts", 3)
	v.SetDefault("mcp.client.retry_wait_time", 2)
	v.SetDefault("mcp.client.keep_alive", true)
	v.SetDefault("mcp.client.keep_alive_time", 60)
	v.SetDefault("mcp.client.reconnect_on_fail", true)

	// Other defaults
	v.SetDefault("log_level", "info")
}

// bindEnvVariables binds environment variables to configuration options
func bindEnvVariables(v *viper.Viper) {
	// ServiceNow environment variables
	v.BindEnv("servicenow.instance", "SERVICENOW_INSTANCE")
	v.BindEnv("servicenow.username", "SERVICENOW_USERNAME")
	v.BindEnv("servicenow.password", "SERVICENOW_PASSWORD")
	v.BindEnv("servicenow.api_path", "SERVICENOW_API_PATH")
	v.BindEnv("servicenow.timeout", "SERVICENOW_TIMEOUT")

	// MCP Server environment variables
	v.BindEnv("mcp.server.host", "MCP_SERVER_HOST")
	v.BindEnv("mcp.server.port", "MCP_SERVER_PORT")
	v.BindEnv("mcp.server.max_connections", "MCP_SERVER_MAX_CONNECTIONS")
	v.BindEnv("mcp.server.read_timeout", "MCP_SERVER_READ_TIMEOUT")
	v.BindEnv("mcp.server.write_timeout", "MCP_SERVER_WRITE_TIMEOUT")
	v.BindEnv("mcp.server.shutdown_timeout", "MCP_SERVER_SHUTDOWN_TIMEOUT")

	// MCP Client environment variables
	v.BindEnv("mcp.client.default_server", "MCP_CLIENT_DEFAULT_SERVER")
	v.BindEnv("mcp.client.connect_timeout", "MCP_CLIENT_CONNECT_TIMEOUT")
	v.BindEnv("mcp.client.request_timeout", "MCP_CLIENT_REQUEST_TIMEOUT")
	v.BindEnv("mcp.client.retry_attempts", "MCP_CLIENT_RETRY_ATTEMPTS")
	v.BindEnv("mcp.client.retry_wait_time", "MCP_CLIENT_RETRY_WAIT_TIME")
	v.BindEnv("mcp.client.keep_alive", "MCP_CLIENT_KEEP_ALIVE")
	v.BindEnv("mcp.client.keep_alive_time", "MCP_CLIENT_KEEP_ALIVE_TIME")
	v.BindEnv("mcp.client.reconnect_on_fail", "MCP_CLIENT_RECONNECT_ON_FAIL")

	// Other environment variables
	v.BindEnv("log_level", "LOG_LEVEL")
}

// validateConfig validates the configuration
func validateConfig(cfg *Config) error {
	var missingFields []string

	// Validate ServiceNow configuration for required fields
	if cfg.ServiceNow.Instance == "" {
		missingFields = append(missingFields, "servicenow.instance")
	}
	if cfg.ServiceNow.Username == "" {
		missingFields = append(missingFields, "servicenow.username")
	}
	if cfg.ServiceNow.Password == "" {
		missingFields = append(missingFields, "servicenow.password")
	}

	// Add validation for other required fields if needed

	if len(missingFields) > 0 {
		return errors.New("missing required configuration fields: " + strings.Join(missingFields, ", "))
	}

	return nil
}

// GetLogLevel converts the string log level to logrus.Level
func GetLogLevel(cfg *Config) logrus.Level {
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		// Default to info level on error
		return logrus.InfoLevel
	}
	return level
}

// GetServiceNowBaseURL constructs the base URL for ServiceNow API
func (c *ServiceNowConfig) GetServiceNowBaseURL() string {
	return fmt.Sprintf("https://%s%s", c.Instance, c.APIPath)
}

// GetMCPServerAddress returns the formatted address for the MCP server
func (c *MCPServerConfig) GetMCPServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// SaveConfigToFile saves the current configuration to a YAML file
func SaveConfigToFile(cfg *Config, filePath string) error {
	v := viper.New()
	v.SetConfigFile(filePath)

	// Set values from config struct
	v.Set("servicenow", cfg.ServiceNow)
	v.Set("mcp", cfg.MCP)
	v.Set("log_level", cfg.LogLevel)

	return v.WriteConfig()
}
