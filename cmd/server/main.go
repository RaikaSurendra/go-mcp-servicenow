package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"mcp-go-servicenow/internal/config"
	"mcp-go-servicenow/internal/mcp"
	"mcp-go-servicenow/internal/servicenow"
)

var (
	cfgFile     string
	debugMode   bool
	logFile     string
	logLevel    string
	serverAddr  string
	serverPort  int
	maxConns    int
	idleTimeout int
	logger      = logrus.New()
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mcp-server",
	Short: "MCP ServiceNow Server",
	Long: `MCP ServiceNow Server acts as an intermediary between clients 
and the ServiceNow REST API, providing an optimized protocol for 
efficient communication and operations management.`,
}

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the MCP server",
	Long: `Start the MCP server which will listen for client connections
and process requests for ServiceNow operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		runServer()
	},
}

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate a default configuration file",
	Long: `Generate a default configuration file for the MCP server. 
This can be used as a template to customize server settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		generateConfig()
	},
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Long:  `Print the version number of the MCP server.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("MCP ServiceNow Server v1.0.0")
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/mcp/server.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "enable debug mode")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "log file path (default is stdout)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")

	// Start command flags
	startCmd.Flags().StringVar(&serverAddr, "addr", "", "server address to listen on")
	startCmd.Flags().IntVar(&serverPort, "port", 0, "server port to listen on")
	startCmd.Flags().IntVar(&maxConns, "max-connections", 0, "maximum number of concurrent connections")
	startCmd.Flags().IntVar(&idleTimeout, "idle-timeout", 0, "idle connection timeout in seconds")

	// Bind flags to viper
	viper.BindPFlag("server.address", startCmd.Flags().Lookup("addr"))
	viper.BindPFlag("server.port", startCmd.Flags().Lookup("port"))
	viper.BindPFlag("server.max_connections", startCmd.Flags().Lookup("max-connections"))
	viper.BindPFlag("server.idle_timeout", startCmd.Flags().Lookup("idle-timeout"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.file", rootCmd.PersistentFlags().Lookup("log-file"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))

	// Add commands
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	setupLogger()

	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in standard directories
		viper.AddConfigPath("/etc/mcp")
		viper.AddConfigPath(".")
		viper.SetConfigName("server")
	}

	viper.AutomaticEnv() // Read environment variables that match

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Warn("No config file found, using defaults")
		} else {
			logger.Warnf("Error reading config file: %v", err)
		}
	}
}

func setupLogger() {
	// Set log level
	level := logrus.InfoLevel
	if debugMode {
		level = logrus.DebugLevel
	} else if logLevel != "" {
		parsedLevel, err := logrus.ParseLevel(logLevel)
		if err == nil {
			level = parsedLevel
		}
	}
	logger.SetLevel(level)

	// Set log output
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			logger.SetOutput(file)
		} else {
			logger.Warnf("Failed to open log file %s: %v", logFile, err)
		}
	}

	// Set log formatter
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
}

func generateConfig() {
	// Set defaults
	viper.SetDefault("server.address", "0.0.0.0")
	viper.SetDefault("server.port", 9090)
	viper.SetDefault("server.max_connections", 100)
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)
	viper.SetDefault("server.idle_timeout", 300)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.file", "")
	viper.SetDefault("debug", false)
	viper.SetDefault("servicenow.url", "https://dev123456.service-now.com")
	viper.SetDefault("servicenow.username", "admin")
	viper.SetDefault("servicenow.password", "password")
	viper.SetDefault("servicenow.timeout", 30)

	// Write config file
	configPath := "server.yaml"
	if cfgFile != "" {
		configPath = cfgFile
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if dir != "." {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			logger.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	err := viper.WriteConfigAs(configPath)
	if err != nil {
		logger.Fatalf("Failed to write config file: %v", err)
	}

	fmt.Printf("Configuration file generated: %s\n", configPath)
}

func runServer() {
	// Load configuration
	serverConfig := config.MCPServerConfig{
		Address:        viper.GetString("server.address"),
		Port:           viper.GetInt("server.port"),
		MaxConnections: viper.GetInt("server.max_connections"),
		ReadTimeout:    viper.GetInt("server.read_timeout"),
		WriteTimeout:   viper.GetInt("server.write_timeout"),
		IdleTimeout:    viper.GetInt("server.idle_timeout"),
	}

	// Override with command line args if provided
	if serverAddr != "" {
		serverConfig.Address = serverAddr
	}
	if serverPort != 0 {
		serverConfig.Port = serverPort
	}
	if maxConns != 0 {
		serverConfig.MaxConnections = maxConns
	}
	if idleTimeout != 0 {
		serverConfig.IdleTimeout = idleTimeout
	}

	// Setup ServiceNow client
	serviceNowConfig := config.ServiceNowConfig{
		URL:      viper.GetString("servicenow.url"),
		Username: viper.GetString("servicenow.username"),
		Password: viper.GetString("servicenow.password"),
		Timeout:  viper.GetInt("servicenow.timeout"),
	}

	snClient := servicenow.NewClient(&serviceNowConfig, logger)

	// Create and start server
	server := mcp.NewServer(&serverConfig, snClient, logger)
	err := server.Start()
	if err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}

	// Start client cleanup
	idleTimeoutDuration := time.Duration(serverConfig.IdleTimeout) * time.Second
	server.StartClientCleanup(idleTimeoutDuration, idleTimeoutDuration/3)

	// Start health check
	server.StartHealthCheck(30 * time.Second)

	// Setup signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	sig := <-signalChan
	logger.Infof("Received %s signal, shutting down...", sig)

	// Shutdown with timeout
	shutdownTimeout := time.Duration(serverConfig.WriteTimeout*2) * time.Second
	if err := server.Shutdown(shutdownTimeout); err != nil {
		logger.Errorf("Server shutdown error: %v", err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

