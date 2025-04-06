package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"mcp-go-servicenow/internal/config"
	"mcp-go-servicenow/internal/mcp"
	"mcp-go-servicenow/internal/servicenow"
)

var (
	cfgFile       string
	debugMode     bool
	logFile       string
	logLevel      string
	serverAddr    string
	serverPort    int
	username      string
	password      string
	outputFormat  string
	timeout       int
	connectOnly   bool
	disconnectAll bool
	incidentID    string
	short         bool
	query         string
	limit         int
	logger        = logrus.New()
	client        *mcp.MCPClient
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mcp-client",
	Short: "MCP ServiceNow Client",
	Long: `MCP ServiceNow Client is a command-line tool for interacting with 
ServiceNow through the MCP server. It provides optimized 
access to ServiceNow incidents and other resources.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip connection for some commands
		cmdName := cmd.Name()
		if cmdName == "version" || cmdName == "config" || cmdName == "help" {
			return
		}

		// Connect to the server if not already connected
		if client == nil {
			connectToServer()
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		// Disconnect after command execution if not in interactive mode
		if disconnectAll && client != nil {
			client.Disconnect()
			client = nil
		}
	},
}

// connectCmd represents the connect command
var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to the MCP server",
	Long: `Connect to the MCP server and authenticate. If credentials are not provided, 
they will be taken from the configuration file or prompted.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Connection is handled in PersistentPreRun
		fmt.Println("Connected to MCP server successfully")

		if connectOnly {
			// Keep the connection open
			fmt.Println("Press Ctrl+C to disconnect")
			select {}
		}
	},
}

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate a default configuration file",
	Long: `Generate a default configuration file for the MCP client. 
This can be used as a template to customize client settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		generateConfig()
	},
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Long:  `Print the version number of the MCP client.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("MCP ServiceNow Client v1.0.0")
	},
}

// getIncidentsCmd represents the get-incidents command
var getIncidentsCmd = &cobra.Command{
	Use:   "get-incidents",
	Short: "Get a list of incidents",
	Long:  `Retrieve a list of incidents from ServiceNow through the MCP server.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set request timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		// Get incidents
		incidents, err := client.GetIncidents(ctx, limit, query)
		if err != nil {
			logger.Fatalf("Failed to get incidents: %v", err)
		}

		// Output incidents
		outputIncidents(incidents)
	},
}

// getIncidentCmd represents the get-incident command
var getIncidentCmd = &cobra.Command{
	Use:   "get-incident",
	Short: "Get a specific incident",
	Long:  `Retrieve a specific incident from ServiceNow through the MCP server.`,
	Run: func(cmd *cobra.Command, args []string) {
		if incidentID == "" {
			logger.Fatal("Incident ID is required")
		}

		// Set request timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		// Get incident
		incident, err := client.GetIncident(ctx, incidentID)
		if err != nil {
			logger.Fatalf("Failed to get incident %s: %v", incidentID, err)
		}

		// Output incident
		outputIncident(incident)
	},
}

// createIncidentCmd represents the create-incident command
var createIncidentCmd = &cobra.Command{
	Use:   "create-incident",
	Short: "Create a new incident",
	Long:  `Create a new incident in ServiceNow through the MCP server.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse incident data from args or stdin
		incident, err := parseIncidentData(args)
		if err != nil {
			logger.Fatalf("Failed to parse incident data: %v", err)
		}

		// Set request timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		// Create incident
		createdIncident, err := client.CreateIncident(ctx, incident)
		if err != nil {
			logger.Fatalf("Failed to create incident: %v", err)
		}

		fmt.Printf("Incident created successfully with ID: %s\n", createdIncident.SysID)
		outputIncident(createdIncident)
	},
}

// updateIncidentCmd represents the update-incident command
var updateIncidentCmd = &cobra.Command{
	Use:   "update-incident",
	Short: "Update an existing incident",
	Long:  `Update an existing incident in ServiceNow through the MCP server.`,
	Run: func(cmd *cobra.Command, args []string) {
		if incidentID == "" {
			logger.Fatal("Incident ID is required")
		}

		// Parse incident data from args or stdin
		incident, err := parseIncidentData(args)
		if err != nil {
			logger.Fatalf("Failed to parse incident data: %v", err)
		}

		// Set request timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		// Update incident
		updatedIncident, err := client.UpdateIncident(ctx, incidentID, incident)
		if err != nil {
			logger.Fatalf("Failed to update incident %s: %v", incidentID, err)
		}

		fmt.Printf("Incident %s updated successfully\n", incidentID)
		outputIncident(updatedIncident)
	},
}

// deleteIncidentCmd represents the delete-incident command
var deleteIncidentCmd = &cobra.Command{
	Use:   "delete-incident",
	Short: "Delete an incident",
	Long:  `Delete an incident from ServiceNow through the MCP server.`,
	Run: func(cmd *cobra.Command, args []string) {
		if incidentID == "" {
			logger.Fatal("Incident ID is required")
		}

		// Set request timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		// Delete incident
		err := client.DeleteIncident(ctx, incidentID)
		if err != nil {
			logger.Fatalf("Failed to delete incident %s: %v", incidentID, err)
		}

		fmt.Printf("Incident %s deleted successfully\n", incidentID)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.mcp/client.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "enable debug mode")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", "", "log file path (default is stdout)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "server address (host:port)")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 30, "operation timeout in seconds")
	rootCmd.PersistentFlags().StringVar(&username, "username", "", "username for authentication")
	rootCmd.PersistentFlags().StringVar(&password, "password", "", "password for authentication")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", "human", "output format (human, json)")
	rootCmd.PersistentFlags().BoolVar(&disconnectAll, "disconnect", true, "disconnect after command execution")

	// Connect command flags
	connectCmd.Flags().BoolVar(&connectOnly, "keep-open", false, "keep the connection open without executing other commands")

	// Get incidents command flags
	getIncidentsCmd.Flags().IntVar(&limit, "limit", 10, "maximum number of incidents to retrieve")
	getIncidentsCmd.Flags().StringVar(&query, "query", "", "query string to filter incidents")
	getIncidentsCmd.Flags().BoolVar(&short, "short", false, "display short output")

	// Get/Update/Delete incident commands flags
	getIncidentCmd.Flags().StringVar(&incidentID, "id", "", "incident ID (sys_id)")
	updateIncidentCmd.Flags().StringVar(&incidentID, "id", "", "incident ID (sys_id)")
	deleteIncidentCmd.Flags().StringVar(&incidentID, "id", "", "incident ID (sys_id)")

	// Bind flags to viper
	viper.BindPFlag("server.address", rootCmd.PersistentFlags().Lookup("server"))
	viper.BindPFlag("client.timeout", rootCmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("client.output_format", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("auth.username", rootCmd.PersistentFlags().Lookup("username"))
	viper.BindPFlag("auth.password", rootCmd.PersistentFlags().Lookup("password"))
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.file", rootCmd.PersistentFlags().Lookup("log-file"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))

	// Mark required flags
	updateIncidentCmd.MarkFlagRequired("id")
	deleteIncidentCmd.MarkFlagRequired("id")
	getIncidentCmd.MarkFlagRequired("id")

	// Add commands
	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(getIncidentsCmd)
	rootCmd.AddCommand(getIncidentCmd)
	rootCmd.AddCommand(createIncidentCmd)
	rootCmd.AddCommand(updateIncidentCmd)
	rootCmd.AddCommand(deleteIncidentCmd)
}

func initConfig() {
	setupLogger()

	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in standard directories
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(filepath.Join(home, ".mcp"))
		}
		viper.AddConfigPath("/etc/mcp")
		viper.AddConfigPath(".")
		viper.SetConfigName("client")
	}

	viper.AutomaticEnv() // Read environment variables that match

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		logger.Infof("Using config file: %s", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Debug("No config file found, using defaults")
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
	viper.SetDefault("server.address", "localhost:9090")
	viper.SetDefault("client.timeout", 30)
	viper.SetDefault("client.output_format", "human")
	viper.SetDefault("client.retry_attempts", 3)
	viper.SetDefault("client.retry_wait_time", 2)
	viper.SetDefault("client.reconnect_on_fail", true)
	viper.SetDefault("client.connect_timeout", 10)
	viper.SetDefault("auth.username", "admin")
	viper.SetDefault("auth.password", "password")
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.file", "")
	viper.SetDefault("debug", false)

	// Write config file
	configPath := "client.yaml"
	if cfgFile != "" {
		configPath = cfgFile
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			configDir := filepath.Join(home, ".mcp")
			err := os.MkdirAll(configDir, 0755)
			if err == nil {
				configPath = filepath.Join(configDir, "client.yaml")
			}
		}
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

// connectToServer establishes a connection to the MCP server and authenticates
func connectToServer() {
	// Get server address from config
	serverAddress := viper.GetString("server.address")
	if serverAddr != "" {
		serverAddress = serverAddr
	}

	if serverAddress == "" {
		logger.Fatal("Server address not specified. Use --server flag or configuration file.")
	}

	// Create client config
	clientConfig := &config.MCPClientConfig{
		DefaultServer:   serverAddress,
		ConnectTimeout:  viper.GetInt("client.connect_timeout"),
		RequestTimeout:  viper.GetInt("client.timeout"),
		ReconnectOnFail: viper.GetBool("client.reconnect_on_fail"),
		RetryAttempts:   viper.GetInt("client.retry_attempts"),
		RetryWaitTime:   viper.GetInt("client.retry_wait_time"),
	}

	// Get username and password from config or flags
	authUsername := viper.GetString("auth.username")
	authPassword := viper.GetString("auth.password")

	if username != "" {
		authUsername = username
	}

	if password != "" {
		authPassword = password
	}

	if authUsername == "" || authPassword == "" {
		logger.Fatal("Username and password are required. Use --username and --password flags or configuration file.")
	}

	// Create MCP client
	client = mcp.NewClient(clientConfig, logger)

	// Connect to server with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(clientConfig.ConnectTimeout)*time.Second)
	defer cancel()

	logger.Infof("Connecting to MCP server at %s...", serverAddress)
	if err := client.Connect(ctx); err != nil {
		logger.Fatalf("Failed to connect to server: %v", err)
	}

	// Authenticate
	ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	logger.Debug("Authenticating with the server...")
	if err := client.Authenticate(ctx, authUsername, authPassword); err != nil {
		logger.Fatalf("Authentication failed: %v", err)
	}

	// Start keep-alive in background
	client.StartKeepAlive(30 * time.Second)

	logger.Info("Successfully connected and authenticated with MCP server")
}

// outputIncidents formats and outputs a list of incidents
func outputIncidents(incidents []servicenow.Incident) {
	if len(incidents) == 0 {
		fmt.Println("No incidents found.")
		return
	}

	switch outputFormat {
	case "json":
		// Output as JSON
		jsonData, err := json.MarshalIndent(incidents, "", "  ")
		if err != nil {
			logger.Fatalf("Failed to format incidents as JSON: %v", err)
		}
		fmt.Println(string(jsonData))

	default:
		// Output as human-readable format
		fmt.Printf("Found %d incidents:\n", len(incidents))
		fmt.Println(strings.Repeat("-", 80))

		for _, incident := range incidents {
			if short {
				// Short format
				fmt.Printf("ID: %s | Number: %s | State: %s | Priority: %s | Created: %s\n",
					incident.SysID, incident.Number, incident.State, incident.Priority, incident.CreatedOn)
				fmt.Printf("  %s\n", incident.ShortDesc)
				fmt.Println(strings.Repeat("-", 80))
			} else {
				// Detailed format
				fmt.Printf("Incident ID: %s\n", incident.SysID)
				fmt.Printf("Number: %s\n", incident.Number)
				fmt.Printf("Short Description: %s\n", incident.ShortDesc)
				fmt.Printf("Description: %s\n", incident.Description)
				fmt.Printf("State: %s\n", incident.State)
				fmt.Printf("Priority: %s\n", incident.Priority)
				fmt.Printf("Created On: %s\n", incident.CreatedOn)
				fmt.Printf("Created By: %s\n", incident.CreatedBy)
				fmt.Printf("Updated On: %s\n", incident.UpdatedOn)
				fmt.Printf("Updated By: %s\n", incident.UpdatedBy)
				fmt.Println(strings.Repeat("-", 80))
			}
		}
	}
}

// outputIncident formats and outputs a single incident
func outputIncident(incident *servicenow.Incident) {
	if incident == nil {
		fmt.Println("No incident data.")
		return
	}

	switch outputFormat {
	case "json":
		// Output as JSON
		jsonData, err := json.MarshalIndent(incident, "", "  ")
		if err != nil {
			logger.Fatalf("Failed to format incident as JSON: %v", err)
		}
		fmt.Println(string(jsonData))

	default:
		// Output as human-readable format
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("Incident ID: %s\n", incident.SysID)
		fmt.Printf("Number: %s\n", incident.Number)
		fmt.Printf("Short Description: %s\n", incident.ShortDesc)
		fmt.Printf("Description: %s\n", incident.Description)
		fmt.Printf("State: %s\n", incident.State)
		fmt.Printf("Priority: %s\n", incident.Priority)
		fmt.Printf("Assigned To: %s\n", incident.AssignedTo)
		fmt.Printf("Assignment Group: %s\n", incident.AssignmentGroup)
		fmt.Printf("Category: %s\n", incident.Category)
		fmt.Printf("Subcategory: %s\n", incident.Subcategory)
		fmt.Printf("Impact: %s\n", incident.Impact)
		fmt.Printf("Urgency: %s\n", incident.Urgency)
		fmt.Printf("Created On: %s\n", incident.CreatedOn)
		fmt.Printf("Created By: %s\n", incident.CreatedBy)
		fmt.Printf("Updated On: %s\n", incident.UpdatedOn)
		fmt.Printf("Updated By: %s\n", incident.UpdatedBy)
		fmt.Println(strings.Repeat("=", 80))
	}
}

// parseIncidentData parses incident data from arguments or stdin
func parseIncidentData(args []string) (*servicenow.Incident, error) {
	var jsonData []byte
	var err error

	// Check if input is from arguments or stdin
	if len(args) > 0 {
		// Join arguments and parse as JSON
		jsonData = []byte(strings.Join(args, " "))
	} else {
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// Data is being piped to stdin
			jsonData, err = os.ReadFile(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("failed to read from stdin: %w", err)
			}
		} else {
			return nil, fmt.Errorf("no incident data provided (use arguments or pipe JSON data)")
		}
	}

	// Parse JSON into incident struct
	var incident servicenow.Incident
	if err := json.Unmarshal(jsonData, &incident); err != nil {
		return nil, fmt.Errorf("invalid JSON data: %w", err)
	}

	return &incident, nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
