package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"mcp-go-servicenow/internal/config"
	"mcp-go-servicenow/internal/servicenow"
)

// MCPClient represents a client for the MCP protocol
type MCPClient struct {
	config            *config.MCPClientConfig
	conn              net.Conn
	reader            *bufio.Reader
	writer            *bufio.Writer
	clientID          string
	clientName        string
	serverFeatures    []string
	authenticated     bool
	sessionToken      string
	connected         bool
	reconnecting      bool
	reconnectAttempts int
	shutdown          chan struct{}
	pendingRequests   map[string]chan *Message
	pendingMutex      sync.RWMutex
	connectMutex      sync.Mutex
	logger            *logrus.Logger
	features          []string
	lastActivity      time.Time
	username          string
	password          string
}

// NewClient creates a new MCP client
func NewClient(cfg *config.MCPClientConfig, logger *logrus.Logger) *MCPClient {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	// Generate a unique client ID
	clientID := fmt.Sprintf("client-%s", uuid.New().String())

	return &MCPClient{
		config:          cfg,
		clientID:        clientID,
		clientName:      "MCP ServiceNow Client",
		shutdown:        make(chan struct{}),
		pendingRequests: make(map[string]chan *Message),
		logger:          logger,
		features:        []string{"incidents"},
	}
}

// Connect establishes a connection to the MCP server
func (c *MCPClient) Connect(ctx context.Context) error {
	c.connectMutex.Lock()
	defer c.connectMutex.Unlock()

	if c.connected {
		return nil
	}

	c.logger.Infof("Connecting to MCP server at %s", c.config.DefaultServer)

	// Dial with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(c.config.ConnectTimeout) * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.config.DefaultServer)
	if err != nil {
		return fmt.Errorf("failed to connect to server %s: %w", c.config.DefaultServer, err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)
	c.connected = true
	c.lastActivity = time.Now()

	// Start message reader
	go c.readMessages()

	// Perform handshake
	if err := c.performHandshake(ctx); err != nil {
		c.disconnect()
		return fmt.Errorf("handshake failed: %w", err)
	}

	c.logger.Info("Connected to MCP server successfully")
	return nil
}

// Disconnect closes the connection to the server
func (c *MCPClient) Disconnect() {
	close(c.shutdown)
	c.disconnect()
}

// disconnect closes the connection without shutting down
func (c *MCPClient) disconnect() {
	c.connectMutex.Lock()
	defer c.connectMutex.Unlock()

	if !c.connected {
		return
	}

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.reader = nil
	c.writer = nil
	c.connected = false
	c.authenticated = false
	c.sessionToken = ""

	c.logger.Info("Disconnected from MCP server")
}

// reconnect attempts to reconnect to the server with backoff
func (c *MCPClient) reconnect() {
	if c.reconnecting {
		return
	}

	c.reconnecting = true
	defer func() { c.reconnecting = false }()

	maxAttempts := c.config.RetryAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3 // Default to 3 attempts
	}

	waitTime := c.config.RetryWaitTime
	if waitTime <= 0 {
		waitTime = 2 // Default to 2 seconds
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c.logger.Infof("Reconnection attempt %d/%d", attempt, maxAttempts)

		// Disconnect if still connected
		c.disconnect()

		// Try to connect
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.config.ConnectTimeout)*time.Second)
		err := c.Connect(ctx)
		cancel()

		if err == nil {
			c.logger.Info("Reconnected successfully")
			
			// If we were previously authenticated, try to authenticate again
			if c.username != "" && c.password != "" {
				authCtx, authCancel := context.WithTimeout(context.Background(), time.Duration(c.config.RequestTimeout)*time.Second)
				authErr := c.Authenticate(authCtx, c.username, c.password)
				authCancel()
				
				if authErr != nil {
					c.logger.Errorf("Failed to re-authenticate after reconnection: %v", authErr)
				}
			}
			
			return
		}

		c.logger.Errorf("Reconnection attempt %d failed: %v", attempt, err)

		// Check if we should stop trying
		select {
		case <-c.shutdown:
			return
		default:
			// Wait before the next attempt with exponential backoff
			waitDuration := time.Duration(waitTime*attempt) * time.Second
			time.Sleep(waitDuration)
		}
	}

	c.logger.Error("Failed to reconnect after maximum number of attempts")
}

// readMessages reads and processes incoming messages
func (c *MCPClient) readMessages() {
	for {
		select {
		case <-c.shutdown:
			return
		default:
			// Read message
			rawMessage, err := c.readMessage()
			if err != nil {
				if err == io.EOF {
					c.logger.Info("Server closed the connection")
				} else {
					c.logger.Errorf("Failed to read message: %v", err)
				}

				// Try to reconnect if enabled
				if c.config.ReconnectOnFail {
					go c.reconnect()
				}
				return
			}

			// Update last activity timestamp
			c.lastActivity = time.Now()

			// Process message
			message, err := DecodeMessage(rawMessage)
			if err != nil {
				c.logger.Errorf("Failed to decode message: %v", err)
				continue
			}

			// Handle the message based on type
			switch message.Type {
			case MessageTypeResponse:
				// Check if this is a response to a pending request
				c.pendingMutex.RLock()
				responseChan, exists := c.pendingRequests[message.ID]
				c.pendingMutex.RUnlock()

				if exists {
					select {
					case responseChan <- message:
						// Response delivered
					default:
						c.logger.Warnf("Response channel for request %s is full or closed", message.ID)
					}
				} else {
					c.logger.Warnf("Received response for unknown request ID: %s", message.ID)
				}

			case MessageTypePing:
				// Respond with a pong
				pong, _ := NewPongMessage()
				c.sendMessage(pong)

			case MessageTypePong:
				// Do nothing, this is a response to our ping

			case MessageTypeError:
				// Log the error
				errorPayload, err := DecodeErrorPayload(message)
				if err != nil {
					c.logger.Errorf("Failed to decode error message: %v", err)
				} else {
					c.logger.Errorf("Received error from server: %s - %s", errorPayload.Code, errorPayload.Message)
				}

				// Check if this is related to a pending request
				c.pendingMutex.RLock()
				responseChan, exists := c.pendingRequests[message.ID]
				c.pendingMutex.RUnlock()

				if exists {
					select {
					case responseChan <- message:
						// Error delivered
					default:
						c.logger.Warnf("Response channel for request %s is full or closed", message.ID)
					}
				}

			default:
				c.logger.Warnf("Received unexpected message type: %s", message.Type)
			}
		}
	}
}

// readMessage reads a complete message from the server
func (c *MCPClient) readMessage() ([]byte, error) {
	if c.reader == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Read message length (4 bytes)
	lengthBytes := make([]byte, 4)
	_, err := io.ReadFull(c.reader, lengthBytes)
	if err != nil {
		return nil, err
	}

	// Convert length to int
	length, err := strconv.Atoi(string(lengthBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid message length: %w", err)
	}

	// Check if message is too large
	if length > 10*1024*1024 { // 10MB limit
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read message body
	message := make([]byte, length)
	_, err = io.ReadFull(c.reader, message)
	if err != nil {
		return nil, err
	}

	return message, nil
}

// sendMessage sends a message to the server
func (c *MCPClient) sendMessage(message *Message) error {
	if c.writer == nil {
		return fmt.Errorf("not connected")
	}

	c.connectMutex.Lock()
	defer c.connectMutex.Unlock()

	// Encode message
	encodedMsg, err := message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// Write message length (4 bytes)
	lengthStr := fmt.Sprintf("%04d", len(encodedMsg))
	if _, err := c.writer.WriteString(lengthStr); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	// Write message body
	if _, err := c.writer.Write(encodedMsg); err != nil {
		return fmt.Errorf("failed to write message body: %w", err)
	}

	// Flush the writer
	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	// Update last activity timestamp
	c.lastActivity = time.Now()

	return nil
}

// performHandshake sends a handshake message to the server
func (c *MCPClient) performHandshake(ctx context.Context) error {
	// Create handshake message
	handshakeMsg, err := NewHandshakeMessage(c.clientID, c.clientName, c.features)
	if err != nil {
		return fmt.Errorf("failed to create handshake message: %w", err)
	}

	// Send the handshake
	if err := c.sendMessage(handshakeMsg); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	c.logger.Debug("Handshake sent to server")

	// Wait for handshake response
	response, err := c.waitForResponse(ctx, handshakeMsg.ID)
	if err != nil {
		return fmt.Errorf("handshake response error: %w", err)
	}

	if response.Type == MessageTypeError {
		errorPayload, err := DecodeErrorPayload(response)
		if err != nil {
			return fmt.Errorf("failed to decode error message: %w", err)
		}
		return fmt.Errorf("handshake failed: %s - %s", errorPayload.Code, errorPayload.Message)
	}

	if response.Type != MessageTypeHandshake {
		return fmt.Errorf("expected handshake response, got %s", response.Type)
	}

	// Parse the handshake response
	handshakePayload, err := DecodeHandshakePayload(response)
	if err != nil {
		return fmt.Errorf("failed to decode handshake response: %w", err)
	}

	// Store server features
	c.serverFeatures = handshakePayload.Features

	c.logger.Debug("Handshake completed successfully")
	return nil
}

// Authenticate authenticates with the server
func (c *MCPClient) Authenticate(ctx context.Context, username, password string) error {
	if !c.connected {
		return fmt.Errorf("not connected")
	}

	// Store credentials for potential reconnection
	c.username = username
	c.password = password

	// Create auth message
	authMsg, err := NewAuthMessage(username, password)
	if err != nil {
		return fmt.Errorf("failed to create auth message: %w", err)
	}

	// Send the auth message
	if err := c.sendMessage(authMsg); err != nil {
		return fmt.Errorf("failed to send auth message: %w", err)
	}

	c.logger.Debug("Authentication message sent to server")

	// Wait for auth response
	response, err := c.waitForResponse(ctx, authMsg.ID)
	if err != nil {
		return fmt.Errorf("auth response error: %w", err)
	}

	if response.Type == MessageTypeError {
		errorPayload, err := DecodeErrorPayload(response)
		if err != nil {
			return fmt.Errorf("failed to decode error message: %w", err)
		}
		return fmt.Errorf("authentication failed: %s - %s", errorPayload.Code, errorPayload.Message)
	}

	if response.Type != MessageTypeAuthResponse {
		return fmt.Errorf("expected auth response, got %s", response.Type)
	}

	// Parse the auth response
	authResponsePayload, err := DecodeAuthResponsePayload(response)
	if err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	if !authResponsePayload.Success {
		return fmt.Errorf("authentication failed: %s", authResponsePayload.Message)
	}

	// Store auth state
	c.authenticated = true
	c.sessionToken = authResponsePayload.Token

	c.logger.Info("Authentication successful")
	return nil
}
// waitForResponse waits for a response to a specific request
func (c *MCPClient) waitForResponse(ctx context.Context, requestID string) (*Message, error) {
	// Create a channel to receive the response
	responseChan := make(chan *Message, 1)

	// Register the pending request
	c.pendingMutex.Lock()
	c.pendingRequests[requestID] = responseChan
	c.pendingMutex.Unlock()

	// Clean up when done
	defer func() {
		c.pendingMutex.Lock()
		delete(c.pendingRequests, requestID)
		c.pendingMutex.Unlock()
		close(responseChan)
	}()

	// Wait for the response or timeout
	select {
	case response := <-responseChan:
		return response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.shutdown:
		return nil, fmt.Errorf("client shutting down")
	}
}

// sendRequest sends a request to the server and waits for a response
func (c *MCPClient) sendRequest(ctx context.Context, requestType string, params map[string]interface{}) (*ResponsePayload, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	if !c.authenticated {
		return nil, fmt.Errorf("not authenticated")
	}

	// Create request message
	requestMsg, err := NewRequestMessage(requestType, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create request message: %w", err)
	}

	// Send the request
	if err := c.sendMessage(requestMsg); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	c.logger.Debugf("Request sent: %s (ID: %s)", requestType, requestMsg.ID)

	// Wait for the response
	response, err := c.waitForResponse(ctx, requestMsg.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get response: %w", err)
	}

	// Handle error responses
	if response.Type == MessageTypeError {
		errorPayload, err := DecodeErrorPayload(response)
		if err != nil {
			return nil, fmt.Errorf("failed to decode error message: %w", err)
		}
		return nil, fmt.Errorf("request failed: %s - %s", errorPayload.Code, errorPayload.Message)
	}

	// Ensure we have a response message
	if response.Type != MessageTypeResponse {
		return nil, fmt.Errorf("expected response message, got %s", response.Type)
	}

	// Parse the response payload
	responsePayload, err := DecodeResponsePayload(response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check if the response indicates success
	if !responsePayload.Success {
		return nil, fmt.Errorf("request failed: %s (status: %d)", responsePayload.Error, responsePayload.StatusCode)
	}

	return responsePayload, nil
}

// StartKeepAlive starts a background goroutine to send ping messages
func (c *MCPClient) StartKeepAlive(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.shutdown:
				return
			case <-ticker.C:
				if !c.connected {
					continue
				}

				// Send ping message
				pingMsg, _ := NewPingMessage()
				if err := c.sendMessage(pingMsg); err != nil {
					c.logger.Warnf("Failed to send ping message: %v", err)
					// Try to reconnect if enabled
					if c.config.ReconnectOnFail {
						go c.reconnect()
					}
				}
			}
		}
	}()

	c.logger.Infof("Keep-alive started (interval: %v)", interval)
}

// IsConnected returns whether the client is currently connected
func (c *MCPClient) IsConnected() bool {
	return c.connected
}

// IsAuthenticated returns whether the client is currently authenticated
func (c *MCPClient) IsAuthenticated() bool {
	return c.authenticated
}

// GetSessionToken returns the current session token
func (c *MCPClient) GetSessionToken() string {
	return c.sessionToken
}

// GetLastActivity returns the timestamp of the last activity
func (c *MCPClient) GetLastActivity() time.Time {
	return c.lastActivity
}

// ServiceNow Operation Methods

// GetIncidents retrieves a list of incidents from ServiceNow
func (c *MCPClient) GetIncidents(ctx context.Context, limit int, query string) ([]servicenow.Incident, error) {
	params := map[string]interface{}{}
	
	if limit > 0 {
		params["limit"] = limit
	}
	
	if query != "" {
		params["query"] = query
	}
	
	// Send request to server
	responsePayload, err := c.sendRequest(ctx, RequestTypeGetIncidents, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get incidents: %w", err)
	}
	
	// Parse the incidents from the response
	var incidents []servicenow.Incident
	if responsePayload.Data != nil {
		// Marshal to JSON then unmarshal to struct
		jsonData, err := json.Marshal(responsePayload.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal incidents data: %w", err)
		}
		
		if err := json.Unmarshal(jsonData, &incidents); err != nil {
			return nil, fmt.Errorf("failed to unmarshal incidents data: %w", err)
		}
	}
	
	return incidents, nil
}

// GetIncident retrieves a specific incident from ServiceNow
func (c *MCPClient) GetIncident(ctx context.Context, sysID string) (*servicenow.Incident, error) {
	if sysID == "" {
		return nil, fmt.Errorf("incident sys_id is required")
	}
	
	params := map[string]interface{}{
		"sys_id": sysID,
	}
	
	// Send request to server
	responsePayload, err := c.sendRequest(ctx, RequestTypeGetIncident, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get incident: %w", err)
	}
	
	// Parse the incident from the response
	var incident servicenow.Incident
	if responsePayload.Data != nil {
		// Marshal to JSON then unmarshal to struct
		jsonData, err := json.Marshal(responsePayload.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal incident data: %w", err)
		}
		
		if err := json.Unmarshal(jsonData, &incident); err != nil {
			return nil, fmt.Errorf("failed to unmarshal incident data: %w", err)
		}
	}
	
	return &incident, nil
}

// CreateIncident creates a new incident in ServiceNow
func (c *MCPClient) CreateIncident(ctx context.Context, incident *servicenow.Incident) (*servicenow.Incident, error) {
	if incident == nil {
		return nil, fmt.Errorf("incident data is required")
	}
	
	params := map[string]interface{}{
		"incident": incident,
	}
	
	// Send request to server
	responsePayload, err := c.sendRequest(ctx, RequestTypeCreateIncident, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create incident: %w", err)
	}
	
	// Parse the created incident from the response
	var createdIncident servicenow.Incident
	if responsePayload.Data != nil {
		// Marshal to JSON then unmarshal to struct
		jsonData, err := json.Marshal(responsePayload.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal created incident data: %w", err)
		}
		
		if err := json.Unmarshal(jsonData, &createdIncident); err != nil {
			return nil, fmt.Errorf("failed to unmarshal created incident data: %w", err)
		}
	}
	
	return &createdIncident, nil
}

// UpdateIncident updates an existing incident in ServiceNow
func (c *MCPClient) UpdateIncident(ctx context.Context, sysID string, incident *servicenow.Incident) (*servicenow.Incident, error) {
	if sysID == "" {
		return nil, fmt.Errorf("incident sys_id is required")
	}
	
	if incident == nil {
		return nil, fmt.Errorf("incident data is required")
	}
	
	params := map[string]interface{}{
		"sys_id":   sysID,
		"incident": incident,
	}
	
	// Send request to server
	responsePayload, err := c.sendRequest(ctx, RequestTypeUpdateIncident, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update incident: %w", err)
	}
	
	// Parse the updated incident from the response
	var updatedIncident servicenow.Incident
	if responsePayload.Data != nil {
		// Marshal to JSON then unmarshal to struct
		jsonData, err := json.Marshal(responsePayload.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal updated incident data: %w", err)
		}
		
		if err := json.Unmarshal(jsonData, &updatedIncident); err != nil {
			return nil, fmt.Errorf("failed to unmarshal updated incident data: %w", err)
		}
	}
	
	return &updatedIncident, nil
}

// DeleteIncident deletes an incident in ServiceNow
func (c *MCPClient) DeleteIncident(ctx context.Context, sysID string) error {
	if sysID == "" {
		return fmt.Errorf("incident sys_id is required")
	}
	
	params := map[string]interface{}{
		"sys_id": sysID,
	}
	
	// Send request to server
	_, err := c.sendRequest(ctx, RequestTypeDeleteIncident, params)
	if err != nil {
		return fmt.Errorf("failed to delete incident: %w", err)
	}
	
	return nil
}

// GetClientInfo returns information about the client
func (c *MCPClient) GetClientInfo() map[string]interface{} {
	info := map[string]interface{}{
		"client_id":        c.clientID,
		"client_name":      c.clientName,
		"connected":        c.connected,
		"authenticated":    c.authenticated,
		"server":           c.config.DefaultServer,
		"last_activity":    c.lastActivity,
		"idle_for":         time.Since(c.lastActivity).String(),
		"features":         c.features,
		"server_features":  c.serverFeatures,
	}
	
	return info
}
