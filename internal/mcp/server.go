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

	"github.com/sirupsen/logrus"

	"mcp-go-servicenow/internal/config"
	"mcp-go-servicenow/internal/servicenow"
)

// Server is the MCP server that handles client connections
type Server struct {
	config         *config.MCPServerConfig
	listener       net.Listener
	servicenowClient *servicenow.Client
	clients        map[string]*Client
	clientsMutex   sync.RWMutex
	wg             sync.WaitGroup
	shutdown       chan struct{}
	logger         *logrus.Logger
}

// Client represents a connected client
type Client struct {
	ID             string
	Name           string
	Conn           net.Conn
	Reader         *bufio.Reader
	Writer         *bufio.Writer
	Authenticated  bool
	ConnectedAt    time.Time
	LastActivity   time.Time
	Features       []string
	SessionToken   string
	MessageCount   int
	RequestCount   int
	ResponseCount  int
	ErrorCount     int
	DisconnectChan chan struct{}
	logger         *logrus.Logger
	sync.Mutex
}

// NewServer creates a new MCP server
func NewServer(cfg *config.MCPServerConfig, snClient *servicenow.Client, logger *logrus.Logger) *Server {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	return &Server{
		config:         cfg,
		servicenowClient: snClient,
		clients:        make(map[string]*Client),
		shutdown:       make(chan struct{}),
		logger:         logger,
	}
}

// Start starts the server and begins accepting connections
func (s *Server) Start() error {
	addr := s.config.GetMCPServerAddress()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start server on %s: %w", addr, err)
	}

	s.listener = listener
	s.logger.Infof("MCP server started on %s", addr)

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// acceptConnections accepts incoming connections and starts a goroutine to handle each one
func (s *Server) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.shutdown:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				// Check if we're shutting down
				select {
				case <-s.shutdown:
					return
				default:
					s.logger.Errorf("Failed to accept connection: %v", err)
					continue
				}
			}

			s.logger.Infof("New connection from %s", conn.RemoteAddr())
			s.wg.Add(1)
			go s.handleConnection(conn)
		}
	}
}

// handleConnection processes a new client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Create a new client
	client := &Client{
		ID:             fmt.Sprintf("%d", time.Now().UnixNano()),
		Conn:           conn,
		Reader:         bufio.NewReader(conn),
		Writer:         bufio.NewWriter(conn),
		ConnectedAt:    time.Now(),
		LastActivity:   time.Now(),
		DisconnectChan: make(chan struct{}),
		logger:         s.logger,
	}

	// Set read/write deadlines
	readTimeout := time.Duration(s.config.ReadTimeout) * time.Second
	writeTimeout := time.Duration(s.config.WriteTimeout) * time.Second

	// Register the client
	s.registerClient(client)
	defer s.unregisterClient(client.ID)

	// Start a goroutine to handle a graceful disconnect
	go func() {
		<-client.DisconnectChan
		s.logger.Infof("Client %s disconnected", client.ID)
		conn.Close()
	}()

	// Wait for handshake
	err := conn.SetReadDeadline(time.Now().Add(readTimeout))
	if err != nil {
		s.logger.Errorf("Failed to set read deadline: %v", err)
		return
	}

	handshakeReceived := false
	authReceived := false
	messageCount := 0

	// Message processing loop
	for {
		// Read message
		rawMessage, err := s.readMessage(client)
		if err != nil {
			if err == io.EOF {
				s.logger.Infof("Client %s closed the connection", client.ID)
			} else {
				s.logger.Errorf("Failed to read message from client %s: %v", client.ID, err)
			}
			break
		}

		// Update last activity timestamp
		client.LastActivity = time.Now()
		messageCount++
		client.MessageCount++

		// Process message
		message, err := DecodeMessage(rawMessage)
		if err != nil {
			s.logger.Errorf("Failed to decode message from client %s: %v", client.ID, err)
			errorMsg, _ := NewErrorMessage("decode_error", "Failed to decode message")
			s.sendMessage(client, errorMsg, writeTimeout)
			continue
		}

		// Validate message
		if err := message.Validate(); err != nil {
			s.logger.Errorf("Invalid message from client %s: %v", client.ID, err)
			errorMsg, _ := NewErrorMessage("invalid_message", err.Error())
			s.sendMessage(client, errorMsg, writeTimeout)
			continue
		}

		// Handle message based on type
		switch message.Type {
		case MessageTypeHandshake:
			if handshakeReceived {
				errorMsg, _ := NewErrorMessage("protocol_error", "Handshake already received")
				s.sendMessage(client, errorMsg, writeTimeout)
				continue
			}

			handshakePayload, err := DecodeHandshakePayload(message)
			if err != nil {
				s.logger.Errorf("Failed to decode handshake from client %s: %v", client.ID, err)
				errorMsg, _ := NewErrorMessage("handshake_error", "Invalid handshake format")
				s.sendMessage(client, errorMsg, writeTimeout)
				continue
			}

			// Update client information
			client.Lock()
			client.ID = handshakePayload.ClientID
			client.Name = handshakePayload.ClientName
			client.Features = handshakePayload.Features
			client.Unlock()

			// Register the client with the updated ID
			s.unregisterClient(client.ID)
			s.registerClient(client)

			// Send handshake response
			response, _ := NewHandshakeMessage("server", "MCP ServiceNow Server", []string{"auth", "incidents"})
			s.sendMessage(client, response, writeTimeout)
			handshakeReceived = true
			s.logger.Infof("Handshake completed with client %s (%s)", client.ID, client.Name)

		case MessageTypeAuth:
			if !handshakeReceived {
				errorMsg, _ := NewErrorMessage("protocol_error", "Handshake required before authentication")
				s.sendMessage(client, errorMsg, writeTimeout)
				continue
			}

			if authReceived {
				errorMsg, _ := NewErrorMessage("protocol_error", "Already authenticated")
				s.sendMessage(client, errorMsg, writeTimeout)
				continue
			}

			authPayload, err := DecodeAuthPayload(message)
			if err != nil {
				s.logger.Errorf("Failed to decode auth from client %s: %v", client.ID, err)
				errorMsg, _ := NewErrorMessage("auth_error", "Invalid auth format")
				s.sendMessage(client, errorMsg, writeTimeout)
				continue
			}

			// Here we would validate the credentials against some auth system
			// For this example, we'll just use a simple check
			if authPayload.Username == "admin" && authPayload.Password == "password" {
				client.Lock()
				client.Authenticated = true
				client.SessionToken = fmt.Sprintf("token-%d", time.Now().UnixNano())
				client.Unlock()

				response, _ := NewAuthResponseMessage(true, client.SessionToken, "Authentication successful")
				s.sendMessage(client, response, writeTimeout)
				authReceived = true
				s.logger.Infof("Client %s (%s) authenticated successfully", client.ID, client.Name)
			} else {
				client.ErrorCount++
				response, _ := NewAuthResponseMessage(false, "", "Invalid credentials")
				s.sendMessage(client, response, writeTimeout)
				s.logger.Warnf("Authentication failed for client %s (%s)", client.ID, client.Name)
			}

		case MessageTypeRequest:
			if !handshakeReceived || !client.Authenticated {
				errorMsg, _ := NewErrorMessage("auth_required", "Authentication required")
				s.sendMessage(client, errorMsg, writeTimeout)
				continue
			}

			client.RequestCount++
			s.handleRequest(client, message, writeTimeout)

		case MessageTypePing:
			// Respond with a pong
			pong, _ := NewPongMessage()
			s.sendMessage(client, pong, writeTimeout)

		case MessageTypePong:
			// Do nothing, this is a response to our ping

		default:
			s.logger.Warnf("Unsupported message type from client %s: %s", client.ID, message.Type)
			errorMsg, _ := NewErrorMessage("unsupported_type", "Unsupported message type")
			s.sendMessage(client, errorMsg, writeTimeout)
		}
	}
}

// readMessage reads a complete message from the client
func (s *Server) readMessage(client *Client) ([]byte, error) {
	// Read message length (4 bytes)
	lengthBytes := make([]byte, 4)
	_, err := io.ReadFull(client.Reader, lengthBytes)
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
	_, err = io.ReadFull(client.Reader, message)
	if err != nil {
		return nil, err
	}

	return message, nil
}

// sendMessage sends a message to a client
func (s *Server) sendMessage(client *Client, message *Message, timeout time.Duration) error {
	client.Lock()
	defer client.Unlock()

	// Set write deadline
	if err := client.Conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Encode message
	encodedMsg, err := message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// Write message length (4 bytes)
	lengthStr := fmt.Sprintf("%04d", len(encodedMsg))
	if _, err := client.Writer.WriteString(lengthStr); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	// Write message body
	if _, err := client.Writer.Write(encodedMsg); err != nil {
		return fmt.Errorf("failed to write message body: %w", err)
	}

	// Flush the writer
	if err := client.Writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

// registerClient registers a client with the server
func (s *Server) registerClient(client *Client) {
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	// Check if we're at the connection limit
	if s.config.MaxConnections > 0 && len(s.clients) >= s.config.MaxConnections {
		s.logger.Warnf("Connection limit reached (%d), refusing new connection", s.config.MaxConnections)
		go func() {
			errorMsg, _ := NewErrorMessage("max_connections", "Maximum number of connections reached")
			s.sendMessage(client, errorMsg, time.Duration(s.config.WriteTimeout)*time.Second)
			time.Sleep(500 * time.Millisecond)
			client.Conn.Close()
		}()
		return
	}

	s.clients[client.ID] = client
	s.logger.Infof("Client registered: %s", client.ID)
}

// unregisterClient removes a client from the server
func (s *Server) unregisterClient(clientID string) {
	s.clientsMutex.Lock()
	defer s.clientsMutex.Unlock()

	if client, exists := s.clients[clientID]; exists {
		close(client.DisconnectChan)
		delete(s.clients, clientID)
		s.logger.Infof("Client unregistered: %s", clientID)
	}
}

// handleRequest processes client requests and integrates with ServiceNow
func (s *Server) handleRequest(client *Client, message *Message, timeout time.Duration) {
	requestPayload, err := DecodeRequestPayload(message)
	if err != nil {
		s.logger.Errorf("Failed to decode request payload from client %s: %v", client.ID, err)
		errorMsg, _ := NewErrorMessage("invalid_request", err.Error())
		s.sendMessage(client, errorMsg, timeout)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var responseData interface{}
	var errorMsg string
	var statusCode int
	success := true

	// Process the request based on type
	switch requestPayload.RequestType {
	case RequestTypeGetIncidents:
		// Extract parameters
		var limit int
		var query string

		if limitParam, ok := requestPayload.Parameters["limit"]; ok {
			switch v := limitParam.(type) {
			case float64:
				limit = int(v)
			case string:
				limit, _ = strconv.Atoi(v)
			}
		}

		if queryParam, ok := requestPayload.Parameters["query"]; ok {
			if v, ok := queryParam.(string); ok {
				query = v
			}
		}

		// Call ServiceNow client
		incidents, err := s.servicenowClient.GetIncidents(ctx, limit, query)
		if err != nil {
			s.logger.Errorf("Failed to get incidents: %v", err)
			errorMsg = fmt.Sprintf("Failed to get incidents: %v", err)
			statusCode = 500
			success = false
		} else {
			responseData = incidents
			statusCode = 200
		}

	case RequestTypeGetIncident:
		// Extract incident ID
		var sysID string
		if idParam, ok := requestPayload.Parameters["sys_id"]; ok {
			if v, ok := idParam.(string); ok {
				sysID = v
			}
		}

		if sysID == "" {
			errorMsg = "Missing required parameter: sys_id"
			statusCode = 400
			success = false
		} else {
			// Call ServiceNow client
			incident, err := s.servicenowClient.GetIncident(ctx, sysID)
			if err != nil {
				s.logger.Errorf("Failed to get incident %s: %v", sysID, err)
				errorMsg = fmt.Sprintf("Failed to get incident: %v", err)
				statusCode = 500
				success = false
			} else {
				responseData = incident
				statusCode = 200
			}
		}

	case RequestTypeCreateIncident:
		// Extract incident data
		var incident servicenow.Incident
		
		if incidentData, ok := requestPayload.Parameters["incident"]; ok {
			// Convert map to JSON then unmarshal to struct
			jsonData, err := json.Marshal(incidentData)
			if err != nil {
				s.logger.Errorf("Failed to marshal incident data: %v", err)
				errorMsg = "Invalid incident data format"
				statusCode = 400
				success = false
				break
			}
			
			if err := json.Unmarshal(jsonData, &incident); err != nil {
				s.logger.Errorf("Failed to unmarshal incident data: %v", err)
				errorMsg = "Invalid incident data format"
				statusCode = 400
				success = false
				break
			}
		} else {
			errorMsg = "Missing required parameter: incident"
			statusCode = 400
			success = false
			break
		}
		
		// Call ServiceNow client
		createdIncident, err := s.servicenowClient.CreateIncident(ctx, &incident)
		if err != nil {
			s.logger.Errorf("Failed to create incident: %v", err)
			errorMsg = fmt.Sprintf("Failed to create incident: %v", err)
			statusCode = 500
			success = false
		} else {
			responseData = createdIncident
			statusCode = 201
		}

	case RequestTypeUpdateIncident:
		// Extract incident ID and data
		var sysID string
		var incident servicenow.Incident
		
		if idParam, ok := requestPayload.Parameters["sys_id"]; ok {
			if v, ok := idParam.(string); ok {
				sysID = v
			}
		}
		
		if sysID == "" {
			errorMsg = "Missing required parameter: sys_id"
			statusCode = 400
			success = false
			break
		}
		
		if incidentData, ok := requestPayload.Parameters["incident"]; ok {
			// Convert map to JSON then unmarshal to struct
			jsonData, err := json.Marshal(incidentData)
			if err != nil {
				s.logger.Errorf("Failed to marshal incident data: %v", err)
				errorMsg = "Invalid incident data format"
				statusCode = 400
				success = false
				break
			}
			
			if err := json.Unmarshal(jsonData, &incident); err != nil {
				s.logger.Errorf("Failed to unmarshal incident data: %v", err)
				errorMsg = "Invalid incident data format"
				statusCode = 400
				success = false
				break
			}
		} else {
			errorMsg = "Missing required parameter: incident"
			statusCode = 400
			success = false
			break
		}
		
		// Call ServiceNow client
		updatedIncident, err := s.servicenowClient.UpdateIncident(ctx, sysID, &incident)
		if err != nil {
			s.logger.Errorf("Failed to update incident %s: %v", sysID, err)
			errorMsg = fmt.Sprintf("Failed to update incident: %v", err)
			statusCode = 500
			success = false
		} else {
			responseData = updatedIncident
			statusCode = 200
		}

	case RequestTypeDeleteIncident:
		// Extract incident ID
		var sysID string
		if idParam, ok := requestPayload.Parameters["sys_id"]; ok {
			if v, ok := idParam.(string); ok {
				sysID = v
			}
		}
		
		if sysID == "" {
			errorMsg = "Missing required parameter: sys_id"
			statusCode = 400
			success = false
			break
		}
		
		// Call ServiceNow client
		err := s.servicenowClient.DeleteIncident(ctx, sysID)
		if err != nil {
			s.logger.Errorf("Failed to delete incident %s: %v", sysID, err)
			errorMsg = fmt.Sprintf("Failed to delete incident: %v", err)
			statusCode = 500
			success = false
		} else {
			statusCode = 204
		}

	default:
		errorMsg = fmt.Sprintf("Unsupported request type: %s", requestPayload.RequestType)
		statusCode = 400
		success = false
	}

	// Send response
	response, err := NewResponseMessage(success, message.ID, responseData, errorMsg, statusCode)
	if err != nil {
		s.logger.Errorf("Failed to create response message: %v", err)
		errorMsg, _ := NewErrorMessage("server_error", "Failed to create response")
		s.sendMessage(client, errorMsg, timeout)
		return
	}

	client.ResponseCount++
	if !success {
		client.ErrorCount++
	}

	if err := s.sendMessage(client, response, timeout); err != nil {
		s.logger.Errorf("Failed to send response to client %s: %v", client.ID, err)
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(timeout time.Duration) error {
	s.logger.Info("Shutting down MCP server...")

	// Signal shutdown
	close(s.shutdown)

	// Close the listener to stop accepting new connections
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Errorf("Error closing listener: %v", err)
		}
	}

	// Notify all clients to disconnect
	s.disconnectAllClients()

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All connections closed gracefully")
	case <-time.After(timeout):
		s.logger.Warn("Shutdown timed out, some connections may not have closed gracefully")
	}

	return nil
}

// disconnectAllClients notifies all clients to disconnect
func (s *Server) disconnectAllClients() {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	for _, client := range s.clients {
		// Send a disconnect message
		errorMsg, _ := NewErrorMessage("server_shutdown", "Server is shutting down")
		s.sendMessage(client, errorMsg, time.Duration(s.config.WriteTimeout)*time.Second)

		// Close the client's connection
		go func(c *Client) {
			time.Sleep(100 * time.Millisecond) // Give the message time to be sent
			c.Conn.Close()
		}(client)
	}
}

// StartClientCleanup starts a background goroutine to clean up idle clients
func (s *Server) StartClientCleanup(idleTimeout time.Duration, interval time.Duration) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.shutdown:
				return
			case <-ticker.C:
				s.cleanupIdleClients(idleTimeout)
			}
		}
	}()

	s.logger.Infof("Client cleanup started (idle timeout: %v, check interval: %v)", idleTimeout, interval)
}

// cleanupIdleClients disconnects clients that have been idle for too long
func (s *Server) cleanupIdleClients(idleTimeout time.Duration) {
	s.clientsMutex.RLock()
	now := time.Now()
	var idleClients []string

	for id, client := range s.clients {
		if now.Sub(client.LastActivity) > idleTimeout {
			idleClients = append(idleClients, id)
		}
	}
	s.clientsMutex.RUnlock()

	for _, id := range idleClients {
		s.clientsMutex.RLock()
		client, exists := s.clients[id]
		s.clientsMutex.RUnlock()

		if exists {
			s.logger.Infof("Disconnecting idle client %s (idle for %v)", id, now.Sub(client.LastActivity))
			errorMsg, _ := NewErrorMessage("idle_timeout", "Connection closed due to inactivity")
			s.sendMessage(client, errorMsg, time.Duration(s.config.WriteTimeout)*time.Second)

			time.Sleep(100 * time.Millisecond) // Give the message time to be sent
			client.Conn.Close()
		}
	}

	if len(idleClients) > 0 {
		s.logger.Infof("Cleaned up %d idle clients", len(idleClients))
	}
}

// StartHealthCheck starts a background goroutine to ping clients periodically
func (s *Server) StartHealthCheck(interval time.Duration) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.shutdown:
				return
			case <-ticker.C:
				s.pingAllClients()
			}
		}
	}()

	s.logger.Infof("Health check started (interval: %v)", interval)
}

// pingAllClients sends a ping message to all connected clients
func (s *Server) pingAllClients() {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	writeTimeout := time.Duration(s.config.WriteTimeout) * time.Second
	pingMessage, _ := NewPingMessage()

	for id, client := range s.clients {
		if err := s.sendMessage(client, pingMessage, writeTimeout); err != nil {
			s.logger.Warnf("Failed to ping client %s: %v", id, err)
		}
	}
}

// GetServerStats returns statistics about the server
func (s *Server) GetServerStats() map[string]interface{} {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	totalMessages := 0
	totalRequests := 0
	totalResponses := 0
	totalErrors := 0

	clientStats := make([]map[string]interface{}, 0, len(s.clients))
	for id, client := range s.clients {
		totalMessages += client.MessageCount
		totalRequests += client.RequestCount
		totalResponses += client.ResponseCount
		totalErrors += client.ErrorCount

		clientStat := map[string]interface{}{
			"id":              id,
			"name":            client.Name,
			"authenticated":   client.Authenticated,
			"connected_at":    client.ConnectedAt,
			"last_activity":   client.LastActivity,
			"connected_for":   time.Since(client.ConnectedAt).String(),
			"idle_for":        time.Since(client.LastActivity).String(),
			"address":         client.Conn.RemoteAddr().String(),
			"message_count":   client.MessageCount,
			"request_count":   client.RequestCount,
			"response_count":  client.ResponseCount,
			"error_count":     client.ErrorCount,
			"features":        client.Features,
		}

		clientStats = append(clientStats, clientStat)
	}

	// Build the stats map
	stats := map[string]interface{}{
		"uptime":          time.Since(time.Now().Add(-s.wg.Counter * time.Second)).String(), // Approximate
		"num_clients":     len(s.clients),
		"total_messages":  totalMessages,
		"total_requests":  totalRequests,
		"total_responses": totalResponses,
		"total_errors":    totalErrors,
		"clients":         clientStats,
		"listen_address":  s.listener.Addr().String(),
		"max_connections": s.config.MaxConnections,
	}

	return stats
}

// GetClient returns a specific client by ID
func (s *Server) GetClient(clientID string) *Client {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	return s.clients[clientID]
}

// GetClientCount returns the number of connected clients
func (s *Server) GetClientCount() int {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	return len(s.clients)
}
