package mcp

import (
	"context"
	"fmt"
	"github.com/mark3labs/mcp-go/mcp"
	"net"
	"sync"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readBuf  chan []byte
	writeBuf []byte
	closed   bool
	mu       sync.Mutex
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf: make(chan []byte, 10),
	}
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	data, ok := <-c.readBuf
	if !ok {
		return 0, fmt.Errorf("connection closed")
	}
	
	n = copy(b, data)
	return n, nil
}

func (c *mockConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}
	
	c.writeBuf = append(c.writeBuf, b...)
	return len(b), nil
}

func (c *mockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.closed {
		c.closed = true
		close(c.readBuf)
	}
	return nil
}

func (c *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockListener implements net.Listener for testing
type mockListener struct {
	conns  chan net.Conn
	closed bool
	mu     sync.Mutex
}

func newMockListener() *mockListener {
	return &mockListener{
		conns: make(chan net.Conn, 10),
	}
}

func (l *mockListener) Accept() (net.Conn, error) {
	conn, ok := <-l.conns
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return conn, nil
}

func (l *mockListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if !l.closed {
		l.closed = true
		close(l.conns)
	}
	return nil
}

func (l *mockListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func (l *mockListener) addConn(conn net.Conn) {
	l.conns <- conn
}

// mockHandler implements mcp.RequestHandler for testing
type mockHandler struct {
	handleFunc func(ctx context.Context, req mcp.Request) (interface{}, error)
	calls      []mcp.Request
	mu         sync.Mutex
}

func newMockHandler() *mockHandler {
	return &mockHandler{
		handleFunc: func(ctx context.Context, req mcp.Request) (interface{}, error) {
			return map[string]interface{}{
				"success": true,
				"message": "Request processed",
				"method":  req.Method,
				"params":  req.Params,
			}, nil
		},
		calls: make([]mcp.Request, 0),
	}
}

func (h *mockHandler) Handle(ctx context.Context, req mcp.Request) (interface{}, error) {
	h.mu.Lock()
	h.calls = append(h.calls, req)
	h.mu.Unlock()
	
	return h.handleFunc(ctx, req)
}

func (h *mockHandler) setHandleFunc(fn func(ctx context.Context, req mcp.Request) (interface{}, error)) {
	h.handleFunc = fn
}

func (h *mockHandler) getCalls() []mcp.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	result := make([]mcp.Request, len(h.calls))
	copy(result, h.calls)
	return result
}

// TestServerStartup tests basic server startup and shutdown
func TestServerStartup(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Create server with default options
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Give server time to start
	time.Sleep(50 * time.Millisecond)
	
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := server.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
	
	// Check if server.Serve returned any errors
	select {
	case err := <-errCh:
		if err != nil && err != mcp.ErrServerClosed {
			t.Fatalf("Server returned unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server did not shut down in time")
	}
}

// TestClientConnection tests handling of client connections
func TestClientConnection(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Create server with default options
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Create a mock connection
	conn := newMockConn()
	
	// Add connection to listener
	listener.addConn(conn)
	
	// Give server time to accept the connection
	time.Sleep(50 * time.Millisecond)
	
	// Send a handshake message
	handshakeMsg := mcp.Message{
		Type: mcp.MessageTypeHandshake,
		Payload: mcp.HandshakePayload{
			Version:      mcp.ProtocolVersion,
			Capabilities: []string{"json"},
		},
	}
	
	msgBytes, err := mcp.EncodeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Failed to encode handshake message: %v", err)
	}
	
	conn.readBuf <- msgBytes
	
	// Give server time to process handshake
	time.Sleep(50 * time.Millisecond)
	
	// Verify response
	if len(conn.writeBuf) == 0 {
		t.Fatal("Server did not respond to handshake")
	}
	
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = server.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}

// TestMessageProcessing tests request processing
func TestMessageProcessing(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Create server with default options
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Create a mock connection
	conn := newMockConn()
	
	// Add connection to listener
	listener.addConn(conn)
	
	// Give server time to accept the connection
	time.Sleep(50 * time.Millisecond)
	
	// Send a handshake message
	handshakeMsg := mcp.Message{
		Type: mcp.MessageTypeHandshake,
		Payload: mcp.HandshakePayload{
			Version:      mcp.ProtocolVersion,
			Capabilities: []string{"json"},
		},
	}
	
	msgBytes, err := mcp.EncodeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Failed to encode handshake message: %v", err)
	}
	
	conn.readBuf <- msgBytes
	
	// Give server time to process handshake
	time.Sleep(50 * time.Millisecond)
	
	// Clear previous responses
	conn.writeBuf = nil
	
	// Send a request message
	requestMsg := mcp.Message{
		Type:          mcp.MessageTypeRequest,
		CorrelationID: 123,
		Payload: mcp.Request{
			Method: "getIncident",
			Params: map[string]interface{}{
				"id": "INC0000001",
			},
		},
	}
	
	msgBytes, err = mcp.EncodeMessage(requestMsg)
	if err != nil {
		t.Fatalf("Failed to encode request message: %v", err)
	}
	
	conn.readBuf <- msgBytes
	
	// Give server time to process request
	time.Sleep(50 * time.Millisecond)
	
	// Verify response
	if len(conn.writeBuf) == 0 {
		t.Fatal("Server did not respond to request")
	}
	
	// Decode response
	resp, err := mcp.DecodeMessage(conn.writeBuf)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	
	// Verify response properties
	if resp.Type != mcp.MessageTypeResponse {
		t.Errorf("Expected response type %d, got %d", mcp.MessageTypeResponse, resp.Type)
	}
	
	if resp.CorrelationID != 123 {
		t.Errorf("Expected correlation ID 123, got %d", resp.CorrelationID)
	}
	
	// Verify handler was called
	calls := handler.getCalls()
	if len(calls) != 1 {
		t.Fatalf("Expected handler to be called once, got %d calls", len(calls))
	}
	
	if calls[0].Method != "getIncident" {
		t.Errorf("Expected method 'getIncident', got '%s'", calls[0].Method)
	}
	
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = server.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}

// TestErrorHandling tests error responses
func TestErrorHandling(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Configure handler to return an error
	handler.setHandleFunc(func(ctx context.Context, req mcp.Request) (interface{}, error) {
		if req.Method == "causeError" {
			return nil, fmt.Errorf("intentional error")
		}
		return map[string]interface{}{"success": true}, nil
	})
	
	// Create server with default options
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Create a mock connection
	conn := newMockConn()
	
	// Add connection to listener
	listener.addConn(conn)
	
	// Give server time to accept the connection
	time.Sleep(50 * time.Millisecond)
	
	// Send a handshake message
	handshakeMsg := mcp.Message{
		Type: mcp.MessageTypeHandshake,
		Payload: mcp.HandshakePayload{
			Version:      mcp.ProtocolVersion,
			Capabilities: []string{"json"},
		},
	}
	
	msgBytes, err := mcp.EncodeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Failed to encode handshake message: %v", err)
	}
	
	conn.readBuf <- msgBytes
	
	// Give server time to process handshake
	time.Sleep(50 * time.Millisecond)
	
	// Clear previous responses
	conn.writeBuf = nil
	
	// Send a request that will cause an error
	requestMsg := mcp.Message{
		Type:          mcp.MessageTypeRequest,
		CorrelationID: 456,
		Payload: mcp.Request{
			Method: "causeError",
			Params: map[string]interface{}{},
		},
	}
	
	msgBytes, err = mcp.EncodeMessage(requestMsg)
	if err != nil {
		t.Fatalf("Failed to encode request message: %v", err)
	}
	
	conn.readBuf <- msgBytes
	
	// Give server time to process request
	time.Sleep(50 * time.Millisecond)
	
	// Verify response
	if len(conn.writeBuf) == 0 {
		t.Fatal("Server did not respond to error request")
	}
	
	// Decode response
	resp, err := mcp.DecodeMessage(conn.writeBuf)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	
	// Verify error response
	if resp.Type != mcp.MessageTypeError {
		t.Errorf("Expected error type %d, got %d", mcp.MessageTypeError, resp.Type)
	}
	
	if resp.CorrelationID != 456 {
		t.Errorf("Expected correlation ID 456, got %d", resp.CorrelationID)
	}
	
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = server.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}

// TestConcurrentClients tests handling of multiple simultaneous clients
func TestConcurrentClients(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Create server with default options
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Number of concurrent clients to test
	numClients := 5
	
	// Create multiple connections
	conns := make([]*mockConn, numClients)
	for i := 0; i < numClients; i++ {
		conns[i] = newMockConn()
		listener.addConn(conns[i])
	}
	
	// Give server time to accept the connections
	time.Sleep(100 * time.Millisecond)
	
	// Send handshake messages from all clients
	for i, conn := range conns {
		handshakeMsg := mcp.Message{
			Type: mcp.MessageTypeHandshake,
			Payload: mcp.HandshakePayload{
				Version:      mcp.ProtocolVersion,
				Capabilities: []string{"json"},
			},
		}
		
		msgBytes, err := mcp.EncodeMessage(handshakeMsg)
		if err != nil {
			t.Fatalf("Failed to encode handshake message for client %d: %v", i, err)
		}
		
		conn.readBuf <- msgBytes
	}
	
	// Give server time to process handshakes
	time.Sleep(100 * time.Millisecond)
	
	// Send a request from each client concurrently
	var wg sync.WaitGroup
	for i, conn := range conns {
		wg.Add(1)
		go func(idx int, c *mockConn) {
			defer wg.Done()
			
			// Clear previous responses
			c.writeBuf = nil
			
			// Create a unique request for this client
			requestMsg := mcp.Message{
				Type:          mcp.MessageTypeRequest,
				CorrelationID: uint32(1000 + idx),
				Payload: mcp.Request{
					Method: "getIncident",
					Params: map[string]interface{}{
						"id":     fmt.Sprintf("INC%07d", idx),
						"client": idx,
					},
				},
			}
			
			msgBytes, err := mcp.EncodeMessage(requestMsg)
			if err != nil {
				t.Errorf("Failed to encode request message for client %d: %v", idx, err)
				return
			}
			
			c.readBuf <- msgBytes
		}(i, conn)
	}
	
	// Wait for all requests to be sent
	wg.Wait()
	
	// Give server time to process all requests
	time.Sleep(100 * time.Millisecond)
	
	// Verify all clients received responses
	for i, conn := range conns {
		if len(conn.writeBuf) == 0 {
			t.Errorf("Client %d did not receive a response", i)
			continue
		}
		
		// Decode response
		resp, err := mcp.DecodeMessage(conn.writeBuf)
		if err != nil {
			t.Errorf("Failed to decode response for client %d: %v", i, err)
			continue
		}
		
		// Verify response properties
		if resp.Type != mcp.MessageTypeResponse {
			t.Errorf("Client %d: Expected response type %d, got %d", i, mcp.MessageTypeResponse, resp.Type)
		}
		
		expectedCorrelationID := uint32(1000 + i)
		if resp.CorrelationID != expectedCorrelationID {
			t.Errorf("Client %d: Expected correlation ID %d, got %d", i, expectedCorrelationID, resp.CorrelationID)
		}
	}
	
	// Check that handler received all requests
	calls := handler.getCalls()
	if len(calls) != numClients {
		t.Errorf("Expected handler to be called %d times, got %d calls", numClients, len(calls))
	}
	
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err := server.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}

// TestReconnection tests client reconnection behavior
func TestReconnection(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Create server with default options
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Step 1: Create initial connection
	conn1 := newMockConn()
	listener.addConn(conn1)
	
	// Give server time to accept the connection
	time.Sleep(50 * time.Millisecond)
	
	// Send handshake message
	handshakeMsg := mcp.Message{
		Type: mcp.MessageTypeHandshake,
		Payload: mcp.HandshakePayload{
			Version:      mcp.ProtocolVersion,
			Capabilities: []string{"json"},
		},
	}
	
	msgBytes, err := mcp.EncodeMessage(handshakeMsg)
	if err != nil {
		t.Fatalf("Failed to encode handshake message: %v", err)
	}
	
	conn1.readBuf <- msgBytes
	
	// Give server time to process handshake
	time.Sleep(50 * time.Millisecond)
	
	// Send a request message
	requestMsg := mcp.Message{
		Type:          mcp.MessageTypeRequest,
		CorrelationID: 123,
		Payload: mcp.Request{
			Method: "getIncident",
			Params: map[string]interface{}{
				"id": "INC0000001",
			},
		},
	}
	
	msgBytes, err = mcp.EncodeMessage(requestMsg)
	if err != nil {
		t.Fatalf("Failed to encode request message: %v", err)
	}
	
	conn1.readBuf <- msgBytes
	
	// Give server time to process request
	time.Sleep(50 * time.Millisecond)
	
	// Verify first connection received a response
	if len(conn1.writeBuf) == 0 {
		t.Fatal("First connection did not receive a response")
	}
	
	// Step 2: Close first connection and create a new one
	conn1.Close()
	
	// Give server time to detect the closed connection
	time.Sleep(100 * time.Millisecond)
	
	// Create new connection
	conn2 := newMockConn()
	listener.addConn(conn2)
	
	// Give server time to accept the new connection
	time.Sleep(50 * time.Millisecond)
	
	// Send handshake message from new connection
	conn2.readBuf <- msgBytes
	
	// Give server time to process handshake
	time.Sleep(50 * time.Millisecond)
	
	// Clear any responses
	conn2.writeBuf = nil
	
	// Send a new request from the second connection
	requestMsg = mcp.Message{
		Type:          mcp.MessageTypeRequest,
		CorrelationID: 456,
		Payload: mcp.Request{
			Method: "getIncident",
			Params: map[string]interface{}{
				"id": "INC0000002",
			},
		},
	}
	
	msgBytes, err = mcp.EncodeMessage(requestMsg)
	if err != nil {
		t.Fatalf("Failed to encode request message: %v", err)
	}
	
	conn2.readBuf <- msgBytes
	
	// Give server time to process request
	time.Sleep(50 * time.Millisecond)
	
	// Verify second connection received a response
	if len(conn2.writeBuf) == 0 {
		t.Fatal("Second connection did not receive a response")
	}
	
	// Decode response from second connection
	resp, err := mcp.DecodeMessage(conn2.writeBuf)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	
	// Verify response properties
	if resp.Type != mcp.MessageTypeResponse {
		t.Errorf("Expected response type %d, got %d", mcp.MessageTypeResponse, resp.Type)
	}
	
	if resp.CorrelationID != 456 {
		t.Errorf("Expected correlation ID 456, got %d", resp.CorrelationID)
	}
	
	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = server.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}

// TestGracefulShutdown tests proper cleanup during server shutdown
func TestGracefulShutdown(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Create server with default options
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Create multiple connections
	numConnections := 3
	conns := make([]*mockConn, numConnections)
	
	for i := 0; i < numConnections; i++ {
		conns[i] = newMockConn()
		listener.addConn(conns[i])
		
		// Give server time to accept each connection
		time.Sleep(20 * time.Millisecond)
		
		// Send handshake message
		handshakeMsg := mcp.Message{
			Type: mcp.MessageTypeHandshake,
			Payload: mcp.HandshakePayload{
				Version:      mcp.ProtocolVersion,
				Capabilities: []string{"json"},
			},
		}
		
		msgBytes, err := mcp.EncodeMessage(handshakeMsg)
		if err != nil {
			t.Fatalf("Failed to encode handshake message: %v", err)
		}
		
		conns[i].readBuf <- msgBytes
	}
	
	// Give server time to process all handshakes
	time.Sleep(100 * time.Millisecond)
	
	// Initiate a long-running request on one connection
	// Configure handler to delay response
	handler.setHandleFunc(func(ctx context.Context, req mcp.Request) (interface{}, error) {
		if req.Method == "longRunning" {
			select {
			case <-time.After(2 * time.Second):
				return map[string]interface{}{"completed": true}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return map[string]interface{}{"success": true}, nil
	})
	
	// Send long-running request
	longRequestMsg := mcp.Message{
		Type:          mcp.MessageTypeRequest,
		CorrelationID: 999,
		Payload: mcp.Request{
			Method: "longRunning",
			Params: map[string]interface{}{},
		},
	}
	msgBytes, err := mcp.EncodeMessage(longRequestMsg)
	if err != nil {
		t.Fatalf("Failed to encode long-running request message: %v", err)
	}
	
	// Send the long-running request to the first connection
	conns[0].readBuf <- msgBytes
	
	// Send normal requests to other connections
	for i := 1; i < numConnections; i++ {
		normalRequestMsg := mcp.Message{
			Type:          mcp.MessageTypeRequest,
			CorrelationID: uint32(2000 + i),
			Payload: mcp.Request{
				Method: "getIncident",
				Params: map[string]interface{}{
					"id": fmt.Sprintf("INC%07d", i),
				},
			},
		}
		
		msgBytes, err := mcp.EncodeMessage(normalRequestMsg)
		if err != nil {
			t.Fatalf("Failed to encode normal request message: %v", err)
		}
		
		conns[i].readBuf <- msgBytes
	}
	
	// Wait a short time for the requests to be received
	time.Sleep(100 * time.Millisecond)
	
	// Now initiate shutdown with a short timeout
	// Long enough for normal requests but too short for the long-running one to complete
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	
	// Start shutdown in goroutine so we can check connection state concurrently
	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- server.Shutdown(ctx)
	}()
	
	// The server should take approximately the timeout duration to shut down
	select {
	case err := <-shutdownDone:
		if err != nil && err != context.DeadlineExceeded {
			t.Errorf("Unexpected error during shutdown: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Server shutdown did not complete in time")
	}
	
	// Verify all connections are now closed
	for i, conn := range conns {
		if !conn.closed {
			t.Errorf("Connection %d was not closed during shutdown", i)
		}
	}
	
	// Verify the server returned from Serve with the expected error
	select {
	case err := <-errCh:
		if err != mcp.ErrServerClosed {
			t.Errorf("Expected ErrServerClosed, got: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Server did not return from Serve method")
	}
}

// TestAuthenticationFlow tests client authentication
func TestAuthenticationFlow(t *testing.T) {
	listener := newMockListener()
	handler := newMockHandler()
	
	// Create server with authentication enabled
	server := mcp.NewServer(mcp.ServerOptions{
		RequestHandler: handler,
		Authenticator: &mockAuthenticator{
			// Valid credentials
			validCredentials: map[string]string{
				"validUser": "validPassword",
			},
		},
		SessionTimeout: 500 * time.Millisecond, // Short timeout for testing
	})
	
	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	
	// Test successful authentication flow
	t.Run("Successful Authentication", func(t *testing.T) {
		conn := newMockConn()
		listener.addConn(conn)
		
		// Give server time to accept the connection
		time.Sleep(50 * time.Millisecond)
		
		// Send handshake message
		handshakeMsg := mcp.Message{
			Type: mcp.MessageTypeHandshake,
			Payload: mcp.HandshakePayload{
				Version:      mcp.ProtocolVersion,
				Capabilities: []string{"json"},
			},
		}
		
		msgBytes, err := mcp.EncodeMessage(handshakeMsg)
		if err != nil {
			t.Fatalf("Failed to encode handshake message: %v", err)
		}
		
		conn.readBuf <- msgBytes
		
		// Give server time to process handshake
		time.Sleep(50 * time.Millisecond)
		
		// Clear any handshake response
		conn.writeBuf = nil
		
		// Send authentication message with valid credentials
		authMsg := mcp.Message{
			Type: mcp.MessageTypeAuth,
			Payload: mcp.AuthPayload{
				Username: "validUser",
				Password: "validPassword",
			},
		}
		
		msgBytes, err = mcp.EncodeMessage(authMsg)
		if err != nil {
			t.Fatalf("Failed to encode auth message: %v", err)
		}
		
		conn.readBuf <- msgBytes
		
		// Give server time to process authentication
		time.Sleep(50 * time.Millisecond)
		
		// Verify authentication response
		if len(conn.writeBuf) == 0 {
			t.Fatal("No authentication response received")
		}
		
		resp, err := mcp.DecodeMessage(conn.writeBuf)
		if err != nil {
			t.Fatalf("Failed to decode auth response: %v", err)
		}
		
		if resp.Type != mcp.MessageTypeResponse {
			t.Errorf("Expected response type %d, got %d", mcp.MessageTypeResponse, resp.Type)
		}
		
		// Clear response
		conn.writeBuf = nil
		
		// Now send a request that should be processed (authenticated)
		requestMsg := mcp.Message{
			Type:          mcp.MessageTypeRequest,
			CorrelationID: 789,
			Payload: mcp.Request{
				Method: "getIncident",
				Params: map[string]interface{}{
					"id": "INC0000001",
				},
			},
		}
		
		msgBytes, err = mcp.EncodeMessage(requestMsg)
		if err != nil {
			t.Fatalf("Failed to encode request message: %v", err)
		}
		
		conn.readBuf <- msgBytes
		
		// Give server time to process request
		time.Sleep(50 * time.Millisecond)
		
		// Verify request was processed
		if len(conn.writeBuf) == 0 {
			t.Fatal("No response received for authenticated request")
		}
		
		resp, err = mcp.DecodeMessage(conn.writeBuf)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		
		if resp.Type != mcp.MessageTypeResponse {
			t.Errorf("Expected response type %d, got %d", mcp.MessageTypeResponse, resp.Type)
		}
		
		if resp.CorrelationID != 789 {
			t.Errorf("Expected correlation ID 789, got %d", resp.CorrelationID)
		}
	})
	
	// Test failed authentication
	t.Run("Failed Authentication", func(t *testing.T) {
		conn := newMockConn()
		listener.addConn(conn)
		
		// Give server time to accept the connection
		time.Sleep(50 * time.Millisecond)
		
		// Send handshake message
		handshakeMsg := mcp.Message{
			Type: mcp.MessageTypeHandshake,
			Payload: mcp.HandshakePayload{
				Version:      mcp.ProtocolVersion,
				Capabilities: []string{"json"},
			},
		}
		
		msgBytes, err := mcp.EncodeMessage(handshakeMsg)
		if err != nil {
			t.Fatalf("Failed to encode handshake message: %v", err)
		}
		
		conn.readBuf <- msgBytes
		
		// Give server time to process handshake
		time.Sleep(50 * time.Millisecond)
		
		// Clear any handshake response
		conn.writeBuf = nil
		
		// Send authentication message with invalid credentials
		authMsg := mcp.Message{
			Type: mcp.MessageTypeAuth,
			Payload: mcp.AuthPayload{
				Username: "invalidUser",
				Password: "invalidPassword",
			},
		}
		
		msgBytes, err = mcp.EncodeMessage(authMsg)
		if err != nil {
			t.Fatalf("Failed to encode auth message: %v", err)
		}
		
		conn.readBuf <- msgBytes
		
		// Give server time to process authentication
		time.Sleep(50 * time.Millisecond)
		
		// Verify error response
		if len(conn.writeBuf) == 0 {
			t.Fatal("No authentication response received")
		}
		
		resp, err := mcp.DecodeMessage(conn.writeBuf)
		if err != nil {
			t.Fatalf("Failed to decode auth response: %v", err)
		}
		
		if resp.Type != mcp.MessageTypeError {
			t.Errorf("Expected error type %d, got %d", mcp.MessageTypeError, resp.Type)
		}
		
		// Clear response
		conn.writeBuf = nil
		
		// Now send a request that should be rejected (not authenticated)
		requestMsg := mcp.Message{
			Type:          mcp.MessageTypeRequest,
			CorrelationID: 101,
			Payload: mcp.Request{
				Method: "getIncident",
				Params: map[string]interface{}{
					"id": "INC0000001",
				},
			},
		}
		
		msgBytes, err = mcp.EncodeMessage(requestMsg)
		if err != nil {
			t.Fatalf("Failed to encode request message: %v", err)
		}
		
		conn.readBuf <- msgBytes
		
		// Give server time to process request
		time.Sleep(50 * time.Millisecond)
		
		// Verify authentication error response
		if len(conn.writeBuf) == 0 {
			t.Fatal("No response received for unauthenticated request")
		}
		
		resp, err = mcp.DecodeMessage(conn.writeBuf)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		
		if resp.Type != mcp.MessageTypeError {
			t.Errorf("Expected error type %d, got %d", mcp.MessageTypeError, resp.Type)
		}
	})
	
	// Test session timeout
	t.Run("Session Timeout", func(t *testing.T) {
		conn := newMockConn()
		listener.addConn(conn)
		
		// Give server time to accept the connection
		time.Sleep(50 * time.Millisecond)
		
		// Send handshake message
		handshakeMsg := mcp.Message{
			Type: mcp.MessageTypeHandshake,
			Payload: mcp.HandshakePayload{
				Version:      mcp.ProtocolVersion,
				Capabilities: []string{"json"},
			},
		}
		
		msgBytes, err := mcp.EncodeMessage(handshakeMsg)
		if err != nil {
			t.Fatalf("Failed to encode handshake message: %v", err)
		}
		
		conn.readBuf <- msgBytes
		
		// Give server time to process handshake
		time.Sleep(50 * time.Millisecond)
		
		// Clear any handshake response
		conn.writeBuf = nil
		
		// Send authentication message with valid credentials
		authMsg := mcp.Message{
			Type: mcp.Message
