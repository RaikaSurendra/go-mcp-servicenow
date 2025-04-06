package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// ProtocolVersion is the current version of the MCP protocol
	ProtocolVersion = "1.0"

	// Message types
	MessageTypeHandshake    = "handshake"
	MessageTypeAuth         = "auth"
	MessageTypeAuthResponse = "auth_response"
	MessageTypeRequest      = "request"
	MessageTypeResponse     = "response"
	MessageTypeError        = "error"
	MessageTypePing         = "ping"
	MessageTypePong         = "pong"
)

// RequestType defines different request operations
const (
	RequestTypeGetIncidents  = "get_incidents"
	RequestTypeGetIncident   = "get_incident"
	RequestTypeCreateIncident = "create_incident"
	RequestTypeUpdateIncident = "update_incident"
	RequestTypeDeleteIncident = "delete_incident"
)

var (
	// ErrInvalidMessage is returned when a message is invalid
	ErrInvalidMessage = errors.New("invalid message format")
	
	// ErrUnsupportedVersion is returned when the protocol version is not supported
	ErrUnsupportedVersion = errors.New("unsupported protocol version")
	
	// ErrAuthenticationFailed is returned when authentication fails
	ErrAuthenticationFailed = errors.New("authentication failed")
	
	// ErrInvalidMessageType is returned when the message type is invalid
	ErrInvalidMessageType = errors.New("invalid message type")
	
	// ErrMissingRequiredField is returned when a required field is missing
	ErrMissingRequiredField = errors.New("missing required field")
	
	// ErrInvalidRequestType is returned when the request type is invalid
	ErrInvalidRequestType = errors.New("invalid request type")
)

// Message is the base structure for all MCP messages
type Message struct {
	Type        string    `json:"type"`
	Version     string    `json:"version"`
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ContentType string    `json:"content_type,omitempty"`
	Payload     []byte    `json:"payload,omitempty"`
}

// NewMessage creates a new message with the given type and payload
func NewMessage(messageType string, payload interface{}) (*Message, error) {
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	
	var payloadBytes []byte
	var err error
	
	if payload != nil {
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
	}
	
	return &Message{
		Type:        messageType,
		Version:     ProtocolVersion,
		ID:          id,
		Timestamp:   time.Now(),
		ContentType: "application/json",
		Payload:     payloadBytes,
	}, nil
}

// Encode serializes the message to JSON
func (m *Message) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeMessage decodes a JSON message into a Message struct
func DecodeMessage(data []byte) (*Message, error) {
	var message Message
	if err := json.Unmarshal(data, &message); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	return &message, nil
}

// Validate checks if the message is valid
func (m *Message) Validate() error {
	if m.Type == "" {
		return fmt.Errorf("%w: type", ErrMissingRequiredField)
	}
	
	if m.Version == "" {
		return fmt.Errorf("%w: version", ErrMissingRequiredField)
	}
	
	if m.ID == "" {
		return fmt.Errorf("%w: id", ErrMissingRequiredField)
	}
	
	// Check if the message type is supported
	switch m.Type {
	case MessageTypeHandshake, MessageTypeAuth, MessageTypeAuthResponse,
		MessageTypeRequest, MessageTypeResponse, MessageTypeError,
		MessageTypePing, MessageTypePong:
		// Valid message type
	default:
		return fmt.Errorf("%w: %s", ErrInvalidMessageType, m.Type)
	}
	
	// Check if the protocol version is supported
	if m.Version != ProtocolVersion {
		return fmt.Errorf("%w: got %s, want %s", ErrUnsupportedVersion, m.Version, ProtocolVersion)
	}
	
	return nil
}

// HandshakePayload contains handshake information
type HandshakePayload struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Features   []string `json:"features,omitempty"`
}

// NewHandshakeMessage creates a new handshake message
func NewHandshakeMessage(clientID, clientName string, features []string) (*Message, error) {
	payload := HandshakePayload{
		ClientID:   clientID,
		ClientName: clientName,
		Features:   features,
	}
	
	return NewMessage(MessageTypeHandshake, payload)
}

// DecodeHandshakePayload decodes the handshake payload
func DecodeHandshakePayload(message *Message) (*HandshakePayload, error) {
	if message.Type != MessageTypeHandshake {
		return nil, fmt.Errorf("expected message type %s, got %s", MessageTypeHandshake, message.Type)
	}
	
	var payload HandshakePayload
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal handshake payload: %w", err)
	}
	
	return &payload, nil
}

// AuthPayload contains authentication information
type AuthPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// NewAuthMessage creates a new authentication message
func NewAuthMessage(username, password string) (*Message, error) {
	payload := AuthPayload{
		Username: username,
		Password: password,
	}
	
	return NewMessage(MessageTypeAuth, payload)
}

// DecodeAuthPayload decodes the authentication payload
func DecodeAuthPayload(message *Message) (*AuthPayload, error) {
	if message.Type != MessageTypeAuth {
		return nil, fmt.Errorf("expected message type %s, got %s", MessageTypeAuth, message.Type)
	}
	
	var payload AuthPayload
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth payload: %w", err)
	}
	
	return &payload, nil
}

// AuthResponsePayload contains authentication response information
type AuthResponsePayload struct {
	Success bool   `json:"success"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

// NewAuthResponseMessage creates a new authentication response message
func NewAuthResponseMessage(success bool, token, message string) (*Message, error) {
	payload := AuthResponsePayload{
		Success: success,
		Token:   token,
		Message: message,
	}
	
	return NewMessage(MessageTypeAuthResponse, payload)
}

// DecodeAuthResponsePayload decodes the authentication response payload
func DecodeAuthResponsePayload(message *Message) (*AuthResponsePayload, error) {
	if message.Type != MessageTypeAuthResponse {
		return nil, fmt.Errorf("expected message type %s, got %s", MessageTypeAuthResponse, message.Type)
	}
	
	var payload AuthResponsePayload
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth response payload: %w", err)
	}
	
	return &payload, nil
}

// RequestPayload contains request information
type RequestPayload struct {
	RequestType string                 `json:"request_type"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// NewRequestMessage creates a new request message
func NewRequestMessage(requestType string, parameters map[string]interface{}) (*Message, error) {
	payload := RequestPayload{
		RequestType: requestType,
		Parameters:  parameters,
	}
	
	return NewMessage(MessageTypeRequest, payload)
}

// ValidateRequestPayload validates the request payload
func ValidateRequestPayload(payload *RequestPayload) error {
	if payload.RequestType == "" {
		return fmt.Errorf("%w: request_type", ErrMissingRequiredField)
	}
	
	// Check if the request type is supported
	switch payload.RequestType {
	case RequestTypeGetIncidents, RequestTypeGetIncident, 
		RequestTypeCreateIncident, RequestTypeUpdateIncident, 
		RequestTypeDeleteIncident:
		// Valid request type
	default:
		return fmt.Errorf("%w: %s", ErrInvalidRequestType, payload.RequestType)
	}
	
	return nil
}

// DecodeRequestPayload decodes the request payload
func DecodeRequestPayload(message *Message) (*RequestPayload, error) {
	if message.Type != MessageTypeRequest {
		return nil, fmt.Errorf("expected message type %s, got %s", MessageTypeRequest, message.Type)
	}
	
	var payload RequestPayload
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request payload: %w", err)
	}
	
	if err := ValidateRequestPayload(&payload); err != nil {
		return nil, err
	}
	
	return &payload, nil
}

// ResponsePayload contains response information
type ResponsePayload struct {
	Success    bool        `json:"success"`
	RequestID  string      `json:"request_id"`
	Data       interface{} `json:"data,omitempty"`
	Error      string      `json:"error,omitempty"`
	StatusCode int         `json:"status_code,omitempty"`
}

// NewResponseMessage creates a new response message
func NewResponseMessage(success bool, requestID string, data interface{}, errorMsg string, statusCode int) (*Message, error) {
	payload := ResponsePayload{
		Success:    success,
		RequestID:  requestID,
		Data:       data,
		Error:      errorMsg,
		StatusCode: statusCode,
	}
	
	return NewMessage(MessageTypeResponse, payload)
}

// DecodeResponsePayload decodes the response payload
func DecodeResponsePayload(message *Message) (*ResponsePayload, error) {
	if message.Type != MessageTypeResponse {
		return nil, fmt.Errorf("expected message type %s, got %s", MessageTypeResponse, message.Type)
	}
	
	var payload ResponsePayload
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response payload: %w", err)
	}
	
	return &payload, nil
}

// ErrorPayload contains error information
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// NewErrorMessage creates a new error message
func NewErrorMessage(code, message string) (*Message, error) {
	payload := ErrorPayload{
		Code:    code,
		Message: message,
	}
	
	return NewMessage(MessageTypeError, payload)
}

// DecodeErrorPayload decodes the error payload
func DecodeErrorPayload(message *Message) (*ErrorPayload, error) {
	if message.Type != MessageTypeError {
		return nil, fmt.Errorf("expected message type %s, got %s", MessageTypeError, message.Type)
	}
	
	var payload ErrorPayload
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal error payload: %w", err)
	}
	
	return &payload, nil
}

// NewPingMessage creates a new ping message
func NewPingMessage() (*Message, error) {
	return NewMessage(MessageTypePing, nil)
}

// NewPongMessage creates a new pong message
func NewPongMessage() (*Message, error) {
	return NewMessage(MessageTypePong, nil)
}

