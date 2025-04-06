package mcp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Test message encoding and decoding for all message types
func TestMessageEncoding(t *testing.T) {
	// Test cases for different message types
	testCases := []struct {
		name        string
		message     Message
		expectError bool
	}{
		{
			name: "Handshake Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeHandshake,
				CorrelationID: 0, // Handshake doesn't need correlation ID
				Payload: HandshakePayload{
					ClientVersion: "1.0.0",
					Capabilities:  []string{"compression", "encryption"},
				},
			},
			expectError: false,
		},
		{
			name: "Auth Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeAuth,
				CorrelationID: 1,
				Payload: AuthPayload{
					Username: "testuser",
					Password: "testpassword",
				},
			},
			expectError: false,
		},
		{
			name: "Request Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeRequest,
				CorrelationID: 2,
				Payload: RequestPayload{
					Operation: "getIncident",
					Params: map[string]interface{}{
						"id": "1234567890abcdef",
					},
				},
			},
			expectError: false,
		},
		{
			name: "Response Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeResponse,
				CorrelationID: 2, // Matching a request
				Payload: ResponsePayload{
					Data: map[string]interface{}{
						"sys_id":            "1234567890abcdef",
						"number":            "INC0000001",
						"short_description": "Server is down",
						"priority":          "1",
					},
				},
			},
			expectError: false,
		},
		{
			name: "Error Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeError,
				CorrelationID: 2, // Matching a request
				Payload: ErrorPayload{
					Code:    404,
					Message: "Incident not found",
					Details: "The requested incident with ID 1234567890abcdef was not found",
				},
			},
			expectError: false,
		},
		{
			name: "Heartbeat Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeHeartbeat,
				CorrelationID: 0, // Heartbeat doesn't need correlation ID
				Payload:       nil,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode the message
			encoded, err := EncodeMessage(tc.message)
			if err != nil && !tc.expectError {
				t.Fatalf("EncodeMessage() error = %v", err)
			}
			if err == nil && tc.expectError {
				t.Error("EncodeMessage() expected error, got nil")
			}
			if tc.expectError {
				return
			}

			// Decode the message
			decoded, err := DecodeMessage(encoded)
			if err != nil {
				t.Fatalf("DecodeMessage() error = %v", err)
			}

			// Verify message fields
			if decoded.Version != tc.message.Version {
				t.Errorf("Expected version %d, got %d", tc.message.Version, decoded.Version)
			}
			if decoded.Type != tc.message.Type {
				t.Errorf("Expected type %d, got %d", tc.message.Type, decoded.Type)
			}
			if decoded.CorrelationID != tc.message.CorrelationID {
				t.Errorf("Expected correlation ID %d, got %d", tc.message.CorrelationID, decoded.CorrelationID)
			}

			// Verify payload based on message type
			switch tc.message.Type {
			case TypeHandshake:
				original, ok := tc.message.Payload.(HandshakePayload)
				if !ok {
					t.Fatalf("Invalid original payload type: %T", tc.message.Payload)
				}
				decoded, ok := decoded.Payload.(HandshakePayload)
				if !ok {
					t.Fatalf("Invalid decoded payload type: %T", decoded.Payload)
				}
				if decoded.ClientVersion != original.ClientVersion {
					t.Errorf("Expected client version %s, got %s", original.ClientVersion, decoded.ClientVersion)
				}
				if !reflect.DeepEqual(decoded.Capabilities, original.Capabilities) {
					t.Errorf("Expected capabilities %v, got %v", original.Capabilities, decoded.Capabilities)
				}

			case TypeAuth:
				original, ok := tc.message.Payload.(AuthPayload)
				if !ok {
					t.Fatalf("Invalid original payload type: %T", tc.message.Payload)
				}
				decoded, ok := decoded.Payload.(AuthPayload)
				if !ok {
					t.Fatalf("Invalid decoded payload type: %T", decoded.Payload)
				}
				if decoded.Username != original.Username {
					t.Errorf("Expected username %s, got %s", original.Username, decoded.Username)
				}
				if decoded.Password != original.Password {
					t.Errorf("Expected password %s, got %s", original.Password, decoded.Password)
				}

			case TypeRequest:
				original, ok := tc.message.Payload.(RequestPayload)
				if !ok {
					t.Fatalf("Invalid original payload type: %T", tc.message.Payload)
				}
				decoded, ok := decoded.Payload.(RequestPayload)
				if !ok {
					t.Fatalf("Invalid decoded payload type: %T", decoded.Payload)
				}
				if decoded.Operation != original.Operation {
					t.Errorf("Expected operation %s, got %s", original.Operation, decoded.Operation)
				}
				if !reflect.DeepEqual(decoded.Params, original.Params) {
					t.Errorf("Expected params %v, got %v", original.Params, decoded.Params)
				}

			case TypeResponse:
				original, ok := tc.message.Payload.(ResponsePayload)
				if !ok {
					t.Fatalf("Invalid original payload type: %T", tc.message.Payload)
				}
				decoded, ok := decoded.Payload.(ResponsePayload)
				if !ok {
					t.Fatalf("Invalid decoded payload type: %T", decoded.Payload)
				}
				if !reflect.DeepEqual(decoded.Data, original.Data) {
					t.Errorf("Expected data %v, got %v", original.Data, decoded.Data)
				}

			case TypeError:
				original, ok := tc.message.Payload.(ErrorPayload)
				if !ok {
					t.Fatalf("Invalid original payload type: %T", tc.message.Payload)
				}
				decoded, ok := decoded.Payload.(ErrorPayload)
				if !ok {
					t.Fatalf("Invalid decoded payload type: %T", decoded.Payload)
				}
				if decoded.Code != original.Code {
					t.Errorf("Expected error code %d, got %d", original.Code, decoded.Code)
				}
				if decoded.Message != original.Message {
					t.Errorf("Expected error message %s, got %s", original.Message, decoded.Message)
				}
				if decoded.Details != original.Details {
					t.Errorf("Expected error details %s, got %s", original.Details, decoded.Details)
				}
			}
		})
	}
}

// Test message validation for different scenarios
func TestMessageValidation(t *testing.T) {
	testCases := []struct {
		name        string
		message     Message
		expectError bool
		errorMatch  string
	}{
		{
			name: "Valid Request Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeRequest,
				CorrelationID: 1,
				Payload: RequestPayload{
					Operation: "getIncident",
					Params: map[string]interface{}{
						"id": "1234567890abcdef",
					},
				},
			},
			expectError: false,
		},
		{
			name: "Unsupported Version",
			message: Message{
				Version:       255, // Unsupported version
				Type:          TypeRequest,
				CorrelationID: 1,
				Payload: RequestPayload{
					Operation: "getIncident",
					Params: map[string]interface{}{
						"id": "1234567890abcdef",
					},
				},
			},
			expectError: true,
			errorMatch:  "unsupported protocol version",
		},
		{
			name: "Invalid Message Type",
			message: Message{
				Version:       CurrentVersion,
				Type:          255, // Invalid type
				CorrelationID: 1,
				Payload: RequestPayload{
					Operation: "getIncident",
					Params: map[string]interface{}{
						"id": "1234567890abcdef",
					},
				},
			},
			expectError: true,
			errorMatch:  "invalid message type",
		},
		{
			name: "Missing Correlation ID for Request",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeRequest,
				CorrelationID: 0, // Missing correlation ID
				Payload: RequestPayload{
					Operation: "getIncident",
					Params: map[string]interface{}{
						"id": "1234567890abcdef",
					},
				},
			},
			expectError: true,
			errorMatch:  "correlation ID is required",
		},
		{
			name: "Missing Operation in Request Payload",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeRequest,
				CorrelationID: 1,
				Payload: RequestPayload{
					Operation: "", // Missing operation
					Params: map[string]interface{}{
						"id": "1234567890abcdef",
					},
				},
			},
			expectError: true,
			errorMatch:  "operation is required",
		},
		{
			name: "Missing Username in Auth Payload",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeAuth,
				CorrelationID: 1,
				Payload: AuthPayload{
					Username: "", // Missing username
					Password: "testpassword",
				},
			},
			expectError: true,
			errorMatch:  "username is required",
		},
		{
			name: "Missing Password in Auth Payload",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeAuth,
				CorrelationID: 1,
				Payload: AuthPayload{
					Username: "testuser",
					Password: "", // Missing password
				},
			},
			expectError: true,
			errorMatch:  "password is required",
		},
		{
			name: "Missing Code in Error Payload",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeError,
				CorrelationID: 1,
				Payload: ErrorPayload{
					Code:    0, // Missing code
					Message: "Error message",
					Details: "Error details",
				},
			},
			expectError: true,
			errorMatch:  "error code is required",
		},
		{
			name: "Missing Message in Error Payload",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeError,
				CorrelationID: 1,
				Payload: ErrorPayload{
					Code:    404,
					Message: "", // Missing message
					Details: "Error details",
				},
			},
			expectError: true,
			errorMatch:  "error message is required",
		},
		{
			name: "Nil Payload",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeRequest,
				CorrelationID: 1,
				Payload:       nil, // Nil payload
			},
			expectError: true,
			errorMatch:  "payload is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Validate the message
			err := ValidateMessage(tc.message)
			if tc.expectError {
				if err == nil {
					t.Error("ValidateMessage() expected error, got nil")
					return
				}
				if tc.errorMatch != "" && !strings.Contains(err.Error(), tc.errorMatch) {
					t.Errorf("ValidateMessage() error = %v, expected to contain: %s", err, tc.errorMatch)
				}
			} else if err != nil {
				t.Errorf("ValidateMessage() error = %v", err)
			}
		})
	}
}

// Test payload encoding and decoding
func TestPayloadEncoding(t *testing.T) {
	testCases := []struct {
		name        string
		messageType MessageType
		payload     interface{}
		expectError bool
	}{
		{
			name:        "Encode/Decode Handshake Payload",
			messageType: TypeHandshake,
			payload: HandshakePayload{
				ClientVersion: "1.0.0",
				Capabilities:  []string{"compression", "encryption"},
			},
			expectError: false,
		},
		{
			name:        "Encode/Decode Auth Payload",
			messageType: TypeAuth,
			payload: AuthPayload{
				Username: "testuser",
				Password: "testpassword",
			},
			expectError: false,
		},
		{
			name:        "Encode/Decode Request Payload",
			messageType: TypeRequest,
			payload: RequestPayload{
				Operation: "getIncidents",
				Params: map[string]interface{}{
					"limit": 10,
					"query": "priority=1",
				},
			},
			expectError: false,
		},
		{
			name:        "Encode/Decode Response Payload",
			messageType: TypeResponse,
			payload: ResponsePayload{
				Data: map[string]interface{}{
					"incidents": []map[string]interface{}{
						{
							"sys_id":            "1234567890abcdef",
							"number":            "INC0000001",
							"short_description": "Server is down",
						},
						{
							"sys_id":            "234567890abcdef1",
							"number":            "INC0000002",
							"short_description": "Email service unavailable",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name:        "Encode/Decode Error Payload",
			messageType: TypeError,
			payload: ErrorPayload{
				Code:    404,
				Message: "Not Found",
				Details: "The requested resource was not found on the server",
			},
			expectError: false,
		},
		{
			name:        "Encode/Decode Heartbeat Payload (nil)",
			messageType: TypeHeartbeat,
			payload:     nil,
			expectError: false,
		},
		{
			name:        "Invalid Payload Type",
			messageType: TypeRequest,
			payload:     "invalid payload type",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode the payload
			encoded, err := EncodePayload(tc.messageType, tc.payload)
			if err != nil && !tc.expectError {
				t.Fatalf("EncodePayload() error = %v", err)
			}
			if err == nil && tc.expectError {
				t.Error("EncodePayload() expected error, got nil")
				return
			}
			if tc.expectError {
				return
			}

			// Decode the payload
			decoded, err := DecodePayload(tc.messageType, encoded)
			if err != nil {
				t.Fatalf("DecodePayload() error = %v", err)
			}

			// Verify decoded payload matches original
			switch tc.messageType {
			case TypeHandshake:
				original, _ := tc.payload.(HandshakePayload)
				result, ok := decoded.(HandshakePayload)
				if !ok {
					t.Fatalf("Decoded payload is not HandshakePayload: %T", decoded)
				}
				if result.ClientVersion != original.ClientVersion {
					t.Errorf("Expected ClientVersion %s, got %s", original.ClientVersion, result.ClientVersion)
				}
				if !reflect.DeepEqual(result.Capabilities, original.Capabilities) {
					t.Errorf("Expected Capabilities %v, got %v", original.Capabilities, result.Capabilities)
				}

			case TypeAuth:
				original, _ := tc.payload.(AuthPayload)
				result, ok := decoded.(AuthPayload)
				if !ok {
					t.Fatalf("Decoded payload is not AuthPayload: %T", decoded)
				}
				if result.Username != original.Username {
					t.Errorf("Expected Username %s, got %s", original.Username, result.Username)
				}
				if result.Password != original.Password {
					t.Errorf("Expected Password %s, got %s", original.Password, result.Password)
				}

			case TypeRequest:
				original, _ := tc.payload.(RequestPayload)
				result, ok := decoded.(RequestPayload)
				if !ok {
					t.Fatalf("Decoded payload is not RequestPayload: %T", decoded)
				}
				if result.Operation != original.Operation {
					t.Errorf("Expected Operation %s, got %s", original.Operation, result.Operation)
				}
				if !reflect.DeepEqual(result.Params, original.Params) {
					t.Errorf("Expected Params %v, got %v", original.Params, result.Params)
				}

			case TypeResponse:
				original, _ := tc.payload.(ResponsePayload)
				result, ok := decoded.(ResponsePayload)
				if !ok {
					t.Fatalf("Decoded payload is not ResponsePayload: %T", decoded)
				}
				if !reflect.DeepEqual(result.Data, original.Data) {
					t.Errorf("Expected Data %v, got %v", original.Data, result.Data)
				}

			case TypeError:
				original, _ := tc.payload.(ErrorPayload)
				result, ok := decoded.(ErrorPayload)
				if !ok {
					t.Fatalf("Decoded payload is not ErrorPayload: %T", decoded)
				}
				if result.Code != original.Code {
					t.Errorf("Expected Code %d, got %d", original.Code, result.Code)
				}
				if result.Message != original.Message {
					t.Errorf("Expected Message %s, got %s", original.Message, result.Message)
				}
				if result.Details != original.Details {
					t.Errorf("Expected Details %s, got %s", original.Details, result.Details)
				}
			}
		})
	}
}

// Test correlation ID handling
func TestCorrelationIDHandling(t *testing.T) {
	// Create a request message
	requestMsg := Message{
		Version:       CurrentVersion,
		Type:          TypeRequest,
		CorrelationID: 12345,
		Payload: RequestPayload{
			Operation: "getIncident",
			Params: map[string]interface{}{
				"id": "1234567890abcdef",
			},
		},
	}

	// Create a response message with matching correlation ID
	responseMsg := Message{
		Version:       CurrentVersion,
		Type:          TypeResponse,
		CorrelationID: 12345, // Same as request
		Payload: ResponsePayload{
			Data: map[string]interface{}{
				"sys_id":            "1234567890abcdef",
				"number":            "INC0000001",
				"short_description": "Server is down",
			},
		},
	}

	// Create an error message with matching correlation ID
	errorMsg := Message{
		Version:       CurrentVersion,
		Type:          TypeError,
		CorrelationID: 12345, // Same as request
		Payload: ErrorPayload{
			Code:    404,
			Message: "Not Found",
			Details: "Incident not found",
		},
	}

	// Test matching correlation IDs
	t.Run("Matching Correlation IDs", func(t *testing.T) {
		// Encode and decode request
		requestBytes, err := EncodeMessage(requestMsg)
		if err != nil {
			t.Fatalf("Failed to encode request: %v", err)
		}
		decodedRequest, err := DecodeMessage(requestBytes)
		if err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		// Encode and decode response
		responseBytes, err := EncodeMessage(responseMsg)
		if err != nil {
			t.Fatalf("Failed to encode response: %v", err)
		}
		decodedResponse, err := DecodeMessage(responseBytes)
		if err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify correlation IDs match
		if decodedRequest.CorrelationID != decodedResponse.CorrelationID {
			t.Errorf("Correlation IDs don't match: request=%d, response=%d", 
				decodedRequest.CorrelationID, decodedResponse.CorrelationID)
		}
	})

	// Test correlation ID generation
	t.Run("Correlation ID Generation", func(t *testing.T) {
		// Generate a batch of correlation IDs
		ids := make(map[uint32]bool)
		for i := 0; i < 1000; i++ {
			id := GenerateCorrelationID()
			if id == 0 {
				t.Error("Generated correlation ID is 0")
			}
			if ids[id] {
				t.Errorf("Duplicate correlation ID generated: %d", id)
			}
			ids[id] = true
		}
	})

	// Test message matching
	t.Run("Message Matching", func(t *testing.T) {
		// Check if response matches request
		if !IsResponseForRequest(responseMsg, requestMsg) {
			t.Error("Response should match request")
		}

		// Check if error matches request
		if !IsResponseForRequest(errorMsg, requestMsg) {
			t.Error("Error should match request")
		}

		// Create a response with different correlation ID
		mismatchedResponse := responseMsg
		mismatchedResponse.CorrelationID = 54321

		// Check that mismatched response doesn't match request
		if IsResponseForRequest(mismatchedResponse, requestMsg) {
			t.Error("Mismatched response should not match request")
		}
	})
}

// Test protocol version compatibility
func TestProtocolVersionCompatibility(t *testing.T) {
	// Test current version
	t.Run("Current Version", func(t *testing.T) {
		msg := Message{
			Version:       CurrentVersion,
			Type:          TypeRequest,
			CorrelationID: 1,
			Payload: RequestPayload{
				Operation: "getIncident",
				Params: map[string]interface{}{
					"id": "1234567890abcdef",
				},
			},
		}

		err := ValidateMessage(msg)
		if err != nil {
			t.Errorf("Current version should be valid: %v", err)
		}
	})

	// Test minimum supported version
	t.Run("Minimum Supported Version", func(t *testing.T) {
		msg := Message{
			Version:       MinSupportedVersion,
			Type:          TypeRequest,
			CorrelationID: 1,
			Payload: RequestPayload{
				Operation: "getIncident",
				Params: map[string]interface{}{
					"id": "1234567890abcdef",
				},
			},
		}

		err := ValidateMessage(msg)
		if err != nil {
			t.Errorf("Minimum supported version should be valid: %v", err)
		}
	})

	// Test unsupported version (too low)
	t.Run("Unsupported Version (Too Low)", func(t *testing.T) {
		msg := Message{
			Version:       MinSupportedVersion - 1,
			Type:          TypeRequest,
			CorrelationID: 1,
			Payload: RequestPayload{
				Operation: "getIncident",
				Params: map[string]interface{}{
					"id": "1234567890abcdef",
				},
			},
		}

		err := ValidateMessage(msg)
		if err == nil {
			t.Error("Version below minimum should be invalid")
		}
		if !strings.Contains(err.Error(), "unsupported protocol version") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	// Test unsupported version (too high)
	t.Run("Unsupported Version (Too High)", func(t *testing.T) {
		msg := Message{
			Version:       CurrentVersion + 1,
			Type:          TypeRequest,
			CorrelationID: 1,
			Payload: RequestPayload{
				Operation: "getIncident",
				Params: map[string]interface{}{
					"id": "1234567890abcdef",
				},
			},
		}

		err := ValidateMessage(msg)
		if err == nil {
			t.Error("Version above current should be invalid")
		}
		if !strings.Contains(err.Error(), "unsupported protocol version") {
			t.Errorf("Expected negotiated version %d, got %d", CurrentVersion - 1, negotiatedVersion)
		}
	})

	// Test no common versions
	t.Run("No Common Versions", func(t *testing.T) {
		clientVersions := []uint8{CurrentVersion}
		serverVersions := []uint8{MinSupportedVersion}

		// Assuming CurrentVersion > MinSupportedVersion+1 for this test
		if CurrentVersion <= MinSupportedVersion+1 {
			t.Skip("Test requires CurrentVersion > MinSupportedVersion+1")
		}

		_, err := NegotiateVersion(clientVersions, serverVersions)
		if err == nil {
			t.Error("Expected error for no common versions, got nil")
		}
	})

	// Test empty version arrays
	t.Run("Empty Version Arrays", func(t *testing.T) {
		_, err := NegotiateVersion([]uint8{}, []uint8{CurrentVersion})
		if err == nil {
			t.Error("Expected error for empty client versions, got nil")
		}

		_, err = NegotiateVersion([]uint8{CurrentVersion}, []uint8{})
		if err == nil {
			t.Error("Expected error for empty server versions, got nil")
		}
	})

	// Test identical supported versions
	t.Run("Identical Supported Versions", func(t *testing.T) {
		versions := []uint8{CurrentVersion, MinSupportedVersion}

		negotiatedVersion, err := NegotiateVersion(versions, versions)
		if err != nil {
			t.Fatalf("Version negotiation failed: %v", err)
		}

		// Should choose highest version
		if negotiatedVersion != CurrentVersion {
			t.Errorf("Expected negotiated version %d, got %d", CurrentVersion, negotiatedVersion)
		}
	})
}

// Test complete message serialization process
func TestMessageSerialization(t *testing.T) {
	// Test cases for different message types and scenarios
	testCases := []struct {
		name        string
		message     Message
		expectError bool
		verifyFunc  func(t *testing.T, data []byte, msg Message)
	}{
		{
			name: "Serialize Request Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeRequest,
				CorrelationID: 42,
				Payload: RequestPayload{
					Operation: "getIncident",
					Params: map[string]interface{}{
						"id": "1234567890abcdef",
					},
				},
			},
			expectError: false,
			verifyFunc: func(t *testing.T, data []byte, msg Message) {
				// Verify header format (first 6 bytes)
				if len(data) < 6 {
					t.Fatalf("Serialized data too short: %d bytes", len(data))
				}

				// Check version (1st byte)
				if data[0] != CurrentVersion {
					t.Errorf("Expected version byte %d, got %d", CurrentVersion, data[0])
				}

				// Check message type (2nd byte)
				if data[1] != byte(TypeRequest) {
					t.Errorf("Expected message type byte %d, got %d", TypeRequest, data[1])
				}

				// Check correlation ID (bytes 2-5)
				var correlationID uint32
				// Assuming little endian encoding
				correlationID = binary.LittleEndian.Uint32(data[2:6])
				if correlationID != 42 {
					t.Errorf("Expected correlation ID 42, got %d", correlationID)
				}

				// Check if payload exists (should be after header)
				if len(data) <= 6 {
					t.Error("No payload found in serialized message")
				}

				// Verify we can deserialize back to the original message
				decoded, err := DecodeMessage(data)
				if err != nil {
					t.Fatalf("Failed to decode serialized message: %v", err)
				}

				// Verify fields match
				if decoded.Version != msg.Version {
					t.Errorf("Decoded version doesn't match: expected %d, got %d", 
						msg.Version, decoded.Version)
				}
				if decoded.Type != msg.Type {
					t.Errorf("Decoded type doesn't match: expected %d, got %d", 
						msg.Type, decoded.Type)
				}
				if decoded.CorrelationID != msg.CorrelationID {
					t.Errorf("Decoded correlation ID doesn't match: expected %d, got %d", 
						msg.CorrelationID, decoded.CorrelationID)
				}

				// Verify payload type and content
				req, ok := decoded.Payload.(RequestPayload)
				if !ok {
					t.Fatalf("Decoded payload has wrong type: %T", decoded.Payload)
				}
				if req.Operation != "getIncident" {
					t.Errorf("Decoded operation doesn't match: expected %s, got %s", 
						"getIncident", req.Operation)
				}
			},
		},
		{
			name: "Serialize Large Response Message",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeResponse,
				CorrelationID: 1234,
				Payload: ResponsePayload{
					Data: map[string]interface{}{
						"incidents": generateLargeIncidentList(100),
					},
				},
			},
			expectError: false,
			verifyFunc: func(t *testing.T, data []byte, msg Message) {
				// Verify the length of the data is substantial
				if len(data) < 1000 {
					t.Errorf("Expected large data payload, got only %d bytes", len(data))
				}

				// Verify we can deserialize back to the original message
				decoded, err := DecodeMessage(data)
				if err != nil {
					t.Fatalf("Failed to decode large serialized message: %v", err)
				}

				// Check response type
				resp, ok := decoded.Payload.(ResponsePayload)
				if !ok {
					t.Fatalf("Decoded payload has wrong type: %T", decoded.Payload)
				}

				// Check data field exists and has incidents
				incidents, ok := resp.Data["incidents"].([]interface{})
				if !ok {
					t.Fatalf("Incidents field missing or wrong type: %T", resp.Data["incidents"])
				}

				// Check incident count
				if len(incidents) != 100 {
					t.Errorf("Expected 100 incidents, got %d", len(incidents))
				}
			},
		},
		{
			name: "Serialize Heartbeat (Minimal Message)",
			message: Message{
				Version:       CurrentVersion,
				Type:          TypeHeartbeat,
				CorrelationID: 0,
				Payload:       nil,
			},
			expectError: false,
			verifyFunc: func(t *testing.T, data []byte, msg Message) {
				// Heartbeat should be a minimal message with just the header
				if len(data) != 6 {
					t.Errorf("Expected 6 bytes for heartbeat, got %d bytes", len(data))
				}

				// Check type byte
				if data[1] != byte(TypeHeartbeat) {
					t.Errorf("Expected message type byte %d, got %d", TypeHeartbeat, data[1])
				}

				// Verify we can deserialize back to a heartbeat message
				decoded, err := DecodeMessage(data)
				if err != nil {
					t.Fatalf("Failed to decode heartbeat message: %v", err)
				}

				if decoded.Type != TypeHeartbeat {
					t.Errorf("Expected heartbeat type, got %d", decoded.Type)
				}

				if decoded.Payload != nil {
					t.Errorf("Expected nil payload for heartbeat, got %T", decoded.Payload)
				}
			},
		},
		{
			name: "Invalid Message Type",
			message: Message{
				Version:       CurrentVersion,
				Type:          255, // Invalid type
				CorrelationID: 1,
				Payload: RequestPayload{
					Operation: "getIncident",
					Params:    map[string]interface{}{"id": "123"},
				},
			},
			expectError: true,
			verifyFunc:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize the message
			data, err := EncodeMessage(tc.message)
			if err != nil && !tc.expectError {
				t.Fatalf("EncodeMessage() error = %v", err)
			}
			if err == nil && tc.expectError {
				t.Error("EncodeMessage() expected error, got nil")
			}
			if tc.expectError {
				return
			}

			// Run custom verification if provided
			if tc.verifyFunc != nil {
				tc.verifyFunc(t, data, tc.message)
			}
		})
	}

	// Test partial reads and buffer manipulation
	t.Run("Partial Read Handling", func(t *testing.T) {
		// Create sample message
		msg := Message{
			Version:       CurrentVersion,
			Type:          TypeRequest,
			CorrelationID: 42,
			Payload: RequestPayload{
				Operation: "getIncident",
				Params: map[string]interface{}{
					"id": "1234567890abcdef",
				},
			},
		}

		// Encode the message
		fullData, err := EncodeMessage(msg)
		if err != nil {
			t.Fatalf("Failed to encode message: %v", err)
		}

		// Test truncated data (header incomplete)
		truncatedHeader := fullData[:3] // Only first 3 bytes of header
		_, err = DecodeMessage(truncatedHeader)
		if err == nil {
			t.Error("Expected error for truncated header, got nil")
		}

		// Test truncated data (header complete, payload incomplete)
		headerWithPartialPayload := fullData[:10] // header + some payload
		_, err = DecodeMessage(headerWithPartialPayload)
		if err == nil {
			t.Error("Expected error for truncated payload, got nil")
		}

		// Test corrupted header
		corruptedData := append([]byte{}, fullData...)
		corruptedData[1] = 255 // Invalid message type
		_, err = DecodeMessage(corruptedData)
		if err == nil {
			t.Error("Expected error for corrupted header, got nil")
		}

		// Test corrupted payload
		corruptedPayload := append([]byte{}, fullData...)
		// Corrupt some bytes in the payload
		if len(corruptedPayload) > 10 {
			corruptedPayload[8] = 0xFF
			corruptedPayload[9] = 0xFF
		}
		_, err = DecodeMessage(corruptedPayload)
		if err == nil {
			t.Error("Expected error for corrupted payload, got nil")
		}
	})

	// Test endianness handling
	t.Run("Endianness Handling", func(t *testing.T) {
		// Create a message with a specific correlation ID that has different
		// byte representations in little vs big endian
		correlationID := uint32(0x12345678) // Very different between little/big endian
		msg := Message{
			Version:       CurrentVersion,
			Type:          TypeRequest,
			CorrelationID: correlationID,
			Payload: RequestPayload{
				Operation: "testEndianness",
				Params:    map[string]interface{}{},
			},
		}

		// Encode the message
		data, err := EncodeMessage(msg)
		if err != nil
	})

	// Test version negotiation
	t.Run("Version Negotiation", func(t *testing.T) {
		clientVersions := []uint8{CurrentVersion, CurrentVersion - 1, MinSupportedVersion}
		serverVersions := []uint8{CurrentVersion - 1, MinSupportedVersion}

		negotiatedVersion, err := NegotiateVersion(clientVersions, serverVersions)
		if err != nil {
			t.Fatalf("Version negotiation failed: %v", err)
		}

		// Should choose highest common version
		if negotiatedVersion != CurrentVersion - 1 {
			t.Errorf("Expected negotiated version %d, got %d", CurrentVersion - 1, negotiatedVersion)
