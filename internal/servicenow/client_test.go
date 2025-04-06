package servicenow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mcp-go-servicenow/internal/config"
)

// Test fixtures - Sample incident data
var testIncidents = []Incident{
	{
		SysID:          "1234567890abcdef1234567890abcdef",
		Number:         "INC0000001",
		ShortDesc:      "Server is down",
		Description:    "The production server is not responding to ping requests",
		State:          "1",
		Priority:       "1",
		Impact:         "1",
		Urgency:        "1",
		Category:       "hardware",
		Subcategory:    "server",
		AssignedTo:     "admin",
		AssignmentGroup: "Network",
		CreatedOn:      "2025-04-05 10:30:00",
		CreatedBy:      "system",
		UpdatedOn:      "2025-04-05 10:35:00",
		UpdatedBy:      "admin",
	},
	{
		SysID:          "234567890abcdef1234567890abcdef1",
		Number:         "INC0000002",
		ShortDesc:      "Email service unavailable",
		Description:    "Users cannot send or receive emails",
		State:          "2",
		Priority:       "2",
		Impact:         "2",
		Urgency:        "2",
		Category:       "software",
		Subcategory:    "email",
		AssignedTo:     "john.doe",
		AssignmentGroup: "Email Support",
		CreatedOn:      "2025-04-05 11:15:00",
		CreatedBy:      "jane.smith",
		UpdatedOn:      "2025-04-05 11:30:00",
		UpdatedBy:      "john.doe",
	},
}

// Helper function to create a new test server
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify authentication header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"error":{"message":"No authorization header","detail":"Authorization header is required"}}`)
			return
		}

		// Check for Accept header
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, `{"error":{"message":"Invalid Accept header","detail":"Accept header must be application/json"}}`)
			return
		}

		// Call the provided handler
		handler(w, r)
	}))

	return server
}

// Helper function to create a new test client
func newTestClient(t *testing.T, server *httptest.Server) *ServiceNowClient {
	// Parse the server URL
	serverURL := server.URL

	// Create a config
	cfg := &config.ServiceNowConfig{
		URL:      serverURL,
		Username: "test-user",
		Password: "test-password",
		Timeout:  30,
	}

	// Create a client
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	return client
}

// Helper to convert incident to ServiceNow API response format
func incidentToResponse(incident Incident) map[string]interface{} {
	result := map[string]interface{}{
		"result": map[string]interface{}{
			"sys_id":           incident.SysID,
			"number":           incident.Number,
			"short_description": incident.ShortDesc,
			"description":      incident.Description,
			"state":            incident.State,
			"priority":         incident.Priority,
			"impact":           incident.Impact,
			"urgency":          incident.Urgency,
			"category":         incident.Category,
			"subcategory":      incident.Subcategory,
			"assigned_to":      incident.AssignedTo,
			"assignment_group": incident.AssignmentGroup,
			"sys_created_on":   incident.CreatedOn,
			"sys_created_by":   incident.CreatedBy,
			"sys_updated_on":   incident.UpdatedOn,
			"sys_updated_by":   incident.UpdatedBy,
		},
	}
	return result
}

// Helper to convert multiple incidents to ServiceNow API response format
func incidentsToResponse(incidents []Incident) map[string]interface{} {
	result := map[string]interface{}{
		"result": []interface{}{},
	}

	for _, incident := range incidents {
		incidentMap := map[string]interface{}{
			"sys_id":           incident.SysID,
			"number":           incident.Number,
			"short_description": incident.ShortDesc,
			"description":      incident.Description,
			"state":            incident.State,
			"priority":         incident.Priority,
			"impact":           incident.Impact,
			"urgency":          incident.Urgency,
			"category":         incident.Category,
			"subcategory":      incident.Subcategory,
			"assigned_to":      incident.AssignedTo,
			"assignment_group": incident.AssignmentGroup,
			"sys_created_on":   incident.CreatedOn,
			"sys_created_by":   incident.CreatedBy,
			"sys_updated_on":   incident.UpdatedOn,
			"sys_updated_by":   incident.UpdatedBy,
		}
		result["result"] = append(result["result"].([]interface{}), incidentMap)
	}

	return result
}

// Test for GetIncident
func TestGetIncident(t *testing.T) {
	// Test successful incident retrieval
	t.Run("Success", func(t *testing.T) {
		expectedIncident := testIncidents[0]

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Verify request method and path
			if r.Method != http.MethodGet {
				t.Errorf("Expected GET request, got %s", r.Method)
			}

			expectedPath := fmt.Sprintf("/api/now/table/incident/%s", expectedIncident.SysID)
			if r.URL.Path != expectedPath {
				t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
			}

			// Return successful response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := incidentToResponse(expectedIncident)
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Get the incident
		ctx := context.Background()
		incident, err := client.GetIncident(ctx, expectedIncident.SysID)
		if err != nil {
			t.Fatalf("GetIncident() error = %v", err)
		}

		// Verify the incident
		if incident.SysID != expectedIncident.SysID {
			t.Errorf("Expected incident sys_id %s, got %s", expectedIncident.SysID, incident.SysID)
		}
		if incident.Number != expectedIncident.Number {
			t.Errorf("Expected incident number %s, got %s", expectedIncident.Number, incident.Number)
		}
		if incident.ShortDesc != expectedIncident.ShortDesc {
			t.Errorf("Expected incident short_description %s, got %s", expectedIncident.ShortDesc, incident.ShortDesc)
		}
	})

	// Test incident not found
	t.Run("Not Found", func(t *testing.T) {
		nonExistentID := "nonexistentid"

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, `{"error":{"message":"No Record found","detail":"Incident not found"}}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Try to get the incident
		ctx := context.Background()
		_, err := client.GetIncident(ctx, nonExistentID)
		if err == nil {
			t.Error("Expected error for non-existent incident, got nil")
		}
	})

	// Test server error
	t.Run("Server Error", func(t *testing.T) {
		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, `{"error":{"message":"Internal server error","detail":"An unexpected error occurred"}}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Try to get the incident
		ctx := context.Background()
		_, err := client.GetIncident(ctx, "anyid")
		if err == nil {
			t.Error("Expected error for server error, got nil")
		}
	})

	// Test context timeout
	t.Run("Context Timeout", func(t *testing.T) {
		// Create test server with delay
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Simulate a delay
			time.Sleep(100 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := incidentToResponse(testIncidents[0])
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Create a context with a short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		// Try to get the incident
		_, err := client.GetIncident(ctx, testIncidents[0].SysID)
		if err == nil {
			t.Error("Expected error for context timeout, got nil")
		}
	})
}

// Test for GetIncidents
func TestGetIncidents(t *testing.T) {
	// Test successful incidents retrieval
	t.Run("Success", func(t *testing.T) {
		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Verify request method and path
			if r.Method != http.MethodGet {
				t.Errorf("Expected GET request, got %s", r.Method)
			}

			if r.URL.Path != "/api/now/table/incident" {
				t.Errorf("Expected path /api/now/table/incident, got %s", r.URL.Path)
			}

			// Verify query parameters
			query := r.URL.Query()
			if query.Get("sysparm_limit") != "10" {
				t.Errorf("Expected sysparm_limit=10, got %s", query.Get("sysparm_limit"))
			}

			// Return successful response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := incidentsToResponse(testIncidents)
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Get incidents
		ctx := context.Background()
		incidents, err := client.GetIncidents(ctx, 10, "")
		if err != nil {
			t.Fatalf("GetIncidents() error = %v", err)
		}

		// Verify incidents count
		if len(incidents) != len(testIncidents) {
			t.Errorf("Expected %d incidents, got %d", len(testIncidents), len(incidents))
		}

		// Verify first incident
		if incidents[0].SysID != testIncidents[0].SysID {
			t.Errorf("Expected incident sys_id %s, got %s", testIncidents[0].SysID, incidents[0].SysID)
		}
	})

	// Test with query filter
	t.Run("With Query", func(t *testing.T) {
		testQuery := "priority=1^state=1"

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Verify query parameters
			query := r.URL.Query()
			if query.Get("sysparm_query") != testQuery {
				t.Errorf("Expected sysparm_query=%s, got %s", testQuery, query.Get("sysparm_query"))
			}

			// Return successful response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return only the first incident as filtered result
			response := incidentsToResponse([]Incident{testIncidents[0]})
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Get incidents with query
		ctx := context.Background()
		incidents, err := client.GetIncidents(ctx, 10, testQuery)
		if err != nil {
			t.Fatalf("GetIncidents() error = %v", err)
		}

		// Verify incidents count
		if len(incidents) != 1 {
			t.Errorf("Expected 1 incident, got %d", len(incidents))
		}
	})

	// Test empty result
	t.Run("Empty Result", func(t *testing.T) {
		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Return empty result
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"result":[]}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Get incidents
		ctx := context.Background()
		incidents, err := client.GetIncidents(ctx, 10, "")
		if err != nil {
			t.Fatalf("GetIncidents() error = %v", err)
		}

		// Verify incidents count
		if len(incidents) != 0 {
			t.Errorf("Expected 0 incidents, got %d", len(incidents))
		}
	})

	// Test server error
	t.Run("Server Error", func(t *testing.T) {
		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, `{"error":{"message":"Internal server error","detail":"An unexpected error occurred"}}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Try to get incidents
		ctx := context.Background()
		_, err := client.GetIncidents(ctx, 10, "")
		if err == nil {
			t.Error("Expected error for server error, got nil")
		}
	})
}

// Test for CreateIncident
func TestCreateIncident(t *testing.T) {
	// Test successful incident creation
	t.Run("Success", func(t *testing.T) {
		newIncident := &Incident{
			ShortDesc:   "New incident",
			Description: "This is a new test incident",
			Priority:    "3",
			State:       "1",
			Category:    "software",
		}

		expectedIncident := *newIncident
		expectedIncident.SysID = "654321fedcba654321fedcba654321fe"
		expectedIncident.Number = "INC0000003"
		expectedIncident.CreatedOn = "2025-04-06 09:15:00"
		expectedIncident.CreatedBy = "test-user"

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Verify request method and path
			if r.Method != http.MethodPost {
				t.Errorf("Expected POST request, got %s", r.Method)
			}

			if r.URL.Path != "/api/now/table/incident" {
				t.Errorf("Expected path /api/now/table/incident, got %s", r.URL.Path)
			}

			// Verify request content type
			contentType := r.Header.Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", contentType)
			}

			// Decode request body
			var requestBody map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&requestBody)
			if err != nil {
				t.Fatalf("Failed to decode request body: %v", err)
			}

			// Verify request body fields
			if requestBody["short_description"] != newIncident.ShortDesc {
				t.Errorf("Expected short_description %s, got %v", newIncident.ShortDesc, requestBody["short_description"])
			}
			if requestBody["description"] != newIncident.Description {
				t.Errorf("Expected description %s, got %v", newIncident.Description, requestBody["description"])
			}
			if requestBody["priority"] != newIncident.Priority {
				t.Errorf("Expected priority %s, got %v", newIncident.Priority, requestBody["priority"])
			}

			// Return successful response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			response := incidentToResponse(expectedIncident)
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Create the incident
		ctx := context.Background()
		createdIncident, err := client.CreateIncident(ctx, newIncident)
		if err != nil {
			t.Fatalf("CreateIncident() error = %v", err)
		}

		// Verify the created incident
		if createdIncident.SysID != expectedIncident.SysID {
			t.Errorf("Expected incident sys_id %s, got %s", expectedIncident.SysID, createdIncident.SysID)
		}
		if createdIncident.Number != expectedIncident.Number {
			t.Errorf("Expected incident number %s, got %s", expectedIncident.Number, createdIncident.Number)
		}
		if createdIncident.ShortDesc != expectedIncident.ShortDesc {
			t.Errorf("Expected incident short_description %s, got %s", expectedIncident.ShortDesc, createdIncident.ShortDesc)
		}
		if createdIncident.CreatedBy != expectedIncident.CreatedBy {
			t.Errorf("Expected incident created_by %s, got %s", expectedIncident.CreatedBy, createdIncident.CreatedBy)
		}
	})

	// Test validation error
	t.Run("Validation Error", func(t *testing.T) {
		// Missing required fields
		invalidIncident := &Incident{
			// Missing short description
			Description: "This is a test incident",
			Priority:    "3",
		}

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, `{"error":{"message":"Validation failed","detail":"Required field 'short_description' is missing"}}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Try to create the incident
		ctx := context.Background()
		_, err := client.CreateIncident(ctx, invalidIncident)
		if err == nil {
			t.Error("Expected error for validation failure, got nil")
		}
	})

	// Test nil incident
	t.Run("Nil Incident", func(t *testing.T) {
		// Create test client with mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Server should not be called for nil incident")
		}))
		defer server.Close()

		client := newTestClient(t, server)

		// Try to create a nil incident
		ctx := context.Background()
		_, err := client.CreateIncident(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil incident, got nil")
		}
	})
}

// Test for UpdateIncident
func TestUpdateIncident(t *testing.T) {
	// Test successful incident update
	t.Run("Success", func(t *testing.T) {
		existingIncident := testIncidents[0]
		updates := &Incident{
			State:    "2",
			Priority: "2",
			ShortDesc: "Updated incident description",
			AssignedTo: "jane.smith",
		}

		expectedIncident := existingIncident
		expectedIncident.State = updates.State
		expectedIncident.Priority = updates.Priority
		expectedIncident.ShortDesc = updates.ShortDesc
		expectedIncident.AssignedTo = updates.AssignedTo
		expectedIncident.UpdatedOn = "2025-04-06 10:00:00"
		expectedIncident.UpdatedBy = "test-user"

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Verify request method and path
			if r.Method != http.MethodPut && r.Method != http.MethodPatch {
				t.Errorf("Expected PUT or PATCH request, got %s", r.Method)
			}

			expectedPath := fmt.Sprintf("/api/now/table/incident/%s", existingIncident.SysID)
			if r.URL.Path != expectedPath {
				t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
			}

			// Verify request content type
			contentType := r.Header.Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", contentType)
			}

			// Decode request body
			var requestBody map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&requestBody)
			if err != nil {
				t.Fatalf("Failed to decode request body: %v", err)
			}

			// Verify request body fields
			if requestBody["state"] != updates.State {
				t.Errorf("Expected state %s, got %v", updates.State, requestBody["state"])
			}
			if requestBody["priority"] != updates.Priority {
				t.Errorf("Expected priority %s, got %v", updates.Priority, requestBody["priority"])
			}
			if requestBody["short_description"] != updates.ShortDesc {
				t.Errorf("Expected short_description %s, got %v", updates.ShortDesc, requestBody["short_description"])
			}

			// Return successful response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := incidentToResponse(expectedIncident)
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Update the incident
		ctx := context.Background()
		updatedIncident, err := client.UpdateIncident(ctx, existingIncident.SysID, updates)
		if err != nil {
			t.Fatalf("UpdateIncident() error = %v", err)
		}

		// Verify the updated incident
		if updatedIncident.State != updates.State {
			t.Errorf("Expected state %s, got %s", updates.State, updatedIncident.State)
		}
		if updatedIncident.Priority != updates.Priority {
			t.Errorf("Expected priority %s, got %s", updates.Priority, updatedIncident.Priority)
		}
		if updatedIncident.ShortDesc != updates.ShortDesc {
			t.Errorf("Expected short_description %s, got %s", updates.ShortDesc, updatedIncident.ShortDesc)
		}
		if updatedIncident.AssignedTo != updates.AssignedTo {
			t.Errorf("Expected assigned_to %s, got %s", updates.AssignedTo, updatedIncident.AssignedTo)
		}
		if updatedIncident.UpdatedBy != expectedIncident.UpdatedBy {
			t.Errorf("Expected updated_by %s, got %s", expectedIncident.UpdatedBy, updatedIncident.UpdatedBy)
		}
	})

	// Test incident not found
	t.Run("Not Found", func(t *testing.T) {
		nonExistentID := "nonexistentid"
		updates := &Incident{
			State:    "2",
			Priority: "2",
		}

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, `{"error":{"message":"No Record found","detail":"Incident not found"}}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Try to update the incident
		ctx := context.Background()
		_, err := client.UpdateIncident(ctx, nonExistentID, updates)
		if err == nil {
			t.Error("Expected error for non-existent incident, got nil")
		}
	})

	// Test nil updates
	t.Run("Nil Updates", func(t *testing.T) {
		// Create test client with mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Server should not be called for nil updates")
		}))
		defer server.Close()

		client := newTestClient(t, server)

		// Try to update with nil data
		ctx := context.Background()
		_, err := client.UpdateIncident(ctx, testIncidents[0].SysID, nil)
		if err == nil {
			t.Error("Expected error for nil updates, got nil")
		}
	})
}

// Test for DeleteIncident
func TestDeleteIncident(t *testing.T) {
	// Test successful incident deletion
	t.Run("Success", func(t *testing.T) {
		existingIncident := testIncidents[0]

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// Verify request method and path
			if r.Method != http.MethodDelete {
				t.Errorf("Expected DELETE request, got %s", r.Method)
			}

			expectedPath := fmt.Sprintf("/api/now/table/incident/%s", existingIncident.SysID)
			if r.URL.Path != expectedPath {
				t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
			}

			// Return successful response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNoContent)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Delete the incident
		ctx := context.Background()
		err := client.DeleteIncident(ctx, existingIncident.SysID)
		if err != nil {
			t.Fatalf("DeleteIncident() error = %v", err)
		}
	})

	// Test incident not found
	t.Run("Not Found", func(t *testing.T) {
		nonExistentID := "nonexistentid"

		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintln(w, `{"error":{"message":"No Record found","detail":"Incident not found"}}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Try to delete the incident
		ctx := context.Background()
		err := client.DeleteIncident(ctx, nonExistentID)
		if err == nil {
			t.Error("Expected error for non-existent incident, got nil")
		}
	})

	// Test server error
	t.Run("Server Error", func(t *testing.T) {
		// Create test server
		server := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, `{"error":{"message":"Internal server error","detail":"An unexpected error occurred"}}`)
		})
		defer server.Close()

		// Create test client
		client := newTestClient(t, server)

		// Try to delete the incident
		ctx := context.Background()
		err := client.DeleteIncident(ctx, testIncidents[0].SysID)
		if err == nil {
			t.Error("Expected error for server error, got nil")
		}
	})

	// Test empty ID
	t.Run("Empty ID", func(t *testing.T) {
		// Create test client with mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Server should not be called for empty ID")
		}))
		defer server.Close()

		client := newTestClient(t, server)

		// Try to delete with empty ID
		ctx := context.Background()
		err := client.DeleteIncident(ctx, "")
		if err == nil {
			t.Error("Expected error for empty ID, got nil")
		}
	})
}

// Test for Authentication behavior
func TestAuthentication(t *testing.T) {
	// Test proper auth header formation
	t.Run("Auth Header Format", func(t *testing.T) {
		username := "test-user"
		password := "test-password"
		expectedAuthValue := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

		// Create test server that validates the auth header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != expectedAuthValue {
				t.Errorf("Expected auth header %s, got %s", expectedAuthValue, authHeader)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []interface{}{},
			})
		}))
		defer server.Close()

		// Create config and client
		cfg := &config.ServiceNowConfig{
			URL:      server.URL,
			Username: username,
			Password: password,
			Timeout:  30,
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("Failed to create test client: %v", err)
		}

		// Make a request
		ctx := context.Background()
		_, err = client.GetIncidents(ctx, 10, "")
		if err != nil {
			t.Errorf("GetIncidents() error = %v", err)
		}
	})

	// Test authentication failure
	t.Run("Auth Failure", func(t *testing.T) {
		// Create test server that always returns 401
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"error":{"message":"User Not Authenticated","detail":"Invalid username or password"}}`)
		}))
		defer server.Close()

		// Create config and client
		cfg := &config.ServiceNowConfig{
			URL:      server.URL,
			Username: "wrong-user",
			Password: "wrong-password",
			Timeout:  30,
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("Failed to create test client: %v", err)
		}

		// Make a request
		ctx := context.Background()
		_, err = client.GetIncidents(ctx, 10, "")
		if err == nil {
			t.Error("Expected error for auth failure, got nil")
		}

		// Verify the error indicates authentication problem
		if !strings.Contains(err.Error(), "User Not Authenticated") {
			t.Errorf("Expected auth error, got: %v", err)
		}
	})

	// Test auth retry logic (first try fails, second succeeds)
	t.Run("Auth Retry", func(t *testing.T) {
		attempts := 0
		// Create test server that fails first auth, then succeeds
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts == 1 {
				// First attempt fails
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, `{"error":{"message":"Session Timeout","detail":"Session expired"}}`)
				return
			}
			// Second attempt succeeds
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []interface{}{},
			})
		}))
		defer server.Close()

		// Create config and client
		cfg := &config.ServiceNowConfig{
			URL:      server.URL,
			Username: "test-user",
			Password: "test-password",
			Timeout:  30,
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("Failed to create test client: %v", err)
		}

		// Make a request
		ctx := context.Background()
		_, err = client.GetIncidents(ctx, 10, "")
		if err != nil {
			t.Errorf("GetIncidents() error = %v", err)
		}

		// Verify it took 2 attempts
		if attempts != 2 {
			t.Errorf("Expected 2 attempts, got %d", attempts)
		}
	})
}

// Test for Network Error handling
func TestNetworkErrors(t *testing.T) {
	// Test connection failure
	t.Run("Connection Failure", func(t *testing.T) {
		// Create a config with an invalid URL
		cfg := &config.ServiceNowConfig{
			URL:      "http://invalid-host-that-does-not-exist.local",
			Username: "test-user",
			Password: "test-password",
			Timeout:  1, // Short timeout
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("Failed to create test client: %v", err)
		}

		// Make a request
		ctx := context.Background()
		_, err = client.GetIncidents(ctx, 10, "")
		if err == nil {
			t.Error("Expected error for connection failure, got nil")
		}
	})

	// Test retry on temporary network errors
	t.Run("Retry on Temporary Error", func(t *testing.T) {
		attempts := 0
		// Create test server that simulates temporary network issues
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			// Check auth header to avoid getting caught by the auth middleware
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if attempts <= 2 {
				// First two attempts fail with a 5xx error
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintln(w, `{"error":{"message":"Service Unavailable","detail":"Try again later"}}`)
				return
			}
			// Third attempt succeeds
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": []interface{}{},
			})
		}))
		defer server.Close()

		// Create config and client
		cfg := &config.ServiceNowConfig{
			URL:      server.URL,
			Username: "test-user",
			Password: "test-password",
			Timeout:  30,
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("Failed to create test client: %v", err)
		}

		// Make a request
		ctx := context.Background()
		_, err = client.GetIncidents(ctx, 10, "")
		if err != nil {
			t.Errorf("GetIncidents() error = %v", err)
		}

		// Verify it took 3 attempts
		if attempts != 3 {
			t.Errorf("Expected 3 attempts, got %d", attempts)
		}
	})

	// Test max retries exceeded
	t.Run("Max Retries Exceeded", func(t *testing.T) {
		attempts := 0
		// Create test server that always returns 503
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			// Check auth header to avoid getting caught by the auth middleware
			authHeader := r.Header.Get("Authorization")
			if authHeader == ""
