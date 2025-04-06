package servicenow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"

	"mcp-go-servicenow/internal/config"
)

// Client represents a ServiceNow API client
type Client struct {
	httpClient *http.Client
	baseURL    string
	username   string
	password   string
	headers    map[string]string
	logger     *logrus.Logger
}

// NewClient creates a new ServiceNow client
func NewClient(cfg *config.ServiceNowConfig, logger *logrus.Logger) *Client {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	client := &Client{
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
		baseURL:  cfg.GetServiceNowBaseURL(),
		username: cfg.Username,
		password: cfg.Password,
		headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		logger: logger,
	}

	return client
}

// doRequest performs the HTTP request with authentication and headers
func (c *Client) doRequest(ctx context.Context, method, endpoint string, queryParams url.Values, body interface{}) ([]byte, int, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, endpoint)
	if queryParams != nil && len(queryParams) > 0 {
		url = fmt.Sprintf("%s?%s", url, queryParams.Encode())
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add basic auth
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.username, c.password)))
	req.Header.Set("Authorization", authHeader)

	// Add headers
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}

	c.logger.WithFields(logrus.Fields{
		"method":   method,
		"endpoint": endpoint,
		"url":      url,
	}).Debug("Sending request to ServiceNow")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		c.logger.WithFields(logrus.Fields{
			"status_code": resp.StatusCode,
			"response":    string(respBody),
			"method":      method,
			"url":         url,
		}).Error("ServiceNow API request failed")
		return respBody, resp.StatusCode, fmt.Errorf("API error: %s, status code: %d", string(respBody), resp.StatusCode)
	}

	return respBody, resp.StatusCode, nil
}

// Get performs a GET request to the specified endpoint
func (c *Client) Get(ctx context.Context, endpoint string, queryParams url.Values) ([]byte, error) {
	resp, statusCode, err := c.doRequest(ctx, http.MethodGet, endpoint, queryParams, nil)
	if err != nil {
		return nil, fmt.Errorf("GET request failed: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"status_code": statusCode,
		"endpoint":    endpoint,
	}).Debug("GET request successful")

	return resp, nil
}

// Post performs a POST request to the specified endpoint
func (c *Client) Post(ctx context.Context, endpoint string, queryParams url.Values, body interface{}) ([]byte, error) {
	resp, statusCode, err := c.doRequest(ctx, http.MethodPost, endpoint, queryParams, body)
	if err != nil {
		return nil, fmt.Errorf("POST request failed: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"status_code": statusCode,
		"endpoint":    endpoint,
	}).Debug("POST request successful")

	return resp, nil
}

// Put performs a PUT request to the specified endpoint
func (c *Client) Put(ctx context.Context, endpoint string, queryParams url.Values, body interface{}) ([]byte, error) {
	resp, statusCode, err := c.doRequest(ctx, http.MethodPut, endpoint, queryParams, body)
	if err != nil {
		return nil, fmt.Errorf("PUT request failed: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"status_code": statusCode,
		"endpoint":    endpoint,
	}).Debug("PUT request successful")

	return resp, nil
}

// Delete performs a DELETE request to the specified endpoint
func (c *Client) Delete(ctx context.Context, endpoint string, queryParams url.Values) ([]byte, error) {
	resp, statusCode, err := c.doRequest(ctx, http.MethodDelete, endpoint, queryParams, nil)
	if err != nil {
		return nil, fmt.Errorf("DELETE request failed: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"status_code": statusCode,
		"endpoint":    endpoint,
	}).Debug("DELETE request successful")

	return resp, nil
}

// ServiceNowResponse is a generic response structure
type ServiceNowResponse struct {
	Result interface{} `json:"result"`
}

// Incident represents a ServiceNow incident
type Incident struct {
	SysID           string `json:"sys_id,omitempty"`
	Number          string `json:"number,omitempty"`
	ShortDesc       string `json:"short_description,omitempty"`
	Description     string `json:"description,omitempty"`
	Priority        string `json:"priority,omitempty"`
	State           string `json:"state,omitempty"`
	AssignedTo      string `json:"assigned_to,omitempty"`
	SysCreatedOn    string `json:"sys_created_on,omitempty"`
	SysUpdatedOn    string `json:"sys_updated_on,omitempty"`
	CreatedBy       string `json:"created_by,omitempty"`
	AssignmentGroup string `json:"assignment_group,omitempty"`
	Category        string `json:"category,omitempty"`
	Subcategory     string `json:"subcategory,omitempty"`
	Impact          string `json:"impact,omitempty"`
	Urgency         string `json:"urgency,omitempty"`
	CreatedOn       string `json:"created_on,omitempty"`
	UpdatedOn       string `json:"updated_on,omitempty"`
	UpdatedBy       string `json:"updated_by,omitempty"`
}

// GetIncidents retrieves a list of incidents
func (c *Client) GetIncidents(ctx context.Context, limit int, query string) ([]Incident, error) {
	queryParams := url.Values{}
	if limit > 0 {
		queryParams.Set("sysparm_limit", fmt.Sprintf("%d", limit))
	}
	queryParams.Set("sysparm_display_value", "true")

	if query != "" {
		queryParams.Set("sysparm_query", query)
	}

	endpoint := "incident"
	respBody, err := c.Get(ctx, endpoint, queryParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get incidents: %w", err)
	}

	var response struct {
		Result []Incident `json:"result"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse incidents response: %w", err)
	}

	return response.Result, nil
}

// GetIncident retrieves a specific incident by its

func (c *Client) GetIncident(ctx context.Context, sysID string) (*Incident, error) {
	if sysID == "" {
		return nil, fmt.Errorf("incident sys_id is required")
	}

	endpoint := fmt.Sprintf("incident/%s", sysID)
	respBody, err := c.Get(ctx, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get incident %s: %w", sysID, err)
	}

	var response struct {
		Result Incident `json:"result"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse incident response: %w", err)
	}

	return &response.Result, nil
}

// CreateIncident creates a new incident
func (c *Client) CreateIncident(ctx context.Context, incident *Incident) (*Incident, error) {
	if incident == nil {
		return nil, fmt.Errorf("incident data is required")
	}

	endpoint := "incident"
	respBody, err := c.Post(ctx, endpoint, nil, incident)
	if err != nil {
		return nil, fmt.Errorf("failed to create incident: %w", err)
	}

	var response struct {
		Result Incident `json:"result"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse create incident response: %w", err)
	}

	return &response.Result, nil
}

// UpdateIncident updates an existing incident
func (c *Client) UpdateIncident(ctx context.Context, sysID string, incident *Incident) (*Incident, error) {
	if sysID == "" {
		return nil, fmt.Errorf("incident sys_id is required")
	}
	if incident == nil {
		return nil, fmt.Errorf("incident data is required")
	}

	endpoint := fmt.Sprintf("incident/%s", sysID)
	respBody, err := c.Put(ctx, endpoint, nil, incident)
	if err != nil {
		return nil, fmt.Errorf("failed to update incident %s: %w", sysID, err)
	}

	var response struct {
		Result Incident `json:"result"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse update incident response: %w", err)
	}

	return &response.Result, nil
}

// DeleteIncident deletes an incident by its sys_id
func (c *Client) DeleteIncident(ctx context.Context, sysID string) error {
	if sysID == "" {
		return fmt.Errorf("incident sys_id is required")
	}

	endpoint := fmt.Sprintf("incident/%s", sysID)
	_, err := c.Delete(ctx, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to delete incident %s: %w", sysID, err)
	}

	return nil
}
