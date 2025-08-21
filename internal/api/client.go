package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	BaseURL = "https://api.endorlabs.com/v1"
)

// Client represents an Endor Labs API client
type Client struct {
	apiKey     string
	apiSecret  string
	namespace  string
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient(apiKey, apiSecret, namespace string) *Client {
	return &Client{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		namespace: namespace,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// GetToken authenticates with the API and returns a token
func (c *Client) GetToken() (string, error) {
	url := fmt.Sprintf("%s/auth/api-key", BaseURL)

	payload := map[string]string{
		"key":    c.apiKey,
		"secret": c.apiSecret,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Request-Timeout", "60")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var authResp struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if authResp.Token == "" {
		return "", fmt.Errorf("no token received in response")
	}

	return authResp.Token, nil
}
