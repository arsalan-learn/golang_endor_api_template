package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

// Finding represents a security finding from Endor Labs
type Finding struct {
	UUID string `json:"uuid"`
	Meta struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		CreateTime  string `json:"create_time"`
		UpdateTime  string `json:"update_time"`
		Kind        string `json:"kind"`
		ParentKind  string `json:"parent_kind"`
		ParentUUID  string `json:"parent_uuid"`
	} `json:"meta"`
	Spec struct {
		ProjectUUID string `json:"project_uuid"`
	} `json:"spec"`
}

// FindingsListResponse represents the actual API response structure
type FindingsListResponse struct {
	List struct {
		Objects  []Finding `json:"objects"`
		Response struct {
			NextPageID    string `json:"next_page_id"`
			NextPageToken int    `json:"next_page_token"`
		} `json:"response"`
	} `json:"list"`
}

// GetFindings retrieves all findings for a specific project
func (c *Client) GetFindings(token, projectUUID string) ([]Finding, error) {
	var allFindings []Finding
	pageSize := 100

	for {
		findings, nextPageID, hasMore, err := c.getFindingsPage(token, projectUUID, pageSize)
		if err != nil {
			return nil, err
		}

		log.Printf("Page: Found %d findings", len(findings))

		allFindings = append(allFindings, findings...)

		if !hasMore {
			break
		}

		// Use next_page_id for pagination
		if nextPageID == "" {
			break
		}
	}

	return allFindings, nil
}

// getFindingsPage retrieves a single page of findings
func (c *Client) getFindingsPage(token, projectUUID string, pageSize int) ([]Finding, string, bool, error) {
	baseURL := fmt.Sprintf("%s/namespaces/%s/findings", BaseURL, c.namespace)

	// Create query parameters using correct format from endorctl example
	params := url.Values{}
	params.Set("list_parameters.filter", fmt.Sprintf("spec.project_uuid==%s", projectUUID))
	params.Set("list_parameters.mask", "meta,spec.project_uuid")
	params.Set("list_parameters.page_size", fmt.Sprintf("%d", pageSize))

	// Add the query string to the URL
	fullURL := baseURL + "?" + params.Encode()

	log.Printf("Requesting URL: %s", fullURL)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Request-Timeout", "600")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("Response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("failed to fetch findings with status: %d", resp.StatusCode)
	}

	var findingsResp FindingsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&findingsResp); err != nil {
		return nil, "", false, fmt.Errorf("failed to decode response: %w", err)
	}

	log.Printf("API Response: Found %d findings, NextPageID: %s",
		len(findingsResp.List.Objects), findingsResp.List.Response.NextPageID)

	hasMore := findingsResp.List.Response.NextPageID != ""

	return findingsResp.List.Objects, findingsResp.List.Response.NextPageID, hasMore, nil
}
