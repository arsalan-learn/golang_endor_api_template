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
		Description string `json:"description"`
		Name        string `json:"name"`
		ParentUUID  string `json:"parent_uuid"`
	} `json:"meta"`
	Spec struct {
		Approximation               bool              `json:"approximation"`
		DependencyFilePath          []string          `json:"dependency_file_paths"`
		Ecosystem                   string            `json:"ecosystem"`
		Explanation                 string            `json:"explanation"`
		FindingCategories           []string          `json:"finding_categories"`
		FindingTags                 []string          `json:"finding_tags"`
		Level                       string            `json:"level"`
		LocationUrls                map[string]string `json:"location_urls"`
		ProjectUUID                 string            `json:"project_uuid"`
		Relationship                string            `json:"relationship"`
		Summary                     string            `json:"summary"`
		TargetDependencyPackageName string            `json:"target_dependency_package_name"`
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

	// Create query parameters using the exact working filter from endorctl
	params := url.Values{}

	// Exact filter from the working endorctl command
	complexFilter := fmt.Sprintf(`spec.project_uuid==%s and context.type == "CONTEXT_TYPE_MAIN" and (spec.level in ["FINDING_LEVEL_CRITICAL"] and spec.finding_tags not contains ["FINDING_TAGS_EXCEPTION"] and spec.finding_categories contains ["FINDING_CATEGORY_VULNERABILITY"] and (spec.finding_tags contains ["FINDING_TAGS_POTENTIALLY_REACHABLE_FUNCTION","FINDING_TAGS_REACHABLE_FUNCTION"] and spec.finding_tags contains ["FINDING_TAGS_REACHABLE_DEPENDENCY"] and spec.finding_tags contains ["FINDING_TAGS_FIX_AVAILABLE"] and spec.finding_tags contains ["FINDING_TAGS_NORMAL"]) and spec.finding_metadata.vulnerability.spec.epss_score.probability_score >= 0.01)`, projectUUID)

	params.Set("list_parameters.filter", complexFilter)
	// Use the exact field mask from the working endorctl command
	params.Set("list_parameters.mask", "meta.description,meta.name,meta.parent_uuid,spec.approximation,spec.dependency_file_paths,spec.ecosystem,spec.explanation,spec.finding_categories,spec.finding_tags,spec.level,spec.location_urls,spec.project_uuid,spec.relationship,spec.summary,spec.target_dependency_package_name")
	params.Set("list_parameters.page_size", fmt.Sprintf("%d", pageSize))
	params.Set("list_parameters.traverse", "true") // Enable searching through child namespaces

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
