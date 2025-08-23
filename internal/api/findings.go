package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
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
	pageCount := 0
	var nextPageID string

	for {
		pageCount++
		findings, newNextPageID, _, err := c.getFindingsPage(token, projectUUID, pageSize, nextPageID)
		if err != nil {
			return nil, err
		}

		log.Printf("Page %d: Found %d findings", pageCount, len(findings))

		allFindings = append(allFindings, findings...)

		// Update nextPageID for the next iteration
		nextPageID = newNextPageID

		// Break if no next_page_id (means no more pages) - exactly like Python script
		if nextPageID == "" {
			log.Printf("No more pages to fetch. Total pages: %d", pageCount)
			break
		}

		log.Printf("Next Page ID: %s", nextPageID)

		// Safety check to prevent infinite loops
		if pageCount > 100 {
			log.Printf("Safety limit reached: %d pages. Stopping pagination.", pageCount)
			break
		}
	}

	return allFindings, nil
}

// buildFindingsFilter creates the filter string for findings queries
func (c *Client) buildFindingsFilter(projectUUID string) string {
	template := `context.type == "CONTEXT_TYPE_MAIN" and (
		spec.level in ["FINDING_LEVEL_CRITICAL"] and 
		spec.finding_tags not contains ["FINDING_TAGS_EXCEPTION"] and 
		spec.finding_categories contains ["FINDING_CATEGORY_VULNERABILITY"] and 
		(spec.finding_tags contains ["FINDING_TAGS_POTENTIALLY_REACHABLE_FUNCTION","FINDING_TAGS_REACHABLE_FUNCTION"] and 
		spec.finding_tags contains ["FINDING_TAGS_REACHABLE_DEPENDENCY"] and 
		spec.finding_tags contains ["FINDING_TAGS_FIX_AVAILABLE"] and 
		spec.finding_tags contains ["FINDING_TAGS_NORMAL"]) and 
		spec.finding_metadata.vulnerability.spec.epss_score.probability_score >= 0.01
	)`

	// Clean up whitespace and newlines to create a clean single-line filter
	baseFilter := strings.ReplaceAll(strings.ReplaceAll(template, "\n", ""), "\t", "")

	if projectUUID != "" {
		return fmt.Sprintf("spec.project_uuid==%s and %s", projectUUID, baseFilter)
	}
	return baseFilter
}

// getFindingsFieldMask returns the field mask for findings queries
func (c *Client) getFindingsFieldMask() string {
	template := `meta.description,
		meta.name,
		meta.parent_uuid,
		spec.approximation,
		spec.dependency_file_paths,
		spec.ecosystem,
		spec.explanation,
		spec.finding_categories,
		spec.finding_tags,
		spec.level,
		spec.location_urls,
		spec.project_uuid,
		spec.relationship,
		spec.summary,
		spec.target_dependency_package_name`

	// Clean up whitespace and newlines to create a clean single-line field mask
	return strings.ReplaceAll(strings.ReplaceAll(template, "\n", ""), "\t", "")
}

// getFindingsPageInternal handles the common logic for retrieving a single page of findings
func (c *Client) getFindingsPageInternal(token, projectUUID string, pageSize int, pageID string) ([]Finding, string, bool, error) {
	baseURL := fmt.Sprintf("%s/namespaces/%s/findings", BaseURL, c.namespace)

	// Create query parameters
	params := url.Values{}

	// Build the complex filter using the shared function
	complexFilter := c.buildFindingsFilter(projectUUID)

	params.Set("list_parameters.filter", complexFilter)
	// Use the shared field mask function
	params.Set("list_parameters.mask", c.getFindingsFieldMask())
	params.Set("list_parameters.page_size", fmt.Sprintf("%d", pageSize))
	params.Set("list_parameters.traverse", "true") // Enable searching through child namespaces

	// Add page_id for pagination if provided
	if pageID != "" {
		params.Set("list_parameters.page_id", pageID)
	}

	// Add the query string to the URL
	fullURL := baseURL + "?" + params.Encode()

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

	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("failed to fetch findings with status: %d", resp.StatusCode)
	}

	var findingsResp FindingsListResponse
	if err := json.NewDecoder(resp.Body).Decode(&findingsResp); err != nil {
		return nil, "", false, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check if there are more pages by looking at next_page_id
	hasMore := findingsResp.List.Response.NextPageID != ""

	return findingsResp.List.Objects, findingsResp.List.Response.NextPageID, hasMore, nil
}

// getFindingsPage retrieves a single page of findings
func (c *Client) getFindingsPage(token, projectUUID string, pageSize int, pageID string) ([]Finding, string, bool, error) {
	return c.getFindingsPageInternal(token, projectUUID, pageSize, pageID)
}

// GetFindingsForAllProjects retrieves findings for all projects (without project_uuid filter)
func (c *Client) GetFindingsForAllProjects(token string) ([]Finding, error) {
	var allFindings []Finding
	pageSize := 100
	pageCount := 0
	var nextPageID string

	for {
		pageCount++
		findings, newNextPageID, _, err := c.getFindingsPageForAllProjects(token, pageSize, nextPageID)
		if err != nil {
			return nil, err
		}

		log.Printf("Page %d: Found %d findings", pageCount, len(findings))

		allFindings = append(allFindings, findings...)

		// Update nextPageID for the next iteration
		nextPageID = newNextPageID

		// Break if no next_page_id (means no more pages) - exactly like Python script
		if nextPageID == "" {
			log.Printf("No more pages to fetch. Total pages: %d", pageCount)
			break
		}

		log.Printf("Next Page ID: %s", nextPageID)

		// Safety check to prevent infinite loops
		if pageCount > 100 {
			log.Printf("Safety limit reached: %d pages. Stopping pagination.", pageCount)
			break
		}
	}

	return allFindings, nil
}

// getFindingsPageForAllProjects retrieves a single page of findings for all projects
func (c *Client) getFindingsPageForAllProjects(token string, pageSize int, pageID string) ([]Finding, string, bool, error) {
	return c.getFindingsPageInternal(token, "", pageSize, pageID)
}
