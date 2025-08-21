package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/endor-labs/findings-api/internal/api"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file automatically (like Python)
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found or could not be loaded: %v", err)
	}

	// Parse command line flags
	projectUUID := flag.String("project_uuid", "", "The UUID of the project to fetch findings for")
	allProjects := flag.Bool("all-projects", false, "Fetch findings for all projects (ignores project_uuid)")
	flag.Parse()

	// Validate arguments
	if !*allProjects && *projectUUID == "" {
		fmt.Println("Usage:")
		fmt.Println("  For specific project: go run . --project_uuid <project_uuid>")
		fmt.Println("  For all projects: go run . --all-projects")
		fmt.Println("Example:")
		fmt.Println("  go run . --project_uuid abc123-def456-ghi789")
		fmt.Println("  go run . --all-projects")
		os.Exit(1)
	}

	// Get environment variables
	apiKey := os.Getenv("ENDOR_API_KEY")
	apiSecret := os.Getenv("ENDOR_API_SECRET")
	namespace := os.Getenv("ENDOR_API_NAMESPACE")

	if apiKey == "" || apiSecret == "" || namespace == "" {
		fmt.Println("Error: Please set the following environment variables:")
		fmt.Println("  ENDOR_API_KEY")
		fmt.Println("  ENDOR_API_SECRET")
		fmt.Println("  ENDOR_API_NAMESPACE")
		os.Exit(1)
	}

	// Create API client
	client := api.NewClient(apiKey, apiSecret, namespace)

	// Get authentication token
	token, err := client.GetToken()
	if err != nil {
		log.Fatalf("Failed to get authentication token: %v", err)
	}

	log.Printf("Successfully authenticated with Endor Labs API")

	// Fetch findings
	var findings []api.Finding
	var searchDescription string

	if *allProjects {
		log.Printf("Fetching findings for ALL projects...")
		findings, err = client.GetFindingsForAllProjects(token)
		searchDescription = "all projects"
	} else {
		log.Printf("Fetching findings for project: %s", *projectUUID)
		findings, err = client.GetFindings(token, *projectUUID)
		searchDescription = fmt.Sprintf("project %s", *projectUUID)
	}

	if err != nil {
		log.Fatalf("Failed to fetch findings: %v", err)
	}

	// Display findings in terminal
	fmt.Printf("Found %d findings for %s:\n\n", len(findings), searchDescription)

	// Save findings to JSON file
	filename := ""
	if *allProjects {
		filename = fmt.Sprintf("findings_all_projects_%s.json", time.Now().Format("2006-01-02_15-04-05"))
	} else {
		filename = fmt.Sprintf("findings_%s_%s.json", *projectUUID, time.Now().Format("2006-01-02_15-04-05"))
	}

	if err := saveFindingsToJSON(findings, filename, searchDescription); err != nil {
		log.Printf("Warning: Failed to save findings to JSON file: %v", err)
	} else {
		fmt.Printf("Findings saved to JSON file successfully!\n")
	}
}

// saveFindingsToJSON saves the findings to a JSON file with timestamp
func saveFindingsToJSON(findings []api.Finding, filename, searchDescription string) error {
	// Create the output data structure
	output := struct {
		Timestamp         string        `json:"timestamp"`
		SearchDescription string        `json:"search_description"`
		TotalFindings     int           `json:"total_findings"`
		Findings          []api.Finding `json:"findings"`
	}{
		Timestamp:         time.Now().Format(time.RFC3339),
		SearchDescription: searchDescription,
		TotalFindings:     len(findings),
		Findings:          findings,
	}

	// Marshal to JSON with pretty formatting
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	fmt.Printf("Findings saved to: %s\n", filename)
	return nil
}
