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
	flag.Parse()

	if *projectUUID == "" {
		fmt.Println("Usage: go run . --project_uuid <project_uuid>")
		fmt.Println("Example: go run . --project_uuid abc123-def456-ghi789")
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

	// Fetch findings for the project
	findings, err := client.GetFindings(token, *projectUUID)
	if err != nil {
		log.Fatalf("Failed to fetch findings: %v", err)
	}

	// Display findings in terminal
	fmt.Printf("Found %d findings for project %s:\n\n", len(findings), *projectUUID)

	for i, finding := range findings {
		fmt.Printf("Finding %d:\n", i+1)
		fmt.Printf("  UUID: %s\n", finding.UUID)
		fmt.Printf("  Name: %s\n", finding.Meta.Name)
		fmt.Printf("  Description: %s\n", finding.Meta.Description)
		fmt.Printf("  Level: %s\n", finding.Spec.Level)
		fmt.Printf("  Ecosystem: %s\n", finding.Spec.Ecosystem)
		fmt.Printf("  Target Package: %s\n", finding.Spec.TargetDependencyPackageName)
		fmt.Printf("  Approximation: %t\n", finding.Spec.Approximation)
		fmt.Printf("  Finding Tags: %v\n", finding.Spec.FindingTags)
		fmt.Printf("  Finding Categories: %v\n", finding.Spec.FindingCategories)
		fmt.Printf("  Dependency Files: %v\n", finding.Spec.DependencyFilePath)
		fmt.Printf("  Relationship: %s\n", finding.Spec.Relationship)
		fmt.Printf("  Explanation: %s\n", finding.Spec.Explanation)
		fmt.Printf("  Summary: %s\n", finding.Spec.Summary)
		fmt.Printf("  Parent UUID: %s\n", finding.Meta.ParentUUID)
		fmt.Printf("  Project UUID: %s\n", finding.Spec.ProjectUUID)
		if len(finding.Spec.LocationUrls) > 0 {
			fmt.Printf("  Location URLs:\n")
			for file, url := range finding.Spec.LocationUrls {
				fmt.Printf("    %s: %s\n", file, url)
			}
		}
		fmt.Println()
	}

	// Save findings to JSON file
	if err := saveFindingsToJSON(findings, *projectUUID); err != nil {
		log.Printf("Warning: Failed to save findings to JSON file: %v", err)
	} else {
		fmt.Printf("Findings saved to JSON file successfully!\n")
	}
}

// saveFindingsToJSON saves the findings to a JSON file with timestamp
func saveFindingsToJSON(findings []api.Finding, projectUUID string) error {
	// Create filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("findings_%s_%s.json", projectUUID, timestamp)

	// Create the output data structure
	output := struct {
		Timestamp     string        `json:"timestamp"`
		ProjectUUID   string        `json:"project_uuid"`
		TotalFindings int           `json:"total_findings"`
		Findings      []api.Finding `json:"findings"`
	}{
		Timestamp:     time.Now().Format(time.RFC3339),
		ProjectUUID:   projectUUID,
		TotalFindings: len(findings),
		Findings:      findings,
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
