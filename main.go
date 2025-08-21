package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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

	// Display findings
	fmt.Printf("Found %d findings for project %s:\n\n", len(findings), *projectUUID)

	for i, finding := range findings {
		fmt.Printf("Finding %d:\n", i+1)
		fmt.Printf("  UUID: %s\n", finding.UUID)
		fmt.Printf("  Name: %s\n", finding.Meta.Name)
		fmt.Printf("  Description: %s\n", finding.Meta.Description)
		fmt.Printf("  Kind: %s\n", finding.Meta.Kind)
		fmt.Printf("  Parent Kind: %s\n", finding.Meta.ParentKind)
		fmt.Printf("  Parent UUID: %s\n", finding.Meta.ParentUUID)
		fmt.Printf("  Project UUID: %s\n", finding.Spec.ProjectUUID)
		fmt.Printf("  Created: %s\n", finding.Meta.CreateTime)
		fmt.Printf("  Updated: %s\n", finding.Meta.UpdateTime)
		fmt.Println()
	}
}
