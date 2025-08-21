# Endor Labs Findings API - Go Client

A simple Go tool to fetch security findings from the Endor Labs API for a specific project.

## Files

- `main.go` - Main Go program
- `internal/api/client.go` - API client for authentication
- `internal/api/findings.go` - API methods for fetching findings
- `go.mod` - Go module file
- `env.example` - Environment variables template
- `.env` - Your actual environment variables (create this)

## Setup

1. Set your environment variables:
```bash
cp env.example .env
# Edit .env with your actual values
```

2. Run the program:
```bash
go run . --project_uuid <your_project_uuid>
```

## Example

```bash
go run . --project_uuid abc123-def456-ghi789
```

## Environment Variables

- `ENDOR_API_KEY` - Your Endor Labs API key
- `ENDOR_API_SECRET` - Your Endor Labs API secret  
- `ENDOR_NAMESPACE` - Your Endor Labs namespace