package context

import (
	"encoding/json"
	"os"
	"time"
)

// TargetContext holds all the intelligence gathered by the recon engine.
type TargetContext struct {
	Timestamp         time.Time       `json:"timestamp"`
	Domain            string          `json:"domain"`
	Subdomains        []string        `json:"subdomains"`
	Endpoints         []string        `json:"endpoints"`
	Parameters        []string        `json:"parameters"`
	JSFiles           []JSFinding     `json:"js_files_with_findings"`
	APIs              []string        `json:"api_discovery"`
	WAF               string          `json:"waf"`
	CORS              []string        `json:"cors_issues"`
	Technologies      []string        `json:"technologies"`
	RequestSmuggling  string          `json:"request_smuggling_status"`
}

// JSFinding is a sub-struct for detailed JavaScript analysis results.
type JSFinding struct {
	FileURL   string   `json:"FileURL"`
	Secrets   []string `json:"Secrets"`
	Endpoints []string `json:"Endpoints"`
}

// LoadContextFromFile reads and parses the JSON recon report.
func LoadContextFromFile(filepath string) (*TargetContext, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var ctx TargetContext
	if err := json.Unmarshal(data, &ctx); err != nil {
		return nil, err
	}

	return &ctx, nil
}
