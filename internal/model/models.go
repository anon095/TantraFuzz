package model

import "time"

// JSFinding is a sub-struct for detailed JavaScript analysis results.
type JSFinding struct {
	FileURL   string   `json:"FileURL"`
	Secrets   []string `json:"Secrets"`
	Endpoints []string `json:"Endpoints"`
}

// ReconResult holds all aggregated findings from all recon modules. This is our central data model.
type ReconResult struct {
	Timestamp         time.Time   `json:"timestamp"`
	Domain            string      `json:"domain"`
	Subdomains        []string    `json:"subdomains"`
	Endpoints         []string    `json:"endpoints"`
	Parameters        []string    `json:"parameters"`
	JSFiles           []JSFinding `json:"js_files_with_findings"`
	APIs              []string    `json:"api_discovery"`
	WAF               string      `json:"waf"`
	CORS              []string    `json:"cors_issues"`
	Technologies      []string    `json:"technologies"`
	RequestSmuggling  string      `json:"request_smuggling_status"`
}
