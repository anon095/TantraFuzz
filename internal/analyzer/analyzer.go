package analyzer

import (
	"io"
	"net/http"
	"strings"
)

// Finding represents a confirmed vulnerability.
type Finding struct {
	Payload  string
	Evidence string
}

// AnalysisResult provides detailed feedback on an HTTP response.
type AnalysisResult struct {
	Finding           *Finding
	IsBlocked         bool
	BlockReason       string
	IsReflected       bool
	ReflectionContext string // e.g., "HTML", "JSON", "HTML_ATTRIBUTE"
}

// Common WAF block signatures
var wafBlockSignatures = map[string]string{
	"Cloudflare": "Attention Required! | Cloudflare",
	"Incapsula":  "Powered by Incapsula",
	"Akamai":     "AkamaiGHost",
	"AWS WAF":    "awselb",
	"Sucuri":     "Sucuri/Cloudproxy",
}

// Common SQL error patterns
var sqlErrorPatterns = []string{
	"you have an error in your sql syntax",
	"unclosed quotation mark",
	"supplied argument is not a valid mysql result resource",
}

// AnalyzeResponse performs a deep analysis of an HTTP response.
func AnalyzeResponse(resp *http.Response, payloadContent string) (*AnalysisResult, error) {
	result := &AnalysisResult{}
	
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyString := string(bodyBytes)
	headers := resp.Header

	// 1. Check for WAF blocks first (from headers and body)
	for name, pattern := range wafBlockSignatures {
		if strings.Contains(bodyString, pattern) || strings.Contains(headers.Get("Server"), pattern) {
			result.IsBlocked = true
			result.BlockReason = "Request blocked by " + name
			return result, nil
		}
	}
	// Also check for generic blocking status codes
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
		result.IsBlocked = true
		result.BlockReason = "Request blocked with status code " + resp.Status
		return result, nil
	}

	// 2. If not blocked, check for successful vulnerability evidence (e.g., SQLi)
	for _, pattern := range sqlErrorPatterns {
		if strings.Contains(bodyString, pattern) {
			result.Finding = &Finding{
				Payload:  payloadContent,
				Evidence: "SQL Error: " + pattern,
			}
			return result, nil // Found a vulnerability, analysis complete.
		}
	}

	// 3. If no vulnerability found, check for payload reflection
	if strings.Contains(bodyString, payloadContent) {
		result.IsReflected = true
		// Simple context detection. This can be made much more advanced.
		if strings.HasPrefix(strings.TrimSpace(resp.Header.Get("Content-Type")), "application/json") {
			result.ReflectionContext = "JSON"
		} else {
			result.ReflectionContext = "HTML"
		}
	}

	return result, nil
}
