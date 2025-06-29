package analyzer

import (
	"io"
	"net/http"
	"strings"
)

// Finding represents a potential vulnerability that has been discovered.
type Finding struct {
	Payload  string
	Evidence string // The string that was found in the response (e.g., the SQL error)
}

// sqlErrorPatterns is a list of common database error messages.
var sqlErrorPatterns = []string{
	"you have an error in your sql syntax",
	"unclosed quotation mark",
	"supplied argument is not a valid mysql result resource",
	"microsoft ole db provider for odbc drivers",
	"invalid input syntax for type", // PostgreSQL
	"ora-01756",                      // Oracle
	"unclosed-quote",
	"sql error",
	"procedure syntax error",
}

// analyzeForSQLi inspects the response body for SQL error patterns.
func analyzeForSQLi(body, payloadContent string) *Finding {
	bodyLower := strings.ToLower(body)
	for _, pattern := range sqlErrorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return &Finding{
				Payload:  payloadContent,
				Evidence: pattern,
			}
		}
	}
	return nil
}

// AnalyzeResponse is the main entry point for the analyzer.
// It dispatches to the correct analysis function based on vulnerability type.
func AnalyzeResponse(resp *http.Response, vulnType, payloadContent string) (*Finding, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyString := string(bodyBytes)

	switch strings.ToLower(vulnType) {
	case "sqli":
		return analyzeForSQLi(bodyString, payloadContent), nil
	case "xss":
		// Future implementation for XSS analysis would go here.
		// For example, checking if the payload string is reflected in the response.
		return nil, nil
	default:
		// No analysis for this type yet
		return nil, nil
	}
}
