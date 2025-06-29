package payload

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Payload represents a single attack string and its associated metadata.
type Payload struct {
	Content string
	Source  string
	Target  string
	Purpose string
}

// LoadPayloads reads a payload file based on vulnerability type and parses it.
// Note: This is a simplified loader. A real implementation would scan all files
// in the directory for a given vulnerability type.
func LoadPayloads(vulnType string) ([]Payload, error) {
	// For now, we use a simple mapping. This can be made more dynamic later.
	var payloadFile string
	switch vulnType {
	case "sqli":
		payloadFile = "payloads/sqli/union_based/payloads.txt"
	case "xss":
		// We would point to an xss file here, e.g., "payloads/xss/html_injection/payloads.txt"
		return nil, fmt.Errorf("payloads for '%s' are not yet implemented", vulnType)
	default:
		return nil, fmt.Errorf("unknown vulnerability type: %s", vulnType)
	}

	if _, err := os.Stat(payloadFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("payload file does not exist: %s. Please populate it", payloadFile)
	}

	file, err := os.Open(filepath.Clean(payloadFile))
	if err != nil {
		return nil, fmt.Errorf("failed to open payload file: %w", err)
	}
	defer file.Close()

	var payloads []Payload
	scanner := bufio.NewScanner(file)
	
	// Temporary variables to hold metadata for the next payload
	var currentSource, currentTarget, currentPurpose string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue // Skip empty lines
		}

		// Check for metadata comments
		if strings.HasPrefix(line, "#") {
			parts := strings.SplitN(strings.TrimSpace(line[1:]), ":", 2)
			if len(parts) == 2 {
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				value := strings.TrimSpace(parts[1])

				switch key {
				case "source":
					currentSource = value
				case "target":
					currentTarget = value
				case "purpose":
					currentPurpose = value
				}
			}
			continue
		}

		// If it's not a comment, it's a payload.
		// We assign the collected metadata to it and then reset the metadata.
		p := Payload{
			Content: line,
			Source:  currentSource,
			Target:  currentTarget,
			Purpose: currentPurpose,
		}
		payloads = append(payloads, p)

		// Reset metadata for the next payload block
		currentSource, currentTarget, currentPurpose = "", "", ""
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning payload file: %w", err)
	}

	return payloads, nil
}
