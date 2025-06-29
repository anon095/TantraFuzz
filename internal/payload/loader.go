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
func LoadPayloads(vulnType string) ([]Payload, error) {
	var payloadFile string
	// This mapping can be expanded or made dynamic.
	switch vulnType {
	case "sqli":
		payloadFile = "payloads/sqli/union_based/payloads.txt"
	case "xss":
		// Example for future expansion
		payloadFile = "payloads/xss/html_injection/payloads.txt"
	default:
		return nil, fmt.Errorf("unknown or unsupported vulnerability type: %s", vulnType)
	}

	cleanPath := filepath.Clean(payloadFile)
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("payload file does not exist: %s. Please populate it", cleanPath)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open payload file: %w", err)
	}
	defer file.Close()

	var payloads []Payload
	scanner := bufio.NewScanner(file)
	
	var currentSource, currentTarget, currentPurpose string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			parts := strings.SplitN(strings.TrimSpace(line[1:]), ":", 2)
			if len(parts) == 2 {
				key, value := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
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

		p := Payload{
			Content: line,
			Source:  currentSource,
			Target:  currentTarget,
			Purpose: currentPurpose,
		}
		payloads = append(payloads, p)
		currentSource, currentTarget, currentPurpose = "", "", "" // Reset for next block
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning payload file: %w", err)
	}
	return payloads, nil
}
