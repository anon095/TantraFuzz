package fuzzer

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/anon095/TantraFuzz/internal/analyzer" // Import the analyzer
	"github.com/anon095/TantraFuzz/internal/payload"
)

// Start begins the fuzzing process.
func Start(baseURL, paramToFuzz string, payloads []payload.Payload, userAgent string) {
	log.Println("🚀 Fuzzer Chakra activated. Beginning attack sequence...")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, p := range payloads {
		targetURL, err := url.Parse(baseURL)
		if err != nil {
			log.Printf("💀 Invalid base URL %s: %v", baseURL, err)
			continue
		}

		queryParams := targetURL.Query()
		queryParams.Set(paramToFuzz, p.Content)
		targetURL.RawQuery = queryParams.Encode()

		req, err := http.NewRequest("GET", targetURL.String(), nil)
		if err != nil {
			log.Printf("💀 Failed to create request for payload '%s': %v", p.Content, err)
			continue
		}
		req.Header.Set("User-Agent", userAgent)

		fmt.Printf("✨ Sending payload: %s\n", p.Content)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("💀 Request failed for payload '%s': %v", p.Content, err)
			continue
		}

		// *** NEW: Pass the response to the Analyzer ***
		finding, err := analyzer.AnalyzeResponse(resp, "sqli", p.Content)
		if err != nil {
			log.Printf("💀 Error analyzing response: %v", err)
		}

		// Close the body after analysis is complete
		resp.Body.Close()

		if finding != nil {
			// A potential vulnerability was found!
			fmt.Println("=====================================================")
			fmt.Println("🚨🚨🚨 POTENTIAL VULNERABILITY FOUND! 🚨🚨🚨")
			fmt.Printf("  Payload:  %s\n", finding.Payload)
			fmt.Printf("  Evidence: Found matching pattern '%s'\n", finding.Evidence)
			fmt.Println("=====================================================")
		} else {
			// Report the normal status if nothing was found
			log.Printf("✅ Response for payload '%s': [%s] (No findings)", p.Content, resp.Status)
		}
	}
}
