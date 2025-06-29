package fuzzer

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/anon095/TantraFuzz/internal/payload"
)

// Start begins the fuzzing process.
// It takes the base URL, the parameter to fuzz, and the loaded payloads.
func Start(baseURL, paramToFuzz string, payloads []payload.Payload, userAgent string) {
	log.Println("🚀 Fuzzer Chakra activated. Beginning attack sequence...")

	// Create a reusable HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, p := range payloads {
		// 1. Construct the target URL with the payload
		targetURL, err := url.Parse(baseURL)
		if err != nil {
			log.Printf("💀 Invalid base URL %s: %v", baseURL, err)
			continue // Skip to the next payload
		}

		// Add the payload as a query parameter
		queryParams := targetURL.Query()
		queryParams.Set(paramToFuzz, p.Content)
		targetURL.RawQuery = queryParams.Encode()

		// 2. Create the HTTP GET request
		req, err := http.NewRequest("GET", targetURL.String(), nil)
		if err != nil {
			log.Printf("💀 Failed to create request for payload '%s': %v", p.Content, err)
			continue
		}

		// Set the User-Agent from our config
		req.Header.Set("User-Agent", userAgent)

		// 3. Send the request and get the response
		fmt.Printf("✨ Sending payload: %s\n", p.Content)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("💀 Request failed for payload '%s': %v", p.Content, err)
			continue
		}
		defer resp.Body.Close()

		// 4. Report the result (for now, just the status code)
		log.Printf("✅ Response for payload '%s': [%s]", p.Content, resp.Status)
	}
}
