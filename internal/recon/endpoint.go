package recon

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// EnumerateEndpoints orchestrates the discovery of URLs from live sources.
func (e *Engine) EnumerateEndpoints(ctx context.Context, subdomains []string) ([]string, error) {
	var wg sync.WaitGroup
	endpointChan := make(chan string, 5000)
	// Use a worker pool to avoid overwhelming the target or external APIs
	concurrencyLimit := make(chan struct{}, e.Options.Concurrency)

	for _, domain := range subdomains {
		wg.Add(1)
		concurrencyLimit <- struct{}{} // Acquire a slot in the pool

		go func(d string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }() // Release the slot
			getEndpointsFromWayback(ctx, e.httpClient, d, endpointChan, e.Options.Verbose)
		}(domain)
	}

	go func() {
		wg.Wait()
		close(endpointChan)
	}()

	uniqueEndpoints := make(map[string]struct{})
	for endpoint := range endpointChan {
		uniqueEndpoints[endpoint] = struct{}{}
	}

	var result []string
	for endpoint := range uniqueEndpoints {
		result = append(result, endpoint)
	}

	return result, nil
}

// getEndpointsFromWayback performs a LIVE query to the Wayback Machine CDX API.
func getEndpointsFromWayback(ctx context.Context, client *http.Client, domain string, out chan<- string, verbose bool) {
	if verbose {
		color.HiBlack("  [endpoint] Querying Wayback Machine for %s...", domain)
	}

	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			if verbose {
				color.Cyan("  [endpoint] Found: %s", line)
			}
			out <- line
		}
	}
}
