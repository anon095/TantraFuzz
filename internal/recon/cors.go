package recon

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/fatih/color"
)

const maliciousOrigin = "https://evil.com"

func (e *Engine) CheckCORS(ctx context.Context, endpoints []string) ([]string, error) {
	var vulnerableEndpoints []string
	hostsChecked := make(map[string]struct{})
	var wg sync.WaitGroup
	resultsChan := make(chan string, len(endpoints))
	concurrencyLimit := make(chan struct{}, e.Options.Concurrency)

	for _, endpoint := range endpoints {
		reqURL, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			continue
		}
		host := fmt.Sprintf("%s://%s", reqURL.URL.Scheme, reqURL.URL.Host)
		if _, exists := hostsChecked[host]; exists {
			continue
		}
		hostsChecked[host] = struct{}{}

		wg.Add(1)
		concurrencyLimit <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()
			if e.Options.Verbose {
				color.Cyan("  [cors] Probing: %s", u)
			}
			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("Origin", maliciousOrigin)
			req.Header.Set("User-Agent", e.Options.UserAgent)
			resp, err := e.httpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			acaoHeader := resp.Header.Get("Access-Control-Allow-Origin")
			if acaoHeader == maliciousOrigin || acaoHeader == "*" {
				finding := fmt.Sprintf("VULNERABLE: [%s] - Responded with ACAO header: %s", u, acaoHeader)
				if e.Options.Verbose {
					color.Yellow("    -> VULNERABLE: %s reflected origin!", u)
				}
				resultsChan <- finding
			}
		}(host)
	}
	wg.Wait()
	close(resultsChan)
	for res := range resultsChan {
		vulnerableEndpoints = append(vulnerableEndpoints, res)
	}
	return vulnerableEndpoints, nil
}
