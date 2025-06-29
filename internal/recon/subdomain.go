package recon

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/tidwall/gjson"
)

// passiveSource represents a function that can find subdomains.
type passiveSource func(ctx context.Context, client *http.Client, domain string, out chan<- string, verbose bool)

// EnumerateSubdomains orchestrates all live subdomain discovery methods.
func (e *Engine) EnumerateSubdomains(ctx context.Context) ([]string, error) {
	var wg sync.WaitGroup
	subdomainChan := make(chan string, 1000)

	sources := []passiveSource{
		getSubdomainsFromCrtSh,
		getSubdomainsFromOTX,
	}

	for _, sourceFunc := range sources {
		wg.Add(1)
		go func(f passiveSource) {
			defer wg.Done()
			f(ctx, e.httpClient, e.Options.Domain, subdomainChan, e.Options.Verbose)
		}(sourceFunc)
	}

	// AI-Assisted Expansion (remains the same)
	if e.Options.AiAssist && e.aiClient != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.generateSubdomainsWithAI(ctx, subdomainChan)
		}()
	}

	go func() {
		wg.Wait()
		close(subdomainChan)
	}()

	uniqueSubdomains := make(map[string]struct{})
	for sub := range subdomainChan {
		// Clean up potential wildcard prefixes
		cleanSub := strings.TrimPrefix(sub, "*.")
		if _, exists := uniqueSubdomains[cleanSub]; !exists {
			if e.Options.Verbose {
				color.Cyan("  [subdomain] Found: %s", cleanSub)
			}
			uniqueSubdomains[cleanSub] = struct{}{}
		}
	}

	var result []string
	for sub := range uniqueSubdomains {
		result = append(result, sub)
	}

	return result, nil
}

// getSubdomainsFromCrtSh performs a LIVE query to crt.sh
func getSubdomainsFromCrtSh(ctx context.Context, client *http.Client, domain string, out chan<- string, verbose bool) {
	if verbose { color.HiBlack("  [subdomain] Querying crt.sh...") }
	
	req, err := http.NewRequestWithContext(ctx, "GET", "https://crt.sh/?q=%25."+domain+"&output=json", nil)
	if err != nil { return }

	resp, err := client.Do(req)
	if err != nil { return }
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK { return }

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil { return }

	results := gjson.ParseBytes(bodyBytes)
	for _, record := range results.Array() {
		name := record.Get("name_value").String()
		// crt.sh sometimes returns multiple domains in one entry
		for _, d := range strings.Split(name, "\n") {
			if strings.HasSuffix(d, "."+domain) {
				out <- d
			}
		}
	}
}

// getSubdomainsFromOTX performs a LIVE query to AlienVault OTX
func getSubdomainsFromOTX(ctx context.Context, client *http.Client, domain string, out chan<- string, verbose bool) {
	if verbose { color.HiBlack("  [subdomain] Querying AlienVault OTX...") }

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil { return }

	resp, err := client.Do(req)
	if err != nil { return }
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK { return }
	
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil { return }

	results := gjson.Get(string(bodyBytes), "passive_dns.#.hostname")
	for _, hostname := range results.Array() {
		out <- hostname.String()
	}
}
