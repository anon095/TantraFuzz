package recon

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/anon095/TantraFuzz/internal/model"
)

var secretRegexDB = map[string]*regexp.Regexp{
	"Google API Key":    regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"Firebase API Key":  regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"AWS Access Key ID": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"Generic API Key":   regexp.MustCompile(`(?i)(api_key|apikey|api-key)\s*[:=]\s*['"]([a-zA-Z0-9-_]+)['"]`),
	"JWT Token":         regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`),
}

var endpointRegex = regexp.MustCompile(`['"](/api/|/v[1-9]/|/graphql|/users|/auth)[^'"]*['"]`)

func (e *Engine) MineJavaScript(ctx context.Context, endpoints []string) ([]model.JSFinding, error) {
	var jsFiles []string
	for _, endpoint := range endpoints {
		if strings.HasSuffix(endpoint, ".js") {
			jsFiles = append(jsFiles, endpoint)
		}
	}
	if len(jsFiles) == 0 {
		return []model.JSFinding{}, nil
	}

	var wg sync.WaitGroup
	findingsChan := make(chan model.JSFinding, len(jsFiles))
	concurrencyLimit := make(chan struct{}, e.Options.Concurrency)

	for _, jsURL := range jsFiles {
		wg.Add(1)
		concurrencyLimit <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil { return }
			req.Header.Set("User-Agent", e.Options.UserAgent)
			
			if e.Options.Verbose { color.Cyan("  [js] Analyzing: %s", u) }
			resp, err := e.httpClient.Do(req)
			if err != nil { return }
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK { return }
			
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil { return }
			body := string(bodyBytes)

			foundSecrets := []string{}
			foundEndpoints := []string{}
			
			for name, re := range secretRegexDB {
				matches := re.FindAllString(body, -1)
				if len(matches) > 0 {
					if e.Options.Verbose { color.Yellow("    -> Secret hint '%s' found in %s", name, u) }
					foundSecrets = append(foundSecrets, matches...)
				}
			}
			matches := endpointRegex.FindAllString(body, -1)
			if len(matches) > 0 {
				if e.Options.Verbose { color.Yellow("    -> Endpoint hint found in %s", u) }
				for _, match := range matches {
					foundEndpoints = append(foundEndpoints, strings.Trim(match, `'" `))
				}
			}
			
			if len(foundSecrets) > 0 || len(foundEndpoints) > 0 {
				findingsChan <- model.JSFinding{
					FileURL: u, Secrets: foundSecrets, Endpoints: foundEndpoints,
				}
			}
		}(jsURL)
	}
	wg.Wait()
	close(findingsChan)

	var allFindings []model.JSFinding
	for f := range findingsChan {
		allFindings = append(allFindings, f)
	}
	return allFindings, nil
}
