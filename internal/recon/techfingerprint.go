package recon

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/fatih/color"
)

type techSignature struct {
	Name    string
	Type    string
	Pattern string
}

var techSignaturesDB = []techSignature{
	{"Nginx", "header", "server: nginx"},
	{"Apache", "header", "server: Apache"},
	{"Cloudflare", "header", "server: cloudflare"},
	{"PHP", "header", "x-powered-by: PHP"},
	{"ASP.NET", "header", "x-aspnet-version:"},
	{"PHP Session", "cookie", "PHPSESSID"},
	{"Java Session", "cookie", "JSESSIONID"},
	{"WordPress", "body", "wp-content"},
	{"React", "body", "data-reactroot"},
	{"Angular", "body", "ng-version"},
}

func (e *Engine) FingerprintTechnologies(ctx context.Context, urls []string) ([]string, error) {
	if len(urls) == 0 {
		return []string{}, nil
	}

	var wg sync.WaitGroup
	detectedTech := &sync.Map{}
	concurrencyLimit := make(chan struct{}, e.Options.Concurrency)

	checkLimit := 5
	if len(urls) < checkLimit {
		checkLimit = len(urls)
	}

	for _, url := range urls[:checkLimit] {
		wg.Add(1)
		concurrencyLimit <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				return
			}

			if e.Options.Verbose {
				color.Cyan("  [tech] Probing: %s", u)
			}
			resp, err := e.httpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			headers := resp.Header
			cookies := resp.Cookies()
			bodyBytes, _ := io.ReadAll(resp.Body)
			body := string(bodyBytes)

			for _, sig := range techSignaturesDB {
				var found bool
				switch sig.Type {
				case "header":
					for hKey, hValues := range headers {
						headerLine := strings.ToLower(hKey) + ": " + strings.ToLower(strings.Join(hValues, ","))
						if strings.Contains(headerLine, strings.ToLower(sig.Pattern)) {
							found = true
						}
					}
				case "cookie":
					for _, c := range cookies {
						if strings.EqualFold(c.Name, sig.Pattern) {
							found = true
						}
					}
				case "body":
					if strings.Contains(body, sig.Pattern) {
						found = true
					}
				}
				if found {
					if _, loaded := detectedTech.LoadOrStore(sig.Name, struct{}{}); !loaded && e.Options.Verbose {
						color.Yellow("    -> Detected: %s", sig.Name)
					}
				}
			}
		}(url)
	}
	wg.Wait()

	var result []string
	detectedTech.Range(func(key, value interface{}) bool {
		result = append(result, key.(string))
		return true
	})

	return result, nil
}
