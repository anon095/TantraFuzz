package recon

import (
	"context"
	"net/url"

	"github.com/fatih/color"
)

func (e *Engine) DiscoverParameters(ctx context.Context, endpoints []string) ([]string, error) {
	uniqueParams := make(map[string]struct{})

	for _, endpoint := range endpoints {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		parsedURL, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		for paramName := range parsedURL.Query() {
			if _, exists := uniqueParams[paramName]; !exists {
				if e.Options.Verbose {
					color.Cyan("  [param] Discovered parameter: %s", paramName)
				}
				uniqueParams[paramName] = struct{}{}
			}
		}
	}

	var result []string
	for param := range uniqueParams {
		result = append(result, param)
	}
	return result, nil
}
