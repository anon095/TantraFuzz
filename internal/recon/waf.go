package recon

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/fatih/color"
)

type wafSignature struct {
	Name    string
	Type    string
	Pattern string
}

var wafSignaturesDB = []wafSignature{
	{"Cloudflare", "header", "server: cloudflare"},
	{"Cloudflare", "body", "Attention Required! | Cloudflare"},
	{"Akamai", "header", "x-akamai-transformed"},
	{"Sucuri", "header", "x-sucuri-id"},
	{"Imperva", "body", "Powered by Incapsula"},
	{"AWS WAF", "header", "awselb"},
}

func (e *Engine) FingerprintWAF(ctx context.Context) (string, error) {
	probeURL := "https://" + e.Options.Domain + "/?id=<script>alert(1)</script>"

	req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", e.Options.UserAgent)

	if e.Options.Verbose {
		color.Cyan("  [waf] Sending WAF detection probe to %s...", e.Options.Domain)
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "Unknown (Probe Failed)", err
	}
	defer resp.Body.Close()

	headers := resp.Header
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if resp.StatusCode == 403 || resp.StatusCode == 406 {
		if e.Options.Verbose {
			color.Yellow("    -> WAF Hint: Received a blocking status code %s", resp.Status)
		}
	}

	for _, sig := range wafSignaturesDB {
		var detected bool
		switch sig.Type {
		case "header":
			for hKey, hValues := range headers {
				headerLine := strings.ToLower(hKey) + ": " + strings.ToLower(strings.Join(hValues, ","))
				if strings.Contains(headerLine, strings.ToLower(sig.Pattern)) {
					detected = true
				}
			}
		case "body":
			if strings.Contains(body, sig.Pattern) {
				detected = true
			}
		}
		if detected {
			return sig.Name, nil
		}
	}

	return "Not Detected", nil
}
