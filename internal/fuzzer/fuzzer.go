package fuzzer

import (
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/anon095/TantraFuzz/internal/analyzer"
	"github.com/anon095/TantraFuzz/internal/payload"
)

// Fuzzer manages the concurrent fuzzing process.
type Fuzzer struct {
	BaseURL      string
	ParamToFuzz  string
	Payloads     []payload.Payload
	UserAgent    string
	Concurrency  int
	HTTPClient   *http.Client
	VulnType     string
}

// Job represents a single fuzzing task.
type Job struct {
	Payload payload.Payload
}

// Result holds the outcome of a single job.
// This is corrected to hold the entire AnalysisResult.
type Result struct {
	Analysis *analyzer.AnalysisResult
}

// NewFuzzer creates and configures a new fuzzer instance.
func NewFuzzer(baseURL, param, userAgent, vulnType string, payloads []payload.Payload, concurrency, timeoutSec int) *Fuzzer {
	return &Fuzzer{
		BaseURL:     baseURL,
		ParamToFuzz: param,
		Payloads:    payloads,
		UserAgent:   userAgent,
		Concurrency: concurrency,
		HTTPClient: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
		VulnType:    vulnType,
	}
}

// Start launches the fuzzer and returns the analysis results.
func (f *Fuzzer) Start() []*analyzer.AnalysisResult {
	log.Printf("🚀 Fuzzer Chakra activated. Beginning attack sequence with %d workers...", f.Concurrency)

	jobs := make(chan Job, len(f.Payloads))
	results := make(chan Result, len(f.Payloads))
	var analysisResults []*analyzer.AnalysisResult

	var wg sync.WaitGroup

	for i := 0; i < f.Concurrency; i++ {
		wg.Add(1)
		go f.worker(&wg, jobs, results)
	}

	for _, p := range f.Payloads {
		jobs <- Job{Payload: p}
	}
	close(jobs)

	wg.Wait()
	close(results)

	for res := range results {
		if res.Analysis != nil {
			analysisResults = append(analysisResults, res.Analysis)
		}
	}

	return analysisResults
}

func (f *Fuzzer) worker(wg *sync.WaitGroup, jobs <-chan Job, results chan<- Result) {
	defer wg.Done()
	for job := range jobs {
		targetURL, err := url.Parse(f.BaseURL)
		if err != nil {
			log.Printf("💀 Invalid base URL %s: %v", f.BaseURL, err)
			continue
		}

		queryParams := targetURL.Query()
		queryParams.Set(f.ParamToFuzz, job.Payload.Content)
		targetURL.RawQuery = queryParams.Encode()

		req, err := http.NewRequest("GET", targetURL.String(), nil)
		if err != nil {
			log.Printf("💀 Failed to create request for payload '%s': %v", job.Payload.Content, err)
			continue
		}
		req.Header.Set("User-Agent", f.UserAgent)

		resp, err := f.HTTPClient.Do(req)
		if err != nil {
			log.Printf("💀 Request failed for payload '%s': %v", job.Payload.Content, err)
			continue
		}

		// Corrected call to AnalyzeResponse with two arguments
		analysis, err := analyzer.AnalyzeResponse(resp, job.Payload.Content)
		if err != nil {
			log.Printf("💀 Error analyzing response for payload '%s': %v", job.Payload.Content, err)
		}
		resp.Body.Close()

		// Corrected assignment to the Result struct
		results <- Result{Analysis: analysis}
	}
}
