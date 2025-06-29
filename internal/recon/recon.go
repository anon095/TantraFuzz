package recon

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/anon095/TantraFuzz/internal/api"
	"github.com/anon095/TantraFuzz/internal/model"
	"github.com/anon095/TantraFuzz/internal/storage"
	"github.com/fatih/color"
)

// Options defines the configuration for a recon scan.
type Options struct {
	Domain           string
	Concurrency      int
	Timeout          int
	UserAgent        string
	AiAssist         bool
	DeepJS           bool
	SmugglingCheck   bool
	Verbose          bool
}

// Engine is the main orchestrator for all reconnaissance activities.
type Engine struct {
	Options    *Options
	Result     *model.ReconResult
	aiClient   *api.Client
	httpClient *http.Client
	Store      *storage.Store
}

// NewEngine creates a new reconnaissance engine.
func NewEngine(opts *Options, aiClient *api.Client, store *storage.Store) *Engine {
	return &Engine{
		Options: opts,
		Result: &model.ReconResult{
			Timestamp:    time.Now().UTC(),
			Domain:       opts.Domain,
			Subdomains:   []string{},
			Endpoints:    []string{},
			Parameters:   []string{},
			JSFiles:      []model.JSFinding{},
			APIs:         []string{},
			CORS:         []string{},
			Technologies: []string{},
		},
		aiClient: aiClient,
		httpClient: &http.Client{
			Timeout: time.Duration(opts.Timeout) * time.Second,
		},
		Store: store,
	}
}

// Start begins the full reconnaissance process with live data sources.
func (e *Engine) Start(ctx context.Context) {
	previousResult, _ := e.Store.GetPreviousResult(e.Options.Domain)

	// --- Phase 1: Subdomain Enumeration ---
	log.Println("🔎 Starting Subdomain Enumeration (Live)...")
	subs, _ := e.EnumerateSubdomains(ctx)
	e.Result.Subdomains = subs
	color.Green("✅ Found %d unique subdomains.", len(subs))

	// --- Phase 2: Endpoint Harvesting ---
	if len(e.Result.Subdomains) > 0 {
		log.Println("📡 Starting Endpoint Harvesting (Live)...")
		endpoints, _ := e.EnumerateEndpoints(ctx, e.Result.Subdomains)
		e.Result.Endpoints = endpoints
		color.Green("✅ Found %d unique endpoints.", len(endpoints))
	} else {
		log.Println("⚠️ No subdomains found, skipping endpoint harvesting and further analysis.")
		return
	}

	// --- Phase 3: Parallel Intelligence Gathering on Discovered Assets ---
	var intelligenceWG sync.WaitGroup
	if len(e.Result.Endpoints) > 0 {
		intelligenceWG.Add(1)
		go func() {
			defer intelligenceWG.Done()
			log.Println("🔎 Fingerprinting Technologies...")
			tech, _ := e.FingerprintTechnologies(ctx, e.Result.Endpoints)
			e.Result.Technologies = tech
			color.Green("✅ Detected Technologies: %v", tech)
		}()

		intelligenceWG.Add(1)
		go func() {
			defer intelligenceWG.Done()
			log.Println("🛡️  Probing for WAF...")
			waf, _ := e.FingerprintWAF(ctx)
			e.Result.WAF = waf
			color.Green("✅ WAF Detection Result: %s", waf)
		}()

		intelligenceWG.Add(1)
		go func() {
			defer intelligenceWG.Done()
			log.Println("🔑 Discovering Parameters...")
			params, _ := e.DiscoverParameters(ctx, e.Result.Endpoints)
			e.Result.Parameters = params
			color.Green("✅ Found %d unique parameters.", len(params))
		}()
		
		if e.Options.DeepJS {
			intelligenceWG.Add(1)
			go func() {
				defer intelligenceWG.Done()
				log.Println("💎 Mining JavaScript Files...")
				jsFindings, _ := e.MineJavaScript(ctx, e.Result.Endpoints)
				e.Result.JSFiles = jsFindings
				for _, finding := range jsFindings {
					e.Result.APIs = append(e.Result.APIs, finding.Endpoints...)
				}
				color.Green("✅ JavaScript Mining found %d files with interesting content.", len(jsFindings))
			}()
		}
	}
	intelligenceWG.Wait()
	log.Println("✨ Reconnaissance cycle complete.")

	// --- Phase 4: Final Report and Save ---
	if previousResult != nil {
		color.Cyan("--- Change Detection Report ---")
		newSubdomains := diffStringSlices(previousResult.Subdomains, e.Result.Subdomains)
		if len(newSubdomains) > 0 {
			color.Yellow("🚀 Found %d new subdomains: %v", len(newSubdomains), newSubdomains)
		} else {
			log.Println("No new subdomains found.")
		}
		color.Cyan("-----------------------------")
	}

	if err := e.Store.SaveResult(e.Result); err != nil {
		log.Printf("💀 Failed to save results to database: %v", err)
	} else {
		log.Println("💾 Current state saved to database for future comparison.")
	}
}

// SaveOutput saves the aggregated results to a file.
func (e *Engine) SaveOutput(filename string) error {
	log.Printf("💾 Saving results to %s...", filename)
	file, err := json.MarshalIndent(e.Result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, file, 0644)
}

func diffStringSlices(old, neu []string) []string {
	oldSet := make(map[string]struct{})
	for _, s := range old {
		oldSet[s] = struct{}{}
	}
	var diff []string
	for _, s := range neu {
		if _, found := oldSet[s]; !found {
			diff = append(diff, s)
		}
	}
	return diff
}
