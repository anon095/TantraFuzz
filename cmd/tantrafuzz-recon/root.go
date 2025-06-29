package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/anon095/TantraFuzz/internal/api"
	"github.com/anon095/TantraFuzz/internal/recon"
	"github.com/anon095/TantraFuzz/internal/storage"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	opts   recon.Options
	output string
	dbPath string
)

var rootCmd = &cobra.Command{
	Use:   "tantrafuzz-recon",
	Short: "A supreme-level, AI-powered reconnaissance engine.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		printBanner()
	},
	Run: func(cmd *cobra.Command, args []string) {
		runScan(cmd.Context())
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Persistent flags are available to the root command and all sub-commands
	rootCmd.PersistentFlags().StringVarP(&opts.Domain, "domain", "d", "", "The target domain to scan (required)")
	rootCmd.PersistentFlags().StringVar(&dbPath, "db-path", "./recon_db", "Path to the persistent database directory")
	rootCmd.PersistentFlags().IntVarP(&opts.Concurrency, "threads", "t", 50, "Number of concurrent threads")
	rootCmd.PersistentFlags().BoolVar(&opts.AiAssist, "ai-assist", false, "Enable AI-assisted subdomain generation")
	rootCmd.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "Enable verbose real-time output")

	// Local flags are only for the root 'scan' command
	rootCmd.Flags().StringVarP(&output, "output", "o", "recon_results.json", "Output file for scan results (JSON)")
	rootCmd.Flags().BoolVar(&opts.DeepJS, "deep-js", false, "Enable in-depth JavaScript file analysis")
	
	rootCmd.MarkPersistentFlagRequired("domain")
}

func runScan(ctx context.Context) {
	store, err := storage.NewStore(dbPath)
	if err != nil {
		log.Fatalf("💀 Failed to initialize database: %v", err)
	}
	defer store.Close()
	color.Cyan("💾 Database initialized at: %s", dbPath)

	var aiClient *api.Client
	if opts.AiAssist {
		apiKey := os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			log.Fatal("💀 --ai-assist flag requires GEMINI_API_KEY environment variable to be set.")
		}
		aiClient = api.NewClient(apiKey)
	}

	opts.Timeout = 15 // Default timeout for individual HTTP requests
	opts.UserAgent = "TantraFuzz-Recon/1.3-Audit"

	engine := recon.NewEngine(&opts, aiClient, store)
	engine.Start(ctx)

	if err := engine.SaveOutput(output); err != nil {
		log.Fatalf("💀 Failed to save output file: %v", err)
	}
}
