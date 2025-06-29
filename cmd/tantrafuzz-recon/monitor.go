package main

import (
	"context"
	"log"

	"github.com/anon095/TantraFuzz/internal/recon"
	"github.com/anon095/TantraFuzz/internal/storage"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Run in persistent, real-time monitoring mode for a domain.",
	Long:  `Connects to real-time Certificate Transparency Logs and watches for newly created subdomains for the target domain.`,
	Run: func(cmd *cobra.Command, args []string) {
		store, err := storage.NewStore(dbPath)
		if err != nil {
			log.Fatalf("💀 Failed to initialize database: %v", err)
		}
		defer store.Close()
		color.Cyan("💾 Database initialized at: %s", dbPath)

		opts.UserAgent = "TantraFuzz-Recon/1.3-Monitor"
		engine := recon.NewEngine(&opts, nil, store) // Monitor doesn't need AI
		
		engine.StartMonitoring(context.Background())
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
