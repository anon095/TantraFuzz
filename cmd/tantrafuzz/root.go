package main

import (
	"fmt"
	"log"
	"os"

	"github.com/anon095/TantraFuzz/internal/payload" // Import our new payload package
	"github.com/spf13/cobra"
)

var (
	targetURL string
	param     string
	vulnType  string
)

var rootCmd = &cobra.Command{
	Use:   "tantrafuzz",
	Short: "TantraFuzz is an AI-powered offensive security framework.",
	Long: `A context-aware, technique-driven security tool that uses AI to 
evolve its attacks in real-time. It moves beyond simple "spray-and-pray" 
tactics towards a more intelligent, targeted approach.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔥 TantraFuzz Initializing 🔥")
		fmt.Println("--------------------------------")
		fmt.Printf("Target URL: %s\n", targetURL)
		fmt.Printf("Vulnerability Type: %s\n", vulnType)
		fmt.Println("--------------------------------")

		// Load payloads based on the vulnerability type flag
		payloads, err := payload.LoadPayloads(vulnType)
		if err != nil {
			log.Fatalf("💀 Error loading payloads: %v", err)
		}

		fmt.Printf("✅ Successfully loaded %d payloads for '%s'.\n\n", len(payloads), vulnType)

		// Print the details of each loaded payload
		for i, p := range payloads {
			fmt.Printf("--- Payload %d ---\n", i+1)
			fmt.Printf("Content: %s\n", p.Content)
			fmt.Printf("  Source: %s\n", p.Source)
			fmt.Printf("  Target: %s\n", p.Target)
			fmt.Printf("  Purpose: %s\n", p.Purpose)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&targetURL, "url", "u", "", "The target URL to scan (required)")
	rootCmd.PersistentFlags().StringVarP(&param, "param", "p", "", "The specific parameter to fuzz")
	rootCmd.PersistentFlags().StringVarP(&vulnType, "vuln-type", "v", "", "Vulnerability type to test for (e.g., xss, sqli)")
	rootCmd.MarkPersistentFlagRequired("url")
	rootCmd.MarkPersistentFlagRequired("vuln-type") // Making vuln-type required for this test
}
