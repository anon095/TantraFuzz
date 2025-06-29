package main

import (
	"fmt"
	"log"
	"os"

	"github.com/anon095/TantraFuzz/internal/fuzzer"  // Import the fuzzer
	"github.com/anon095/TantraFuzz/internal/payload" // Import our payload package
	"github.com/spf13/cobra"
)

var (
	targetURL  string
	param      string
	vulnType   string
	configFile string
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
		fmt.Printf("Parameter:  %s\n", param)
		fmt.Printf("Vuln Type:  %s\n", vulnType)
		fmt.Println("--------------------------------")

		// For now, we are not using the main config loader from previous steps
		// to keep this step focused. We'll add it back later.
		// A default user agent is used in the fuzzer.

		// 1. Load payloads
		payloads, err := payload.LoadPayloads(vulnType)
		if err != nil {
			log.Fatalf("💀 Error loading payloads: %v", err)
		}
		log.Printf("✅ Successfully loaded %d payloads for '%s'.", len(payloads), vulnType)

		// 2. Start the fuzzer
		// We'll pass a default User-Agent for now.
		fuzzer.Start(targetURL, param, payloads, "TantraFuzz/0.2")
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
	rootCmd.PersistentFlags().StringVarP(&param, "param", "p", "", "The specific parameter to fuzz (required)")
	rootCmd.PersistentFlags().StringVarP(&vulnType, "vuln-type", "v", "", "Vulnerability type to test for (e.g., xss, sqli) (required)")
	
	rootCmd.MarkPersistentFlagRequired("url")
	rootCmd.MarkPersistentFlagRequired("param")
	rootCmd.MarkPersistentFlagRequired("vuln-type")
}
