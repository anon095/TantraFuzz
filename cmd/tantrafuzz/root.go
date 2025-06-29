package main

import (
	"log"
	"os"

	"github.com/anon095/TantraFuzz/internal/analyzer"
	"github.com/anon095/TantraFuzz/internal/api"
	ctx "github.com/anon095/TantraFuzz/internal/context"
	"github.com/anon095/TantraFuzz/internal/fuzzer"
	"github.com/anon095/TantraFuzz/internal/mutation"
	"github.com/anon095/TantraFuzz/internal/payload"
	"github.com/spf13/cobra"
)

var (
	reconFile      string
	aiMutate       bool
	vulnType       string
)

var rootCmd = &cobra.Command{
	Use:   "tantrafuzz",
	Short: "A recon-driven, AI-powered, adaptive fuzzing engine.",
	Long: `TantraFuzz uses reconnaissance data to craft context-aware payloads,
then enters a recursive AI-mutation loop to bypass defenses in real-time.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("🔥 TantraFuzz Fuzzer Initializing 🔥")

		log.Printf("Ingesting recon data from: %s", reconFile)
		targetCtx, err := ctx.LoadContextFromFile(reconFile)
		if err != nil {
			log.Fatalf("💀 Failed to load recon file: %v", err)
		}
		log.Printf("✅ Context loaded for domain '%s'. WAF: %s.", targetCtx.Domain, targetCtx.WAF)

		initialPayloads, err := payload.LoadPayloads(vulnType)
		if err != nil {
			log.Fatalf("💀 Failed to load payloads for vuln-type '%s': %v", vulnType, err)
		}

		var mutator *mutation.Mutator
		if aiMutate {
			apiKey := os.Getenv("GEMINI_API_KEY")
			if apiKey == "" {
				log.Fatal("💀 --ai-mutate flag requires GEMINI_API_KEY environment variable to be set.")
			}
			apiClient := api.NewClient(apiKey)
			mutator = mutation.NewMutator(apiClient)
		}

		for _, endpoint := range targetCtx.Endpoints {
			for _, param := range targetCtx.Parameters {
				log.Printf("🎯 Targeting endpoint: %s with parameter: %s", endpoint, param)

				fuzz := fuzzer.NewFuzzer(endpoint, param, "TantraFuzz/1.0", vulnType, initialPayloads, 20, 10)
				analysisResults := fuzz.Start()

				found := false
				var lastFailedResult *analyzer.AnalysisResult
				// Corrected loop to handle the new result structure
				for _, result := range analysisResults {
					if result.Finding != nil {
						log.Printf("🎉 VULNERABILITY FOUND: %s", result.Finding.Evidence)
						found = true
						break
					}
					lastFailedResult = result
				}

				if found {
					continue
				}

				if aiMutate && lastFailedResult != nil {
					log.Printf("Initial scan failed. Invoking AI with last result: Blocked=%t, Reflected=%t in %s context.", lastFailedResult.IsBlocked, lastFailedResult.IsReflected, lastFailedResult.ReflectionContext)
					
					mutatedPayload, err := mutator.MutateWithAI(initialPayloads[0], targetCtx, lastFailedResult)
					if err != nil {
						log.Printf("💀 AI mutation failed: %v", err)
						continue
					}
					
					log.Println("🚀 Re-running scan with single AI-generated payload...")
					aiFuzzer := fuzzer.NewFuzzer(endpoint, param, "TantraFuzz/1.0", vulnType, []payload.Payload{*mutatedPayload}, 1, 10)
					aiAnalysisResults := aiFuzzer.Start()

					for _, result := range aiAnalysisResults {
						if result.Finding != nil {
							log.Printf("🎉 VULNERABILITY FOUND WITH AI-MUTATED PAYLOAD: %s", result.Finding.Evidence)
							found = true
							break
						}
					}
				}
			}
		}
		log.Println("✨ Fuzzing cycle complete.")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&reconFile, "recon-file", "", "Path to the JSON output from the TantraFuzz-Recon engine (required)")
	rootCmd.Flags().StringVarP(&vulnType, "vuln-type", "v", "sqli", "Vulnerability type to test for (e.g., sqli, xss)")
	rootCmd.Flags().BoolVar(&aiMutate, "ai-mutate", false, "Enable AI-driven payload mutation if initial scan fails")
	rootCmd.MarkFlagRequired("recon-file")
}
