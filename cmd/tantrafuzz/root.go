package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Variables to hold the values from our flags
var (
	targetURL  string
	param      string
	vulnType   string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "tantrafuzz",
	Short: "TantraFuzz is an AI-powered offensive security framework.",
	Long: `A context-aware, technique-driven security tool that uses AI to 
evolve its attacks in real-time. It moves beyond simple "spray-and-pray" 
tactics towards a more intelligent, targeted approach.`,
	// This is the main action of our command
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔥 TantraFuzz Initializing 🔥")
		fmt.Println("--------------------------------")
		fmt.Printf("Target URL: %s\n", targetURL)
		fmt.Printf("Parameter to Fuzz: %s\n", param)
		fmt.Printf("Vulnerability Type: %s\n", vulnType)
		fmt.Println("--------------------------------")

		// Later, we will trigger the main application logic here.
		// For now, we are just confirming the flags are parsed correctly.
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Here we define our flags and bind them to the variables declared above.
	rootCmd.PersistentFlags().StringVarP(&targetURL, "url", "u", "", "The target URL to scan (required)")
	rootCmd.PersistentFlags().StringVarP(&param, "param", "p", "", "The specific parameter to fuzz")
	rootCmd.PersistentFlags().StringVarP(&vulnType, "vuln-type", "v", "", "Vulnerability type to test for (e.g., xss, sqli)")

	// Mark the 'url' flag as required
	rootCmd.MarkPersistentFlagRequired("url")
}
