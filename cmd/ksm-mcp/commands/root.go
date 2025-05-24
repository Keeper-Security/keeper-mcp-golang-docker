package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	configFile string
	profile    string
	verbose    bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "ksm-mcp",
	Short: "KSM MCP Server",
	Long: `A secure Model Context Protocol (MCP) server for Keeper Secrets Manager (KSM).
	
This tool acts as a secure intermediary between AI agents and Keeper Secrets Manager,
preventing direct credential exposure while maintaining usability for AI-powered workflows.`,
	Version: version,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Configure cobra to use stderr for all output (important for MCP)
	rootCmd.SetOut(os.Stderr)
	rootCmd.SetErr(os.Stderr)
	
	// Global flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is ~/.keeper/ksm-mcp/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "", "profile to use (overrides config default)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")
}

// SetVersion sets the version for the CLI
func SetVersion(v string) {
	version = v
	rootCmd.Version = v
}

// verboseLog prints a message only if verbose mode is enabled
func verboseLog(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}
