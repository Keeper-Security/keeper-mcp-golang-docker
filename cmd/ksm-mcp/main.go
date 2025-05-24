package main

import (
	"os"

	"github.com/keeper-security/ksm-mcp/cmd/ksm-mcp/commands"
)

// Version is the current version of ksm-mcp
// This must match the git tag when creating releases
const Version = "v1.0.0"

func main() {
	// Set version for commands
	commands.SetVersion(Version)
	
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}