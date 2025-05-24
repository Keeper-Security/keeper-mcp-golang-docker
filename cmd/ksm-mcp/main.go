package main

import (
	"os"

	"github.com/keeper-security/ksm-mcp/cmd/ksm-mcp/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}