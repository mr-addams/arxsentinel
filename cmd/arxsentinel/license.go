package main

import (
	_ "embed"
	"fmt"
	"os"
)

//go:embed LICENSE
var licenseText string

// runLicenseSubcommand prints the full license text and exits.
// Triggered by: arxsentinel license
func runLicenseSubcommand() {
	fmt.Print(licenseText)
	os.Exit(0)
}