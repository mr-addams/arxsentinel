// ========================== License subcommand =======================================
//   arxsentinel license — prints the full license text and exits.
//   Built with go:embed to embed the LICENSE file directly into the binary.
//   No parsing or external file access at runtime.
//
//   Purpose: satisfies license visibility requirements (e.g. for container
//   distributions that want a single binary with all legal text embedded).

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