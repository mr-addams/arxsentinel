// ========================== Profile plugin-file generator ===========================
//
//	Reads profiles/*.yaml and emits cmd/arxsentinel/plugins_<name>.go for each
//	non-full profile. Generated files carry `//go:build arx_tag && <name>` and
//	register the profile's transports via blank-imports.
//
//	Import paths are derived from each entry's `module` field (Flow 084, post
//	arx-core split): `module: arxsentinel` resolves to the local
//	pkg/<kind>plugins/<name> split-package tree; `module: arx-core` resolves to
//	the external github.com/mr-addams/arx-core/pkg/<kind>/<name> module.
//	Detector entries never carry a `module` field — detectors are always
//	product-local (pkg/detectorplugins/<name>).
//
//	Driven by the `//go:generate` directive in cmd/arxsentinel/main.go:
//	  //go:generate go run ./tools/gen-plugins -profiles ../../profiles -out .
//
//	See: docs/architecture/adr/003-build-modularity.md, DECISIONS.md Flow 075,
//	scripts/check-build-profiles.sh (the invariant (a) verifier this output
//	must match).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// localModuleRoot hosts the product's own split-plugin packages
// (pkg/<kind>plugins/<name>). externalModuleRoots maps a `module:` YAML value
// to the external Go module root it resolves to; only "arx-core" exists today
// (Flow 084 split). Any other module value is a hard error — DECISIONS.md
// covers exactly two modules, silently emitting a wrong path would defeat the
// point of this generator.
const localModuleRoot = "github.com/mr-addams/arxsentinel"

var externalModuleRoots = map[string]string{
	"arx-core": "github.com/mr-addams/arx-core",
}

// kindSingular maps the plural profile-YAML kind key to the singular
// directory segment used by both the local pkg/<kind>plugins/ tree and the
// external arx-core pkg/<kind>/ tree.
var kindSingular = map[string]string{
	"sources":    "source",
	"sinks":      "sink",
	"executors":  "executor",
	"processors": "processor",
	"detectors":  "detector",
}

// pluginEntry mirrors one row under plugins.<kind>[] in profiles/<name>.yaml.
// Detector entries never set Module — detectors are always local.
type pluginEntry struct {
	Name   string `yaml:"name"`
	Module string `yaml:"module"`
}

// profileSchema mirrors the top-level structure of profiles/<name>.yaml.
type profileSchema struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Plugins     struct {
		Executors  []pluginEntry `yaml:"executors"`
		Processors []pluginEntry `yaml:"processors"`
		Sinks      []pluginEntry `yaml:"sinks"`
		Sources    []pluginEntry `yaml:"sources"`
		Detectors  []pluginEntry `yaml:"detectors"`
	} `yaml:"plugins"`
}

// nameToPkgSuffix overrides the package-suffix (directory name) for plugin
// names that don't match the sub-package directory. Keyed by `kind/name` so
// the same name in different kinds is unambiguous. Mirrors pkg_suffix_for()
// in scripts/check-build-profiles.sh exactly — the two must stay in sync or
// invariant (a) fails:
//   - sinks/sentinel-threat lives in pkg/sink/sentinel (Decision 15/16, Flow 075).
//   - detectors/ua lives in pkg/detectorplugins/useragent (Flow 076, Task 6.1).
var nameToPkgSuffix = map[string]string{
	"sinks/sentinel-threat": "sentinel",
	"detectors/ua":          "useragent",
}

// pkgSuffix resolves the package-suffix (directory name) for a given (kind,
// name). Override map wins; default is the plugin name itself.
func pkgSuffix(kind, name string) string {
	if s, ok := nameToPkgSuffix[kind+"/"+name]; ok {
		return s
	}
	return name
}

// kindPath derives the blank-import path for one plugin entry from its
// `module` field. Empty Module defaults to "arxsentinel" (detector entries
// never set it). Unknown module values abort generation loudly rather than
// silently minting a path that can never match reality.
func kindPath(kind string, e pluginEntry) (string, error) {
	suffix := pkgSuffix(kind, e.Name)
	singular, ok := kindSingular[kind]
	if !ok {
		return "", fmt.Errorf("unknown plugin kind %q", kind)
	}

	module := e.Module
	if module == "" {
		module = "arxsentinel"
	}

	if module == "arxsentinel" {
		return localModuleRoot + "/pkg/" + singular + "plugins/" + suffix, nil
	}
	if root, ok := externalModuleRoots[module]; ok {
		return root + "/pkg/" + singular + "/" + suffix, nil
	}
	return "", fmt.Errorf("plugin %s/%s: unrecognized module %q", kind, e.Name, module)
}

func main() {
	profilesDir := flag.String("profiles", "../../profiles", "directory containing profile YAML files")
	outDir := flag.String("out", ".", "directory to emit plugins_<name>.go into")
	flag.Parse()

	entries, err := os.ReadDir(*profilesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-plugins: read profiles dir %q: %v\n", *profilesDir, err)
		os.Exit(1)
	}

	var names []string
	byName := make(map[string]profileSchema)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".yaml")
		var p profileSchema
		data, err := os.ReadFile(filepath.Join(*profilesDir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-plugins: read %s: %v\n", e.Name(), err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &p); err != nil {
			fmt.Fprintf(os.Stderr, "gen-plugins: parse %s: %v\n", e.Name(), err)
			os.Exit(1)
		}
		// `full` is hand-maintained in plugins_full.go — parse but do not emit.
		if base == "full" {
			continue
		}
		names = append(names, base)
		byName[base] = p
	}
	sort.Strings(names)

	for _, name := range names {
		p := byName[name]
		if err := emit(filepath.Join(*outDir, "plugins_"+name+".go"), name, p); err != nil {
			fmt.Fprintf(os.Stderr, "gen-plugins: emit %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("gen-plugins: wrote plugins_%s.go (%d imports)\n", name, countImports(p))
	}
}

// emit writes a single plugins_<name>.go file. Imports are split into three
// blocks matching the hand-maintained plugins_full.go layout (and what
// invariant (a) of scripts/check-build-profiles.sh accepts):
//
//  1. local non-detector plugins (executors, processors — pkg/<kind>plugins/)
//  2. local detector plugins (pkg/detectorplugins/), under a fixed comment
//  3. external plugins (arx-core — pkg/<kind>/)
//
// Each block is sorted alphabetically on its own for a stable diff; blocks
// are separated by a single blank line and omitted entirely when empty.
func emit(path, name string, p profileSchema) error {
	var localOther, localDetectors, external []string

	add := func(kind string, entries []pluginEntry) error {
		for _, e := range entries {
			imp, err := kindPath(kind, e)
			if err != nil {
				return err
			}
			switch {
			case kind == "detectors":
				localDetectors = append(localDetectors, imp)
			case strings.HasPrefix(imp, localModuleRoot+"/"):
				localOther = append(localOther, imp)
			default:
				external = append(external, imp)
			}
		}
		return nil
	}
	for _, kv := range []struct {
		kind    string
		entries []pluginEntry
	}{
		{"executors", p.Plugins.Executors},
		{"processors", p.Plugins.Processors},
		{"detectors", p.Plugins.Detectors},
		{"sources", p.Plugins.Sources},
		{"sinks", p.Plugins.Sinks},
	} {
		if err := add(kv.kind, kv.entries); err != nil {
			return err
		}
	}
	sort.Strings(localOther)
	sort.Strings(localDetectors)
	sort.Strings(external)

	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by tools/gen-plugins; DO NOT EDIT.\n\n")
	fmt.Fprintf(&b, "//go:build arx_tag && %s\n\n", name)
	fmt.Fprintf(&b, "// ========================== Plugin blank-imports — %s profile =======================\n", name)
	fmt.Fprintf(&b, "//\n")
	fmt.Fprintf(&b, "//\tSide-effect registration of plugins declared in profiles/%s.yaml.\n", name)
	fmt.Fprintf(&b, "//\tActive only under build tags: -tags \"arx_tag %s\".\n", name)
	fmt.Fprintf(&b, "//\tSee docs/architecture/adr/003-build-modularity.md and DECISIONS.md Flow 075.\n")
	fmt.Fprintf(&b, "package main\n\n")
	fmt.Fprintf(&b, "import (\n")

	blocks := 0
	writeBlock := func(header string, imps []string) {
		if len(imps) == 0 {
			return
		}
		if blocks > 0 {
			fmt.Fprintf(&b, "\n")
		}
		if header != "" {
			fmt.Fprintf(&b, "%s\n", header)
		}
		for _, imp := range imps {
			fmt.Fprintf(&b, "\t_ %q\n", imp)
		}
		blocks++
	}
	writeBlock("", localOther)
	writeBlock("\t// Plugin detectors (tree-shakeable side-effect registration, Flow 076)", localDetectors)
	writeBlock("", external)

	fmt.Fprintf(&b, ")\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func countImports(p profileSchema) int {
	return len(p.Plugins.Sources) + len(p.Plugins.Sinks) +
		len(p.Plugins.Executors) + len(p.Plugins.Processors) +
		len(p.Plugins.Detectors)
}
