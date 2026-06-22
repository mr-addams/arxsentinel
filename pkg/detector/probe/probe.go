// ========================== Probe detector ==============================================
//   Detects requests to sensitive paths: .env, .git, wp-config, aws-exports, etc.
//   A single matched path = a fixed score penalty for the IP.
//
//   ALGORITHM:
//     1. Exact match in map[string]struct{} — O(1), covers static paths (.env, wp-config.php)
//     2. Prefix match — catches /wp-admin/page.php, /actuator/env, etc.
//     Paths ending with "/" in config → prefix check.
//     All others → exact-match map.
//
//   Params (DetectorConfig.Params):
//     score  int      — threat score per match (default: 25)
//     paths  []string — list of paths and prefixes to watch (default: defaultProbePaths)
//
//   Registered as "probe" via init() in sub-package probe.

package probe

import (
	"strings"

	"github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	detector.Register("probe", newProbeFactory)
}

// probeDetector detects requests to sensitive paths.
type probeDetector struct {
	score    int
	pathSet  map[string]struct{} // exact-match paths: O(1) lookup
	prefixes []string            // prefix paths (ending with "/"): catches any sub-path
}

// newProbeFactory creates a probeDetector from DetectorConfig.
// Called only when cfg.Enabled == true (Build() guards this).
func newProbeFactory(cfg detector.DetectorConfig, _ detector.SharedResources) (plugin.Detector, error) {
	score := detector.GetInt(detector.DetectorConfig{Params: cfg.Params}, "score", 25)
	paths := detector.GetStrings(detector.DetectorConfig{Params: cfg.Params}, "paths", defaultProbePaths())

	pathSet := make(map[string]struct{}, len(paths))
	var prefixes []string
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			// /wp-admin/, /actuator/ — prefix check catches any sub-path
			prefixes = append(prefixes, p)
		} else {
			pathSet[p] = struct{}{}
		}
	}

	return &probeDetector{
		score:    score,
		pathSet:  pathSet,
		prefixes: prefixes,
	}, nil
}

// Name returns the detector identifier used in threat log and metrics.
func (d *probeDetector) Name() string { return "probe" }

// Detect checks the request path against sensitive paths.
//
// Order: exact match → prefix match.
// Exact match first: O(1) and covers the majority of static sensitive paths.
// Prefix match second: O(n) over prefix count, catches sub-paths (/wp-admin/login.php).
// Called from: pipeline.processEntries.
//
// Non-blocking.
func (d *probeDetector) Detect(_ plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
	path := entry.Path

	// ── Exact match ───────────────────────────────────────────────────────────────────
	if _, ok := d.pathSet[path]; ok {
		return plugin.DetectResult{
			Score:  d.score,
			Module: "probe",
			Reason: "probe:" + path,
		}
	}

	// ── Prefix match ──────────────────────────────────────────────────────────────────
	// /wp-admin/ in config → triggers on /wp-admin/options-general.php, /wp-admin/, etc.
	for _, prefix := range d.prefixes {
		if strings.HasPrefix(path, prefix) {
			return plugin.DetectResult{
				Score:  d.score,
				Module: "probe",
				Reason: "probe:" + path,
			}
		}
	}

	return plugin.DetectResult{}
}

// defaultProbePaths returns the built-in list of sensitive paths.
// Matches the defaults in internal/sys/config.defaultProbePaths().
func defaultProbePaths() []string {
	return []string{
		// Application configuration files
		"/.env", "/.env.backup", "/.env.local", "/.env.production", "/.env.staging",
		"/config.yml", "/config.yaml", "/config.json", "/application.properties",
		"/settings.py", "/local_settings.py", "/database.yml", "/database.yaml",
		"/web.config", "/app.config",

		// Git / VCS
		"/.git/config", "/.git/HEAD", "/.gitignore",
		"/.svn/entries", "/.hg/", "/.bzr/",

		// Cloud credentials
		"/.aws/credentials", "/.docker/config.json",
		"/aws-exports.json", "/.gcloud/credentials",

		// CMS: WordPress
		"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
		"/wp-login.php", "/xmlrpc.php", "/wp-admin/",

		// CMS: general
		"/administrator/", "/admin/", "/phpmyadmin/", "/pma/",
		"/joomla/", "/drupal/", "/typo3/",

		// Backup files
		"/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.sql.gz",
		"/db.dump", "/database.sql", "/dump.sql", "/site.sql",

		// Infrastructure and monitoring
		"/server-status", "/server-info",
		"/phpinfo.php", "/info.php", "/php.php",

		// Runtime and containers
		"/actuator/", "/.well-known/", "/docker-compose.yml", "/Dockerfile",

		// Security and credentials
		"/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
		"/.ssh/", "/.bash_history", "/.bashrc",
	}
}
