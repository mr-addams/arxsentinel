// ========================== CLI cleanup subcommand ======================================
//   arxsentinel cleanup --cf — removes Cloudflare IP List items belonging
//   to this sentinel instance. Useful after uninstall: stale bans remain in CF
//   forever (no server-side TTL). This command removes them in 100-item batches.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	cloudflare "github.com/mr-addams/arxsentinel/pkg/executor/cloudflare"
)

var (
	cleanupCmd        = flag.NewFlagSet("cleanup", flag.ExitOnError)
	cleanupDoCF       = cleanupCmd.Bool("cf", false, "cleanup Cloudflare IP List")
	cleanupDryRun     = cleanupCmd.Bool("dry-run", false, "show what would be deleted, do not delete")
	cleanupInstanceID = cleanupCmd.String("instance-id", "", "override instance ID (default: auto-detect)")
	cleanupListID     = cleanupCmd.String("list-id", "", "override list ID (default: from executor config)")
	cleanupCfgPath    = cleanupCmd.String("config", "/etc/arxsentinel/config.yaml", "config file path")
)

// handleCleanup is the entry point for the cleanup subcommand.
func handleCleanup(args []string) {
	if err := cleanupCmd.Parse(args); err != nil {
		os.Exit(1)
	}
	if !*cleanupDoCF {
		fmt.Fprintf(os.Stderr, "arxsentinel: cleanup: use --cf to clean up Cloudflare IP List\n")
		cleanupCmd.Usage()
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*cleanupCfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arxsentinel: cleanup: config error: %v\n", err)
		os.Exit(1)
	}

	info := extractCFInfo(&cfg)
	if info == nil {
		fmt.Fprintf(os.Stderr, "arxsentinel: cleanup: no cloudflare executor found in config\n")
		os.Exit(1)
	}

	if err := runCFCleanup(context.Background(), info, *cleanupDryRun, *cleanupInstanceID, *cleanupListID); err != nil {
		fmt.Fprintf(os.Stderr, "arxsentinel: cleanup: %v\n", err)
		os.Exit(1)
	}
}

// cfInfo holds the subset of cloudflare executor config needed for cleanup.
type cfInfo struct {
	APIToken  string
	AccountID string
	ListName  string
}

// extractCFInfo finds the first cloudflare executor in cfg.Executors and
// extracts its API credentials. Returns nil when none is configured.
func extractCFInfo(cfg *config.Config) *cfInfo {
	for _, ec := range cfg.Executors {
		if ec.Type != "cloudflare" {
			continue
		}
		apiToken, _ := ec.Config["api_token"].(string)
		accountID, _ := ec.Config["account_id"].(string)
		listName, _ := ec.Config["list_name"].(string)
		if apiToken == "" || accountID == "" {
			continue
		}
		return &cfInfo{APIToken: apiToken, AccountID: accountID, ListName: listName}
	}
	return nil
}

// runCFCleanup performs GET→filter→DELETE against the Cloudflare IP List.
func runCFCleanup(ctx context.Context, info *cfInfo, dryRun bool, instanceID, listID string) error {
	client := cloudflare.NewHTTPCFClient(info.AccountID, info.APIToken)

	effectiveListID := listID
	if effectiveListID == "" && info.ListName != "" {
		var err error
		effectiveListID, err = client.FindOrCreateList(ctx, info.ListName)
		if err != nil {
			return fmt.Errorf("resolve list: %w", err)
		}
	}
	if effectiveListID == "" {
		return fmt.Errorf("no list ID specified and no list_name in executor config; use --list-id")
	}

	effectiveInstanceID := instanceID
	if effectiveInstanceID == "" {
		effectiveInstanceID = cloudflare.LoadInstanceID(&cloudflare.Config{})
	}

	items, err := client.GetAllItems(ctx, effectiveListID)
	if err != nil {
		return fmt.Errorf("list items: %w", err)
	}

	prefix := fmt.Sprintf("sentinel-%s", effectiveInstanceID)
	toDelete := FilterByComment(items, prefix)

	if dryRun {
		fmt.Printf("Would delete %d items (instance: %s, list: %s)\n",
			len(toDelete), effectiveInstanceID, effectiveListID)
		for i, item := range toDelete {
			if i >= 5 {
				fmt.Printf("  ... and %d more\n", len(toDelete)-5)
				break
			}
			fmt.Printf("  %s (id: %s, comment: %q)\n", item.IP, item.ID, item.Comment)
		}
		return nil
	}

	if len(toDelete) == 0 {
		fmt.Printf("No items found for instance %q in list %q\n", effectiveInstanceID, effectiveListID)
		return nil
	}

	ids := make([]string, len(toDelete))
	for i, item := range toDelete {
		ids[i] = item.ID
	}

	const batchSize = 100
	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}
		if _, err := client.RemoveItems(ctx, effectiveListID, ids[i:end]); err != nil {
			return fmt.Errorf("delete batch %d-%d: %w", i, end, err)
		}
	}
	fmt.Printf("Deleted %d items from list %q\n", len(toDelete), effectiveListID)
	return nil
}

// FilterByComment returns items whose Comment has the given prefix.
func FilterByComment(items []cloudflare.CFItem, prefix string) []cloudflare.CFItem {
	var result []cloudflare.CFItem
	for _, item := range items {
		if strings.HasPrefix(item.Comment, prefix) {
			result = append(result, item)
		}
	}
	return result
}
