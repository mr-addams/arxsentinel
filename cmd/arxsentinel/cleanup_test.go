// ========================== Cleanup tests =============================================
//   Unit tests for the cleanup subcommand — filtering logic, comment matching.

package main

import (
	"testing"

	cloudflare "github.com/mr-addams/arxsentinel/pkg/executor/cloudflare"
)

func TestFilterByComment_InstancePrefix(t *testing.T) {
	items := []cloudflare.CFItem{
		{ID: "1", IP: "1.1.1.1", Comment: "sentinel-abc-123"},
		{ID: "2", IP: "2.2.2.2", Comment: "sentinel-abc-123"},
		{ID: "3", IP: "3.3.3.3", Comment: "manual-block"},
		{ID: "4", IP: "4.4.4.4", Comment: "sentinel-other-id"},
	}
	filtered := FilterByComment(items, "sentinel-abc-123")
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered items, got %d", len(filtered))
	}
	// IDs should be 1 and 2 (correct ones).
	seen := map[string]bool{}
	for _, f := range filtered {
		seen[f.ID] = true
	}
	if !seen["1"] || !seen["2"] {
		t.Errorf("filtered items: expected IDs 1,2; got %v", seen)
	}
}

func TestFilterByComment_NoMatch(t *testing.T) {
	items := []cloudflare.CFItem{
		{ID: "1", IP: "1.1.1.1", Comment: "manual-block"},
	}
	filtered := FilterByComment(items, "sentinel-abc")
	if len(filtered) != 0 {
		t.Errorf("expected 0 filtered items, got %d", len(filtered))
	}
}

func TestFilterByComment_Empty(t *testing.T) {
	filtered := FilterByComment(nil, "sentinel-abc")
	if len(filtered) != 0 {
		t.Errorf("expected 0 filtered items from nil, got %d", len(filtered))
	}
}
