package mikrotik

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

type MikroTikExecutor struct {
	name   string
	cfg    Config
	client Client
	mu     sync.Mutex
	banned map[string]banRecord
	stats  struct {
		executed atomic.Int64
		skipped  atomic.Int64
		errors   atomic.Int64
	}
}

type banRecord struct {
	id      string
	addedAt time.Time
}

func (e *MikroTikExecutor) Name() string {
	if e.cfg.ListName != "" {
		return e.cfg.ListName
	}
	return "mikrotik"
}

func (e *MikroTikExecutor) Type() string {
	return "mikrotik"
}

func (e *MikroTikExecutor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "mikrotik",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleExecutor,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"routeros-v7", "v7.18.2+", "rest-api", "embedded-capable"},
	}
}