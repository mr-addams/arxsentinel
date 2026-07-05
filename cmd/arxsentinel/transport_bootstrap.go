// ========================== Transport bootstrap — Distributed NCS (Flow 093) =============
//   ЧТО ЗДЕСЬ:
//     - startTransport()                    — transport.New + transportbridge.SetDefault + Run goroutine
//     - preRegisterSinkQueues()              — F2: pre-registers queue: on sentinel-threat outputs
//     - preRegisterInboundTransportQueues()  — F3: pre-registers queue: on sentinel inputs
//     - sentinelQueueName()                  — parses "ncs://<name>" out of InputConfig.Addr
//
//   Both pre-register functions must run AFTER startTransport (so
//   transportbridge.GetDefault has a live Transport for queue.type=transport
//   entries) and BEFORE adaptConfigToStreams starts stream goroutines (so the
//   pre-registered backend wins the fan-in race against the pipeline's own
//   AttachWriter/AttachReader call) — same ordering rule as
//   preRegisterExecutorQueues (executors.go).

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/mr-addams/arx-core/pkg/ncs"
	"github.com/mr-addams/arx-core/pkg/transport"
	"github.com/mr-addams/arx-core/pkg/transportbridge"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
)

// startTransport builds a *transport.Transport from cfg.Transport and starts
// its Run loop as a tracked goroutine when enabled.
//
// Must run BEFORE preRegisterSinkQueues / preRegisterInboundTransportQueues
// / any stream startup — RegisterSinkFromConfig's queue.type=transport case
// resolves the live Transport via transportbridge.GetDefault, which is only
// populated once SetDefault below has run.
//
// When cfg.Transport.Enabled is false, transport.New still succeeds (D21:
// zero-value-safe, no goroutine/socket/disk access) but this function skips
// SetDefault and the Run goroutine entirely. validateTransportWiring
// (internal/sys/config/config.go) already guarantees no queue.type=transport
// entry exists in a valid config with transport disabled, so there is
// nothing for a disabled Transport to serve; skipping the goroutine keeps
// shutdown logs free of a spurious "transport: Run returned" line for a
// transport that was never used.
func startTransport(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup) error {
	if !cfg.Transport.Enabled {
		return nil
	}

	peers := make([]transport.PeerConfig, len(cfg.Transport.Peers))
	for i, p := range cfg.Transport.Peers {
		peers[i] = transport.PeerConfig{Host: p.Host, Fingerprint: p.Fingerprint}
	}

	tr, err := transport.New(transport.Config{
		Enabled:        cfg.Transport.Enabled,
		IdentityPath:   cfg.Transport.IdentityPath,
		Listen:         cfg.Transport.Listen,
		KnownNodesPath: cfg.Transport.KnownNodesPath,
		Peers:          peers,
		PairingSecret:  cfg.Transport.PairingSecret,
	})
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	transportbridge.SetDefault(tr)
	utils.Log("TRANSPORT", fmt.Sprintf("listening on %s (%d peer(s) configured)", cfg.Transport.Listen, len(peers)), "info")

	// Tracked like every other long-lived goroutine (STARTUP SEQUENCE
	// invariant in main.go's file header) — wg.Wait() in main() must not
	// return while the transport's QUIC listener/peer goroutines are
	// still tearing down after ctx cancellation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := tr.Run(ctx); err != nil {
			utils.Log("TRANSPORT", "Run error: "+err.Error(), "error")
		}
	}()
	return nil
}

// preRegisterSinkQueues pre-registers each sentinel-threat output's queue:
// backend (F2) before any pipeline's own sink construction runs its
// AttachWriter call. Outputs without queue: are skipped — existing plain
// in-process AttachWriter behaviour is unaffected.
//
// Walks all three locations a SinkConfig can appear in (top-level, per-stream,
// per-pipeline), mirroring validateTransportWiring's walk in config.go.
func preRegisterSinkQueues(cfg *config.Config) error {
	register := func(location string, outs []config.SinkConfig) error {
		for i, o := range outs {
			if o.Type != "sentinel-threat" || o.Queue == nil {
				continue
			}
			if o.Name == "" {
				return fmt.Errorf("%s[%d]: sentinel-threat output with queue: must set name", location, i)
			}
			if err := ncs.RegisterSinkFromConfig(o.Name, o.Queue, utils.AsLogger()); err != nil {
				return fmt.Errorf("%s[%d] (name=%q): %w", location, i, o.Name, err)
			}
		}
		return nil
	}

	if err := register("outputs", cfg.Outputs); err != nil {
		return err
	}
	for i, s := range cfg.Streams {
		if err := register(fmt.Sprintf("streams[%d].outputs", i), s.Outputs); err != nil {
			return err
		}
		for j, p := range s.Pipelines {
			if err := register(fmt.Sprintf("streams[%d].pipelines[%d].outputs", i, j), p.Outputs); err != nil {
				return err
			}
		}
	}
	return nil
}

// preRegisterInboundTransportQueues pre-registers each "sentinel" input's
// queue: backend (F3) before any pipeline's own source construction runs
// its AttachReader call (pkg/source/sentinel.New calls ncs.AttachReader
// internally). Inputs without queue: are skipped — existing plain
// in-process AttachReader behaviour is unaffected.
//
// Walks all three locations an InputConfig can appear in (top-level,
// per-stream, per-pipeline), mirroring validateTransportWiring's walk.
func preRegisterInboundTransportQueues(cfg *config.Config) error {
	register := func(location string, ins []config.InputConfig) error {
		for i, in := range ins {
			if in.Type != "sentinel" || in.Queue == nil {
				continue
			}
			name, err := sentinelQueueName(in.Addr)
			if err != nil {
				return fmt.Errorf("%s[%d]: %w", location, i, err)
			}
			if err := ncs.RegisterSinkFromConfig(name, in.Queue, utils.AsLogger()); err != nil {
				return fmt.Errorf("%s[%d] (name=%q): %w", location, i, name, err)
			}
		}
		return nil
	}

	if err := register("inputs", cfg.Inputs); err != nil {
		return err
	}
	for i, s := range cfg.Streams {
		if err := register(fmt.Sprintf("streams[%d].inputs", i), s.Inputs); err != nil {
			return err
		}
		for j, p := range s.Pipelines {
			if err := register(fmt.Sprintf("streams[%d].pipelines[%d].inputs", i, j), p.Inputs); err != nil {
				return err
			}
		}
	}
	return nil
}

// sentinelQueueName extracts the NCS queue name from a "sentinel" input's
// Addr field ("ncs://<name>"), matching the addressing scheme
// pkg/source/sentinel.parseAddr enforces internally (that helper is
// unexported, so this is a small standalone re-implementation rather than a
// cross-package call).
func sentinelQueueName(addr string) (string, error) {
	const scheme = "ncs://"
	if !strings.HasPrefix(addr, scheme) {
		return "", fmt.Errorf("invalid sentinel address %q: expected %q scheme", addr, scheme)
	}
	name := strings.TrimPrefix(addr, scheme)
	if name == "" {
		return "", fmt.Errorf("invalid sentinel address %q: queue name is empty", addr)
	}
	return name, nil
}
