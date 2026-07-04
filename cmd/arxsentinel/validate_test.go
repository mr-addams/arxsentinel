package main

import (
	"testing"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// TestSentinelChannelNames_TransportSendModeExempt is the Flow 093 Group H
// regression test for the "writer but no reader" validation gap the
// distributed_ncs_integration_test.go acceptance test caught: a
// sentinel-threat sink whose queue: is a transport backend in mode=send has
// its reader on a remote node (a separate process/config entirely) — it
// must not be counted among the channels requiring a LOCAL executor reader.
func TestSentinelChannelNames_TransportSendModeExempt(t *testing.T) {
	pl := config.PipelineConfig{
		Outputs: []config.SinkConfig{
			{
				Type: "sentinel-threat",
				Name: "edge-raw",
				Queue: &queue.QueueConfig{
					Type: queue.QueueTypeTransport,
					Mode: "send",
					Peer: "127.0.0.1:4098",
				},
			},
		},
	}
	names := sentinelChannelNames(pl)
	if len(names) != 0 {
		t.Errorf("sentinelChannelNames(mode=send) = %v, want empty (remote reader, no local wiring requirement)", names)
	}
}

// TestSentinelChannelNames_TransportBothModeStillRequiresReader verifies the
// mode=send exemption does NOT leak into mode=both (or the default, empty
// mode) — those still mean "a local reader is also expected on this node"
// per QueueConfig.Mode's doc comment, so the channel must stay in the
// writer-without-reader check's scope.
func TestSentinelChannelNames_TransportBothModeStillRequiresReader(t *testing.T) {
	cases := []struct {
		name string
		mode string
	}{
		{"explicit both", "both"},
		{"empty mode (defaults to both)", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pl := config.PipelineConfig{
				Outputs: []config.SinkConfig{
					{
						Type: "sentinel-threat",
						Name: "edge-raw",
						Queue: &queue.QueueConfig{
							Type: queue.QueueTypeTransport,
							Mode: tc.mode,
						},
					},
				},
			}
			names := sentinelChannelNames(pl)
			if len(names) != 1 || names[0] != "edge-raw" {
				t.Errorf("sentinelChannelNames(mode=%q) = %v, want [edge-raw]", tc.mode, names)
			}
		})
	}
}

// TestSentinelChannelNames_NonTransportQueueUnaffected verifies a plain
// memory/bbolt/redis queue: (or no queue: at all) is unaffected by the
// Flow 093 exemption — only queue.type=transport, mode=send is special-cased.
func TestSentinelChannelNames_NonTransportQueueUnaffected(t *testing.T) {
	pl := config.PipelineConfig{
		Outputs: []config.SinkConfig{
			{Type: "sentinel-threat", Name: "local-only"}, // Queue == nil
			{Type: "sentinel-threat", Name: "bbolt-backed", Queue: &queue.QueueConfig{Type: queue.QueueTypeBbolt}},
			{Type: "file", Path: "/dev/null"}, // not sentinel-threat at all
		},
	}
	names := sentinelChannelNames(pl)
	if len(names) != 2 {
		t.Fatalf("sentinelChannelNames = %v, want 2 entries (local-only, bbolt-backed)", names)
	}
}
