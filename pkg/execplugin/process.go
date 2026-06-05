// ========================== pkg/execplugin — ManagedProcess ===============================
//   Subprocess lifecycle management with NDJSON communication.
//
//   WHAT IS HERE:
//     - ManagedProcess — owns plugin binary process, stdin/stdout pipes
//     - Mutex-protected Send/Recv for atomic request-response cycles
//     - Graceful shutdown: SIGTERM + timeout, fallback to SIGKILL
//
//   WHAT IS NOT HERE:
//     - Protocol message types (protocol.go)
//     - Detector/Sink/Source plugin implementations

package execplugin

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ManagedProcess owns the lifecycle of a single plugin subprocess.
// Communication is via newline-delimited JSON over stdin/stdout pipes.
//
// All Send/Recv operations are protected by a mutex — callers must acquire
// the lock before sending a request and receiving its response as a single
// atomic operation. This prevents interleaving of messages from concurrent
// request handlers.
//
// INVARIANTS:
//   - cmd.Start() is called in NewManagedProcess — the process is immediately running
//   - Send() and Recv() MUST be called with lock held — no internal locking
//   - Close() should be called during shutdown to clean up resources
// Consumer: detector.go, sink.go, executor.go, source.go.
type ManagedProcess struct {
	cmd    *exec.Cmd         // Internal — spawned plugin subprocess. Consumer: Lock, Send, Recv, Close
	stdin  io.WriteCloser   // Internal — plugin stdin pipe for sending requests. Consumer: Send, Close
	stdout *bufio.Scanner    // Internal — plugin stdout scanner for reading responses. Consumer: Recv
	mu     sync.Mutex        // Internal — protects atomic Send/Recv cycles. Consumer: Lock, Unlock
}

// NewManagedProcess spawns the plugin binary at execPath and wires up stdin/stdout pipes.
// The process is started immediately.
//
// ctx cancellation does NOT kill the process — call Close() explicitly during shutdown.
// ctx is stored in cmd for context-aware Wait; the process runs independently.
//
// Returns an error if the binary is not executable or cannot be started.
// Called from: detector.New, sink.New, executor.New, source.New.
//
// Blocking — Start() is called synchronously; process begins execution.
func NewManagedProcess(ctx context.Context, execPath string) (*ManagedProcess, error) {
	cmd := exec.CommandContext(ctx, execPath)

	// Redirect stderr to parent's stderr so plugin diagnostics are visible
	cmd.Stderr = os.Stderr

	// Wire stdin for sending requests
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Wire stdout for receiving responses
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to start plugin: %w", err)
	}

	// Create scanner with default buffer (64KB line buffer is sufficient for one LogEntry JSON)
	scanner := bufio.NewScanner(stdout)
	// Optionally increase buffer if LogEntry JSON lines exceed 64KB (uncomment if needed)
	// buf := make([]byte, 0, 256*1024)
	// scanner.Buffer(buf, 1*1024*1024)

	return &ManagedProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: scanner,
	}, nil
}

// Lock acquires the process mutex. Must be paired with Unlock.
// Called from: Detector.SendRequest, Sink.SendRequest, Executor.SendRequest, Source.SendRequest.
// Non-blocking.
func (p *ManagedProcess) Lock() {
	p.mu.Lock()
}

// Unlock releases the process mutex.
// Called from: Detector.SendRequest, Sink.SendRequest, Executor.SendRequest, Source.SendRequest.
// Non-blocking.
func (p *ManagedProcess) Unlock() {
	p.mu.Unlock()
}

// Send writes a line followed by '\n' to the plugin's stdin.
// line may contain embedded newlines (which will be preserved as-is in the JSON).
//
// CRITICAL: Must be called with lock held. Concurrent Send calls will corrupt
// the protocol if mu is not held by the caller.
//
// Returns an error if the pipe is closed (plugin exited) or write fails.
// Called from: Detector.SendRequest, Sink.SendRequest, Executor.SendRequest, Source.SendRequest.
// Non-blocking.
func (p *ManagedProcess) Send(line []byte) error {
	_, err := p.stdin.Write(append(line, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write to plugin stdin: %w", err)
	}
	return nil
}

// Recv reads one line from the plugin's stdout.
// Returns an error if the scanner stopped (process exited or pipe closed).
//
// CRITICAL: Must be called with lock held. Concurrent Recv calls will read
// messages out-of-order if mu is not held by the caller.
//
// Returns (nil, error) if stdout closed or scanner.Err() is non-nil.
// Called from: Detector.SendRequest, Sink.SendRequest, Executor.SendRequest, Source.SendRequest.
// Non-blocking.
func (p *ManagedProcess) Recv() ([]byte, error) {
	if !p.stdout.Scan() {
		// Scan returned false: either EOF or error
		if err := p.stdout.Err(); err != nil {
			return nil, fmt.Errorf("plugin stdout scanner error: %w", err)
		}
		return nil, fmt.Errorf("plugin stdout closed: EOF")
	}
	// Return a copy of the scanned line (Scan() reuses buffer)
	return append([]byte{}, p.stdout.Bytes()...), nil
}

// Close gracefully shuts down the plugin process.
// Sends SIGTERM and waits up to 3 seconds for clean exit.
// If the process doesn't exit, sends SIGKILL.
//
// It is safe to call Close multiple times (idempotent).
// Called from: detector.Close, sink.Close, executor.Close, source.Close.
//
// Blocking — waits up to 3 seconds for process exit.
func (p *ManagedProcess) Close() error {
	// Close stdin to signal end-of-input to the plugin
	if err := p.stdin.Close(); err != nil && err != io.ErrClosedPipe {
		// Ignore "pipe already closed" errors
	}

	// If process hasn't already exited, send SIGTERM
	if p.cmd.ProcessState == nil {
		_ = p.cmd.Process.Signal(os.Interrupt) // SIGTERM on Unix, CtrlBreak on Windows
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()

	select {
	case err := <-done:
		// Process exited cleanly
		return err
	case <-time.After(3 * time.Second):
		// Timeout: process didn't exit, send SIGKILL
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		// Wait for the kill to take effect
		p.cmd.Wait()
		return fmt.Errorf("plugin process did not exit within 3s, killed")
	}
}
