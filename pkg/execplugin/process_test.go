package execplugin

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// newLongProcess creates a ManagedProcess wrapping a long-running shell command.
// Used to test the timeout/kill path in Close().
func newLongProcess(t *testing.T) *ManagedProcess {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "sh", "-c", "sleep 30")
	// /dev/null as *os.File: avoids exec.Cmd's copy-goroutine (triggered for
	// non-*os.File writers). A copy-goroutine blocks cmd.Wait() on EOF, but
	// orphaned child processes (sleep spawned by sh) keep the write end open
	// → deadlock. With *os.File(/dev/null), no copy-goroutine is created and
	// orphans only hold a harmless /dev/null fd.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("skip: cannot open /dev/null: %v", err)
	}
	t.Cleanup(func() { devNull.Close() })
	cmd.Stderr = devNull
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Skipf("skip: stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Skipf("skip: stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("skip: cannot start long subprocess: %v", err)
	}
	return &ManagedProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewScanner(stdout),
	}
}

// TestManagedProcess_CloseTimeout verifies that Close() does not panic when
// the subprocess does not exit within the 3s grace period (C1 regression).
func TestManagedProcess_CloseTimeout(t *testing.T) {
	proc := newLongProcess(t)
	time.Sleep(100 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		done <- proc.Close()
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error (timeout/kill), got nil")
		} else {
			t.Logf("Close returned expected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung — possible deadlock or panic")
	}
}

// TestManagedProcess_DoubleClose verifies that calling Close twice is safe
// and does not panic (regression test for C1 double-Wait).
func TestManagedProcess_DoubleClose(t *testing.T) {
	proc, err := NewManagedProcess(context.Background(), "echo")
	if err != nil {
		t.Skipf("skip: echo not available: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	err1 := proc.Close()
	err2 := proc.Close()

	t.Logf("First Close: %v", err1)
	t.Logf("Second Close: %v", err2)
}

// TestManagedProcess_ConcurrentClose verifies that concurrent Close calls
// are safe and do not panic (regression for C1).
func TestManagedProcess_ConcurrentClose(t *testing.T) {
	proc := newLongProcess(t)
	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = proc.Close()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All Close calls completed without panic/block
	case <-time.After(10 * time.Second):
		t.Fatal("Concurrent Close calls hung — possible deadlock")
	}
}

// TestManagedProcess_NormalExit verifies the normal close path works
// with a process that exits quickly when stdin is closed.
func TestManagedProcess_NormalExit(t *testing.T) {
	proc, err := NewManagedProcess(context.Background(), "cat")
	if err != nil {
		t.Skipf("skip: cat not available: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	err = proc.Close()
	t.Logf("Close returned: %v", err)
}
