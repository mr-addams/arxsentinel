package chaincheck

import (
	"io"
	"os"
	"testing"

	"github.com/mr-addams/arxsentinel/internal/sys/utils"
)

// TestMain silences utils.Log console output during the test run.
// TestCloudflareChecker_Fetch_KeepsOldOnError intentionally provokes fetch
// failures, which emit CHAIN_WARN lines via utils.Log. Those are expected and
// must not pollute go test -v output or alarm readers.
// We redirect utils.ConsoleWriter (not os.Stdout) so the testing framework's
// own -v output is unaffected.
func TestMain(m *testing.M) {
	utils.ConsoleWriter = io.Discard
	os.Exit(m.Run())
}
