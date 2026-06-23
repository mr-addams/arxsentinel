// ========================== arx-core/pkg/input/const.go =========================================
//   Package-level constants for the input subsystem.
//
//   What is here:
//     - defaultLinesBufSize: default capacity for line buffering.
//
//   What is NOT here:
//     - Config-driven parameters (see Config struct in input.go).
// ==================================================================================================

package input

// defaultLinesBufSize — default buffer capacity for line-based input sources.
// Not in config: this is a hardcoded implementation detail of the channel buffer.
// Consumer: input.NewLineReader.
const defaultLinesBufSize = 1000
