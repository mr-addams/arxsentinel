# Contributing to ArxSentinel

Thank you for your interest in contributing!

## Ways to contribute

- **Bug reports** — open an issue using the Bug Report template
- **Feature requests** — open an issue using the Feature Request template
- **Pull requests** — fixes, new detectors, package support, documentation

## Before you start

- Check [open issues](https://github.com/mr-addams/arxsentinel/issues) to avoid duplicates
- For significant changes, open an issue first to discuss the approach

## Development setup

```bash
git clone https://github.com/mr-addams/arxsentinel
cd arxsentinel
go mod tidy
go build ./...
go test ./...
```

For end-to-end tests:

```bash
go test -tags e2e ./... -v
```

## Pull request guidelines

- One logical change per PR
- `go test ./...` must pass
- `go vet ./...` must be clean
- Follow existing code style — comments in English, no unnecessary abstractions
- Update `README.md` if the change affects user-facing behavior or config

## Adding a new detector

1. Create `internal/core/detector/yourdetector.go` implementing the `Detector` interface
2. Add config fields to `internal/sys/config/config.go`
3. Register the detector in `cmd/arxsentinel/main.go` `buildDetectors()`
4. Add a test in `internal/core/detector/yourdetector_test.go`
5. Document the detector in `README.md` under the Detectors table

## Coding style

- Go standard formatting (`gofmt`)
- Comments explain **why**, not what
- No unnecessary error wrapping for internal errors
- Prefer explicit over clever

## License

By contributing, you agree that your contributions will be licensed under the [GNU GPLv3 License](LICENSE).
