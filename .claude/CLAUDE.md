@~/.claude/go-conventions.md

## Project rules — nginx-sentinel

### Testing

**No untested code goes into a commit. Ever.**

Every new or modified function that contains logic must have a corresponding test
committed in the same change. No exceptions, no "I'll add tests later".

What counts as coverage:
- New package (config, metrics, utils) → unit tests in `_test.go` in the same package
- New public function with logic → at minimum: happy path + one error/edge path
- `main.go` changes (pipeline, goroutines) → e2e test or explicit justification why it's untestable
- Pure refactoring with no logic change → existing tests must stay green; no new tests required

When `utils/`, `sys/` packages lack a `_test.go` — add one before committing logic changes to them.
