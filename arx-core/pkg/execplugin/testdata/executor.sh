#!/usr/bin/env bash
# Test executor plugin for ExecExecutor unit tests.
# Reads NDJSON (one JSON object per line) from stdin, ignores the content,
# prints {"ok":true} for each line regardless of action field.

while IFS= read -r _; do
    printf '{"ok":true}\n'
done
