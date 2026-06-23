#!/usr/bin/env bash
# Test sink plugin for ExecSink unit tests.
# Reads WriteRequest JSON lines from stdin, prints {"ok":true} for each.

while IFS= read -r line; do
    printf '{"ok":true}\n'
done
