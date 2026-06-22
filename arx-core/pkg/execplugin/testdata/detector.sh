#!/usr/bin/env bash
# Test detector plugin for ExecDetector unit tests.
# Reads DetectRequest JSON from stdin, ignores the content,
# returns a fixed DetectResponse with score=42, module=test-detector.

while IFS= read -r line; do
    printf '{"score":42,"module":"test-detector","reason":"test:1"}\n'
done
