#!/usr/bin/env bash
# Test source plugin for ExecSource unit tests.
# Waits for {"action":"start"} on stdin, then emits 3 fixed LogEntry lines.
# On {"action":"stop"} or stdin close, exits.

# Read start command (blocking)
IFS= read -r _start_line

# Emit 3 fixed log entries as SourceEntry JSON
for i in 1 2 3; do
    printf '{"entry":{"remote_addr":"1.2.3.%d","remote_user":"-","time":"2026-01-01T00:00:00Z","method":"GET","raw_uri":"/test","path":"/test","query":"","protocol":"HTTP/1.1","status":200,"bytes_sent":100,"referer":"-","user_agent":"test-agent","real_ip":"1.2.3.%d"}}\n' "$i" "$i"
done

# Exit cleanly
