# tests/integration-freebsd/litespeed/LiteSpeedChain.Dockerfile —
# Flow 092 FreeBSD-specific fork of
# tests/integration/dockerfiles/LiteSpeedBackend.Dockerfile.
#
# Only difference from the upstream file: uses this directory's
# patch-ols-logformat-chain.py (adds trailing Referer/User-Agent
# fields the upstream patch omits — see that file's header for the
# full WHY). Everything else (base image, python3 install for the
# patch script) is verbatim from the upstream Dockerfile.

FROM litespeedtech/openlitespeed:latest

COPY patch-ols-logformat-chain.py /tmp/patch-ols-logformat-chain.py
RUN apt-get update -qq && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
RUN python3 /tmp/patch-ols-logformat-chain.py
