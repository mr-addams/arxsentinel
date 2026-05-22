FROM litespeedtech/openlitespeed:latest

# Patch the OLS docker vhost template to log X-Forwarded-For as the client IP
# field in the access log. Required for proxy-chain integration tests: when OLS
# sits behind a proxy, the access log must record the real attacker IP (from XFF)
# not the proxy container IP.
#
# useIpInHeader is unreliable in the OLS plain-text config path (Docker image).
# Instead: inject a logFormat directive into the accesslog block that puts
# %{X-Forwarded-For}i in the first (client IP) field position.
# The format keeps the standard CLF structure so the litespeed sentinel parser
# (apacheCLFPattern) can still extract all required fields.
#
# Python handles the quote escaping correctly: \" in the logFormat string tells
# OLS to output a literal " around the request field (%r).
COPY dockerfiles/patch-ols-logformat.py /tmp/patch-ols-logformat.py
# litespeedtech/openlitespeed removed python3 from the base image; install it explicitly.
RUN apt-get update -qq && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
RUN python3 /tmp/patch-ols-logformat.py
