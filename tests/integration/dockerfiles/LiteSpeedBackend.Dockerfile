FROM litespeedtech/openlitespeed:latest

# Enable useIpInHeader=2 in the HTTP listener (port 80) so the access log
# records the real client IP from X-Forwarded-For when OLS sits behind a proxy.
# Without this, the log contains the proxy container's IP — the IP leakage
# class of failures in assert_chain() would always trigger.
#
# Value 2 (trust XFF from any source) is required here: value 1 only applies
# when the connecting peer is in a configured trusted-proxy range, which is
# not set up in the integration test environment.
#
# OLS Docker image has two active listeners: "Default" (port 8088) and "HTTP"
# (port 80). Only the HTTP listener handles proxy-chain test traffic, so we
# patch that one specifically.
#
# Verify the patch took effect: grep will fail the build if sed matched nothing.
RUN sed -i '/^listener HTTP {/a\  useIpInHeader           2' \
    /usr/local/lsws/conf/httpd_config.conf \
    && grep -q 'useIpInHeader' /usr/local/lsws/conf/httpd_config.conf
