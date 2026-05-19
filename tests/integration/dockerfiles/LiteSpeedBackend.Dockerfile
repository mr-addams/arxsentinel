FROM litespeedtech/openlitespeed:latest

# Enable useIpInHeader=2 in the Default listener so the access log records
# the real client IP from X-Forwarded-For when OLS sits behind a proxy.
# Without this, the log contains the proxy container's IP — the IP leakage
# class of failures in assert_chain() would always trigger.
#
# Value 2 (trust XFF from any source) is required here: value 1 only applies
# when the connecting peer is in a configured trusted-proxy range, which is
# not set up in the integration test environment.
#
# sed appends the directive on the line immediately after "listener Default{".
# Verify the patch took effect: if sed fails or the pattern was missing,
# the grep will fail the build rather than silently producing a broken image.
RUN sed -i '/^listener Default{/a\  useIpInHeader           2' \
    /usr/local/lsws/conf/httpd_config.conf \
    && grep -q 'useIpInHeader' /usr/local/lsws/conf/httpd_config.conf
