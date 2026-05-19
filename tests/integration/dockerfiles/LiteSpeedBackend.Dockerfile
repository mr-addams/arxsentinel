FROM litespeedtech/openlitespeed:latest

# Enable useIpInHeader in the Default listener so the access log records
# the real client IP from X-Forwarded-For when OLS sits behind a proxy.
# Without this, the log contains the proxy container's IP — the IP leakage
# class of failures in assert_chain() would always trigger.
#
# sed appends the directive on the line immediately after "listener Default{".
# The || true guard keeps the build succeeding even if the config path or
# listener name changes in a future OLS release.
# Verify the patch took effect: if sed fails or the pattern was missing,
# the grep will fail the build rather than silently producing a broken image.
RUN sed -i '/^listener Default{/a\  useIpInHeader           1' \
    /usr/local/lsws/conf/httpd_config.conf \
    && grep -q 'useIpInHeader' /usr/local/lsws/conf/httpd_config.conf
