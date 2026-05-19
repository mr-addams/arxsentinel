FROM litespeedtech/openlitespeed:latest

# Enable useIpInHeader=2 in the docker vhost template so OLS uses the
# X-Forwarded-For header as the client IP in access logs when sitting behind
# a proxy. Without this, the log contains the proxy container's IP — the
# IP leakage class of failures in assert_chain() would always trigger.
#
# Value 2 (trust XFF from any source) is required: value 1 requires explicit
# trusted-proxy ranges which are not configured in the integration test env.
#
# useIpInHeader is a virtualhost-level setting in OLS, not listener-level.
# The docker image serves all traffic via the "docker" vhTemplate whose
# config lives in conf/templates/docker.conf — that is the correct place.
#
# Verify: grep will fail the build if sed matched nothing.
RUN sed -i '/^virtualHostConfig  {/a\  useIpInHeader           2' \
    /usr/local/lsws/conf/templates/docker.conf \
    && grep -q 'useIpInHeader' /usr/local/lsws/conf/templates/docker.conf
