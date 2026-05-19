FROM litespeedtech/openlitespeed:latest

# Patch the OLS docker vhost template to log X-Forwarded-For as the client IP
# field in the access log. This is required for proxy-chain integration tests:
# when OLS sits behind a proxy, the access log must record the real attacker IP
# (from XFF) not the proxy container IP.
#
# Approach: inject a logFormat directive into the accesslog block that puts
# %{X-Forwarded-For}i in the first (client IP) field position.
# useIpInHeader is unreliable in the plain-text config path for this OLS
# Docker image — log format override is the authoritative alternative.
#
# awk prints the accesslog opening line, then inserts the logFormat line, then
# continues normally. The verification grep ensures the patch was applied.
RUN awk '/accesslog \$SERVER_ROOT\/logs\/\$VH_NAME.access.log \{/ { \
        print; \
        print "    logFormat             \"%{X-Forwarded-For}i %l %u %t \\\\\"%r\\\\\" %>s %b\""; \
        next \
    } 1' /usr/local/lsws/conf/templates/docker.conf \
    > /tmp/docker.conf.patched \
    && mv /tmp/docker.conf.patched /usr/local/lsws/conf/templates/docker.conf \
    && grep -q 'logFormat' /usr/local/lsws/conf/templates/docker.conf
