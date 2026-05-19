# Patches the OLS docker vhost template to log X-Forwarded-For as the client
# IP field in the access log. Required for proxy-chain integration tests: OLS
# must record the real attacker IP from XFF, not the proxy container IP.
#
# The logFormat value written to docker.conf:
#   "%{X-Forwarded-For}i %l %u %t \"%r\" %>s %b"
#
# OLS interprets \" as an escaped quote inside the format string, so the
# logged line has "%r" (request) properly quoted — matching apacheCLFPattern
# used by the sentinel litespeed parser profile.

CONF = '/usr/local/lsws/conf/templates/docker.conf'
MARKER = 'accesslog $SERVER_ROOT/logs/$VH_NAME.access.log {'
LOG_FORMAT_LINE = '    logFormat             "%{X-Forwarded-For}i %l %u %t \\"%r\\" %>s %b"\n'

content = open(CONF).read()
assert MARKER in content, f'Marker not found in {CONF} — OLS template changed?'
content = content.replace(MARKER, MARKER + '\n' + LOG_FORMAT_LINE)
open(CONF, 'w').write(content)
assert 'logFormat' in open(CONF).read(), 'Patch failed: logFormat not in config'
