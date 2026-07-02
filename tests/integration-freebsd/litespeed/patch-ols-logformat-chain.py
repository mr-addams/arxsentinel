# tests/integration-freebsd/litespeed/patch-ols-logformat-chain.py —
# Flow 092 FreeBSD-specific fork of tests/integration/dockerfiles/
# patch-ols-logformat.py.
#
# WHY a fork instead of reusing the shared file: the upstream patch's
# logFormat is `"%{X-Forwarded-For}i %l %u %t \"%r\" %>s %b"` — it
# stops at status/bytes, with NO trailing Referer/User-Agent fields.
# Live run 28598033404 found this breaks Flow 092's chain-scenario
# assertion, which (like all 5 other backends' Track B) identifies
# the sqlmap request by grep'ing the raw chain access log for the
# sqlmap User-Agent string — a field that simply isn't in the
# upstream format. Extending the shared upstream file was considered
# and rejected: it's consumed by the Docker battle suite's own CI,
# and this flow has no visibility into whether that suite's own
# chain assertions depend on the CURRENT (UA-less) format. Forking
# a flow-092-local copy keeps the blast radius to this one file.
#
# The only difference from the upstream file: the trailing
# `\"%{Referer}i\" \"%{User-Agent}i\"` fields are appended, matching
# the SAME full CLF-with-UA shape the direct-scenario's stock image
# already emits by default (and that apacheCLFPattern expects for
# 9-field parsing generally). Appending fields at the end of a CLF
# line is additive/safe for the parser — apacheCLFPattern's trailing
# groups are optional, existing consumers of the upstream file are
# unaffected because this is a SEPARATE file, not a shared edit.

CONF = '/usr/local/lsws/conf/templates/docker.conf'
MARKER = 'accesslog $SERVER_ROOT/logs/$VH_NAME.access.log {'
LOG_FORMAT_LINE = '    logFormat             "%{X-Forwarded-For}i %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\""\n'

content = open(CONF).read()
assert MARKER in content, f'Marker not found in {CONF} — OLS template changed?'
content = content.replace(MARKER, MARKER + '\n' + LOG_FORMAT_LINE)
open(CONF, 'w').write(content)
assert 'logFormat' in open(CONF).read(), 'Patch failed: logFormat not in config'
