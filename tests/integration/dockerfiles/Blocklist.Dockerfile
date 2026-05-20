# lighttpd serving downloaded blocklist pattern files for integration tests.
# Files are fetched from the real upstream source by run.sh before docker build,
# so this image contains the actual patterns sentinel will load at test runtime.
FROM lighttpd:latest
COPY blocklist/badbot-ua.list /var/www/localhost/htdocs/badbot-ua.list
COPY blocklist/badbot-ref.list /var/www/localhost/htdocs/badbot-ref.list
