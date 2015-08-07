lib_LTLIBRARIES = libstreamsecurity.la
libstreamsecurity_la_SOURCES = base64.c hmac.c json_util.c keys.c policy.c resource_request.c
libstreamsecurity_la_CFLAGS= -fpic
include_HEADERS = base64.h hmac.h json_util.h keys.h policy.h resource_request.h
EXTRA_DIST = stream_security.c stream-security-keys.json LICENSE NOTICES README.md
INCLUDES = -I@apache_dir@ -I@apr_dir@
install-exec-local:
	apxs -i -a -c $(srcdir)/stream_security.c -L.libs -lstreamsecurity -ljansson -lcrypto
