# Licensed to The Apereo Foundation under one or more contributor license
# agreements. See the NOTICE file distributed with this work for additional
# information regarding copyright ownership.
#
#
# The Apereo Foundation licenses this file to you under the Educational
# Community License, Version 2.0 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of the License
# at:
#
#   http://opensource.org/licenses/ecl2.txt
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

CC=gcc
CFLAGS=-c -Wall

SOURCES=base64.c hmac.c keys.c json_util.c policy.c resource_request.c
OBJECTS=.libs/base64.o .libs/hmac.o .libs/keys.o .libs/json_util.o .libs/policy.o .libs/resource_request.o
EXTERNAL_LIBS=-ljansson -lcrypto
TEST_EXECUTABLE=unit_tests
DEBUG_OBJECTS=*.expand *.sibling *.initvals *.unshare *.vregs *.into_cfglayout *.split1 *.jump *.reginfo *.outof_cfglayout *.dfinit *.mode_sw *.asmcons *.subregs_of_mode_init *.ira *.subregs_of_mode_finish *.split2 *.pro_and_epilogue *.stack *.alignments *.mach *.barriers *.eh_ranges *.shorten *.final *.dfinish
HTTPD_HEADERS=-I/usr/include/httpd -I/usr/include/apr-1
VERSION=1.0.1
DISTRIBUTION_FILE=stream-security-httpd-$(VERSION).tar.gz

all: library

install: 
	apxs -i -a -c stream_security.c -L. -lstreamsecurity -ljansson -lcrypto

test: 
	gcc -Wall -g -O0 -o $(TEST_EXECUTABLE) $(HTTPD_HEADERS) json_util.c keys.c hmac.c resource_request.c unit_tests.c base64.c policy.c -ljansson -lcrypto

base64.o:
	libtool --mode=compile gcc -g -O -Wall $(HTTPD_HEADERS) -c base64.c

hmac.o:
	libtool --mode=compile gcc -g -O0 -Wall $(HTTPD_HEADERS) -c hmac.c

keys.o:
	libtool --mode=compile gcc -g -O -Wall $(HTTPD_HEADERS) -c keys.c

json_util.o:
	libtool --mode=compile gcc -g -O -Wall $(HTTPD_HEADERS) -c json_util.c

policy.o:
	libtool --mode=compile gcc -g -O -Wall $(HTTPD_HEADERS) -c policy.c

resource_request.o:
	libtool --mode=compile gcc -g -O -Wall $(HTTPD_HEADERS) -c resource_request.c

library: base64.o hmac.o keys.o json_util.o policy.o resource_request.o
	ar -cvq libstreamsecurity.a $(OBJECTS)

zip:
	zip $(DISTRIBUTION_FILE) Makefile *.c *.h *.json

clean:
	rm -f *.o *.lo *.slo *.la *.a $(TEST_EXECUTABLE) $(DEBUG_OBJECTS) $(DISTRIBUTION_FILE)
