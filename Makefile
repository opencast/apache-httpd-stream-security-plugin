CC=gcc
CFLAGS=-c -Wall

SOURCES=base64.c hmac.c keys.c json_util.c policy.c resource_request.c
OBJECTS=.libs/base64.o .libs/hmac.o .libs/keys.o .libs/json_util.o .libs/policy.o .libs/resource_request.o
EXTERNAL_LIBS=-ljansson -lcrypto
EXECUTABLE=unit_tests

all: module

notright: stream_security.o json_util.o hmac.o resource_request.o unit_tests.o base64.o policy.o
	apxs -i -a -c stream_security.c json_util.c keys.c hmac.c resource_request.c unit_tests.c base64.c policy.c -ljansson -lcrypto

module: library
	apxs -i -a -c stream_security.c -L. -lstreamsecurity -ljansson -lcrypto

test: 
	gcc -Wall -g -O0 -o unit_tests json_util.c keys.c hmac.c resource_request.c unit_tests.c base64.c policy.c -ljansson -lcrypto

base64.o:
	libtool --mode=compile gcc -g -O -Wall -c base64.c

hmac.o:
	libtool --mode=compile gcc -g -O -Wall -c hmac.c

keys.o:
	libtool --mode=compile gcc -g -O -Wall -c keys.c

json_util.o:
	libtool --mode=compile gcc -g -O -Wall -c json_util.c

policy.o:
	libtool --mode=compile gcc -g -O -Wall -c policy.c

resource_request.o:
	libtool --mode=compile gcc -g -O -Wall -c resource_request.c

library: base64.o hmac.o keys.o json_util.o policy.o resource_request.o
	ar -cvq libstreamsecurity.a $(OBJECTS)

clean:
	rm -f *.o *.lo *.slo *.la *.a $(EXECUTABLE) *.expand *.sibling *.initvals *.unshare *.vregs *.into_cfglayout *.split1 *.jump *.reginfo *.outof_cfglayout *.dfinit *.mode_sw *.asmcons *.subregs_of_mode_init *.ira *.subregs_of_mode_finish *.split2 *.pro_and_epilogue *.stack *.alignments *.mach *.barriers *.eh_ranges *.shorten *.final *.dfinish
