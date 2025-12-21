AUTOMAKE_OPTIONS = subdir-objects

ACLOCAL_AMFLAGS = -I macros

CLEANFILES = *.a *.h *.o *.so *.slo *.lo *.la *.h *.dylib

if LINUX
SHARED_EXT=so
endif
if OSX
SHARED_EXT=dylib
endif

all: coraza/coraza.h libcoraza.a libcoraza.$(SHARED_EXT)

coraza/coraza.h: libcoraza/coraza.go libcoraza/log.go
	@mkdir -p coraza
	go tool cgo -exportheader $@ $^

libcoraza.a: libcoraza/coraza.go libcoraza/log.go
	go build -buildmode=c-archive -o $@ $^

libcoraza.$(SHARED_EXT): libcoraza/coraza.go libcoraza/log.go
	go build -buildmode=c-shared -o $@ $^

install-data-local: all check
	@INSTALL@ -d $(DESTDIR)@prefix@/lib
	@INSTALL@ -d $(DESTDIR)@prefix@/include/coraza
	@INSTALL@ libcoraza.a $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcoraza.$(SHARED_EXT) $(DESTDIR)@prefix@/lib/
	@INSTALL@ coraza/coraza.h $(DESTDIR)@prefix@/include/coraza/coraza.h

.PHONY: docs
docs:
# build C header doxygen
	@doxygen ./Doxyfile

check_PROGRAMS = tests/simple_get

if OSX
AM_LDFLAGS = -framework CoreFoundation -framework Security
endif

if LINUX
AM_LDFLAGS = -fPIC -m64 -pthread -fno-common
endif

tests_simple_get_LDFLAGS = $(AM_LDFLAGS)
tests_simple_get_LDADD = ./libcoraza.a

check: tests/simple_get
	go test -race ./...
	cd tests && ./check_result.sh simple_get
