
ACLOCAL_AMFLAGS = -I macros

CLEANFILES = *.a *.h *.o *.so *.slo *.lo *.la *.h *.dylib

SUBDIRS = tests

if LINUX
SHARED_EXT=so
endif
if OSX
SHARED_EXT=dylib
endif

all: coraza/core.h coraza/utils.h libcorazacore.a libcorazautils.a libcorazacore.$(SHARED_EXT) libcorazautils.$(SHARED_EXT)

coraza/core.h: libcoraza-core/core.go
	@mkdir -p coraza
	go tool cgo -exportheader $@ $<

coraza/utils.h: libcoraza-utils/utils.go
	@mkdir -p coraza
	go tool cgo -exportheader $@ $<

libcorazacore.a: libcoraza-core/core.go
	go build -buildmode=c-archive -o $@ $<

libcorazautils.a: libcoraza-utils/utils.go
	go build -buildmode=c-archive -o $@ $<

libcorazacore.$(SHARED_EXT): libcoraza-core/core.go
	go build -buildmode=c-shared -o $@ $<

libcorazautils.$(SHARED_EXT): libcoraza-utils/utils.go
	go build -buildmode=c-shared -o $@ $<

install-data-local: all test
	@INSTALL@ -d $(DESTDIR)@prefix@/lib
	@INSTALL@ -d $(DESTDIR)@prefix@/include/coraza
	@INSTALL@ libcorazacore.a $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcorazautils.a $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcorazacore.$(SHARED_EXT) $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcorazautils.$(SHARED_EXT) $(DESTDIR)@prefix@/lib/
	@INSTALL@ coraza/core.h $(DESTDIR)@prefix@/include/coraza/core.h
	@INSTALL@ coraza/utils.h $(DESTDIR)@prefix@/include/coraza/utils.h

.PHONY: docs
docs:
# build C header doxygen
	@doxygen ./Doxyfile

test:
	cd tests && $(MAKE) test
	@./tests/simple_get 2>&1>/dev/null

clean-local:
	cd tests && $(MAKE) clean
