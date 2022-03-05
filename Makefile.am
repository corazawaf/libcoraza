
ACLOCAL_AMFLAGS = -I macros

CLEANFILES = *.o *.so *.slo *.lo *.la *.h *.dylib

if LINUX
SHARED_EXT=so
endif
if OSX
SHARED_EXT=dynlib
endif

all: build

build:
	CC=@CC@ go build -buildmode=c-archive -o libcorazacore.a libcoraza-core/core.go
	CC=@CC@ go build -buildmode=c-archive -o libcorazautils.a libcoraza-utils/utils.go
	CC=@CC@ go build -buildmode=c-shared -o libcorazacore.$(SHARED_EXT) libcoraza-core/core.go
	CC=@CC@ go build -buildmode=c-shared -o libcorazautils.$(SHARED_EXT) libcoraza-utils/utils.go
	mv libcorazacore.h coraza_core.h
	mv libcorazautils.h coraza_utils.h

install-data-local:
	@INSTALL@ -d $(DESTDIR)@prefix@/lib
	@INSTALL@ -d $(DESTDIR)@prefix@/include
	@INSTALL@ libcorazacore.a $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcorazautils.a $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcorazacore.$(SHARED_EXT) $(DESTDIR)@prefix@/lib/
	@INSTALL@ libcorazautils.$(SHARED_EXT) $(DESTDIR)@prefix@/lib/
	@INSTALL@ coraza_core.h $(DESTDIR)@prefix@/include/
	@INSTALL@ coraza_utils.h $(DESTDIR)@prefix@/include/

test: build
	cd tests && make test

.PHONY: docs
docs:
# build C header doxygen
	@doxygen ./Doxyfile

clean-local:
	cd tests && make clean
